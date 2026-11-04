#!/usr/bin/env python3
# Copyright (c) 2026 Arista Networks, Inc.  All rights reserved.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.
# FOR INTERNAL USE ONLY. NOT FOR DISTRIBUTION.

"""Exercise request-scoped CA filtering without changing system trust."""

import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import os
from pathlib import Path
import select
import socket
from socketserver import StreamRequestHandler, ThreadingTCPServer
import ssl
import subprocess
import sys
import threading
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


try:
    import requests as real_requests
except ImportError:
    try:
        from pip._vendor import requests as real_requests
    except ImportError:
        real_requests = None


SCRIPT = Path(__file__).resolve().parents[1] / "BootstrapScriptWithToken/bootstrap.py"


def load_bootstrap(requests_module=None):
    """Load the script without EOS packages or executing its main entrypoint."""
    spec = importlib.util.spec_from_file_location("bootstrap_ca_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sysdb = types.ModuleType("SysdbHelperUtils")
    sysdb.SysdbPathHelper = object
    if requests_module is None:
        requests_module = types.ModuleType("requests")
        requests_module.certs = types.SimpleNamespace(where=Mock())
        requests_module.exceptions = types.SimpleNamespace(RequestException=RuntimeError)
        requests_module.post = Mock()
        requests_module.get = Mock()
    with patch.dict(sys.modules, {
        "Cell": types.ModuleType("Cell"),
        "requests": requests_module,
        "SysdbHelperUtils": sysdb,
    }):
        spec.loader.exec_module(module)
    return module


def fingerprint(certificate):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()


@unittest.skipUnless(os.path.isfile("/usr/bin/openssl"), "OpenSSL is required")
class CaTrustTest(unittest.TestCase):
    """Filtering writes only private files; the source trust bundle stays unchanged."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory()
        directory = Path(cls.fixtures.name)
        (directory / "root.cnf").write_text(
            "[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\n"
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n")
        for name in ("affected", "unrelated"):
            subprocess.run([
                "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=" + name,
                "-config", str(directory / "root.cnf"), "-extensions", "v3_ca",
                "-keyout", str(directory / (name + ".key")),
                "-out", str(directory / (name + ".pem")),
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # A second issuer signs the same public key, changing the certificate fingerprint.
        subprocess.run([
            "/usr/bin/openssl", "req", "-new", "-key", str(directory / "affected.key"),
            "-subj", "/CN=affected", "-out", str(directory / "cross.csr"),
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run([
            "/usr/bin/openssl", "x509", "-req", "-in", str(directory / "cross.csr"),
            "-CA", str(directory / "unrelated.pem"),
            "-CAkey", str(directory / "unrelated.key"), "-set_serial", "2", "-days", "1",
            "-out", str(directory / "cross.pem"),
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (directory / "leaf.ext").write_text(
            "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n"
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        for name in ("affected", "unrelated"):
            subprocess.run([
                "/usr/bin/openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=127.0.0.1", "-keyout", str(directory / (name + "-leaf.key")),
                "-out", str(directory / (name + "-leaf.csr")),
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run([
                "/usr/bin/openssl", "x509", "-req", "-in", str(directory / (name + "-leaf.csr")),
                "-CA", str(directory / (name + ".pem")),
                "-CAkey", str(directory / (name + ".key")), "-set_serial", "3", "-days", "1",
                "-extfile", str(directory / "leaf.ext"),
                "-out", str(directory / (name + "-leaf.pem")),
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.affected = (directory / "affected.pem").read_text()
        cls.unrelated = (directory / "unrelated.pem").read_text()
        cls.cross_signed = (directory / "cross.pem").read_text()

    @classmethod
    def tearDownClass(cls):
        cls.fixtures.cleanup()

    def setUp(self):
        self.bootstrap = load_bootstrap()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.bundle = self.directory / "ca-bundle.crt"
        self.bundle.write_text(self.affected + self.unrelated)
        self.bootstrap.requests.certs.where.return_value = str(self.bundle)
        self.bootstrap.DISTRUSTED_ROOT_FINGERPRINTS = {fingerprint(self.affected)}
        self.bootstrap.DISTRUSTED_SPKI_HASHES = set()
        self.start_patch(patch.dict(os.environ))
        os.environ.pop("REQUESTS_CA_BUNDLE", None)
        os.environ.pop("CURL_CA_BUNDLE", None)
        self.environment = dict(os.environ)
        self.log = self.start_patch(patch.object(self.bootstrap, "log"))
        self.created = []
        self.addCleanup(self.cleanup_bundles)

    def start_patch(self, patcher):
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def cleanup_bundles(self):
        for path in self.created:
            if os.path.exists(path):
                os.unlink(path)

    def create_bundle(self):
        result = self.bootstrap.createBootstrapCaBundle()
        self.created.append(result)
        return result

    def test_filter_preserves_source_environment_and_unrelated_roots(self):
        filtered = Path(self.create_bundle())
        self.assertEqual(filtered.read_text(), self.unrelated)
        self.assertEqual(filtered.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.bundle.read_text(), self.affected + self.unrelated)
        self.assertEqual(dict(os.environ), self.environment)

    def test_repeated_creation_and_already_absent_roots(self):
        first = self.create_bundle()
        second = self.create_bundle()
        self.assertNotEqual(first, second)
        self.assertEqual(Path(first).read_bytes(), Path(second).read_bytes())
        self.bundle.write_text(self.unrelated)
        self.assertEqual(Path(self.create_bundle()).read_text(), self.unrelated)

    def test_direct_trust_matches_cross_signed_public_key(self):
        self.bootstrap.DISTRUSTED_ROOT_FINGERPRINTS = set()
        public_key = self.bootstrap.runCertificateCommand(
            ["/usr/bin/openssl", "x509", "-pubkey", "-noout"], self.affected.encode("ascii"))
        spki = self.bootstrap.runCertificateCommand(
            ["/usr/bin/openssl", "pkey", "-pubin", "-outform", "DER"], public_key)
        self.bootstrap.DISTRUSTED_SPKI_HASHES = {hashlib.sha256(spki).hexdigest()}
        self.bundle.write_text(self.affected + self.cross_signed + self.unrelated)
        self.assertEqual(Path(self.create_bundle()).read_text(), self.unrelated)

    def test_environment_ca_override_is_filtered_without_mutation(self):
        alternate = self.directory / "alternate.pem"
        alternate.write_text(self.unrelated)
        for variable in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            with self.subTest(variable=variable), patch.dict(os.environ, {variable: str(alternate)}):
                self.assertEqual(Path(self.create_bundle()).read_text(), self.unrelated)
                self.assertEqual(os.environ[variable], str(alternate))

    def test_setup_errors_are_fatal(self):
        for contents in ("", "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
                         self.affected):
            with self.subTest(contents=contents):
                self.bundle.write_text(contents)
                with self.assertRaises(Exception):
                    self.bootstrap.prepareBootstrapCaBundle()
        self.bundle.unlink()
        with self.assertRaises(OSError):
            self.bootstrap.prepareBootstrapCaBundle()
        self.assertEqual(dict(os.environ), self.environment)
        self.assertIn("aborting ZTP", self.log.call_args.args[0])

    def test_missing_openssl_is_fatal(self):
        with patch.object(self.bootstrap.subprocess, "Popen", side_effect=OSError("no OpenSSL")):
            with self.assertRaisesRegex(OSError, "no OpenSSL"):
                self.bootstrap.prepareBootstrapCaBundle()
        self.assertEqual(dict(os.environ), self.environment)

    def test_temporary_bundle_creation_failure_is_fatal(self):
        with patch.object(self.bootstrap.tempfile, "mkstemp", side_effect=OSError("no space")):
            with self.assertRaisesRegex(OSError, "no space"):
                self.bootstrap.prepareBootstrapCaBundle()
        self.assertIn("aborting ZTP", self.log.call_args.args[0])

    def test_cloud_run_cleans_bundle_on_success_and_error(self):
        for error in (None, RuntimeError("bootstrap failure"), SystemExit(1)):
            with self.subTest(error=error):
                manager = object.__new__(self.bootstrap.CloudBootstrapManager)
                paths = []

                def parent_run(instance):
                    paths.append(instance.requestCaBundle)
                    self.assertTrue(os.path.isfile(instance.requestCaBundle))
                    if error is not None:
                        raise error

                with patch.object(self.bootstrap.BootstrapManager, "run", new=parent_run):
                    if error is None:
                        manager.run()
                    else:
                        with self.assertRaises(type(error)):
                            manager.run()
                self.assertFalse(os.path.exists(paths[0]))
                self.assertIsNone(manager.requestCaBundle)

    def test_setup_failure_stops_before_enrollment_requests_or_execution(self):
        manager = object.__new__(self.bootstrap.CloudBootstrapManager)
        with patch.object(self.bootstrap, "createBootstrapCaBundle",
                          side_effect=RuntimeError("CA filtering failed")), \
                patch.object(manager, "getClientCertificates") as enroll, \
                patch.object(manager, "executeBootstrap") as execute:
            with self.assertRaisesRegex(RuntimeError, "CA filtering failed"):
                manager.run()
        enroll.assert_not_called()
        self.bootstrap.requests.post.assert_not_called()
        self.bootstrap.requests.get.assert_not_called()
        execute.assert_not_called()

    def test_private_file_cleanup_failure_is_best_effort(self):
        manager = object.__new__(self.bootstrap.CloudBootstrapManager)
        filtered = self.create_bundle()
        with patch.object(self.bootstrap, "prepareBootstrapCaBundle", return_value=filtered), \
                patch.object(self.bootstrap.BootstrapManager, "run"), \
                patch.object(os, "unlink", side_effect=OSError("cleanup denied")):
            manager.run()
        self.assertIsNone(manager.requestCaBundle)
        self.assertIn("Could not remove private", self.log.call_args.args[0])

    def test_on_prem_does_not_prepare_private_trust(self):
        manager = object.__new__(self.bootstrap.OnPremBootstrapManager)
        with contextlib.ExitStack() as stack:
            prepare = stack.enter_context(patch.object(self.bootstrap, "prepareBootstrapCaBundle"))
            for method in ("checkWithRedirector", "getClientCertificates", "getCertificatePaths",
                           "getBootstrapScript", "executeBootstrap"):
                stack.enter_context(patch.object(manager, method))
            manager.run()
        prepare.assert_not_called()

    def test_both_requests_use_private_bundle_and_preserve_client_identity(self):
        manager = object.__new__(self.bootstrap.CloudBootstrapManager)
        manager.requestCaBundle = self.create_bundle()
        manager.bootstrapURL = self.bootstrap.urlparse("https://www.arista.io/ztp/bootstrap")
        manager.redirectorURL = self.bootstrap.urlparse("https://www.arista.io/redirector")
        manager.mibStatus = types.SimpleNamespace(
            systemMacAddr="00:11:22:33:44:55",
            root=types.SimpleNamespace(serialNum="serial", modelName="model", hardwareRev="rev"))
        manager.cellID = "cell"
        manager.pathHelper = Mock()
        manager.pathHelper.getEntity.side_effect = RuntimeError("no TPM")
        manager.certificate, manager.key = "device.crt", "device.key"
        self.bootstrap.requests.post.return_value.json.return_value = [{"value": {
            "clusters": {"values": [{"hosts": {"values": ["www.arista.io"]}}]}}}]
        self.bootstrap.requests.get.return_value.text = "bootstrap instructions"
        with patch.object(self.bootstrap, "BOOT_SCRIPT_PATH", str(self.directory / "download")), \
                patch.object(self.bootstrap, "getKeyValueFromFile", return_value="value"):
            manager.checkWithRedirector()
            manager.getBootstrapScript()
        self.assertEqual(self.bootstrap.requests.post.call_args.kwargs["verify"], manager.requestCaBundle)
        self.assertEqual(self.bootstrap.requests.get.call_args.kwargs["verify"], manager.requestCaBundle)
        self.assertEqual(self.bootstrap.requests.get.call_args.kwargs["cert"], ("device.crt", "device.key"))

    def test_certificate_failure_does_not_retry_with_default_roots(self):
        manager = object.__new__(self.bootstrap.CloudBootstrapManager)
        manager.requestCaBundle = self.create_bundle()
        manager.redirectorURL = self.bootstrap.urlparse("https://www.arista.io/redirector")
        manager.mibStatus = types.SimpleNamespace(root=types.SimpleNamespace(serialNum="serial"))
        self.bootstrap.requests.post.side_effect = RuntimeError("certificate verification failed")
        with self.assertRaisesRegex(Exception, "certificate verification failed"):
            manager.checkWithRedirector()
        self.bootstrap.requests.post.assert_called_once()
        self.assertEqual(self.bootstrap.requests.post.call_args.kwargs["verify"], manager.requestCaBundle)

    @contextlib.contextmanager
    def https_server(self, name, require_client_cert=False):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        fixtures = Path(self.fixtures.name)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(fixtures / (name + "-leaf.pem")),
                                str(fixtures / (name + "-leaf.key")))
        if require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=str(fixtures / "unrelated.pem"))
        server = HTTPServer(("127.0.0.1", 0), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever)
        worker.daemon = True
        worker.start()
        try:
            yield "https://127.0.0.1:{port}/".format(port=server.server_port)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    @contextlib.contextmanager
    def connect_proxy(self, target):
        target_port = int(target.split(":")[2].strip("/"))

        class Handler(StreamRequestHandler):
            def handle(self):
                if not self.rfile.readline().startswith(b"CONNECT "):
                    return
                while self.rfile.readline().strip():
                    pass
                with socket.create_connection(("127.0.0.1", target_port), timeout=5) as upstream:
                    self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    self.wfile.flush()
                    peers = (self.connection, upstream)
                    while True:
                        ready, _, _ = select.select(peers, [], [], 5)
                        if not ready:
                            return
                        for source in ready:
                            try:
                                data = source.recv(65536)
                                if not data:
                                    return
                                destination = upstream if source is self.connection else self.connection
                                destination.sendall(data)
                            except (ConnectionResetError, BrokenPipeError):
                                # A peer closes the tunnel when certificate verification fails.
                                return

        server = ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever)
        worker.daemon = True
        worker.start()
        try:
            yield "http://127.0.0.1:{port}".format(port=server.server_address[1])
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    @unittest.skipUnless(real_requests is not None, "Requests is required for TLS tests")
    def test_requests_rejects_removed_root_without_readding_environment_bundle(self):
        filtered = self.create_bundle()
        with self.https_server("affected") as url:
            response = real_requests.get(url, verify=str(self.bundle), timeout=5,
                                         proxies={"http": "", "https": ""})
            self.assertEqual(response.status_code, 200)
            with patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": str(self.bundle)}):
                with self.assertRaisesRegex(real_requests.exceptions.SSLError,
                                            "(?i)(unable to get local issuer|self.signed|unable to verify)"):
                    real_requests.get(url, verify=filtered, timeout=5,
                                      proxies={"http": "", "https": ""})

    @unittest.skipUnless(real_requests is not None, "Requests is required for TLS tests")
    def test_requests_accepts_allowed_root_and_preserves_mutual_tls(self):
        filtered = self.create_bundle()
        fixtures = Path(self.fixtures.name)
        with self.https_server("unrelated", require_client_cert=True) as url:
            response = real_requests.get(
                url, verify=filtered, timeout=5, proxies={"http": "", "https": ""},
                cert=(str(fixtures / "unrelated-leaf.pem"), str(fixtures / "unrelated-leaf.key")))
            self.assertEqual(response.status_code, 200)

    @unittest.skipUnless(real_requests is not None, "Requests is required for TLS tests")
    def test_requests_still_checks_hostname(self):
        filtered = self.create_bundle()
        with self.https_server("unrelated") as url:
            with self.assertRaisesRegex(real_requests.exceptions.SSLError,
                                        "(?i)(hostname mismatch|not valid for|doesn't match)"):
                real_requests.get(url.replace("127.0.0.1", "localhost"), verify=filtered,
                                  timeout=5, proxies={"http": "", "https": ""})

    @unittest.skipUnless(real_requests is not None, "Requests is required for TLS tests")
    def test_requests_uses_filtered_bundle_through_http_proxy(self):
        filtered = self.create_bundle()
        with self.https_server("affected") as url, self.connect_proxy(url) as proxy:
            response = real_requests.get(url, verify=str(self.bundle), timeout=5,
                                         proxies={"http": proxy, "https": proxy})
            self.assertEqual(response.status_code, 200)
            with self.assertRaisesRegex(real_requests.exceptions.SSLError,
                                        "(?i)(unable to get local issuer|self.signed|unable to verify)"):
                real_requests.get(url, verify=filtered, timeout=5,
                                  proxies={"http": proxy, "https": proxy})


if __name__ == "__main__":
    unittest.main()
