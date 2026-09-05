import http.client
import socket
import time
import unittest
from email.message import Message

from nvlx.http_v16666666663311234567567851234456567 import HealthServer, _request_grpc_status_details_bin_nomination_is_safe


class _MetricsRuntime:
    def __init__(self):
        self.calls = 0

    def metrics_diagnosis(self):
        self.calls += 1
        raise RuntimeError("should not be reached for Grpc-Status-Details-Bin Connection-nomination requests")


class GrpcStatusDetailsBinConnectionNominationContainmentTests(unittest.TestCase):
    @staticmethod
    def raw_request(server, payload: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", server.httpd.server_port), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            response = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
            return response

    @staticmethod
    def wait_for_slots(server, expected: int, timeout: float = 1.5) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if getattr(server._request_slots, "_value", None) == expected:
                return
            time.sleep(0.005)
        raise AssertionError("request slot value did not recover")

    def test_helper_accepts_field_and_nonmatching_connection_options(self):
        for name, value in ((None, None), ("Grpc-Status-Details-Bin", "AQID"), ("Connection", "grpc-status-details-bin-x"), ("Connection", "keep-alive, x-custom")):
            with self.subTest(name=name, value=value):
                headers = Message()
                if name is not None:
                    headers[name] = value
                self.assertTrue(_request_grpc_status_details_bin_nomination_is_safe(headers))

    def test_helper_rejects_exact_nomination_case_insensitively(self):
        for value in ("grpc-status-details-bin", "Grpc-Status-Details-Bin", "GrPc-MeSsAgE", "keep-alive, grpc-status-details-bin"):
            with self.subTest(value=value):
                headers = Message()
                headers["Connection"] = value
                self.assertFalse(_request_grpc_status_details_bin_nomination_is_safe(headers))

    def test_helper_keeps_inherited_fail_closed_contract(self):
        self.assertFalse(_request_grpc_status_details_bin_nomination_is_safe({}))
        headers = Message()
        headers["Connection"] = "grpc-message"
        self.assertFalse(_request_grpc_status_details_bin_nomination_is_safe(headers))

    def test_ordinary_header_remains_accepted(self):
        server = HealthServer(object(), "127.0.0.1", 0).start()
        try:
            response = self.raw_request(server, b"GET /livez HTTP/1.1\r\nHost: localhost\r\nGrpc-Status-Details-Bin: AQID\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.0 200 OK\r\n"))
            self.assertTrue(response.endswith(b"ok\n"))
        finally:
            server.close()

    def test_nomination_is_terminal_400_before_runtime(self):
        runtime = _MetricsRuntime()
        server = HealthServer(runtime, "127.0.0.1", 0).start()
        try:
            response = self.raw_request(server, b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: grpc-status-details-bin\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.0 400 Request Rejected\r\n"))
            self.assertIn(b"Connection: close\r\n", response)
            self.assertTrue(response.endswith(b"request rejected\n"))
            self.assertEqual(runtime.calls, 0)
        finally:
            server.close()

    def test_nomination_lookalike_remains_accepted(self):
        server = HealthServer(object(), "127.0.0.1", 0).start()
        try:
            response = self.raw_request(server, b"GET /livez HTTP/1.1\r\nHost: localhost\r\nConnection: grpc-status-details-bin-x\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.0 200 OK\r\n"))
        finally:
            server.close()

    def test_http_10_nomination_is_also_rejected(self):
        server = HealthServer(object(), "127.0.0.1", 0).start()
        try:
            response = self.raw_request(server, b"GET /livez HTTP/1.0\r\nConnection: Grpc-Status-Details-Bin\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.0 400 Request Rejected\r\n"))
        finally:
            server.close()

    def test_expect_gate_retains_precedence(self):
        server = HealthServer(object(), "127.0.0.1", 0).start()
        try:
            response = self.raw_request(server, b"GET /livez HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nConnection: grpc-status-details-bin\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.0 417 Request Rejected\r\n"))
            self.assertNotIn(b"100 Continue", response)
        finally:
            server.close()

    def test_grpc_message_gate_retains_precedence(self):
        server = HealthServer(object(), "127.0.0.1", 0).start()
        try:
            response = self.raw_request(server, b"GET /livez HTTP/1.1\r\nHost: localhost\r\nConnection: grpc-message, grpc-status-details-bin\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.0 400 Request Rejected\r\n"))
            self.assertEqual(response.count(b"HTTP/1.0 "), 1)
        finally:
            server.close()

    def test_nomination_rejection_head_is_bodyless(self):
        server = HealthServer(object(), "127.0.0.1", 0).start()
        try:
            response = self.raw_request(server, b"HEAD /livez HTTP/1.1\r\nHost: localhost\r\nConnection: grpc-status-details-bin\r\n\r\n")
            head, body = response.split(b"\r\n\r\n", 1)
            self.assertTrue(head.startswith(b"HTTP/1.0 400 Request Rejected\r\n"))
            self.assertIn(b"Content-Length: 17\r\n", head + b"\r\n")
            self.assertIn(b"Connection: close\r\n", head + b"\r\n")
            self.assertEqual(body, b"")
        finally:
            server.close()

    def test_nomination_rejection_terminates_pipeline(self):
        server = HealthServer(object(), "127.0.0.1", 0).start()
        try:
            response = self.raw_request(server, b"GET /livez HTTP/1.1\r\nHost: localhost\r\nConnection: grpc-status-details-bin\r\n\r\nGET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(response.count(b"HTTP/1.0 "), 1)
            self.assertNotIn(b"200 OK", response)
        finally:
            server.close()

    def test_nomination_releases_capacity_and_recovers(self):
        server = HealthServer(object(), "127.0.0.1", 0, max_concurrent_requests=1).start()
        try:
            response = self.raw_request(server, b"GET /livez HTTP/1.1\r\nHost: localhost\r\nConnection: grpc-status-details-bin\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.0 400 Request Rejected\r\n"))
            self.wait_for_slots(server, 1)
            connection = http.client.HTTPConnection("127.0.0.1", server.httpd.server_port, timeout=2)
            try:
                connection.request("GET", "/livez")
                live = connection.getresponse()
                self.assertEqual(live.status, 200)
                self.assertEqual(live.read(), b"ok\n")
            finally:
                connection.close()
        finally:
            server.close()

    def test_inherited_ingress_defaults_are_unchanged(self):
        server = HealthServer(object(), "127.0.0.1", 0)
        try:
            self.assertEqual(server.max_request_header_fields, 32)
            self.assertEqual(server.max_request_line_bytes, 8192)
            self.assertEqual(server.max_request_header_bytes, 32768)
            self.assertEqual(server.request_header_deadline_seconds, 5.0)
            self.assertEqual(server.request_timeout_seconds, 5.0)
            self.assertEqual(server.max_concurrent_requests, 32)
        finally:
            server.httpd.server_close()


if __name__ == "__main__":
    unittest.main()
