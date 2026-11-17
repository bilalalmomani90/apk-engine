"""Tests for server.py. Run from this folder:  python3 -m unittest -v test_server

They use a FAKE runner, so they prove the web layer (limits, privacy, queue,
cleanup, headers), not real builds and not real Docker.
"""
import http.client
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import server as srv

ZIP = b"PK\x03\x04" + b"\0" * 100
APK = b"PK\x03\x04fake-apk-bytes"


class FakeRunner:
    def __init__(self, delay=0.0, gate=None):
        self.delay, self.gate, self.seen = delay, gate, []

    def run(self, job, cfg):
        self.seen.append(job.upload.exists())
        if self.gate:
            self.gate.wait(10)
        time.sleep(self.delay)
        apks = job.out / "apks"
        apks.mkdir(parents=True, exist_ok=True)
        (apks / "app__debug__app-debug.apk").write_bytes(APK)
        (job.work).mkdir(exist_ok=True)
        (job.work / "scratch.txt").write_text("x")
        return {"status": "success", "stage": "done", "warnings": [],
                "apks": [{"name": "app__debug__app-debug.apk", "path": "/secret/host/path/x.apk",
                          "size": len(APK), "sha256": "ab" * 32, "primary": True}],
                "timings": {"build_seconds": 1.5}, "internal": "/secret/host/path"}


class Base(unittest.TestCase):
    def start(self, runner=None, **cfgkw):
        self.tmp = tempfile.mkdtemp()
        cfg = srv.Config(host="127.0.0.1", port=0, data_dir=Path(self.tmp), **cfgkw)
        self.runner = runner or FakeRunner()
        self.httpd, self.mgr = srv.make_server(cfg, self.runner)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.stop)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.mgr.close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def upload(self, body=ZIP):
        r, d = self.req("POST", "/api/jobs", body, {"Content-Type": "application/zip"})
        return r, (json.loads(d) if d and d[:1] == b"{" else d)

    def wait(self, jid, states=("success", "failed", "rejected"), timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            r, d = self.req("GET", f"/api/jobs/{jid}")
            j = json.loads(d)
            if j["status"] in states:
                return j
            time.sleep(0.05)
        self.fail("timeout waiting for job")


class TestLifecycle(Base):
    def test_full_flow_and_cleanup(self):
        self.start(job_ttl_min=1)
        r, j = self.upload()
        self.assertEqual(r.status, 202)
        jid = j["id"]
        done = self.wait(jid)
        self.assertEqual(done["status"], "success")
        self.assertEqual(self.runner.seen, [True])                       # runner saw the upload
        job = self.mgr.jobs[jid]
        self.assertFalse(job.upload.exists())                            # input deleted right after the build
        self.assertFalse(job.work.exists())                              # scratch deleted
        name = done["apks"][0]["name"]
        r, data = self.req("GET", f"/api/jobs/{jid}/apks/{name}")
        self.assertEqual((r.status, data), (200, APK))
        self.assertEqual(r.getheader("Content-Type"), "application/vnd.android.package-archive")
        self.assertIn("attachment", r.getheader("Content-Disposition"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        # TTL cleanup
        job.finished = time.time() - 3600
        end = time.time() + 20
        while time.time() < end and jid in self.mgr.jobs:
            time.sleep(0.2)
        self.assertNotIn(jid, self.mgr.jobs)
        self.assertFalse(job.dir.exists())
        self.assertEqual(self.req("GET", f"/api/jobs/{jid}")[0].status, 404)

    def test_no_server_paths_leak(self):
        self.start()
        r, j = self.upload()
        done = self.wait(j["id"])
        text = json.dumps(done)
        self.assertNotIn("/secret", text)
        self.assertNotIn("path", done["apks"][0])
        self.assertNotIn("internal", done)

    def test_page_and_headers(self):
        self.start()
        r, body = self.req("GET", "/")
        self.assertEqual(r.status, 200)
        self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
        self.assertIn("lang=\"ar\"", body.decode())
        for p in ("/app.js", "/style.css", "/healthz", "/api/config"):
            self.assertEqual(self.req("GET", p)[0].status, 200, p)


class TestPrivacy(Base):
    def test_ids_and_paths(self):
        self.start()
        r, a = self.upload()
        self.wait(a["id"])
        r, b = self.upload()
        self.wait(b["id"])
        name = "app__debug__app-debug.apk"
        self.assertEqual(self.req("GET", f"/api/jobs/{a['id']}/apks/{name}")[0].status, 200)
        for bad in ("/api/jobs/short", "/api/jobs/" + "A" * 24, "/api/jobs/../../etc/passwd",
                    f"/api/jobs/{a['id']}/apks/..%2f..%2fupload.zip", f"/api/jobs/{a['id']}/apks/other.apk",
                    f"/api/jobs/{a['id']}/apks/", "/api/jobs", "/api/jobs/"):
            self.assertEqual(self.req("GET", bad)[0].status, 404, bad)
        self.assertNotEqual(a["id"], b["id"])
        self.assertGreaterEqual(len(a["id"]), 22)

    def test_methods(self):
        self.start()
        self.assertEqual(self.req("DELETE", "/api/jobs/x")[0].status, 405)
        self.assertEqual(self.req("PUT", "/api/jobs")[0].status, 405)


class TestUploadRules(Base):
    def test_rejections(self):
        self.start(max_upload_mb=1)
        r, j = self.upload(b"not a zip, just text that is long enough to pass the size floor")
        self.assertEqual((r.status, j["error"]["code"]), (400, "ZIP_INVALID"))
        r, j = self.upload(b"PK\x03\x04" + b"\0" * (2 * 1024 * 1024))
        self.assertEqual((r.status, j["error"]["code"]), (413, "TOO_LARGE"))
        r, j = self.upload(b"PK")
        self.assertEqual(r.status, 400)
        self.assertEqual(len(self.mgr.jobs), 0)                          # nothing left behind

    def test_length_required(self):
        self.start()
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(b"POST /api/jobs HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        self.assertIn(b" 411 ", s.recv(4096).split(b"\r\n")[0] + b" ")
        s.close()

    def test_rate_limit(self):
        self.start(rate_per_hour=2)
        self.assertEqual(self.upload()[0].status, 202)
        self.assertEqual(self.upload()[0].status, 202)
        r, j = self.upload()
        self.assertEqual((r.status, j["error"]["code"]), (429, "RATE_LIMITED"))

    def test_truncated_body_is_discarded(self):
        self.start()
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(b"POST /api/jobs HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\nPK\x03\x04abc")
        s.shutdown(socket.SHUT_WR)
        time.sleep(0.5)
        s.close()
        end = time.time() + 5
        while time.time() < end and self.mgr.jobs:
            time.sleep(0.1)
        self.assertEqual(len(self.mgr.jobs), 0)


class TestQueue(Base):
    def test_busy_and_position(self):
        gate = threading.Event()
        self.start(runner=FakeRunner(gate=gate), max_concurrent=1, queue_max=1, rate_per_hour=100)
        r1, a = self.upload()                      # running (blocked)
        time.sleep(0.3)
        r2, b = self.upload()                      # queued
        r3, c = self.upload()                      # rejected: queue full
        self.assertEqual((r1.status, r2.status, r3.status), (202, 202, 503))
        self.assertEqual(c["error"]["code"], "BUSY")
        r, d = self.req("GET", f"/api/jobs/{b['id']}")
        v = json.loads(d)
        self.assertEqual((v["status"], v["position"]), ("queued", 1))
        gate.set()
        self.assertEqual(self.wait(a["id"])["status"], "success")
        self.assertEqual(self.wait(b["id"])["status"], "success")


class TestDockerCommand(unittest.TestCase):
    def test_flags(self):
        import os
        cfg = srv.Config(data_dir=Path(tempfile.mkdtemp()), docker_network="apknet", docker_memory="4g")
        job = srv.Job("abcDEF123_-xyzABCDEF12", cfg.data_dir)
        cmd = srv.DockerRunner().command(job, cfg)
        joined = " ".join(cmd)
        for must in ("--rm", "--cap-drop ALL", "no-new-privileges", "--memory 4g", "--memory-swap 4g",
                     "--pids-limit", "--network apknet", ":/in/project.zip:ro"):
            self.assertIn(must, joined)
        for never in ("--privileged", "docker.sock", "--network host", "--cap-add", " -e GITHUB", "TOKEN"):
            self.assertNotIn(never, joined)
        import re
        self.assertIsNone(re.search(r"--pid(?!s)", joined))              # no host PID namespace
        user = cmd[cmd.index("--user") + 1]
        self.assertNotEqual(user.split(":")[0], "0")                     # never root
        self.assertIn("python3", cmd)


class TestSanitize(unittest.TestCase):
    def test_unknown_status_becomes_failed(self):
        self.assertEqual(srv.sanitize({"status": "weird"})["status"], "failed")

    def test_bad_apk_names_dropped(self):
        r = srv.sanitize({"status": "success", "apks": [
            {"name": "../x.apk", "size": 1, "sha256": "a"}, {"name": "ok.apk", "size": 1, "sha256": "a"}]})
        self.assertEqual([a["name"] for a in r["apks"]], ["ok.apk"])


if __name__ == "__main__":
    unittest.main()
