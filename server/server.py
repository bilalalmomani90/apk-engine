#!/usr/bin/env python3
"""APK builder web service. One job only: upload a ZIP, build, download the APK.

Python 3.9+, standard library only. Run it behind an HTTPS reverse proxy.

Security model (what this file does):
  * A job id is an unguessable capability (128+ bits); there is no job listing.
  * Raw-body upload with a hard size cap, ZIP magic check, per-IP rate limit,
    bounded queue, and files deleted after the build / after a TTL.
  * Builds run through a Runner. The default DockerRunner starts one container
    per build (no root, all capabilities dropped, memory/CPU/pids limits).
    LocalRunner is NOT isolated and exists for development only.
  * Only whitelisted fields leave the server (no filesystem paths).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,40}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
TERMINAL = {"success", "failed", "rejected"}
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                               "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 8080
    data_dir: Path = Path("./data")
    web_dir: Path = HERE / "web"
    max_upload_mb: int = 100
    max_concurrent: int = 1
    queue_max: int = 10
    rate_per_hour: int = 5
    job_ttl_min: int = 60
    build_timeout: int = 1500
    runner: str = "docker"
    docker_image: str = "apkengine-builder:latest"
    docker_memory: str = "6g"
    docker_cpus: str = "2"
    docker_network: str = "bridge"
    docker_user: str = ""
    trust_proxy: bool = False


def config_from_env(env=os.environ) -> Config:
    g = env.get
    return Config(
        host=g("HOST", "127.0.0.1"), port=int(g("PORT", "8080")),
        data_dir=Path(g("DATA_DIR", "./data")),
        max_upload_mb=int(g("MAX_UPLOAD_MB", "100")), max_concurrent=int(g("MAX_CONCURRENT", "1")),
        queue_max=int(g("QUEUE_MAX", "10")), rate_per_hour=int(g("RATE_PER_HOUR", "5")),
        job_ttl_min=int(g("JOB_TTL_MIN", "60")), build_timeout=int(g("BUILD_TIMEOUT", "1500")),
        runner=g("RUNNER", "docker"), docker_image=g("DOCKER_IMAGE", "apkengine-builder:latest"),
        docker_memory=g("DOCKER_MEMORY", "6g"), docker_cpus=g("DOCKER_CPUS", "2"),
        docker_network=g("DOCKER_NETWORK", "bridge"), docker_user=g("DOCKER_USER", ""),
        trust_proxy=g("TRUST_PROXY", "") == "1",
    )


# ---------------------------------------------------------------- jobs
class Job:
    def __init__(self, jid: str, root: Path):
        self.id = jid
        self.dir = root / jid
        self.upload = self.dir / "upload.zip"
        self.work = self.dir / "work"
        self.out = self.dir / "out"
        self.status = "uploading"      # uploading -> queued -> running -> success|failed|rejected
        self.public: dict = {}
        self.created = time.time()
        self.finished: float | None = None


class Busy(Exception):
    pass


def sanitize(res: dict) -> dict:
    """Whitelist what may leave the server (never paths)."""
    status = res.get("status") if res.get("status") in TERMINAL else "failed"
    apks = [{"name": a["name"], "size": a["size"], "sha256": a["sha256"], "primary": bool(a.get("primary"))}
            for a in res.get("apks", []) if NAME_RE.match(str(a.get("name", "")))]
    diag = res.get("diagnosis")
    if diag:
        diag = {"code": diag.get("code"), "title_ar": diag.get("title_ar"), "hint_ar": diag.get("hint_ar"),
                "excerpt": str(diag.get("excerpt", ""))[:3000]}
    err = res.get("error")
    if err:
        err = {"code": err.get("code"), "message_ar": err.get("message_ar")}
    return {"status": status, "stage": res.get("stage"), "error": err, "diagnosis": diag, "apks": apks,
            "warnings": [str(w)[:300] for w in res.get("warnings", [])][:10],
            "build_seconds": res.get("timings", {}).get("build_seconds")}


class Manager:
    def __init__(self, cfg: Config, runner):
        self.cfg, self.runner = cfg, runner
        self.root = cfg.data_dir / "jobs"
        shutil.rmtree(self.root, ignore_errors=True)      # stale files from a previous run
        self.root.mkdir(parents=True, exist_ok=True)
        self.jobs: dict[str, Job] = {}
        self.pending: deque[str] = deque()
        self.hits: dict[str, list[float]] = {}
        self.cond = threading.Condition()
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(cfg.max_concurrent)]
        self.threads.append(threading.Thread(target=self._janitor, daemon=True))
        for t in self.threads:
            t.start()

    # -- admission
    def allow_ip(self, ip: str) -> bool:
        now = time.time()
        with self.cond:
            recent = [t for t in self.hits.get(ip, []) if now - t < 3600]
            if len(recent) >= self.cfg.rate_per_hour:
                self.hits[ip] = recent
                return False
            recent.append(now)
            self.hits[ip] = recent
            return True

    def reserve(self) -> Job:
        with self.cond:
            active = sum(1 for j in self.jobs.values() if j.status not in TERMINAL)
            if active >= self.cfg.queue_max + self.cfg.max_concurrent:
                raise Busy()
            job = Job(secrets.token_urlsafe(18), self.root)
            job.dir.mkdir(parents=True)
            self.jobs[job.id] = job
            return job

    def discard(self, job: Job) -> None:
        with self.cond:
            self.jobs.pop(job.id, None)
        shutil.rmtree(job.dir, ignore_errors=True)

    def enqueue(self, job: Job) -> None:
        with self.cond:
            job.status = "queued"
            self.pending.append(job.id)
            self.cond.notify()

    # -- lookup
    def get(self, jid: str) -> Job | None:
        if not ID_RE.match(jid):
            return None
        with self.cond:
            return self.jobs.get(jid)

    def view(self, job: Job) -> dict:
        v = {"id": job.id, "status": job.status}
        if job.status == "queued":
            with self.cond:
                v["position"] = (list(self.pending).index(job.id) + 1) if job.id in self.pending else 1
        elif job.status == "running":
            try:
                v["stage"] = json.loads((job.out / "progress.json").read_text()).get("stage")
            except (OSError, ValueError):
                v["stage"] = "start"
        elif job.status in TERMINAL:
            v.update(job.public)
            v["status"] = job.status
        return v

    # -- workers
    def _worker(self) -> None:
        while not self.stop.is_set():
            with self.cond:
                while not self.pending and not self.stop.is_set():
                    self.cond.wait(0.5)
                if self.stop.is_set():
                    return
                job = self.jobs.get(self.pending.popleft())
                if job is None:
                    continue
                job.status = "running"
            try:
                res = self.runner.run(job, self.cfg)
            except Exception:
                res = {"status": "failed", "stage": "internal", "apks": [],
                       "error": {"code": "INTERNAL_ERROR", "message_ar": "خطأ داخلي في الخدمة."}}
            pub = sanitize(res)
            for leftover in (job.upload, job.work):       # input and scratch are never kept
                if leftover.is_dir():
                    shutil.rmtree(leftover, ignore_errors=True)
                else:
                    leftover.unlink(missing_ok=True)
            with self.cond:
                job.public = pub
                job.finished = time.time()
                job.status = pub["status"]

    def _janitor(self) -> None:
        while not self.stop.wait(15):
            now = time.time()
            with self.cond:
                old = [j for j in self.jobs.values()
                       if j.finished and now - j.finished > self.cfg.job_ttl_min * 60]
                for j in old:
                    self.jobs.pop(j.id, None)
                self.hits = {ip: [t for t in ts if now - t < 3600] for ip, ts in self.hits.items()
                             if any(now - t < 3600 for t in ts)}
            for j in old:
                shutil.rmtree(j.dir, ignore_errors=True)

    def close(self) -> None:
        self.stop.set()
        with self.cond:
            self.cond.notify_all()


# ---------------------------------------------------------------- runners
class LocalRunner:
    """NOT ISOLATED. Development only: runs the engine inside this process tree."""

    def run(self, job: Job, cfg: Config) -> dict:
        sys.path.insert(0, str(HERE.parent / "engine"))
        import apkengine
        return apkengine.run_job(job.upload, job.work, job.out, build_timeout=cfg.build_timeout)


class DockerRunner:
    def command(self, job: Job, cfg: Config) -> list[str]:
        uid = os.getuid()
        user = cfg.docker_user or (f"{uid}:{os.getgid()}" if uid != 0 else "10001:10001")
        return [
            "docker", "run", "--rm", "--name", f"apkjob-{job.id}",
            "--user", user,
            "--memory", cfg.docker_memory, "--memory-swap", cfg.docker_memory,
            "--cpus", cfg.docker_cpus, "--pids-limit", "1024",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--network", cfg.docker_network,
            "-e", "HOME=/work",
            "-v", f"{job.upload.resolve()}:/in/project.zip:ro",
            "-v", f"{job.work.resolve()}:/work",
            "-v", f"{job.out.resolve()}:/out",
            cfg.docker_image,
            "python3", "/app/apkengine.py", "build", "--zip", "/in/project.zip",
            "--work", "/work", "--out", "/out", "--timeout", str(cfg.build_timeout),
        ]

    def run(self, job: Job, cfg: Config) -> dict:
        for d in (job.work, job.out):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o777)
        os.chmod(job.upload, 0o644)
        try:
            subprocess.run(self.command(job, cfg), timeout=cfg.build_timeout + 120,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", f"apkjob-{job.id}"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            return {"status": "failed", "stage": "build", "apks": [],
                    "error": {"code": "BUILD_TIMEOUT", "message_ar": "تجاوز البناء المهلة وأُوقف."}}
        try:
            return json.loads((job.out / "result.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"status": "failed", "stage": "internal", "apks": [],
                    "error": {"code": "RUNNER_ERROR", "message_ar": "تعذّر تشغيل حاوية البناء."}}


# ---------------------------------------------------------------- HTTP
def make_handler(mgr: Manager):
    cfg = mgr.cfg

    class Handler(BaseHTTPRequestHandler):
        server_version = "apkbuilder"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = 60

        def log_message(self, fmt, *args):  # no ids / IPs in logs
            path = re.sub(r"/api/jobs/[A-Za-z0-9_-]+", "/api/jobs/<id>", self.path.split("?")[0])
            sys.stderr.write(f"{self.command} {path} -> {args[1] if len(args) > 1 else ''}\n")

        # helpers
        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None, close=False):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**SEC_HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            if close:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: dict, close=False):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8",
                       {"Cache-Control": "no-store"}, close)

        def _err(self, code: int, ecode: str, msg: str, close=False):
            self._json(code, {"error": {"code": ecode, "message_ar": msg}}, close)

        def _ip(self) -> str:
            if cfg.trust_proxy:
                xff = self.headers.get("X-Forwarded-For", "")
                if xff:
                    return xff.split(",")[-1].strip()
            return self.client_address[0]

        # routes
        def do_GET(self):
            path = self.path.split("?")[0]
            if path in STATIC:
                name, ctype = STATIC[path]
                try:
                    body = (cfg.web_dir / name).read_bytes()
                except OSError:
                    return self._err(404, "NOT_FOUND", "غير موجود.")
                return self._send(200, body, ctype, {"Cache-Control": "no-cache"})
            if path == "/healthz":
                return self._send(200, b"ok", "text/plain")
            if path == "/api/config":
                return self._json(200, {"max_upload_mb": cfg.max_upload_mb, "ttl_min": cfg.job_ttl_min})
            m = re.match(r"^/api/jobs/([^/]+)$", path)
            if m:
                job = mgr.get(m.group(1))
                if not job or job.status == "uploading":
                    return self._err(404, "NOT_FOUND", "الطلب غير موجود أو انتهت صلاحيته.")
                return self._json(200, mgr.view(job))
            m = re.match(r"^/api/jobs/([^/]+)/apks/([^/]+)$", path)
            if m:
                return self._download(m.group(1), m.group(2))
            return self._err(404, "NOT_FOUND", "غير موجود.")

        def _download(self, jid: str, name: str):
            job = mgr.get(jid)
            if (not job or job.status != "success" or not NAME_RE.match(name)
                    or name not in {a["name"] for a in job.public.get("apks", [])}):
                return self._err(404, "NOT_FOUND", "الملف غير موجود أو انتهت صلاحيته.")
            f = job.out / "apks" / name
            try:
                size = f.stat().st_size
                fh = open(f, "rb")
            except OSError:
                return self._err(404, "NOT_FOUND", "الملف غير موجود أو انتهت صلاحيته.")
            with fh:
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.android.package-archive")
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                self.send_header("Cache-Control", "no-store")
                for k, v in SEC_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                shutil.copyfileobj(fh, self.wfile)

        def do_POST(self):
            if self.path.split("?")[0] != "/api/jobs":
                return self._err(404, "NOT_FOUND", "غير موجود.", close=True)
            if self.headers.get("Transfer-Encoding"):
                return self._err(411, "LENGTH_REQUIRED", "يجب تحديد حجم الملف.", close=True)
            length = self.headers.get("Content-Length", "")
            if not length.isdigit():
                return self._err(411, "LENGTH_REQUIRED", "يجب تحديد حجم الملف.", close=True)
            n = int(length)
            if n < 22:
                return self._err(400, "ZIP_INVALID", "الملف ليس ZIP صالحاً.", close=True)
            if n > cfg.max_upload_mb * 1024 * 1024:
                return self._err(413, "TOO_LARGE", f"الحجم الأقصى {cfg.max_upload_mb} MB.", close=True)
            if not mgr.allow_ip(self._ip()):
                return self._err(429, "RATE_LIMITED", "تجاوزت عدد المحاولات المسموح به في الساعة.", close=True)
            try:
                job = mgr.reserve()
            except Busy:
                return self._err(503, "BUSY", "الخدمة مزدحمة الآن؛ أعد المحاولة بعد قليل.", close=True)
            try:
                remaining = n
                with open(job.upload, "wb") as f:
                    while remaining > 0:
                        chunk = self.rfile.read(min(1 << 20, remaining))
                        if not chunk:
                            raise ConnectionError("short body")
                        f.write(chunk)
                        remaining -= len(chunk)
                with open(job.upload, "rb") as f:
                    magic = f.read(4)
                if magic not in (b"PK\x03\x04", b"PK\x05\x06"):
                    mgr.discard(job)
                    return self._err(400, "ZIP_INVALID", "الملف ليس ZIP صالحاً.", close=True)
            except (OSError, ConnectionError):
                mgr.discard(job)
                self.close_connection = True
                return
            mgr.enqueue(job)
            self._json(202, {"id": job.id})

        def _method_not_allowed(self):
            self._err(405, "METHOD_NOT_ALLOWED", "الطريقة غير مسموحة.", close=True)

        do_PUT = do_DELETE = do_PATCH = _method_not_allowed

    return Handler


def make_server(cfg: Config, runner):
    mgr = Manager(cfg, runner)
    httpd = ThreadingHTTPServer((cfg.host, cfg.port), make_handler(mgr))
    httpd.daemon_threads = True
    return httpd, mgr


def main() -> int:
    cfg = config_from_env()
    if cfg.runner == "local":
        if os.environ.get("APKENGINE_ALLOW_LOCAL") != "1":
            print("RUNNER=local is NOT isolated. Set APKENGINE_ALLOW_LOCAL=1 to use it for development only.",
                  file=sys.stderr)
            return 2
        runner = LocalRunner()
        print("WARNING: local runner, builds are not isolated.", file=sys.stderr)
    else:
        runner = DockerRunner()
    httpd, mgr = make_server(cfg, runner)
    print(f"listening on http://{cfg.host}:{cfg.port}", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        mgr.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
