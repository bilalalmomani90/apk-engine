#!/usr/bin/env python3
"""apkengine: native Android project ZIP -> debug APK.

Single purpose: unpack a ZIP, detect the Gradle project, build `assembleDebug`,
collect the real APK, or explain why the build failed. Nothing else.

Design rules (why this file exists instead of reusing AndroidForge scripts as-is):
  * Never modifies the user's project (no repo injection, no gradle.properties edits).
  * Never runs the project's own gradle-wrapper.jar or distributionUrl. Only the
    *version number* is read; the official Gradle distribution is downloaded and
    verified (sha256) by this engine.
  * Hardened ZIP extraction (path traversal, symlinks, bombs, size/count limits).
  * Only APKs produced by this build under build/outputs/apk are returned.
  * Build runs with a minimal environment (no tokens/secrets), its own
    GRADLE_USER_HOME/HOME, a timeout, and process-group kill.
  * Runs identically on a GitHub runner (private test) and on your own server.

Parts of the toolchain-selection idea come from AndroidForge (MIT), see
THIRD_PARTY_NOTICES.md.

Python 3.9+, standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ENGINE_VERSION = "0.1.0"
DEFAULT_GRADLE = "8.9"
DEFAULT_TASK = "assembleDebug"
SKIP_DIRS = {".git", "node_modules", "build", ".gradle", "__MACOSX", ".idea"}


# --------------------------------------------------------------------------
# Errors and limits
# --------------------------------------------------------------------------
class EngineError(Exception):
    """A failure with a stable code, an Arabic message and the stage it came from."""

    def __init__(self, code: str, message_ar: str, stage: str, rejected: bool = False):
        super().__init__(f"{code}: {message_ar}")
        self.code = code
        self.message_ar = message_ar
        self.stage = stage
        self.rejected = rejected  # True = input not acceptable; False = build failure


@dataclass
class Limits:
    max_files: int = 50_000
    max_total_bytes: int = 600 * 1024 * 1024
    max_file_bytes: int = 300 * 1024 * 1024
    max_ratio: int = 200            # uncompressed/compressed, only for big files
    ratio_min_size: int = 1024 * 1024
    max_name_len: int = 300
    max_depth: int = 30


# --------------------------------------------------------------------------
# 1) Hardened ZIP extraction
# --------------------------------------------------------------------------
def safe_extract(zip_path: Path, dest: Path, limits: Limits | None = None,
                 preserve_exec: bool = False, stage: str = "extract") -> dict:
    limits = limits or Limits()
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_real = os.path.realpath(dest)

    def bad(code: str, msg: str) -> EngineError:
        return EngineError(code, msg, stage, rejected=True)

    try:
        zf = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError):
        raise bad("ZIP_INVALID", "الملف ليس ZIP صالحاً.")

    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_files:
            raise bad("ZIP_TOO_MANY_FILES", "عدد الملفات داخل الـ ZIP أكبر من المسموح.")
        declared = sum(i.file_size for i in infos)
        if declared > limits.max_total_bytes:
            raise bad("ZIP_TOO_LARGE", "الحجم بعد فك الضغط أكبر من المسموح.")

        total = 0
        count = 0
        for info in infos:
            name = info.filename
            if "\x00" in name or len(name) > limits.max_name_len:
                raise bad("ZIP_UNSAFE_PATH", "اسم ملف غير صالح داخل الـ ZIP.")
            norm = name.replace("\\", "/")
            p = PurePosixPath(norm)
            if (p.is_absolute() or ".." in p.parts or re.match(r"^[A-Za-z]:", norm)
                    or len(p.parts) > limits.max_depth):
                raise bad("ZIP_UNSAFE_PATH", "الـ ZIP يحتوي مسارات غير آمنة (خروج من المجلد أو مسار مطلق).")
            if info.flag_bits & 0x1:
                raise bad("ZIP_ENCRYPTED", "الـ ZIP مشفّر بكلمة مرور وهذا غير مدعوم.")
            mode = (info.external_attr >> 16) & 0xFFFF
            ftype = stat.S_IFMT(mode)  # 0 when the zip tool stored permission bits only
            if ftype == stat.S_IFLNK:
                raise bad("ZIP_SYMLINK", "الـ ZIP يحتوي روابط رمزية وهذا غير مسموح.")
            if ftype and ftype not in (stat.S_IFREG, stat.S_IFDIR):
                raise bad("ZIP_SPECIAL_FILE", "الـ ZIP يحتوي ملفات خاصة غير مسموحة.")
            if norm.startswith("__MACOSX/") or p.name == ".DS_Store":
                continue
            if (info.file_size > limits.ratio_min_size and info.compress_size > 0
                    and info.file_size / info.compress_size > limits.max_ratio):
                raise bad("ZIP_BOMB", "نسبة الضغط غير طبيعية (ملف ZIP ضار محتمل).")

            target = dest / Path(*p.parts) if p.parts else dest
            target_real = os.path.realpath(target)
            if target_real != dest_real and not target_real.startswith(dest_real + os.sep):
                raise bad("ZIP_UNSAFE_PATH", "الـ ZIP يحاول الكتابة خارج مجلد العمل.")

            if info.is_dir() or norm.endswith("/"):
                try:
                    target.mkdir(parents=True, exist_ok=True)
                except OSError:
                    raise bad("ZIP_INVALID", "بنية الـ ZIP غير صالحة.")
                continue

            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with zf.open(info) as src, open(target, "wb") as out:
                    while True:
                        chunk = src.read(256 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        total += len(chunk)
                        if written > limits.max_file_bytes or total > limits.max_total_bytes:
                            raise bad("ZIP_TOO_LARGE", "الحجم بعد فك الضغط أكبر من المسموح.")
                        out.write(chunk)
            except EngineError:
                raise
            except (OSError, zipfile.BadZipFile, RuntimeError):
                raise bad("ZIP_INVALID", "تعذّر فك أحد الملفات؛ الـ ZIP تالف.")
            os.chmod(target, 0o755 if (preserve_exec and mode & 0o111) else 0o644)
            count += 1
    return {"files": count, "bytes": total}


# --------------------------------------------------------------------------
# 2) Project detection (read-only)
# --------------------------------------------------------------------------
def _read(path: Path, limit: int = 400_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def find_gradle_roots(base: Path, max_depth: int = 3) -> list[Path]:
    roots: list[Path] = []
    base = Path(base)
    for dirpath, dirnames, filenames in os.walk(base):
        depth = len(Path(dirpath).relative_to(base).parts)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS] if depth < max_depth else []
        if "settings.gradle" in filenames or "settings.gradle.kts" in filenames:
            roots.append(Path(dirpath))
    roots.sort(key=lambda p: (len(p.relative_to(base).parts), str(p)))
    return roots


def _fallback_roots(base: Path, max_depth: int = 3) -> list[Path]:
    """Single-module projects without settings.gradle."""
    roots: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(base):
        depth = len(Path(dirpath).relative_to(base).parts)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS] if depth < max_depth else []
        for f in ("build.gradle", "build.gradle.kts"):
            if f in filenames and "com.android.application" in _read(Path(dirpath) / f):
                roots.append(Path(dirpath))
                break
    roots.sort(key=lambda p: (len(p.relative_to(base).parts), str(p)))
    return roots


def detect_framework(root: Path, base: Path) -> str | None:
    """Out-of-scope frameworks (Flutter / React Native / Capacitor / Cordova)."""
    dirs = [root]
    if root != base and root.parent != root:
        dirs.append(root.parent)
    dirs.append(base)
    for d in dirs:
        if (d / "pubspec.yaml").exists():
            return "flutter"
        for cap in ("capacitor.config.json", "capacitor.config.ts", "capacitor.config.js"):
            if (d / cap).exists():
                return "capacitor"
        pj = d / "package.json"
        if pj.exists() and "react-native" in _read(pj, 100_000):
            return "react-native"
        cfg = d / "config.xml"
        if cfg.exists() and "cordova" in _read(cfg, 50_000).lower():
            return "cordova"
    s = _read(root / "settings.gradle") + _read(root / "settings.gradle.kts")
    if "flutter" in s.lower() and ("flutter.sdk" in s or "flutter-gradle-plugin" in s):
        return "flutter"
    return None


AGP_PATTERNS = [
    r"com\.android\.tools\.build:gradle:([0-9][0-9A-Za-z.\-]*)",
    r"com\.android\.(?:application|library)['\"]\)?\s+version\s+['\"]([0-9][0-9A-Za-z.\-]*)['\"]",
    r"^\s*(?:agp|androidGradlePlugin|android-gradle-plugin|androidGradle)\s*=\s*['\"]([0-9][0-9A-Za-z.\-]*)['\"]",
    r"id\s*=\s*['\"]com\.android\.application['\"]\s*,\s*version\s*=\s*['\"]([0-9][0-9A-Za-z.\-]*)['\"]",
]
WRAPPER_RE = re.compile(r"gradle-([0-9][0-9A-Za-z.\-]*?)-(?:bin|all)\.zip")
GRADLE_VERSION_OK = re.compile(r"^\d+(\.\d+){1,2}(-rc-\d+)?$")


def _norm_java(v: str) -> int | None:
    v = v.replace("_", ".")
    if v.startswith("1."):
        v = v[2:]
    m = re.match(r"^(\d+)", v)
    return int(m.group(1)) if m else None


def detect_project(root: Path) -> dict:
    root = Path(root)
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).relative_to(root).parts)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS] if depth < 6 else []
        for f in filenames:
            if f in ("build.gradle", "build.gradle.kts", "libs.versions.toml", "settings.gradle",
                     "settings.gradle.kts"):
                files.append(Path(dirpath) / f)
        if len(files) > 200:
            break
    text = "\n".join(_read(p) for p in files)

    agp = None
    for pat in AGP_PATTERNS:
        m = re.search(pat, text, re.M)
        if m:
            agp = m.group(1)
            break

    wrapper_props = root / "gradle" / "wrapper" / "gradle-wrapper.properties"
    wrapper_version = None
    if wrapper_props.exists():
        m = WRAPPER_RE.search(_read(wrapper_props, 20_000))
        if m and GRADLE_VERSION_OK.match(m.group(1)):
            wrapper_version = m.group(1)

    sdks = [int(x) for x in re.findall(r"compileSdk(?:Version)?\s*(?:=|\()?\s*(\d+)", text)]
    sdks += [int(x) for x in re.findall(r"compileSdk\s*\{[^}]*?release\((\d+)", text, re.S)]

    requested: list[int] = []
    for pat in (r"JavaVersion\.VERSION_([0-9_.]+)", r"JavaLanguageVersion\.of\((\d+)\)",
                r"jvmToolchain\((\d+)\)"):
        for v in re.findall(pat, text):
            n = _norm_java(v)
            if n:
                requested.append(n)

    java_n = kt_n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if f.endswith(".java"):
                java_n += 1
            elif f.endswith(".kt"):
                kt_n += 1
        if java_n + kt_n > 20_000:
            break
    kotlin = kt_n > 0 or bool(re.search(r"org\.jetbrains\.kotlin|kotlin-android|kotlin\(\"android\"\)", text))
    language = "mixed" if java_n and kt_n else "kotlin" if kotlin else "java"

    return {
        "has_application_plugin": "com.android.application" in text,
        "agp_version": agp,
        "wrapper_gradle_version": wrapper_version,
        "wrapper_jar_present": (root / "gradle" / "wrapper" / "gradle-wrapper.jar").exists(),
        "compile_sdk": max(sdks) if sdks else None,
        "java_requested": max(requested) if requested else None,
        "language": language,
        "uses_ndk": bool(re.search(r"ndkVersion|externalNativeBuild", text)),
        "version_catalog": any(p.name == "libs.versions.toml" for p in files),
    }


# --------------------------------------------------------------------------
# 3) Toolchain rules (AGP -> minimum Gradle, JDK to run the build)
#    VERIFY against the official AGP release notes before relying on newer rows.
# --------------------------------------------------------------------------
AGP_RULES = [  # (agp "major.minor", min gradle, jdk to run)
    ("3.0", "4.1", 8), ("3.1", "4.4", 8), ("3.2", "4.6", 8), ("3.3", "4.10.1", 8),
    ("3.4", "5.1.1", 8), ("3.5", "5.4.1", 8), ("3.6", "5.6.4", 8),
    ("4.0", "6.1.1", 8), ("4.1", "6.5", 8), ("4.2", "6.7.1", 8),
    ("7.0", "7.0.2", 11), ("7.1", "7.2", 11), ("7.2", "7.3.3", 11), ("7.3", "7.4", 11),
    ("7.4", "7.5", 11),
    ("8.0", "8.0", 17), ("8.1", "8.0", 17), ("8.2", "8.2", 17), ("8.3", "8.4", 17),
    ("8.4", "8.6", 17), ("8.5", "8.7", 17), ("8.6", "8.7", 17), ("8.7", "8.9", 17),
    ("8.8", "8.10.2", 17), ("8.9", "8.11.1", 17), ("8.10", "8.11.1", 17),
    ("8.11", "8.13", 17), ("8.12", "8.13", 17), ("8.13", "8.13", 17),
    ("9.0", "9.1.0", 17),
]


def _mm(v: str) -> tuple[int, int] | None:
    m = re.match(r"^(\d+)\.(\d+)", v or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def lookup_agp_rule(agp: str | None) -> dict | None:
    key = _mm(agp or "")
    if not key:
        return None
    table = [(tuple(int(x) for x in a.split(".")), g, j) for a, g, j in AGP_RULES]
    if key < table[0][0]:
        return None
    best = None
    for k, g, j in table:
        if k <= key:
            best = (k, g, j)
    outdated = key > table[-1][0]
    return {"min_gradle": best[1], "jdk": best[2], "outdated": outdated}


def plan_toolchain(det: dict) -> dict:
    notes: list[str] = []
    rule = lookup_agp_rule(det.get("agp_version"))
    if rule and rule["outdated"]:
        notes.append("إصدار AGP أحدث من جدول القواعد؛ يُفترض اتباع wrapper المشروع.")
    gradle = det.get("wrapper_gradle_version")
    if not gradle:
        gradle = rule["min_gradle"] if rule else DEFAULT_GRADLE
        notes.append("لا يوجد Gradle wrapper صالح؛ اختير إصدار Gradle من قواعد AGP.")
        if not rule:
            notes.append("تعذّر تحديد إصدار AGP؛ استُخدم Gradle افتراضي.")
    if rule:
        jdk = rule["jdk"]
    else:
        gm = _mm(gradle) or (8, 0)
        jdk = 17 if gm[0] >= 8 else 11 if gm[0] >= 7 else 8
    req = det.get("java_requested")
    if req and req > jdk:
        jdk = min(req, 21)
    return {"gradle_version": gradle, "jdk": jdk, "notes": notes}


# --------------------------------------------------------------------------
# 4) Tools: JDK discovery, official Gradle distribution (verified), SDK
# --------------------------------------------------------------------------
def _jdk_major_from_release(home: Path) -> int | None:
    m = re.search(r'JAVA_VERSION="([^"]+)"', _read(home / "release", 5000))
    return _norm_java(m.group(1)) if m else None


def find_jdks() -> dict[int, str]:
    found: dict[int, str] = {}
    for k, v in os.environ.items():
        m = re.match(r"^JAVA_HOME_(\d+)_(?:X64|ARM64)$", k)
        if m and (Path(v) / "bin" / "java").exists():
            found.setdefault(int(m.group(1)), v)
    cands = []
    if os.environ.get("JAVA_HOME"):
        cands.append(Path(os.environ["JAVA_HOME"]))
    for base in ("/usr/lib/jvm", "/opt/java", "/opt/jdks", "/usr/lib64/jvm"):
        b = Path(base)
        if b.is_dir():
            cands += [c for c in sorted(b.iterdir()) if c.is_dir()]
    for c in cands:
        if (c / "bin" / "java").exists():
            major = _jdk_major_from_release(c)
            if major:
                found.setdefault(major, str(c.resolve()))
    return found


def pick_jdk(required: int, jdks: dict[int, str]) -> tuple[int, str, str | None]:
    if required in jdks:
        return required, jdks[required], None
    higher = sorted(m for m in jdks if m > required)
    if higher:
        m = higher[0]
        return m, jdks[m], f"JDK {required} غير متوفر؛ استُخدم JDK {m}."
    raise EngineError("JDK_MISSING", f"لا يوجد JDK {required} أو أحدث على جهاز البناء.", "toolchain")


def _download(url: str, dest: Path, timeout: int = 120) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": f"apkengine/{ENGINE_VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def ensure_gradle(version: str, cache_dir: Path) -> str:
    """Return path to the `gradle` binary for an official, checksum-verified distribution."""
    if not GRADLE_VERSION_OK.match(version):
        raise EngineError("GRADLE_VERSION_UNSUPPORTED", "إصدار Gradle غير صالح.", "toolchain", rejected=True)
    cache_dir = Path(cache_dir)
    binpath = cache_dir / f"gradle-{version}" / "bin" / "gradle"
    if binpath.exists():
        return str(binpath)
    cache_dir.mkdir(parents=True, exist_ok=True)
    url = f"https://services.gradle.org/distributions/gradle-{version}-bin.zip"
    tmpzip = cache_dir / f"gradle-{version}.zip.part"
    try:
        _download(url, tmpzip)
        sha_file = cache_dir / f"gradle-{version}.sha256.part"
        _download(url + ".sha256", sha_file, timeout=30)
        expected = sha_file.read_text().strip().split()[0].lower()
        h = hashlib.sha256()
        with open(tmpzip, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != expected:
            raise EngineError("GRADLE_CHECKSUM", "فشل التحقق من سلامة تنزيل Gradle.", "toolchain")
        safe_extract(tmpzip, cache_dir, Limits(max_total_bytes=2 << 30, max_file_bytes=1 << 30,
                                               max_files=100_000, max_ratio=2000),
                     preserve_exec=True, stage="toolchain")
    except EngineError:
        raise
    except Exception as e:  # network / disk
        raise EngineError("GRADLE_DOWNLOAD", f"تعذّر تنزيل Gradle {version}: {type(e).__name__}.", "toolchain")
    finally:
        for p in cache_dir.glob("*.part"):
            p.unlink(missing_ok=True)
    if not binpath.exists():
        raise EngineError("GRADLE_DOWNLOAD", "بنية توزيعة Gradle غير متوقعة.", "toolchain")
    os.chmod(binpath, 0o755)
    return str(binpath)


def find_android_sdk() -> str | None:
    for k in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(k)
        if v and Path(v).is_dir():
            return v
    for c in ("/usr/local/lib/android/sdk", str(Path.home() / "Android" / "Sdk"), "/opt/android-sdk"):
        if Path(c).is_dir():
            return c
    return None


# --------------------------------------------------------------------------
# 5) Build (isolated env, timeout, process-group kill, capped log)
# --------------------------------------------------------------------------
def build_env(jdk_home: str, sdk: str | None, jobdir: Path) -> dict:
    home = jobdir / "home"
    tmp = jobdir / "tmp"
    ghome = jobdir / "gradle_home"
    for d in (home, tmp, ghome):
        d.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": f"{jdk_home}/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "LANG": "C.UTF-8",
        "JAVA_HOME": jdk_home,
        "GRADLE_USER_HOME": str(ghome),
        "GRADLE_OPTS": "-Dfile.encoding=UTF-8",
    }
    if sdk:
        env["ANDROID_HOME"] = sdk
        env["ANDROID_SDK_ROOT"] = sdk
    return env


def run_gradle(gradle_bin: str, project_root: Path, env: dict, log_path: Path,
               timeout: int, max_log_bytes: int = 20 * 1024 * 1024) -> tuple[int | None, bool]:
    """Returns (returncode, timed_out)."""
    cmd = [gradle_bin, DEFAULT_TASK, "--console=plain", "--stacktrace", "--no-daemon"]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(cmd, cwd=project_root, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=True)

    def pump() -> None:
        written = 0
        truncated = False
        with open(log_path, "wb") as lf:
            for line in iter(proc.stdout.readline, b""):
                if written < max_log_bytes:
                    lf.write(line)
                    written += len(line)
                elif not truncated:
                    lf.write(b"\n[... log truncated ...]\n")
                    truncated = True

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
    t.join(timeout=10)
    try:
        proc.stdout.close()
    except OSError:
        pass
    return proc.returncode, timed_out


# --------------------------------------------------------------------------
# 6) Collect APKs (only from build/outputs/apk, produced by THIS build)
# --------------------------------------------------------------------------
def is_valid_apk(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
    except (zipfile.BadZipFile, OSError):
        return False
    return "AndroidManifest.xml" in names and (
        any(n.startswith("classes") and n.endswith(".dex") for n in names) or "resources.arsc" in names)


def collect_apks(project_root: Path, out_dir: Path, build_started: float) -> list[dict]:
    project_root = Path(project_root)
    out_apks = Path(out_dir) / "apks"
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".gradle"}]
        norm = dirpath.replace(os.sep, "/") + "/"
        if "/build/outputs/apk/" not in norm:
            continue
        if "/androidTest/" in norm:
            continue
        for f in filenames:
            if not f.endswith(".apk") or "unaligned" in f:
                continue
            p = Path(dirpath) / f
            try:
                if p.stat().st_mtime < build_started - 2:
                    continue  # not produced by this build
            except OSError:
                continue
            if is_valid_apk(p):
                found.append(p)
    results = []
    out_apks.mkdir(parents=True, exist_ok=True)
    for p in sorted(found):
        rel = "/" + p.relative_to(project_root).as_posix()
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", rel.replace("/build/outputs/apk/", "__").lstrip("/"))
        dest = out_apks / safe
        shutil.copy2(p, dest)
        h = hashlib.sha256()
        with open(dest, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        module = rel.split("/build/outputs/apk/")[0].lstrip("/") or "root"
        results.append({"name": safe, "path": str(dest), "size": dest.stat().st_size,
                        "sha256": h.hexdigest(), "module": module, "primary": False})
    app_debug = [r for r in results if r["module"] in ("app", "root") and "debug" in r["name"].lower()]
    if len(results) == 1:
        results[0]["primary"] = True
    elif len(app_debug) == 1:
        app_debug[0]["primary"] = True
    return results


# --------------------------------------------------------------------------
# 7) Failure diagnosis (first matching cause wins; order matters)
# --------------------------------------------------------------------------
DIAG_RULES = [
    ("SDK_LICENSE", r"licenses? (?:for package|have not been accepted)|Failed to install the following Android SDK packages as some licen[cs]es have not been accepted",
     "رخص Android SDK غير مقبولة", "يجب قبول رخص الـ SDK على جهاز البناء (sdkmanager --licenses) ثم إعادة المحاولة."),
    ("SDK_MISSING", r"SDK location not found|Failed to find target with hash string|Failed to find Build Tools revision|No installed build tools found",
     "مكوّن Android SDK مفقود", "المشروع يحتاج منصة أو Build Tools غير مثبتة على جهاز البناء."),
    ("JDK_MISMATCH", r"Unsupported class file major version|Unsupported Java|requires Java \d+|Android Gradle plugin requires Java|invalid source release|Could not target platform: 'Java SE",
     "إصدار JDK غير متوافق", "المشروع يحتاج إصدار JDK مختلفاً عن المستخدم في البناء."),
    ("GRADLE_AGP_MISMATCH", r"Minimum supported Gradle version is|requires Gradle \d|Gradle version .* is required",
     "إصدار Gradle لا يناسب إضافة Android", "إصدار Gradle في المشروع أقدم مما تتطلبه إضافة Android Gradle Plugin."),
    ("OUT_OF_MEMORY", r"OutOfMemoryError|GC overhead limit exceeded|Gradle build daemon disappeared unexpectedly|Metaspace",
     "نفدت الذاكرة أثناء البناء", "المشروع يحتاج ذاكرة أكبر مما هو متاح على جهاز البناء."),
    ("NETWORK", r"SocketTimeoutException|UnknownHostException|Connection (?:reset|refused|timed out)|Read timed out|Could not GET",
     "مشكلة اتصال بالإنترنت أثناء البناء", "تعذّر الوصول إلى مستودع المكتبات؛ أعد المحاولة أو تحقق من الاتصال."),
    ("DEPENDENCY", r"Could not resolve|Could not find [\w.\-]+:[\w.\-]+|Failed to resolve:",
     "تعذّر تنزيل مكتبة يعتمد عليها المشروع", "قد تكون المكتبة محذوفة أو في مستودع خاص أو قديم (مثل JCenter/Bintray)."),
    ("COMPILE_ERROR", r"error: cannot find symbol|error: package .* does not exist|Compilation failed|\be: file://|Unresolved reference",
     "خطأ في شيفرة المشروع", "فشلت ترجمة الشيفرة؛ المشكلة داخل المشروع نفسه."),
    ("RESOURCE_ERROR", r"AAPT: error|Android resource linking failed|Manifest merger failed|resource .* not found",
     "خطأ في الموارد أو ملف المانيفست", "هناك مورد أو إعداد مانيفست غير صالح في المشروع."),
    ("NDK_MISSING", r"NDK is not installed|No version of NDK matched",
     "NDK مفقود", "المشروع يحتاج إصدار NDK غير مثبت على جهاز البناء."),
]


def diagnose(log_text: str) -> dict:
    lines = log_text.splitlines()
    excerpt = ""
    for i, ln in enumerate(lines):
        if "What went wrong" in ln:
            excerpt = "\n".join(lines[i:i + 12])
            break
    if not excerpt:
        keep = [l for l in lines if re.search(r"error:|\be: |FAILURE|Caused by|Exception", l)]
        excerpt = "\n".join((keep or lines)[-25:])
    for code, pat, title, hint in DIAG_RULES:
        if re.search(pat, log_text, re.I):
            return {"code": code, "title_ar": title, "hint_ar": hint, "excerpt": excerpt[:3000]}
    return {"code": "UNKNOWN", "title_ar": "فشل البناء لسبب غير معروف",
            "hint_ar": "راجع مقتطف السجل أدناه.", "excerpt": excerpt[:3000]}


# --------------------------------------------------------------------------
# 8) The job: ZIP -> result.json (+ apks/ + build.log)
# --------------------------------------------------------------------------
def run_job(zip_path, work_root, out_dir, *, limits: Limits | None = None,
            build_timeout: int = 1800, gradle_bin: str | None = None,
            gradle_cache: str | None = None, jdks: dict | None = None,
            cleanup: bool = True) -> dict:
    t0 = time.time()
    job_id = uuid.uuid4().hex[:12]
    jobdir = Path(work_root) / job_id
    src = jobdir / "src"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = jobdir / "build.log"
    result: dict = {"engine_version": ENGINE_VERSION, "job_id": job_id, "status": "rejected",
                    "stage": "start", "apks": [], "warnings": [], "timings": {}}

    def mark(stage: str) -> None:
        result["stage"] = stage
        result["timings"][stage + "_start"] = round(time.time() - t0, 2)
        try:
            (out_dir / "progress.json").write_text(json.dumps({"stage": stage}), encoding="utf-8")
        except OSError:
            pass

    try:
        mark("extract")
        result["extract"] = safe_extract(Path(zip_path), src, limits)

        mark("detect")
        roots = find_gradle_roots(src) or _fallback_roots(src)
        if not roots:
            raise EngineError("NO_GRADLE_PROJECT", "لم يُعثر على مشروع Gradle (settings.gradle) داخل الـ ZIP.",
                              "detect", rejected=True)
        depth0 = len(roots[0].relative_to(src).parts)
        if len([r for r in roots if len(r.relative_to(src).parts) == depth0]) > 1:
            raise EngineError("AMBIGUOUS_PROJECT", "يوجد أكثر من مشروع بنفس المستوى داخل الـ ZIP؛ ارفع مشروعاً واحداً.",
                              "detect", rejected=True)
        root = roots[0]
        fw = detect_framework(root, src)
        if fw:
            raise EngineError("OUT_OF_SCOPE", f"المشروع من نوع {fw}، وهذه الخدمة تدعم مشاريع Android الأصلية فقط (Java/Kotlin).",
                              "detect", rejected=True)
        det = detect_project(root)
        result["detection"] = det
        if not det["has_application_plugin"]:
            raise EngineError("NO_APPLICATION_MODULE", "لا يوجد وحدة تطبيق (com.android.application) في المشروع.",
                              "detect", rejected=True)

        mark("toolchain")
        plan = plan_toolchain(det)
        result["toolchain"] = plan
        result["warnings"] += plan["notes"]
        major, jdk_home, jwarn = pick_jdk(plan["jdk"], jdks if jdks is not None else find_jdks())
        if jwarn:
            result["warnings"].append(jwarn)
        result["toolchain"]["jdk_used"] = major
        cache = Path(gradle_cache or (Path.home() / ".apkengine" / "gradle"))
        gbin = gradle_bin or ensure_gradle(plan["gradle_version"], cache)
        sdk = find_android_sdk()
        if not sdk:
            result["warnings"].append("لم يُعثر على Android SDK على جهاز البناء.")

        mark("build")
        env = build_env(jdk_home, sdk, jobdir)
        started = time.time()
        rc, timed_out = run_gradle(gbin, root, env, log_path, build_timeout)
        result["timings"]["build_seconds"] = round(time.time() - started, 2)
        log_text = _read(log_path, 5 * 1024 * 1024)
        if timed_out:
            raise EngineError("BUILD_TIMEOUT", f"تجاوز البناء المهلة ({build_timeout} ثانية) وأُوقف.", "build")
        if rc != 0:
            result["diagnosis"] = diagnose(log_text)
            raise EngineError("BUILD_FAILED", result["diagnosis"]["title_ar"], "build")

        mark("collect")
        apks = collect_apks(root, out_dir, started)
        if not apks:
            raise EngineError("NO_APK_PRODUCED", "نجح Gradle لكن لم يُنتج أي ملف APK صالح.", "collect")
        result["apks"] = apks
        result["status"] = "success"
        result["stage"] = "done"
    except EngineError as e:
        result["status"] = "rejected" if e.rejected else "failed"
        result["stage"] = e.stage
        result["error"] = {"code": e.code, "message_ar": e.message_ar}
    except Exception as e:  # never leak a traceback to the user
        result["status"] = "failed"
        result["error"] = {"code": "INTERNAL_ERROR", "message_ar": "خطأ داخلي غير متوقع في المحرك."}
        result["internal"] = f"{type(e).__name__}: {e}"
    finally:
        result["timings"]["total_seconds"] = round(time.time() - t0, 2)
        try:
            if log_path.exists():
                shutil.copy2(log_path, out_dir / "build.log")
        except OSError:
            pass
        if cleanup:
            shutil.rmtree(jobdir, ignore_errors=True)
        (out_dir / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


# --------------------------------------------------------------------------
# 9) CLI
# --------------------------------------------------------------------------
def summary_markdown(result: dict) -> str:
    st = result.get("status")
    icon = {"success": "✅", "failed": "❌", "rejected": "⛔"}.get(st, "❔")
    lines = [f"## {icon} النتيجة: {st}", ""]
    if result.get("error"):
        lines += [f"**السبب:** {result['error']['message_ar']}  (`{result['error']['code']}`)", ""]
    d = result.get("diagnosis")
    if d:
        lines += [f"**التشخيص:** {d['title_ar']} — {d['hint_ar']}", "", "```", d["excerpt"], "```", ""]
    for a in result.get("apks", []):
        mark = " (الأساسي)" if a.get("primary") else ""
        lines.append(f"- `{a['name']}`{mark} — {a['size'] / 1024 / 1024:.2f} MB — sha256 `{a['sha256'][:16]}…`")
    t = result.get("toolchain")
    if t:
        lines += ["", f"Gradle `{t['gradle_version']}` — JDK `{t.get('jdk_used', t['jdk'])}`"]
    for w in result.get("warnings", []):
        lines.append(f"- ⚠️ {w}")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="apkengine", description="Android project ZIP -> debug APK")
    ap.add_argument("--version", action="version", version=ENGINE_VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--zip", required=True)
    b.add_argument("--work", required=True, help="scratch directory (per-job subfolders)")
    b.add_argument("--out", required=True, help="output directory (result.json, apks/, build.log)")
    b.add_argument("--timeout", type=int, default=1800)
    b.add_argument("--keep-work", action="store_true")
    s = sub.add_parser("summary")
    s.add_argument("result_json")
    args = ap.parse_args(argv)

    if args.cmd == "summary":
        print(summary_markdown(json.loads(Path(args.result_json).read_text(encoding="utf-8"))))
        return 0
    res = run_job(args.zip, args.work, args.out, build_timeout=args.timeout, cleanup=not args.keep_work)
    print(summary_markdown(res))
    return {"success": 0, "rejected": 2}.get(res["status"], 3)


if __name__ == "__main__":
    sys.exit(main())
