"""Tests for apkengine.py. Run:  python3 -m unittest -v test_apkengine

IMPORTANT: the pipeline tests use a *simulated* gradle script (a tiny Python
program that fabricates an APK). They prove the engine's own logic (limits,
detection, env isolation, timeout, APK collection, cleanup). They do NOT prove
that real Gradle builds succeed; that needs a real build (see README_AR.md).
"""
import json
import os
import stat
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

import apkengine as ae


def make_zip(path, entries, symlink=None):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
        if symlink:
            zi = zipfile.ZipInfo(symlink[0])
            zi.create_system = 3
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(zi, symlink[1])


def fake_apk_bytes():
    import io
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("AndroidManifest.xml", b"<m/>")
        z.writestr("classes.dex", b"dex")
    return b.getvalue()


JAVA_PROJECT = {
    "p/settings.gradle": "include ':app'\n",
    "p/build.gradle": "plugins { id 'com.android.application' version '8.5.2' apply false }\n",
    "p/app/build.gradle": "plugins { id 'com.android.application' }\nandroid { compileSdk 34\n"
                          " compileOptions { sourceCompatibility JavaVersion.VERSION_17 } }\n",
    "p/gradle/wrapper/gradle-wrapper.properties":
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.7-bin.zip\n",
    "p/app/src/main/java/a/Main.java": "class Main {}\n",
}


class TestExtract(unittest.TestCase):
    def setUp(self):
        self.t = Path(tempfile.mkdtemp())

    def run_extract(self, entries, symlink=None, limits=None):
        z = self.t / "x.zip"
        make_zip(z, entries, symlink)
        return ae.safe_extract(z, self.t / "out", limits)

    def code(self, entries, **kw):
        with self.assertRaises(ae.EngineError) as c:
            self.run_extract(entries, **kw)
        return c.exception.code

    def test_ok(self):
        r = self.run_extract({"a/b.txt": "hi"})
        self.assertEqual(r["files"], 1)
        self.assertTrue((self.t / "out/a/b.txt").exists())

    def test_dotdot(self):
        self.assertEqual(self.code({"../evil.txt": "x"}), "ZIP_UNSAFE_PATH")
        self.assertFalse((self.t / "evil.txt").exists())

    def test_absolute(self):
        self.assertEqual(self.code({"/tmp/evil.txt": "x"}), "ZIP_UNSAFE_PATH")

    def test_symlink(self):
        self.assertEqual(self.code({"a": "x"}, symlink=("link", "/etc/passwd")), "ZIP_SYMLINK")

    def test_bomb_ratio(self):
        self.assertEqual(self.code({"zeros.bin": b"\0" * (50 * 1024 * 1024)}), "ZIP_BOMB")

    def test_total_limit(self):
        lim = ae.Limits(max_total_bytes=1000)
        self.assertEqual(self.code({"a": "x" * 2000}, limits=lim), "ZIP_TOO_LARGE")

    def test_file_count(self):
        lim = ae.Limits(max_files=2)
        self.assertEqual(self.code({"a": "1", "b": "2", "c": "3"}, limits=lim), "ZIP_TOO_MANY_FILES")

    def test_not_a_zip(self):
        (self.t / "x.zip").write_bytes(b"not a zip")
        with self.assertRaises(ae.EngineError) as c:
            ae.safe_extract(self.t / "x.zip", self.t / "out")
        self.assertEqual(c.exception.code, "ZIP_INVALID")


class TestDetect(unittest.TestCase):
    def detect(self, entries):
        t = Path(tempfile.mkdtemp())
        make_zip(t / "x.zip", entries)
        ae.safe_extract(t / "x.zip", t / "src")
        roots = ae.find_gradle_roots(t / "src")
        return t, roots, ae.detect_project(roots[0])

    def test_java_modern(self):
        t, roots, d = self.detect(JAVA_PROJECT)
        self.assertEqual(roots[0].name, "p")
        self.assertTrue(d["has_application_plugin"])
        self.assertEqual(d["agp_version"], "8.5.2")
        self.assertEqual(d["wrapper_gradle_version"], "8.7")
        self.assertEqual(d["compile_sdk"], 34)
        self.assertEqual(d["java_requested"], 17)
        self.assertEqual(d["language"], "java")

    def test_kotlin_catalog(self):
        t, roots, d = self.detect({
            "settings.gradle.kts": 'include(":app")\n',
            "build.gradle.kts": "plugins { alias(libs.plugins.android.application) apply false }\n",
            "gradle/libs.versions.toml": '[versions]\nagp = "8.9.0"\n[plugins]\n'
                                         'android-application = { id = "com.android.application", version.ref = "agp" }\n',
            "app/build.gradle.kts": 'plugins { alias(libs.plugins.android.application) }\n'
                                    'android { compileSdk = 35 }\nkotlin { jvmToolchain(17) }\n',
            "app/src/main/java/a/M.kt": "class M\n",
        })
        self.assertEqual(d["agp_version"], "8.9.0")
        self.assertEqual(d["compile_sdk"], 35)
        self.assertEqual(d["language"], "kotlin")
        self.assertTrue(d["version_catalog"])
        self.assertEqual(d["java_requested"], 17)
        self.assertIsNone(d["wrapper_gradle_version"])

    def test_legacy(self):
        t, roots, d = self.detect({
            "settings.gradle": "include ':app'\n",
            "build.gradle": "buildscript { dependencies { classpath 'com.android.tools.build:gradle:3.2.1' } }\n",
            "app/build.gradle": "apply plugin: 'com.android.application'\nandroid { compileSdkVersion 28 }\n",
            "gradle/wrapper/gradle-wrapper.properties":
                "distributionUrl=http\\://services.gradle.org/distributions/gradle-4.6-all.zip\n",
        })
        self.assertEqual(d["agp_version"], "3.2.1")
        self.assertEqual(d["wrapper_gradle_version"], "4.6")
        self.assertEqual(ae.plan_toolchain(d)["jdk"], 8)

    def test_wrapper_url_is_not_trusted(self):
        # A hostile distributionUrl must yield no version (so no download of attacker URL).
        t, roots, d = self.detect({
            "settings.gradle": "",
            "app/build.gradle": "apply plugin: 'com.android.application'\n",
            "gradle/wrapper/gradle-wrapper.properties":
                "distributionUrl=https\\://evil.example/x/gradle-8.7-bin.zip.sh;rm\n",
        })
        self.assertIn(d["wrapper_gradle_version"], ("8.7", None))
        # even if a version is parsed, the engine only ever builds the official URL from it
        self.assertTrue(ae.GRADLE_VERSION_OK.match("8.7"))
        self.assertFalse(ae.GRADLE_VERSION_OK.match("8.7;rm -rf"))

    def test_framework_rejected(self):
        t = Path(tempfile.mkdtemp())
        make_zip(t / "x.zip", {"pubspec.yaml": "name: x\n", "android/settings.gradle": "",
                               "android/app/build.gradle": "apply plugin: 'com.android.application'\n"})
        ae.safe_extract(t / "x.zip", t / "src")
        root = ae.find_gradle_roots(t / "src")[0]
        self.assertEqual(ae.detect_framework(root, t / "src"), "flutter")


class TestRules(unittest.TestCase):
    def test_plans(self):
        p = ae.plan_toolchain({"agp_version": "8.5.2", "wrapper_gradle_version": "8.7", "java_requested": None})
        self.assertEqual((p["gradle_version"], p["jdk"]), ("8.7", 17))
        p = ae.plan_toolchain({"agp_version": "3.2.1", "wrapper_gradle_version": None, "java_requested": None})
        self.assertEqual((p["gradle_version"], p["jdk"]), ("4.6", 8))
        p = ae.plan_toolchain({"agp_version": "9.9.0", "wrapper_gradle_version": "9.1.0", "java_requested": None})
        self.assertTrue(any("أحدث" in n for n in p["notes"]))
        p = ae.plan_toolchain({"agp_version": None, "wrapper_gradle_version": None, "java_requested": None})
        self.assertEqual(p["gradle_version"], ae.DEFAULT_GRADLE)

    def test_pick_jdk(self):
        self.assertEqual(ae.pick_jdk(17, {17: "/a", 21: "/b"})[0], 17)
        self.assertEqual(ae.pick_jdk(17, {21: "/b"})[0], 21)
        with self.assertRaises(ae.EngineError):
            ae.pick_jdk(17, {11: "/c"})


class TestCollect(unittest.TestCase):
    def test_only_fresh_valid_build_outputs(self):
        t = Path(tempfile.mkdtemp())
        proj = t / "proj"
        (proj / "release").mkdir(parents=True)
        (proj / "release" / "Prebuilt-release.apk").write_bytes(fake_apk_bytes())     # planted
        old = proj / "app/build/outputs/apk/debug"
        old.mkdir(parents=True)
        stale = old / "stale.apk"
        stale.write_bytes(fake_apk_bytes())
        os.utime(stale, (1000, 1000))                                                  # not from this build
        started = time.time()
        for mod in ("app", "lib"):
            d = proj / mod / "build/outputs/apk/debug"
            d.mkdir(parents=True, exist_ok=True)
            (d / "app-debug.apk").write_bytes(fake_apk_bytes())                        # same filename, 2 modules
        (proj / "app/build/outputs/apk/androidTest/debug").mkdir(parents=True)
        (proj / "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk").write_bytes(fake_apk_bytes())
        (proj / "app/build/outputs/apk/debug/broken.apk").write_bytes(b"nope")
        res = ae.collect_apks(proj, t / "out", started)
        names = sorted(r["name"] for r in res)
        self.assertEqual(len(res), 2, names)
        self.assertEqual(len(set(names)), 2)                                           # no collision
        self.assertFalse(any("Prebuilt" in n or "stale" in n or "androidTest" in n or "broken" in n for n in names))
        self.assertEqual([r["module"] for r in res if r["primary"]], ["app"])
        self.assertEqual(len(list((t / "out/apks").iterdir())), 2)


class TestDiagnose(unittest.TestCase):
    def test_cases(self):
        c = lambda s: ae.diagnose(s)["code"]
        self.assertEqual(c("error: cannot find symbol\n* What went wrong:\nCompilation failed"), "COMPILE_ERROR")
        self.assertEqual(c("Could not resolve com.x:y:1\nCaused by: java.net.SocketTimeoutException: Read timed out"), "NETWORK")
        self.assertEqual(c("Could not find com.foo:bar:1.0."), "DEPENDENCY")
        self.assertEqual(c("Failed to install the following Android SDK packages as some licences have not been accepted."), "SDK_LICENSE")
        self.assertEqual(c("Unsupported class file major version 65"), "JDK_MISMATCH")
        self.assertEqual(c("Minimum supported Gradle version is 8.9. Current version is 8.4"), "GRADLE_AGP_MISMATCH")
        self.assertEqual(c("java.lang.OutOfMemoryError: Java heap space"), "OUT_OF_MEMORY")
        self.assertEqual(c("Installed at: /opt/sdk\nBUILD FAILED"), "UNKNOWN")  # old false-positive pattern


FAKE_GRADLE_OK = f"""#!{sys.executable}
import os, zipfile, io, json
os.makedirs("app/build/outputs/apk/debug", exist_ok=True)
with zipfile.ZipFile("app/build/outputs/apk/debug/app-debug.apk", "w") as z:
    z.writestr("AndroidManifest.xml", b"<m/>"); z.writestr("classes.dex", b"dex")
json.dump(sorted(os.environ), open(os.path.join(os.environ["TMPDIR"], "env.json"), "w"))
open(os.path.join(os.environ["TMPDIR"], "home.txt"), "w").write(os.environ["HOME"])
print("BUILD SUCCESSFUL")
"""
FAKE_GRADLE_FAIL = f"""#!{sys.executable}
print("* What went wrong:\\nExecution failed for task ':app:compileDebugJavaWithJavac'.\\n> Compilation failed")
import sys; sys.exit(1)
"""
FAKE_GRADLE_HANG = f"""#!{sys.executable}
import time; time.sleep(60)
"""
FAKE_GRADLE_NOAPK = f"""#!{sys.executable}
print("BUILD SUCCESSFUL")
"""


class TestPipeline(unittest.TestCase):
    JDKS = {17: "/usr", 21: "/usr"}  # path is only used for PATH/JAVA_HOME env in the simulation

    def setUp(self):
        self.t = Path(tempfile.mkdtemp())
        make_zip(self.t / "p.zip", JAVA_PROJECT)

    def fake(self, body):
        p = self.t / "fakegradle"
        p.write_text(body)
        p.chmod(0o755)
        return str(p)

    def job(self, body, **kw):
        return ae.run_job(self.t / "p.zip", self.t / "work", self.t / "out",
                          gradle_bin=self.fake(body), jdks=self.JDKS, **kw)

    def test_success_isolation_and_cleanup(self):
        os.environ["GITHUB_TOKEN"] = "secret-token"
        os.environ["MY_API_KEY"] = "secret-key"
        r = self.job(FAKE_GRADLE_OK)
        self.assertEqual(r["status"], "success", r)
        self.assertEqual(len(r["apks"]), 1)
        self.assertTrue(r["apks"][0]["primary"])
        self.assertTrue(Path(r["apks"][0]["path"]).exists())
        self.assertTrue(ae.is_valid_apk(Path(r["apks"][0]["path"])))
        self.assertEqual(list((self.t / "work").iterdir()), [])        # work dir cleaned
        self.assertEqual(json.loads((self.t / "out/progress.json").read_text())["stage"], "collect")
        self.assertTrue((self.t / "out/result.json").exists())
        # the fake gradle recorded its own environment into TMPDIR, which is cleaned up; so re-run keeping work
        r2 = self.job(FAKE_GRADLE_OK, cleanup=False)
        job = next((self.t / "work").iterdir())
        envkeys = json.loads((job / "tmp/env.json").read_text())
        self.assertNotIn("GITHUB_TOKEN", envkeys)
        self.assertNotIn("MY_API_KEY", envkeys)
        self.assertEqual((job / "tmp/home.txt").read_text(), str(job / "home"))

    def test_build_failure_is_diagnosed(self):
        r = self.job(FAKE_GRADLE_FAIL)
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["diagnosis"]["code"], "COMPILE_ERROR")
        self.assertEqual(r["apks"], [])

    def test_timeout_kills_build(self):
        t0 = time.time()
        r = self.job(FAKE_GRADLE_HANG, build_timeout=2)
        self.assertLess(time.time() - t0, 20)
        self.assertEqual(r["error"]["code"], "BUILD_TIMEOUT")

    def test_gradle_ok_but_no_apk(self):
        r = self.job(FAKE_GRADLE_NOAPK)
        self.assertEqual(r["error"]["code"], "NO_APK_PRODUCED")

    def test_prebuilt_apk_in_zip_is_never_returned(self):
        entries = dict(JAVA_PROJECT)
        import base64
        entries["p/release/Evil-release.apk"] = fake_apk_bytes()
        make_zip(self.t / "p.zip", entries)
        r = self.job(FAKE_GRADLE_NOAPK)
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["apks"], [])

    def test_rejections(self):
        make_zip(self.t / "p.zip", {"README.md": "hello"})
        self.assertEqual(self.job(FAKE_GRADLE_OK)["error"]["code"], "NO_GRADLE_PROJECT")
        make_zip(self.t / "p.zip", {"settings.gradle": "", "build.gradle": "// no android\n"})
        self.assertEqual(self.job(FAKE_GRADLE_OK)["error"]["code"], "NO_APPLICATION_MODULE")
        make_zip(self.t / "p.zip", {"pubspec.yaml": "x", "android/settings.gradle": "",
                                    "android/app/build.gradle": "apply plugin: 'com.android.application'"})
        self.assertEqual(self.job(FAKE_GRADLE_OK)["error"]["code"], "OUT_OF_SCOPE")
        make_zip(self.t / "p.zip", {"a/settings.gradle": "", "b/settings.gradle": ""})
        self.assertEqual(self.job(FAKE_GRADLE_OK)["error"]["code"], "AMBIGUOUS_PROJECT")

    def test_user_project_not_modified(self):
        # engine must not edit the user's files: compare a tree hash before/after a run.
        import hashlib
        make_zip(self.t / "p.zip", JAVA_PROJECT)
        r = self.job(FAKE_GRADLE_OK, cleanup=False)
        src = next((self.t / "work").iterdir()) / "src"
        for name, data in JAVA_PROJECT.items():
            self.assertEqual(hashlib.sha256((src / name).read_bytes()).hexdigest(),
                             hashlib.sha256(data.encode()).hexdigest(), name)
        self.assertFalse((src / "p/local.properties").exists())
        self.assertFalse((src / "p/gradle.properties").exists())


if __name__ == "__main__":
    unittest.main()
