(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const ID_RE = /^[A-Za-z0-9_-]{16,40}$/;
  let cfg = { max_upload_mb: 100, ttl_min: 60 };
  let chosen = null;
  let timer = null;

  fetch("/api/config").then((r) => r.json()).then((c) => {
    cfg = c;
    $("limits").textContent = `الحجم الأقصى ${c.max_upload_mb} MB، وتُحذف الملفات بعد ${c.ttl_min} دقيقة من انتهاء البناء.`;
  }).catch(() => {});

  const fmtMB = (n) => (n / 1048576).toFixed(2) + " MB";
  const show = (id, on) => { $(id).hidden = !on; };

  function setRail(current, failed) {
    const order = ["upload", "check", "build", "done"];
    const idx = order.indexOf(current);
    document.querySelectorAll(".rail li").forEach((li) => {
      const i = order.indexOf(li.dataset.s);
      li.className = failed && i === idx ? "failed" : i < idx ? "done" : i === idx ? "active" : "";
    });
  }

  $("file").addEventListener("change", (e) => {
    const f = e.target.files[0];
    show("pick-error", false);
    chosen = null;
    $("go").disabled = true;
    if (!f) { $("file-meta").textContent = "لم يُختر ملف بعد"; return; }
    $("file-label").textContent = f.name;
    $("file-meta").textContent = fmtMB(f.size);
    if (!/\.zip$/i.test(f.name)) return pickError("الملف يجب أن يكون بصيغة ZIP.");
    if (f.size > cfg.max_upload_mb * 1048576) return pickError(`الحجم أكبر من الحد المسموح (${cfg.max_upload_mb} MB).`);
    chosen = f;
    $("go").disabled = false;
  });

  function pickError(msg) { $("pick-error").textContent = msg; show("pick-error", true); }

  $("go").addEventListener("click", () => {
    if (!chosen) return;
    $("go").disabled = true;
    show("pick", false); show("result", false); show("progress", true); show("bar", true);
    setRail("upload");
    $("status-text").textContent = "جارٍ رفع الملف…";
    $("bar-fill").style.width = "0";
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/jobs");
    xhr.setRequestHeader("Content-Type", "application/zip");
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) $("bar-fill").style.width = Math.round((e.loaded / e.total) * 100) + "%";
    };
    xhr.onerror = xhr.ontimeout = () => fail("تعذّر الاتصال بالخادم أثناء الرفع. تحقق من الاتصال وأعد المحاولة.");
    xhr.onload = () => {
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch (_) {}
      if (xhr.status === 202 && ID_RE.test(data.id || "")) {
        show("bar", false);
        history.replaceState(null, "", "#" + data.id);
        poll(data.id);
      } else {
        fail((data.error && data.error.message_ar) || "رفض الخادم الطلب.");
      }
    };
    xhr.send(chosen);
  });

  function fail(msg) {
    clearTimeout(timer);
    show("progress", false);
    renderResult("reject", "تعذّر إكمال الطلب", msg, [], null);
  }

  function railFor(stage) {
    if (["build", "collect"].includes(stage)) return "build";
    return "check";
  }

  let misses = 0;
  const started = Date.now();
  function poll(id) {
    fetch("/api/jobs/" + id, { cache: "no-store" })
      .then((r) => { if (r.status === 404) throw new Error("gone"); return r.json(); })
      .then((j) => {
        misses = 0;
        if (j.status === "queued") {
          setRail("check");
          $("status-text").textContent = `في الانتظار… ترتيبك ${j.position}.`;
        } else if (j.status === "running") {
          const r = railFor(j.stage);
          setRail(r);
          $("status-text").textContent = r === "build"
            ? "جارٍ بناء المشروع. قد يستغرق ذلك عدة دقائق."
            : "جارٍ فحص المشروع وتجهيز أدوات البناء…";
        } else if (j.status === "success") {
          setRail("done");
          show("progress", false);
          renderResult("ok", "تم البناء", "حمّل ملف APK وثبّته على جهازك.", j.apks, null, j.warnings);
          return;
        } else {
          show("progress", false);
          const title = (j.diagnosis && j.diagnosis.title_ar) || (j.error && j.error.message_ar) || "فشل البناء";
          const text = (j.diagnosis && j.diagnosis.hint_ar) || (j.status === "rejected" ? "" : "راجع التفاصيل أدناه.");
          renderResult(j.status === "rejected" ? "reject" : "fail", title, text, [], j.diagnosis && j.diagnosis.excerpt);
          return;
        }
        if (Date.now() - started > 60 * 60 * 1000) return fail("انتهت مهلة الانتظار.");
        timer = setTimeout(() => poll(id), 2000);
      })
      .catch((e) => {
        if (e.message === "gone") return fail("الطلب غير موجود أو انتهت صلاحيته (تُحذف الملفات تلقائياً).");
        if (++misses >= 5) return fail("انقطع الاتصال بالخادم.");
        timer = setTimeout(() => poll(id), 3000);
      });
  }

  function renderResult(kind, title, text, apks, excerpt, warnings) {
    const box = $("result");
    box.className = kind;
    $("result-title").textContent = title;
    $("result-text").textContent = text;
    const list = $("apk-list");
    list.textContent = "";
    const id = location.hash.slice(1);
    [...apks].sort((a, b) => Number(b.primary) - Number(a.primary)).forEach((a) => {
      const li = document.createElement("li");
      const link = document.createElement("a");
      link.href = `/api/jobs/${encodeURIComponent(id)}/apks/${encodeURIComponent(a.name)}`;
      link.setAttribute("download", a.name);
      link.textContent = `تنزيل ${a.name} (${fmtMB(a.size)})`;
      const small = document.createElement("small");
      small.textContent = "sha256: " + a.sha256.slice(0, 16) + "…";
      link.appendChild(small);
      li.appendChild(link);
      list.appendChild(li);
    });
    if (warnings && warnings.length) {
      const p = document.createElement("li");
      p.textContent = "ملاحظات: " + warnings.join(" — ");
      p.style.color = "var(--muted)";
      list.appendChild(p);
    }
    show("details", !!excerpt);
    $("excerpt").textContent = excerpt || "";
    show("result", true);
  }

  $("again").addEventListener("click", () => {
    clearTimeout(timer);
    history.replaceState(null, "", location.pathname);
    $("file").value = "";
    chosen = null;
    $("file-label").textContent = "اختر ملف ZIP";
    $("file-meta").textContent = "لم يُختر ملف بعد";
    $("go").disabled = true;
    show("result", false); show("progress", false); show("pick", true);
  });

  if (ID_RE.test(location.hash.slice(1))) {  // resume after a page reload
    show("pick", false); show("progress", true);
    setRail("check");
    $("status-text").textContent = "جارٍ استعادة حالة الطلب…";
    poll(location.hash.slice(1));
  }
})();
