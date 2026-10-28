const $ = (id) => document.getElementById(id);
const form = $("form"), fileInput = $("file"), drop = $("drop"), pw = $("password"),
  go = $("go"), box = $("status"), result = $("result"), dl = $("download");
const MAX = window.MAX_MB * 1024 * 1024;
let objectUrl = null;

const mode = () => form.elements.mode.value;
const isEnc = () => mode() === "encrypt";
const generate = () => isEnc() && form.elements.key_mode.value === "generate";
const fmt = (n) => (n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB");

function showMsg(text, kind) {
  box.textContent = text;
  box.className = "status " + kind;
  box.hidden = false;
}

function clearOutput() {
  box.hidden = true;
  result.hidden = true;
  $("keybox").hidden = true;
  $("genkey").value = "";
  $("preview").hidden = true;
  $("preview").replaceChildren();
  if (previewUrl) { URL.revokeObjectURL(previewUrl); previewUrl = null; }
  if (objectUrl) { URL.revokeObjectURL(objectUrl); objectUrl = null; }
}

function renderDrop() {
  const f = fileInput.files[0];
  drop.classList.toggle("has-file", !!f);
  $("drop-title").textContent = f ? f.name : isEnc() ? "Choose a file to encrypt" : "Choose a .fmv file to decrypt";
  $("drop-hint").textContent = f ? fmt(f.size)
    : isEnc() ? `Drag it here or click to browse. Images, audio and video up to ${window.MAX_MB} MB.`
              : "Drag it here or click to browse. Only files encrypted with Fortis Media Vault work.";
}

function setBusy(busy) {
  go.disabled = busy;
  go.textContent = busy ? (isEnc() ? "Encrypting…" : "Decrypting…") : (isEnc() ? "Encrypt file" : "Decrypt file");
}

let previewUrl = null;

const MIME = {
  jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif", webp: "image/webp", bmp: "image/bmp",
  svg: "image/svg+xml", avif: "image/avif", heic: "image/heic", tiff: "image/tiff",
  mp3: "audio/mpeg", wav: "audio/wav", flac: "audio/flac", aac: "audio/aac", ogg: "audio/ogg", m4a: "audio/mp4", opus: "audio/ogg",
  mp4: "video/mp4", mov: "video/quicktime", mkv: "video/x-matroska", webm: "video/webm", avi: "video/x-msvideo",
  m4v: "video/x-m4v", mpeg: "video/mpeg", mpg: "video/mpeg",
};

// Upload with real progress (fetch cannot report upload progress)
function send(body, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/process");
    xhr.responseType = "blob";
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
    xhr.upload.onload = () => onProgress(1);
    xhr.onload = () => resolve(xhr);
    xhr.onerror = () => reject(new Error("network"));
    xhr.send(body);
  });
}

function showProgress(f) {
  const pct = Math.round(f * 100);
  $("progress").hidden = false;
  $("prog-fill").style.width = pct + "%";
  $("prog-text").textContent = f < 1 ? `Uploading ${pct}%` : (isEnc() ? "Encrypting on the server…" : "Decrypting on the server…");
}

// Preview of the decrypted file, built from a local blob (images use <img>, so SVG scripts cannot run)
function showPreview(blob, name) {
  const mime = MIME[name.split(".").pop().toLowerCase()];
  if (!mime) return;
  const box = $("preview");
  const kind = mime.split("/")[0];
  previewUrl = URL.createObjectURL(new Blob([blob], { type: mime }));
  const media = document.createElement(kind === "image" ? "img" : kind);
  media.src = previewUrl;
  if (kind === "image") media.alt = "Decrypted file preview"; else media.controls = true;
  const label = document.createElement("span");
  label.textContent = "Preview";
  media.addEventListener("error", () => {
    const p = document.createElement("p");
    p.textContent = "Your browser can't preview this format. You can still download the file.";
    box.replaceChildren(label, p);
  });
  box.replaceChildren(label, media);
  box.hidden = false;
}

function scorePassword(p) {
  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/\d/.test(p)) pool += 10;
  if (/[^A-Za-z0-9]/.test(p)) pool += 32;
  let bits = p.length * Math.log2(pool || 1);
  if (new Set(p).size < p.length / 2) bits *= 0.6;
  if (/^(.)\1+$/.test(p) || /(password|qwerty|123456|abc123|letmein|admin)/i.test(p)) bits = Math.min(bits, 20);
  return bits;
}

function updateMeter() {
  const show = isEnc() && !generate() && pw.value.length > 0;
  $("meter").hidden = !show;
  if (!show) return;
  const bits = scorePassword(pw.value);
  const lvl = pw.value.length < 8 || bits < 28 ? 0 : bits < 45 ? 1 : bits < 60 ? 2 : 3;
  const [name, color, pct] = [["Weak", "var(--bad)", 25], ["Fair", "#f5c26b", 50], ["Good", "var(--accent)", 75], ["Strong", "var(--ok)", 100]][lvl];
  $("meter-fill").style.width = pct + "%";
  $("meter-fill").style.background = color;
  const tip = pw.value.length < 8 ? " (use at least 8 characters)" : lvl < 2 ? " (try a longer password or a few random words)" : "";
  $("meter-text").textContent = "Strength: " + name + tip;
}

function applyKeyMode() {
  $("keymodes").hidden = !isEnc();
  $("pw-field").hidden = generate();
  $("gen-note").hidden = !generate();
  $("pw-label").textContent = isEnc() ? "Password" : "Password or key";
  pw.placeholder = isEnc() ? "Enter a password" : "Enter the password or key";
  updateMeter();
}

function syncMode() {
  applyKeyMode();
  document.body.dataset.mode = mode();
  fileInput.accept = isEnc() ? "image/*,audio/*,video/*" : ".fmv";
  pw.autocomplete = isEnc() ? "new-password" : "current-password";
  fileInput.value = "";
  clearOutput();
  renderDrop();
  setBusy(false);
}

form.querySelectorAll('input[name="mode"]').forEach((r) => r.addEventListener("change", syncMode));
form.querySelectorAll('input[name="key_mode"]').forEach((r) => r.addEventListener("change", applyKeyMode));
fileInput.addEventListener("change", () => { clearOutput(); renderDrop(); });

["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => {
  if (e.dataTransfer.files.length) { fileInput.files = e.dataTransfer.files; clearOutput(); renderDrop(); }
});

pw.addEventListener("input", updateMeter);

$("toggle").addEventListener("click", (e) => {
  const show = pw.type === "password";
  pw.type = show ? "text" : "password";
  e.target.textContent = show ? "Hide" : "Show";
  e.target.setAttribute("aria-pressed", show);
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearOutput();
  const file = fileInput.files[0];
  if (!file) return showMsg("Choose a file first.", "error");
  if (file.size === 0) return showMsg("That file is empty.", "error");
  if (file.size > MAX) return showMsg(`That file is over ${window.MAX_MB} MB. Choose a smaller one.`, "error");
  if (!generate()) {
    if (!pw.value) return showMsg(isEnc() ? "Enter a password." : "Enter the password or key you used to encrypt this file.", "error");
    if (isEnc() && pw.value.length < 8) return showMsg("Use a password with at least 8 characters.", "error");
  }

  const body = new FormData();
  body.append("mode", mode());
  body.append("file", file);
  body.append("password", pw.value);
  if (isEnc()) body.append("key_mode", generate() ? "generate" : "password");

  setBusy(true);
  showProgress(0);
  try {
    const xhr = await send(body, showProgress);
    if (xhr.status < 200 || xhr.status >= 300) {
      let msg = "Something went wrong. Try again.";
      try { msg = JSON.parse(await xhr.response.text()).error || msg; } catch (_) { /* non-JSON error */ }
      return showMsg(msg, "error");
    }
    const name = decodeURIComponent(xhr.getResponseHeader("X-Filename") || "output.bin");
    const blob = xhr.response;
    objectUrl = URL.createObjectURL(blob);
    dl.href = objectUrl;
    dl.download = name;
    $("out-name").textContent = name;
    $("out-size").textContent = fmt(blob.size);
    result.hidden = false;
    const key = xhr.getResponseHeader("X-Generated-Key");
    if (!isEnc()) showPreview(blob, name);
    if (key) { $("genkey").value = key; $("keybox").hidden = false; }
    showMsg(isEnc() ? (key ? "Encrypted. Save the key below: it can't be recovered." : "Encrypted. Keep the password safe: there is no way to recover it.") : "Decrypted. Your original file is ready.", "ok");
  } catch (_) {
    showMsg("Could not reach the server. Check your connection and try again.", "error");
  } finally {
    setBusy(false);
    $("progress").hidden = true;
  }
});

$("copy").addEventListener("click", async (e) => {
  const k = $("genkey");
  k.select();
  try { await navigator.clipboard.writeText(k.value); } catch (_) { document.execCommand("copy"); }
  e.target.textContent = "Copied";
  setTimeout(() => (e.target.textContent = "Copy"), 1500);
});

syncMode();
