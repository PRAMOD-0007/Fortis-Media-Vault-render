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

function applyKeyMode() {
  $("keymodes").hidden = !isEnc();
  $("pw-field").hidden = generate();
  $("gen-note").hidden = !generate();
  $("pw-label").textContent = isEnc() ? "Password" : "Password or key";
  pw.placeholder = isEnc() ? "Enter a password" : "Enter the password or key";
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
  try {
    const res = await fetch("/process", { method: "POST", body });
    if (!res.ok) {
      let msg = "Something went wrong. Try again.";
      try { msg = (await res.json()).error || msg; } catch (_) { /* non-JSON error */ }
      return showMsg(msg, "error");
    }
    const name = decodeURIComponent(res.headers.get("X-Filename") || "output.bin");
    const blob = await res.blob();
    objectUrl = URL.createObjectURL(blob);
    dl.href = objectUrl;
    dl.download = name;
    $("out-name").textContent = name;
    $("out-size").textContent = fmt(blob.size);
    result.hidden = false;
    const key = res.headers.get("X-Generated-Key");
    if (key) { $("genkey").value = key; $("keybox").hidden = false; }
    showMsg(isEnc() ? (key ? "Encrypted. Save the key below: it can't be recovered." : "Encrypted. Keep the password safe: there is no way to recover it.") : "Decrypted. Your original file is ready.", "ok");
  } catch (_) {
    showMsg("Could not reach the server. Check your connection and try again.", "error");
  } finally {
    setBusy(false);
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
