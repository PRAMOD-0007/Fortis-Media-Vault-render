"""Fortis Media Vault: password-based encryption for media files (AES-256-GCM + scrypt)."""
import io
import os
import secrets
import struct
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from flask import Flask, jsonify, render_template, request, send_file

MAGIC = b"FMV01"          # file signature + format version, also bound as AAD
SALT_LEN, NONCE_LEN, TAG_LEN = 16, 12, 16
HEADER_LEN = len(MAGIC) + SALT_LEN + NONCE_LEN
ENC_EXT = ".fmv"
MAX_MB = int(os.environ.get("MAX_MB", "200"))
MIN_PASSWORD = 8
MEDIA_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".svg", ".heic", ".avif",
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".opus",
    ".mp4", ".mov", ".mkv", ".webm", ".avi", ".m4v", ".mpeg", ".mpg",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = (MAX_MB + 1) * 1024 * 1024


class UserError(Exception):
    """An error whose message is safe and useful to show to the user."""


def derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def encrypt(data: bytes, filename: str, password: str) -> bytes:
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    name = filename.encode("utf-8")
    payload = struct.pack(">H", len(name)) + name + data  # original name travels inside the ciphertext
    ciphertext = AESGCM(derive_key(password, salt)).encrypt(nonce, payload, MAGIC)
    return MAGIC + salt + nonce + ciphertext


def decrypt(blob: bytes, password: str):
    if len(blob) < HEADER_LEN + TAG_LEN + 2 or not blob.startswith(MAGIC):
        raise UserError("This isn't a Fortis Media Vault file. Upload a .fmv file made by this app.")
    salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
    nonce = blob[len(MAGIC) + SALT_LEN:HEADER_LEN]
    try:
        payload = AESGCM(derive_key(password, salt)).decrypt(nonce, blob[HEADER_LEN:], MAGIC)
    except InvalidTag:
        raise UserError("Wrong password, or the file was changed or damaged. Check the password and try again.")
    (name_len,) = struct.unpack(">H", payload[:2])
    name = payload[2:2 + name_len].decode("utf-8", errors="replace")
    return payload[2 + name_len:], os.path.basename(name) or "decrypted_file"


@app.get("/")
def index():
    return render_template("index.html", max_mb=MAX_MB)


@app.post("/process")
def process():
    mode = request.form.get("mode", "")
    password = request.form.get("password", "")
    generate = mode == "encrypt" and request.form.get("key_mode") == "generate"
    upload = request.files.get("file")

    if mode not in ("encrypt", "decrypt"):
        raise UserError("Choose encrypt or decrypt.")
    if upload is None or not upload.filename:
        raise UserError("Choose a file first.")
    if generate:
        password = secrets.token_urlsafe(18)  # 24 random characters, shown to the user once
    elif not password:
        raise UserError("Enter a password." if mode == "encrypt" else "Enter the password or key you used to encrypt this file.")

    data = upload.read()
    if not data:
        raise UserError("That file is empty.")
    name = os.path.basename(upload.filename.replace("\\", "/"))[:200]

    if mode == "encrypt":
        if len(password) < MIN_PASSWORD:
            raise UserError(f"Use a password with at least {MIN_PASSWORD} characters.")
        if os.path.splitext(name)[1].lower() not in MEDIA_EXTS:
            raise UserError("Unsupported file type. Upload an image, audio or video file.")
        out, out_name = encrypt(data, name, password), name + ENC_EXT
    else:
        out, out_name = decrypt(data, password)

    response = send_file(io.BytesIO(out), mimetype="application/octet-stream",
                         as_attachment=True, download_name=out_name)
    response.headers["X-Filename"] = quote(out_name)
    response.headers["Cache-Control"] = "no-store"
    if generate:
        response.headers["X-Generated-Key"] = password
    return response


@app.errorhandler(UserError)
def handle_user_error(err):
    return jsonify(error=str(err)), 400


@app.errorhandler(413)
def handle_too_large(_):
    return jsonify(error=f"That file is over {MAX_MB} MB. Choose a smaller one."), 413


@app.errorhandler(Exception)
def handle_unexpected(err):
    if hasattr(err, "code") and hasattr(err, "description"):  # regular HTTP errors (404, 405...)
        return jsonify(error=err.description), err.code
    app.logger.exception("Unexpected error")
    return jsonify(error="Something went wrong on the server. Try again."), 500


if __name__ == "__main__":
    app.run(debug=False)
