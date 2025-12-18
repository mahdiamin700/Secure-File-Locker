from flask import Flask, request, render_template, send_file
from flask_sqlalchemy import SQLAlchemy
from config import Config
from datetime import datetime

# crypto imports
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from passlib.hash import pbkdf2_sha256

import base64, json, hashlib, io, uuid
from pathlib import Path

# ---------------- Flask + DB ----------------
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = BASE_DIR / "encrypted_files"
FILES_DIR.mkdir(exist_ok=True)

# ✅ TEMP cache so we can show success message before file download
# token -> {"filename": str, "data": bytes}
DECRYPT_CACHE = {}

# ---------------- Models ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    public_key_pem = db.Column(db.Text, nullable=False)
    encrypted_private_key_pem = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = pbkdf2_sha256.hash(password)

    def check_password(self, password: str) -> bool:
        return pbkdf2_sha256.verify(password, self.password_hash)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    file_name = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(64), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class FileKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    encrypted_file_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    file_id = db.Column(db.Integer, nullable=True)

    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)


# ✅ Digital Signature table
class FileSignature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    signature_b64 = db.Column(db.Text, nullable=False)
    signed_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- Helpers ----------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def derive_key_from_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return PBKDF2(password, salt, dkLen=32, count=iterations)  # AES-256

# ---------------- AES-CTR ----------------
def aes_ctr_encrypt(plaintext: bytes, key: bytes) -> dict:
    nonce = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return {
        "mode": "CTR",
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }

def aes_ctr_decrypt(data: dict, key: bytes) -> bytes:
    nonce = b64d(data["nonce"])
    ciphertext = b64d(data["ciphertext"])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# ---------------- RSA (wrap file key) ----------------
def generate_rsa_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    priv_pem = key.export_key(format="PEM")
    pub_pem = key.publickey().export_key(format="PEM")
    return priv_pem, pub_pem

def rsa_encrypt(public_key_pem: bytes, data: bytes) -> bytes:
    key = RSA.import_key(public_key_pem)
    return PKCS1_OAEP.new(key).encrypt(data)

def rsa_decrypt(private_key_pem: bytes, data: bytes) -> bytes:
    key = RSA.import_key(private_key_pem)
    return PKCS1_OAEP.new(key).decrypt(data)

# ---------------- Digital Signature (RSA-PSS) ----------------
def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sign_bytes(private_key_pem: bytes, data: bytes) -> bytes:
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(data)
    return pss.new(key).sign(h)

def verify_signature(public_key_pem: bytes, data: bytes, signature: bytes) -> bool:
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(data)
    try:
        pss.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ---------------- Private key decrypt ----------------
def decrypt_private_key_for_user(user: User, password: str) -> bytes:
    pkg = json.loads(user.encrypted_private_key_pem)
    salt = b64d(pkg["salt"])
    enc_dict = pkg["enc"]
    key_for_priv = derive_key_from_password(password, salt)
    return aes_ctr_decrypt(enc_dict, key_for_priv)

# ---------------- Routes ----------------
@app.route("/")
def index():
    return render_template("index.html", title="Crypto Vault")

@app.route("/register", methods=["GET", "POST"])
def register():
    success_msg = ""
    error_msg = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error_msg = "Username and password are required."
        else:
            existing = User.query.filter_by(username=username).first()
            if existing:
                error_msg = "Username already taken."
            else:
                priv_pem, pub_pem = generate_rsa_keypair()

                salt = get_random_bytes(16)
                key_for_priv = derive_key_from_password(password, salt)
                enc_priv = aes_ctr_encrypt(priv_pem, key_for_priv)

                priv_package = {"salt": b64e(salt), "enc": enc_priv}

                user = User(
                    username=username,
                    public_key_pem=pub_pem.decode("utf-8"),
                    encrypted_private_key_pem=json.dumps(priv_package),
                )
                user.set_password(password)

                db.session.add(user)
                db.session.commit()
                success_msg = f"User '{username}' registered successfully."

    return render_template("register.html", title="Register", success=success_msg, error=error_msg)

@app.route("/login", methods=["GET", "POST"])
def login():
    success_msg = ""
    error_msg = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            error_msg = "Invalid username or password."
        else:
            private_key_pem = decrypt_private_key_for_user(user, password)
            success_msg = f"Private key decrypted ({len(private_key_pem)} bytes)."

    return render_template("login.html", title="Login", success=success_msg, error=error_msg)

@app.route("/upload", methods=["GET", "POST"])
def upload():
    success_msg = ""
    error_msg = ""
    file_id = None
    username_keep = ""
    password_keep = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        file = request.files.get("file")

        username_keep = username
        password_keep = password

        if not username or not password or not file:
            error_msg = "Username, password and file are required."
        else:
            user = User.query.filter_by(username=username).first()
            if not user or not user.check_password(password):
                error_msg = "Invalid username or password."
            else:
                file_bytes = file.read()
                file_size = len(file_bytes)
                file_hash = sha256_hex(file_bytes)

                # AES key per file
                file_key = get_random_bytes(32)

                # encrypt file with AES-CTR
                enc_dict = aes_ctr_encrypt(file_bytes, file_key)

                # save encrypted JSON on disk
                enc_name = f"{uuid.uuid4().hex}.json"
                enc_path = FILES_DIR / enc_name
                enc_path.write_text(json.dumps(enc_dict))

                # wrap AES key with user's public RSA key
                enc_file_key_bytes = rsa_encrypt(user.public_key_pem.encode("utf-8"), file_key)
                enc_file_key_b64 = b64e(enc_file_key_bytes)

                # sign encrypted payload
                private_key_pem = decrypt_private_key_for_user(user, password)  # RAM only
                payload_bytes = canonical_json_bytes(enc_dict)
                signature = sign_bytes(private_key_pem, payload_bytes)
                signature_b64 = b64e(signature)

                # store DB
                new_file = File(
                    owner_id=user.id,
                    file_name=file.filename,
                    storage_path=str(enc_path),
                    file_size=file_size,
                    file_hash=file_hash,
                )
                db.session.add(new_file)
                db.session.flush()

                db.session.add(FileKey(
                    file_id=new_file.id,
                    user_id=user.id,
                    encrypted_file_key=enc_file_key_b64,
                ))

                db.session.add(FileSignature(
                    file_id=new_file.id,
                    user_id=user.id,
                    signature_b64=signature_b64,
                ))

                db.session.add(AuditLog(
                    user_id=user.id,
                    file_id=new_file.id,
                    action="UPLOAD",
                    details=f"Uploaded & encrypted '{file.filename}' + signed (RSA-PSS).",
                ))

                db.session.commit()

                file_id = new_file.id
                success_msg = f"✅ File encrypted & signed. File ID = {file_id}"

    return render_template(
        "upload.html",
        title="Encrypt File",
        success=success_msg,
        error=error_msg,
        file_id=file_id,
        username=username_keep,
        password=password_keep
    )

# ✅ Verify + Decrypt (shows message + button, does not download immediately)
@app.route("/download", methods=["GET", "POST"])
def download():
    success_msg = ""
    error_msg = ""
    token = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        file_id_str = request.form.get("file_id", "").strip()

        try:
            file_id = int(file_id_str)
        except ValueError:
            error_msg = "File ID must be a number."
            return render_template("download.html", title="Decrypt File", success=success_msg, error=error_msg, token=None)

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            error_msg = "Invalid username or password."
            return render_template("download.html", title="Decrypt File", success=success_msg, error=error_msg, token=None)

        file_row = File.query.get(file_id)
        if not file_row:
            error_msg = "File not found."
            return render_template("download.html", title="Decrypt File", success=success_msg, error=error_msg, token=None)

        fk = FileKey.query.filter_by(file_id=file_id, user_id=user.id).first()
        if not fk:
            error_msg = "You don't have access to this file."
            return render_template("download.html", title="Decrypt File", success=success_msg, error=error_msg, token=None)

        sig_row = FileSignature.query.filter_by(file_id=file_id, user_id=user.id).first()
        if not sig_row:
            error_msg = "Missing digital signature for this file."
            return render_template("download.html", title="Decrypt File", success=success_msg, error=error_msg, token=None)

        enc_path = Path(file_row.storage_path)
        if not enc_path.exists():
            error_msg = "Encrypted file is missing on disk."
            return render_template("download.html", title="Decrypt File", success=success_msg, error=error_msg, token=None)

        enc_dict = json.loads(enc_path.read_text())

        # ✅ verify signature BEFORE decrypt
        payload_bytes = canonical_json_bytes(enc_dict)
        sig_bytes = b64d(sig_row.signature_b64)

        ok = verify_signature(user.public_key_pem.encode("utf-8"), payload_bytes, sig_bytes)
        if not ok:
            error_msg = "Signature verification FAILED (file may be modified)."
            return render_template("download.html", title="Decrypt File", success=success_msg, error=error_msg, token=None)

        # decrypt user's private key (RAM only)
        private_key_pem = decrypt_private_key_for_user(user, password)

        # unwrap AES key
        file_key = rsa_decrypt(private_key_pem, b64d(fk.encrypted_file_key))

        # decrypt file
        plaintext = aes_ctr_decrypt(enc_dict, file_key)

        db.session.add(AuditLog(
            user_id=user.id,
            file_id=file_row.id,
            action="DOWNLOAD",
            details="Signature verified (RSA-PSS) then decrypted (AES-CTR).",
        ))
        db.session.commit()

        # ✅ store decrypted bytes temporarily to allow showing success message first
        token = uuid.uuid4().hex
        DECRYPT_CACHE[token] = {"filename": file_row.file_name, "data": plaintext}

        success_msg = "✅ Signature verified successfully. File decrypted successfully."

    return render_template("download.html", title="Decrypt File", success=success_msg, error=error_msg, token=token)

# ✅ actual download of decrypted file (after user clicks button)
@app.route("/download_plain/<token>", methods=["GET"])
def download_plain(token):
    item = DECRYPT_CACHE.pop(token, None)  # remove after download
    if not item:
        return "Decrypted file expired or not found.", 404

    memfile = io.BytesIO(item["data"])
    memfile.seek(0)

    return send_file(
        memfile,
        as_attachment=True,
        download_name=item["filename"],
        mimetype="application/octet-stream"
    )

# ---------------- Main ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
