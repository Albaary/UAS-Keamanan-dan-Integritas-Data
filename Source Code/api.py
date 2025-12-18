# api.py (FULL — JWT, AES, Multiuser)
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec

from datetime import datetime, timedelta
import hashlib
import base64
import os
import secrets


from jose import jwt, JWTError

app = FastAPI(title="Security Service (FULL)")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static users (demo)
VALID_USERS = ["luffy", "zoro", "nami", "sanji"]

# Storage
KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

# JWT config
JWT_SECRET = "super-secret-change-me"
JWT_ALGO = "HS256"
TOKEN_EXPIRE_HOURS = 2
security = HTTPBearer()

# Helpers
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def create_token(username: str) -> str:
    payload = {"user": username, "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        username = data.get("user")
        if not username or username not in VALID_USERS:
            raise HTTPException(status_code=403, detail="Invalid token or user not allowed")
        return username
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

def aes_encrypt(message: str, key: bytes) -> str:
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(b64_blob: str, key: bytes) -> str:
    raw = base64.b64decode(b64_blob)
    iv = raw[:16]; ciphertext = raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Basic
@app.get("/health")
def health_check():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

@app.get("/")
def index():
    return {"message": "Security Service — visit /docs"}

# Login -> token
@app.post("/login")
def login(username: str = Form(...)):
    if username not in VALID_USERS:
        raise HTTPException(status_code=400, detail="User not registered")
    token = create_token(username)
    return {"token": token, "user": username}

# Store public key (requires token; user must be token owner)
@app.post("/store")
async def store_pubkey(username: str = Form(...), pubkey_file: UploadFile = File(...), current_user: str = Depends(verify_token)):
    if username != current_user:
        raise HTTPException(status_code=403, detail="Cannot store key for other user")
    if not pubkey_file.filename.endswith(".pem"):
        raise HTTPException(status_code=400, detail="Public key file must be .pem")
    contents = await pubkey_file.read()
    try:
        serialization.load_pem_public_key(contents)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key PEM: {e}")
    file_hash = sha256_hex(contents)
    save_path = os.path.join(KEY_DIR, f"{username}.pem")
    with open(save_path, "wb") as f:
        f.write(contents)
    return {"message": "Public key stored", "user": username, "sha256": file_hash}

# Verify signature (requires token)
@app.post("/verify")
async def verify_signature(username: str = Form(...), message: str = Form(...), signature: str = Form(...), current_user: str = Depends(verify_token)):
    key_path = os.path.join(KEY_DIR, f"{username}.pem")
    if not os.path.exists(key_path):
        raise HTTPException(status_code=404, detail="Public key not found")
    pub_bytes = open(key_path, "rb").read()
    try:
        pubkey = serialization.load_pem_public_key(pub_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="Stored public key invalid")
    try:
        sig_bytes = base64.b64decode(signature)
    except Exception:
        raise HTTPException(status_code=400, detail="Signature must be base64 encoded")
    try:
        pubkey.verify(sig_bytes, message.encode())
        return {"message": "Signature VALID", "user": username}
    except Exception:
        return {"message": "Signature INVALID", "user": username}

# Relay (requires token; sender must match token owner)
@app.post("/relay")
async def relay(sender: str = Form(...), receiver: str = Form(...), message: str = Form(...), current_user: str = Depends(verify_token)):
    if sender != current_user:
        raise HTTPException(status_code=403, detail="Cannot send as other user")
    if sender not in VALID_USERS or receiver not in VALID_USERS:
        raise HTTPException(status_code=400, detail="Sender or receiver not valid")
    recv_key_path = os.path.join(KEY_DIR, f"{receiver}.pem")
    if not os.path.exists(recv_key_path):
        raise HTTPException(status_code=400, detail="Receiver has no public key stored")
    aes_key = secrets.token_bytes(32)
    encrypted = aes_encrypt(message, aes_key)
    return {
        "status": "Message relayed (simulated)",
        "from": sender,
        "to": receiver,
        "encrypted_message": encrypted,
        "aes_key_base64": base64.b64encode(aes_key).decode()
    }

# Decrypt demo (for testing)
@app.post("/decrypt-demo")
def decrypt_demo(encrypted_blob: str = Form(...), aes_key_b64: str = Form(...)):
    try:
        key = base64.b64decode(aes_key_b64)
        plaintext = aes_decrypt(encrypted_blob, key)
        return {"plaintext": plaintext}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Cannot decrypt: {e}")

# SIGN PDF (FIXED - ECDSA)
@app.post("/sign-pdf")
async def sign_pdf(file: UploadFile = File(...), current_user: str = Depends(verify_token)):

    if not file.filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="File must be a PDF")

    try:
        # baca file pdf
        pdf_bytes = await file.read()

        # hash pdf (SHA-256)
        pdf_hash = hashlib.sha256(pdf_bytes).digest()

        # load private key server (ECDSA)
        with open("punkhazard-keys/priv.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # SIGN HASH menggunakan ECDSA + SHA256 (INI YANG BENAR)
        signature = private_key.sign(
            pdf_hash,
            ec.ECDSA(hashes.SHA256())
        )

        signature_b64 = base64.b64encode(signature).decode()

        return {
            "message": "PDF signed successfully",
            "pdf_hash_hex": pdf_hash.hex(),
            "signature_base64": signature_b64,
            "signed_by": current_user
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to sign PDF: {e}")

    try:
        # baca pdf file
        pdf_bytes = await file.read()

        # hitung hash SHA-256 dari PDF
        pdf_hash = hashlib.sha256(pdf_bytes).digest()

        # load private key server untuk tanda tangan
        with open("punkhazard-keys/priv.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # sign hash
        signature = private_key.sign(pdf_hash)

        # encode hasil signature
        signature_b64 = base64.b64encode(signature).decode()

        return {
            "message": "PDF signed successfully.",
            "pdf_hash_hex": pdf_hash.hex(),
            "signature_base64": signature_b64,
            "signed_by": current_user
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to sign PDF: {e}")
