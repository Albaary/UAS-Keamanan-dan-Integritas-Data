# client.py — generate ED25519 keypair, sign messages, demo decrypt
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

# Generate ED25519 keypair (or reuse files if exist)
def generate_keys(priv_path="client_priv.pem", pub_path="client_pub.pem"):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PrivateFormat.PKCS8,
                                   encryption_algorithm=serialization.NoEncryption()))
    with open(pub_path, "wb") as f:
        f.write(pub.public_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Keys written: {priv_path}, {pub_path}")
    return priv, pub

def load_private(path="client_priv.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign_message(priv_key, msg: str):
    sig = priv_key.sign(msg.encode())
    return base64.b64encode(sig).decode()

# Demo usage
if __name__ == "__main__":
    priv, pub = generate_keys()
    msg = "Hello Punk Records!"
    signature = sign_message(priv, msg)
    print("Message:", msg)
    print("Signature (base64):", signature)
    # To test decrypt-demo: use aes_key_base64 returned from /relay and encrypted_message