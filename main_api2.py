# main_api.py (mis à jour)
from fastapi import FastAPI, Form
from aesgestion import AesGestion
from hashgestion import HashGestion
from rsagestion import RsaGestion
import uvicorn
import base64

app = FastAPI()

aes = AesGestion()
hash_gestion = HashGestion()
rsa = RsaGestion()

# ================= AES ====================

@app.post("/aes/encrypt_string")
def encrypt_string(data: str = Form(...), key_b64: str = Form(...)):
    key_bytes = base64.b64decode(key_b64)
    result = aes.encrypt_string_to_base64(data, key_bytes)
    return {"encrypted": result}

@app.post("/aes/decrypt_string")
def decrypt_string(data: str = Form(...), key_b64: str = Form(...)):
    key_bytes = base64.b64decode(key_b64)
    result = aes.decrypt_string_from_base64(data, key_bytes)
    return {"decrypted": result}

# NOUVELLE ROUTE : Génère une clé AES et la renvoie
@app.post("/aes/generate_key")
def generate_aes_key():
    key_bytes = aes.generate_aes_key()
    key_b64 = base64.b64encode(key_bytes).decode('utf-8')
    return {"aes_key_b64": key_b64}

# ================= HASH (inchangé) ====================

@app.post("/hash/sha256")
def sha256_string(data: str = Form(...)):
    result = hash_gestion.calculate_sha256(data)
    return {"sha256": result}

# ================= RSA ====================

@app.post("/rsa/encrypt")
def rsa_encrypt(data: str = Form(...), public_key_pem: str = Form(...)):
    encrypted = rsa.chiffrement_rsa(data, public_key_pem)
    return {"encrypted": encrypted}

@app.post("/rsa/decrypt")
def rsa_decrypt(data: str = Form(...), private_key_pem: str = Form(...)):
    decrypted = rsa.dechiffrement_rsa(data, private_key_pem)
    return {"decrypted": decrypted}

# NOUVELLE ROUTE : Génère des clés RSA et les renvoie
@app.post("/rsa/generate_keys")
def generate_rsa_keys(size: int = Form(2048)):
    private_key_pem, public_key_pem = rsa.generation_clef(size)
    return {
        "private_key_pem": private_key_pem,
        "public_key_pem": public_key_pem
    }

if __name__ == "__main__":
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)