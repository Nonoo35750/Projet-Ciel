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
    # La clé arrive en base64, il faut la décoder en bytes
    key_bytes = base64.b64decode(key_b64)
    result = aes.encrypt_string_to_base64(data, key_bytes)
    return {"encrypted": result}

@app.post("/aes/decrypt_string")
def decrypt_string(data: str = Form(...), key_b64: str = Form(...)):
    key_bytes = base64.b64decode(key_b64)
    result = aes.decrypt_string_from_base64(data, key_bytes)
    return {"decrypted": result}

# Les routes de génération/sauvegarde de clé peuvent rester pour l'administration
@app.post("/aes/generate_and_save_key")
def generate_and_save_aes_key(filename: str = Form(...)):
    aes.generate_aes_key()
    aes.save_aes_key_to_file(filename)
    return {"status": f"New AES key generated and saved to {filename}"}

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

# Route de génération pour l'administration
@app.post("/rsa/generate_keys")
def generate_rsa_keys(public_file: str = Form(...), private_file: str = Form(...), size: int = Form(2048)):
    rsa.generation_clef(public_file, private_file, size)
    return {"status": "RSA keys generated."}


if __name__ == "__main__":
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)