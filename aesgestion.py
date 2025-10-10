# aesgestion.py
import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class AesGestion:
    def __init__(self):
        self.aes_key = None
        self.iv = None

    # Les fonctions de génération et de sauvegarde de clés restent utiles
    # pour créer les fichiers de clés initialement.
    def generate_aes_key(self):
        self.aes_key = get_random_bytes(32)
        print("Clé AES générée avec succès.")

    def save_aes_key_to_file(self, filename="aes.key"):
        if not self.aes_key:
            raise ValueError("Clé AES non générée.")
        os.makedirs("keys", exist_ok=True)
        with open(os.path.join("keys", filename), "wb") as f:
            f.write(self.aes_key)
        print("Clé AES sauvegardée dans le dossier 'keys'.")

    # FONCTIONS MODIFIÉES
    def encrypt_string_to_base64(self, plaintext: str, key_bytes: bytes) -> str:
        iv = get_random_bytes(16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        return base64.b64encode(iv + ciphertext).decode("utf-8")

    def decrypt_string_from_base64(self, base64_data: str, key_bytes: bytes) -> str:
        data = base64.b64decode(base64_data)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode("utf-8")