# rsagestion.py

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RsaGestion:
    def __init__(self):
        print("Construction de la classe")

    def __del__(self):
        print("Destructeur par défaut du RSA")

    def generation_clef(self, nom_fichier_public, nom_fichier_prive, taille):
        key = RSA.generate(taille)
        with open(nom_fichier_prive, 'wb') as f:
            f.write(key.export_key('PEM'))
        print(f"Ecriture clef privée dans {nom_fichier_prive}")

        with open(nom_fichier_public, 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
        print(f"Ecriture clef publique dans {nom_fichier_public}")

    # FONCTIONS MODIFIÉES
    def chiffrement_rsa(self, donne_claire: str, clef_publique_pem: str) -> str:
        clef_publique = RSA.import_key(clef_publique_pem)
        cipher = PKCS1_OAEP.new(clef_publique)
        donne_claire_bytes = donne_claire.encode('utf-8')
        donne_chiffree = cipher.encrypt(donne_claire_bytes)
        return base64.b64encode(donne_chiffree).decode('utf-8')

    def dechiffrement_rsa(self, message_chiffre: str, clef_privee_pem: str) -> str:
        clef_privee = RSA.import_key(clef_privee_pem)
        cipher = PKCS1_OAEP.new(clef_privee)
        donne_chiffree = base64.b64decode(message_chiffre)
        donne_claire = cipher.decrypt(donne_chiffree)
        return donne_claire.decode('utf-8')