# generer_cle.py
from aesgestion import AesGestion

aes_manager = AesGestion()
aes_manager.generate_aes_key()
aes_manager.save_aes_key_to_file("ma_cle.key")

print("Le fichier 'ma_cle.key' de 32 octets a été créé dans le dossier 'keys'.")