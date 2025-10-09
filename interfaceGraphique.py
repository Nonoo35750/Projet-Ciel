import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import requests

API_URL = "http://192.168.1.79:8000"

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        root.title("Crypto GUI")
        self.cipher_type = tk.StringVar(value="AES")

        # Ligne 0 : Choix entre AES et RSA
        tk.Label(root, text="Méthode de chiffrement :").grid(row=0, column=0, sticky='e')
        tk.OptionMenu(root, self.cipher_type, "AES", "RSA").grid(row=0, column=1, sticky='w')

        # Ligne 1 : Charger clé AES
        tk.Label(root, text="Clé AES :").grid(row=1, column=0, sticky='e')
        tk.Button(root, text="Charger", command=self.load_aes_key).grid(row=1, column=1, sticky='w')

        # Ligne 2 : Charger clé RSA
        tk.Label(root, text="Clé RSA :").grid(row=2, column=0, sticky='e')
        tk.Button(root, text="Charger", command=self.load_rsa_keys).grid(row=2, column=1, sticky='w')

        # Ligne 3+ : Actions
        actions = [
            ("Chiffrer", self.encrypt_data),
            ("Déchiffrer", self.decrypt_data),
            ("SHA-256", self.hash_sha256),
        ]

        for i, (label, command) in enumerate(actions, start=3):
            tk.Label(root, text=label + " :").grid(row=i, column=0, sticky='e')
            tk.Button(root, text=label, command=command).grid(row=i, column=1, sticky='w')

    def load_aes_key(self):
        filepath = filedialog.askopenfilename(title="Choisir la clé AES")
        if filepath:
            res = requests.post(f"{API_URL}/aes/load_key", data={"filename": filepath})
            messagebox.showinfo("Chargement AES", res.json()["status"])

    def load_rsa_keys(self):
        pub = filedialog.askopenfilename(title="Clé publique RSA")
        priv = filedialog.askopenfilename(title="Clé privée RSA")
        if pub and priv:
            res = requests.post(f"{API_URL}/rsa/load_keys", data={"pub_file": pub, "priv_file": priv})
            messagebox.showinfo("Chargement RSA", res.json()["status"])

    def encrypt_data(self):
        data = simpledialog.askstring("Chiffrement", "Texte à chiffrer :")
        if not data:
            return

        if self.cipher_type.get() == "AES":
            res = requests.post(f"{API_URL}/aes/encrypt_string", data={"data": data})
        else:
            res = requests.post(f"{API_URL}/rsa/encrypt", data={"data": data})
        
        messagebox.showinfo("Résultat", res.json().get("encrypted", "Erreur"))

    def decrypt_data(self):
        data = simpledialog.askstring("Déchiffrement", "Texte chiffré (Base64) :")
        if not data:
            return

        if self.cipher_type.get() == "AES":
            res = requests.post(f"{API_URL}/aes/decrypt_string", data={"data": data})
        else:
            res = requests.post(f"{API_URL}/rsa/decrypt", data={"data": data})

        messagebox.showinfo("Résultat", res.json().get("decrypted", "Erreur"))

    def hash_sha256(self):
        data = simpledialog.askstring("SHA-256", "Texte à hacher :")
        if data:
            res = requests.post(f"{API_URL}/hash/sha256", data={"data": data})
            messagebox.showinfo("SHA-256", res.json()["sha256"])


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()
