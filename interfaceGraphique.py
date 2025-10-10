# interfaceGraphique.py (corrigé)
import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import base64
import os

import ttkbootstrap as ttk
from ttkbootstrap.scrolled import ScrolledText
from ttkbootstrap.constants import *

API_URL = "http://192.168.1.79:8000"

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        root.title("CryptoTool Pro")

        self.aes_key_b64 = None
        self.rsa_public_key_pem = None
        self.rsa_private_key_pem = None
        
        self.aes_key_status = tk.StringVar(value="Aucune clé chargée")
        self.rsa_key_status = tk.StringVar(value="Aucune clé chargée")
        
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=BOTH, expand=YES)

        settings_frame = ttk.Labelframe(main_frame, text=" ⚙️ Configuration ", padding="10")
        settings_frame.pack(fill=X, padx=5, pady=5)
        settings_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(settings_frame, text="Clé AES :").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        ttk.Label(settings_frame, textvariable=self.aes_key_status, style='info.TLabel').grid(row=0, column=1, sticky='w', padx=5)
        ttk.Button(settings_frame, text="Charger", command=self.load_aes_key, style='info.Outline.TButton').grid(row=0, column=2, padx=5)

        ttk.Label(settings_frame, text="Clés RSA :").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ttk.Label(settings_frame, textvariable=self.rsa_key_status, style='info.TLabel').grid(row=1, column=1, sticky='w', padx=5)
        ttk.Button(settings_frame, text="Charger", command=self.load_rsa_keys, style='info.Outline.TButton').grid(row=1, column=2, padx=5)

        io_frame = ttk.Labelframe(main_frame, text=" 📝 Données ", padding="10")
        io_frame.pack(fill=BOTH, expand=YES, padx=5, pady=5)
        io_frame.grid_rowconfigure(1, weight=1)
        io_frame.grid_columnconfigure(0, weight=1)
        io_frame.grid_columnconfigure(2, weight=1)

        ttk.Label(io_frame, text="Texte d'entrée :").grid(row=0, column=0, columnspan=2, sticky='w', pady=(0,5))
        self.input_text = ScrolledText(io_frame, height=8, width=50, autohide=True)
        self.input_text.grid(row=1, column=0, columnspan=3, sticky='nsew')
        
        ttk.Label(io_frame, text="Texte de sortie :").grid(row=2, column=0, columnspan=2, sticky='w', pady=(10,5))
        self.output_text = ScrolledText(io_frame, height=8, width=50, autohide=True)
        self.output_text.grid(row=3, column=0, columnspan=3, sticky='nsew')
        # LIGNE CORRIGÉE #1
        self.output_text.text.configure(state="disabled") # Lecture seule

        actions_frame = ttk.Frame(main_frame)
        actions_frame.pack(fill=X, padx=5, pady=10)

        buttons = {
            "Chiffrer AES": (self.encrypt_aes, SUCCESS),
            "Déchiffrer AES": (self.decrypt_aes, SUCCESS),
            "Chiffrer RSA": (self.encrypt_rsa, WARNING),
            "Déchiffrer RSA": (self.decrypt_rsa, WARNING),
            "SHA-256": (self.hash_sha256, SECONDARY)
        }
        for i, (text, (command, style)) in enumerate(buttons.items()):
            btn = ttk.Button(actions_frame, text=text, command=command, style=f'{style}.TButton')
            btn.pack(side=LEFT, expand=YES, fill=X, padx=2)

        ttk.Button(actions_frame, text="Copier", command=self.copy_output, style='light.TButton').pack(side=LEFT, padx=2)
        ttk.Button(actions_frame, text="Vider", command=self.clear_fields, style='danger.TButton').pack(side=LEFT, padx=2)


    def _update_output(self, content):
        # LIGNE CORRIGÉE #2
        self.output_text.text.configure(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", content)
        # LIGNE CORRIGÉE #3
        self.output_text.text.configure(state="disabled")
        
    def load_aes_key(self):
        filepath = filedialog.askopenfilename(title="Choisir le fichier de clé AES (.key)")
        if filepath:
            try:
                with open(filepath, 'rb') as f:
                    key_bytes = f.read()
                    self.aes_key_b64 = base64.b64encode(key_bytes).decode('utf-8')
                filename = os.path.basename(filepath)
                self.aes_key_status.set(f"✅ {filename}")
            except Exception as e:
                self.aes_key_status.set("❌ Erreur de chargement")
                messagebox.showerror("Erreur", f"Impossible de lire la clé AES : {e}")

    def load_rsa_keys(self):
        pub_path = filedialog.askopenfilename(title="Choisir la clé publique RSA (.pem)")
        if not pub_path: return
        priv_path = filedialog.askopenfilename(title="Choisir la clé privée RSA (.pem)")
        if not priv_path: return
        try:
            with open(pub_path, 'r', encoding='utf-8') as f:
                self.rsa_public_key_pem = f.read()
            with open(priv_path, 'r', encoding='utf-8') as f:
                self.rsa_private_key_pem = f.read()
            self.rsa_key_status.set("✅ Clés publique et privée chargées")
        except Exception as e:
            self.rsa_key_status.set("❌ Erreur de chargement")
            messagebox.showerror("Erreur", f"Impossible de lire les clés RSA : {e}")

    def _execute_request(self, endpoint, payload, result_key):
        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Entrée vide", "Veuillez saisir du texte dans le champ d'entrée.")
            return

        payload["data"] = data
        try:
            res = requests.post(f"{API_URL}{endpoint}", data=payload)
            res.raise_for_status()
            self._update_output(res.json().get(result_key, "Clé de résultat non trouvée."))
        except requests.exceptions.RequestException as e:
            self._update_output(f"--- ERREUR RÉSEAU ---\n{e}")
        except Exception as e:
            self._update_output(f"--- ERREUR INATTENDUE ---\n{e}")

    def encrypt_aes(self):
        if not self.aes_key_b64:
            messagebox.showwarning("Clé manquante", "Veuillez d'abord charger une clé AES.")
            return
        self._execute_request("/aes/encrypt_string", {"key_b64": self.aes_key_b64}, "encrypted")

    def decrypt_aes(self):
        if not self.aes_key_b64:
            messagebox.showwarning("Clé manquante", "Veuillez d'abord charger une clé AES.")
            return
        self._execute_request("/aes/decrypt_string", {"key_b64": self.aes_key_b64}, "decrypted")

    def encrypt_rsa(self):
        if not self.rsa_public_key_pem:
            messagebox.showwarning("Clé manquante", "Veuillez d'abord charger une clé publique RSA.")
            return
        self._execute_request("/rsa/encrypt", {"public_key_pem": self.rsa_public_key_pem}, "encrypted")

    def decrypt_rsa(self):
        if not self.rsa_private_key_pem:
            messagebox.showwarning("Clé manquante", "Veuillez d'abord charger une clé privée RSA.")
            return
        self._execute_request("/rsa/decrypt", {"private_key_pem": self.rsa_private_key_pem}, "decrypted")

    def hash_sha256(self):
        self._execute_request("/hash/sha256", {}, "sha256")

    def copy_output(self):
        # On accède au contenu via .get() sur le widget principal
        content = self.output_text.get("1.0", tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            # On peut garder le messagebox pour un feedback clair
            # messagebox.showinfo("Copié !", "Le texte de sortie a été copié dans le presse-papiers.")
            
    def clear_fields(self):
        self.input_text.delete("1.0", tk.END)
        self._update_output("")


if __name__ == "__main__":
    root = ttk.Window(themename="superhero")
    app = CryptoGUI(root)
    root.mainloop()