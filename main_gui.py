import sqlite3
import os
import tkinter as tk
from tkinter import messagebox

# =========================
# BASE DE DONNÉES (SQLite)
# =========================

DB_NAME = "security.db"

def init_db():
    db_exists = os.path.exists(DB_NAME)
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            password TEXT NOT NULL
        )
    """)
    if not db_exists:
        c.execute("INSERT INTO passwords (password) VALUES (?)", ("4221",))
        conn.commit()
    conn.close()

def get_password():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT password FROM passwords WHERE id = 1")
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def update_password(new_pass):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE passwords SET password = ? WHERE id = 1", (new_pass,))
    conn.commit()
    conn.close()


# =========================
# VALIDATION IP / MASQUE
# =========================
def checkElements(element, type):
    partieReseau = True

    if "." not in element:
        messagebox.showerror("Erreur", f"{type} n'est pas conforme. Veuillez séparer les nombres avec un point.")
        return False

    adresseDecoupe = element.split(".")
    if len(adresseDecoupe) != 4:
        messagebox.showerror("Erreur", f"{type} n'est pas conforme. Veuillez vérifier sa taille.")
        return False

    for x in range(4):
        # Vérifie que chaque partie est bien numérique
        if not adresseDecoupe[x].isdigit():
            messagebox.showerror("Erreur", f"{type} n'est pas conforme. Veuillez utiliser uniquement des chiffres.")
            return False

        val = int(adresseDecoupe[x])

        # Vérifie les bornes 0-255
        if val < 0 or val > 255:
            messagebox.showerror("Erreur", f"{type} n'est pas conforme. Chaque nombre doit être entre 0 et 255.")
            return False

        # Vérifications spécifiques IP
        if type == "l'adresse IP":
            if x == 0 and (val < 1 or val > 223):
                messagebox.showerror("Erreur", "Le premier numéro de l'adresse IP doit être entre 1 et 223.")
                return False
            if x == 0 and val == 127:
                messagebox.showerror("Erreur", "Adresse IP réservée (127.x.x.x).")
                return False

    # Vérification du masque
    if type == "le masque":
        masque_bits = "".join([format(int(part), "08b") for part in adresseDecoupe])
        if "01" in masque_bits:
            messagebox.showerror("Erreur", "le masque n'est pas conforme. Les bits du masque doivent être continus (ex: 11111111.11111110.00000000.00000000)")
            return False
        if int(adresseDecoupe[0]) != 255:
            messagebox.showerror("Erreur", "le masque n'est pas conforme. Le premier numéro doit être 255.")
            return False
        if int(adresseDecoupe[3]) > 252:
            messagebox.showerror("Erreur", "le masque n'est pas conforme. Un masque ne peut pas se terminer par 253 ou plus.")
            return False

    return True


# =========================
# CALCUL ADRESSE RESEAU / BROADCAST
# =========================
def ip_to_int(ip):
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def int_to_ip(num):
    return f"{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}"

def calcul_reseau_broadcast(ip, masque):
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(masque)
    reseau = ip_int & mask_int
    broadcast = reseau | (~mask_int & 0xFFFFFFFF)
    return int_to_ip(reseau), int_to_ip(broadcast)


# =========================
# INTERFACE
# =========================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Projet Réseau - Authentification & Calcul IP")
        self.geometry("450x380")
        self.resizable(False, False)

        # --- couleurs de thème
        self.bg_color = "#2E2E2E"  # gris foncé
        self.fg_color = "#FFFFFF"  # texte blanc
#        "self.result_color" = "#3BCC01"  # texte vert
        self.entry_bg = "#4B4B4B"  # gris moyen pour champs
        self.button_bg = "#5A5A5A" # gris clair pour boutons

        self.configure(bg=self.bg_color)

        init_db()
        self.current_pw = get_password()

        self.create_login_ui()

    # fonction widgets stylisés
    def create_label(self, text, size=11, bold=False):
        style = ("Arial", size, "bold" if bold else "normal")
        return tk.Label(self, text=text, font=style, bg=self.bg_color, fg=self.fg_color)

    def create_entry(self, show=None):
        return tk.Entry(self, width=30, bg=self.entry_bg, fg=self.fg_color, insertbackground=self.fg_color, show=show)

    def create_button(self, text, command):
        return tk.Button(self, text=text, bg=self.button_bg, fg=self.fg_color, relief="flat", width=18, command=command)

    # UI d’authentification
    def create_login_ui(self):
        for widget in self.winfo_children():
            widget.destroy()

        self.create_label("Veuillez entrer le mot de passe :", 12, True).pack(pady=20)
        self.entry_pw = self.create_entry(show="*")
        self.entry_pw.pack(pady=5)
        self.create_button("Se connecter", self.verify_password).pack(pady=15)

    # Vérification du mot de passe
    def verify_password(self):
        entered = self.entry_pw.get().strip()
        if entered == self.current_pw:
            if messagebox.askyesno("Mot de passe correct", "Voulez-vous modifier le mot de passe ?"):
                self.modify_password()
            else:
                messagebox.showinfo("Accès autorisé", "Mot de passe accepté.")
                self.create_ip_ui()
        else:
            messagebox.showerror("Erreur", "Mot de passe incorrect, veuillez réessayer.")

    # Modification du mot de passe
    def modify_password(self):
        for widget in self.winfo_children():
            widget.destroy()

        self.create_label("Entrez le nouveau mot de passe :", 12, True).pack(pady=20)
        new_pw_entry = self.create_entry(show="*")
        new_pw_entry.pack(pady=5)

        def save_new_pw():
            new_pw = new_pw_entry.get().strip()
            if new_pw:
                update_password(new_pw)
                self.current_pw = new_pw
                messagebox.showinfo("Succès", "Mot de passe mis à jour avec succès.")
                self.create_ip_ui()
            else:
                messagebox.showerror("Erreur", "Le mot de passe ne peut pas être vide.")

        self.create_button("Valider", save_new_pw).pack(pady=15)

    # Interface IP / Masque
    def create_ip_ui(self):
        for widget in self.winfo_children():
            widget.destroy()

        self.create_label("=== Calcul d'adresse réseau ===", 13, True).pack(pady=15)
        self.create_label("Adresse IP :").pack()
        self.ip_entry = self.create_entry()
        self.ip_entry.pack(pady=5)
        self.create_label("Masque :").pack()
        self.mask_entry = self.create_entry()
        self.mask_entry.pack(pady=5)

        self.create_button("Calculer", self.calculate).pack(pady=15)

        self.result_label = self.create_label("", size=10)
        self.result_label.pack(pady=15)

    # Calcul des adresses
    def calculate(self):
        ip = self.ip_entry.get().strip()
        masque = self.mask_entry.get().strip()

        if not checkElements(ip, "l'adresse IP"):
            return
        if not checkElements(masque, "le masque"):
            return

        reseau, broadcast = calcul_reseau_broadcast(ip, masque)
        self.result_label.config(
            text=f"✅ IP et masque valides !\nAdresse réseau : {reseau}\nAdresse broadcast : {broadcast}"
        )


# =========================
# LANCEMENT DU PROGRAMME
# =========================
if __name__ == "__main__":
    app = App()
    app.mainloop()
