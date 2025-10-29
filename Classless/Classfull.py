import sqlite3
import os
import tkinter as tk
from tkinter import messagebox

# ======================================================
# BASE DE DONNÉES SQLITE - MOT DE PASSE
# ======================================================
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


# ======================================================
# CALCUL IP / MASQUE
# ======================================================
def ip_to_int(ip):
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def int_to_ip(num):
    return f"{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}"

def cidr_to_mask(bits):
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return int_to_ip(mask)

def calcul_reseau_broadcast(ip, masque):
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(masque)
    reseau = ip_int & mask_int
    broadcast = reseau | (~mask_int & 0xFFFFFFFF)
    return int_to_ip(reseau), int_to_ip(broadcast)


# ======================================================
# VALIDATION DES SAISIES IP / MASQUE
# ======================================================
def checkElements(element, type):
    """Valide les IP et masques selon IPv4 (avec vérif complètes)."""
    if "." not in element:
        messagebox.showerror("Erreur", f"{type} n'est pas conforme. Utilisez des points.")
        return False

    adresseDecoupe = element.split(".")
    if len(adresseDecoupe) != 4:
        messagebox.showerror("Erreur", f"{type} doit avoir 4 parties.")
        return False

    for x in adresseDecoupe:
        if not x.isdigit():
            messagebox.showerror("Erreur", f"{type} contient des caractères non numériques.")
            return False
        val = int(x)
        if val < 0 or val > 255:
            messagebox.showerror("Erreur", f"{type} contient des valeurs invalides (0-255).")
            return False

    # --- Vérifications IP spécifiques ---
    if type == "l'adresse IP":
        a, b, c, d = map(int, adresseDecoupe)
        if a == 127:
            messagebox.showerror("Erreur", "Adresse de boucle locale (127.x.x.x) interdite.")
            return False
        if a == 0 and b == 0 and c == 0 and d == 0:
            messagebox.showerror("Erreur", "Adresse IP nulle (0.0.0.0) interdite.")
            return False
        if a == 255 and b == 255 and c == 255 and d == 255:
            messagebox.showerror("Erreur", "Adresse de broadcast (255.255.255.255) interdite.")
            return False
        if not (1 <= a <= 223):
            messagebox.showerror("Erreur", "Le premier octet de l'adresse IP doit être entre 1 et 223.")
            return False

    # --- Vérifications masque ---
    if type == "le masque":
        masque_bits = "".join([format(int(part), "08b") for part in adresseDecoupe])
        if "01" in masque_bits:
            messagebox.showerror("Erreur", "Le masque n'est pas conforme (bits non continus).")
            return False
        if int(adresseDecoupe[0]) != 255:
            messagebox.showerror("Erreur", "Le premier octet du masque doit être 255.")
            return False
        if int(adresseDecoupe[3]) > 252:
            messagebox.showerror("Erreur", "Un masque ne peut pas se terminer par 253, 254 ou 255.")
            return False

    return True


# ======================================================
# INTERFACE GRAPHIQUE AVEC TKINTER
# ======================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Projet Réseau - Authentification & Calcul IP")
        self.geometry("480x400")
        self.resizable(False, False)

        # Couleurs
        self.bg_color = "#2E2E2E"
        self.fg_color = "#FFFFFF"
        self.entry_bg = "#4B4B4B"
        self.button_bg = "#5A5A5A"

        self.configure(bg=self.bg_color)
        init_db()
        self.current_pw = get_password()
        self.create_login_ui()


    # Utilitaires graphiques
    def create_label(self, text, size=11, bold=False, master=None):
        style = ("Arial", size, "bold" if bold else "normal")
        if master is None:
            master = self
        return tk.Label(master, text=text, font=style, bg=self.bg_color, fg=self.fg_color)

    def create_entry(self, show=None, master=None):
        if master is None:
            master = self
        return tk.Entry(master, width=30, bg=self.entry_bg, fg=self.fg_color, insertbackground=self.fg_color, show=show)

    def create_button(self, text, command, master=None):
        if master is None:
            master = self
        return tk.Button(master, text=text, bg=self.button_bg, fg=self.fg_color, relief="flat", width=18, command=command)


    # Authentification
    def create_login_ui(self):
        for widget in self.winfo_children():
            widget.destroy()
        self.create_label("Veuillez entrer le mot de passe :", 12, True).pack(pady=20)
        self.entry_pw = self.create_entry(show="*")
        self.entry_pw.pack(pady=5)
        self.create_button("Se connecter", self.verify_password).pack(pady=15)

    def verify_password(self):
        entered = self.entry_pw.get().strip()
        if entered == self.current_pw:
            if messagebox.askyesno("Mot de passe correct", "Voulez-vous modifier le mot de passe ?"):
                self.modify_password()
            else:
                self.create_ip_ui()
        else:
            messagebox.showerror("Erreur", "Mot de passe incorrect, veuillez réessayer.")

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


    # Interface IP
    def create_ip_ui(self):
        for widget in self.winfo_children():
            widget.destroy()
        self.create_label("=== Calcul d'adresse réseau ===", 13, True).pack(pady=15)

        # Sélecteur de mode
        mode_frame = tk.Frame(self, bg=self.bg_color)
        mode_frame.pack(pady=10)
        self.class_mode = tk.StringVar(value="classful")

        tk.Radiobutton(mode_frame, text="Classful", variable=self.class_mode, value="classful",
                       bg=self.bg_color, fg=self.fg_color, selectcolor=self.button_bg,
                       command=self.refresh_ip_ui).pack(side="left", padx=10)
        tk.Radiobutton(mode_frame, text="Classless", variable=self.class_mode, value="classless",
                       bg=self.bg_color, fg=self.fg_color, selectcolor=self.button_bg,
                       command=self.refresh_ip_ui).pack(side="left", padx=10)

        self.input_frame = tk.Frame(self, bg=self.bg_color)
        self.input_frame.pack(pady=5)
        self.build_ip_fields()

        self.create_button("Calculer", self.calculate).pack(pady=15)
        self.result_label = self.create_label("", size=10)
        self.result_label.pack(pady=15)

    def refresh_ip_ui(self):
        for widget in self.input_frame.winfo_children():
            widget.destroy()
        self.build_ip_fields()

    def build_ip_fields(self):
        if self.class_mode.get() == "classful":
            self.create_label("Adresse IP :", master=self.input_frame).pack(anchor="w")
            self.ip_entry = self.create_entry(master=self.input_frame)
            self.ip_entry.pack(pady=5)
            self.create_label("Masque :", master=self.input_frame).pack(anchor="w")
            self.mask_entry = self.create_entry(master=self.input_frame)
            self.mask_entry.pack(pady=5)
        else:
            self.create_label("Adresse IP avec /CIDR (ex: 192.168.1.1/24) :", master=self.input_frame).pack(anchor="w")
            self.ip_entry = self.create_entry(master=self.input_frame)
            self.ip_entry.pack(pady=5)

    # Calcul IP
    def calculate(self):
        mode = self.class_mode.get()
        if mode == "classful":
            ip = self.ip_entry.get().strip()
            masque = self.mask_entry.get().strip()
            if not checkElements(ip, "l'adresse IP"):
                return
            if not checkElements(masque, "le masque"):
                return
        else:
            ip_input = self.ip_entry.get().strip()
            if "/" not in ip_input:
                messagebox.showerror("Erreur", "Format invalide. Exemple : 192.168.10.10/24")
                return
            try:
                ip, bits = ip_input.split("/")
                ip = ip.strip()
                bits = int(bits)
                if bits < 1 or bits > 31:
                    messagebox.showerror("Erreur", "Le masque doit être entre 1 et 31 bits.")
                    return
                masque = cidr_to_mask(bits)
            except Exception:
                messagebox.showerror("Erreur", "Format incorrect. Exemple : 192.168.10.10/24")
                return
            if not checkElements(ip, "l'adresse IP"):
                return

        reseau, broadcast = calcul_reseau_broadcast(ip, masque)
        self.result_label.config(
            text=f" IP et masque valides !\nAdresse réseau : {reseau}\nAdresse broadcast : {broadcast}"
        )


# ======================================================
# LANCEMENT DU PROGRAMME
# ======================================================
if __name__ == "__main__":
    app = App()
    app.mainloop()
