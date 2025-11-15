import decimal
import sqlite3
import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
import io
import contextlib

# ======================================================
# BASE DE DONNÉES SQLITE
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
    if "." not in element:
        messagebox.showerror("Erreur", f"{type} n'est pas conforme. Utilisez des points.")
        return False

    adresseDecoupe = element.split(".")
    if len(adresseDecoupe) != 4:
        messagebox.showerror("Erreur", f"{type} doit avoir 4 octets.")
        return False

    for x in adresseDecoupe:
        if not x.isdigit():
            messagebox.showerror("Erreur", f"{type} contient des caractères non numériques.")
            return False
        val = int(x)
        if val < 0 or val > 255:
            messagebox.showerror("Erreur", f"{type} contient des valeurs invalides (0-255).")
            return False

    # Vérif IP
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

    # Vérif masque
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


# =========================
# FONCTIONS CLASSLESS
# =========================
def toBinary(masque):
    masqueBinary = []
    while len(masqueBinary) < 4:
        segment = []
        for x in range(0, 8):
            if int(masque) > 0:
                segment.append("1")
                masque = int(masque) - 1
            else:
                segment.append("0")
        if len(masqueBinary) != 3:
            masqueBinary.append(("".join(segment) + "."))
        else:
            masqueBinary.append("".join(segment))

    return("".join(masqueBinary))

def calculBinaire(element):
    adresseDecoupe = element.split(".", 3)
    adresseBinaire = []

    for n in adresseDecoupe:
        partieAdresse = []
        while int(n) > 0:
            n = int(n) / 2
            d = decimal.Decimal(n)
            positive_result = abs(d.as_tuple().exponent)
            if positive_result != 0:
                partieAdresse.append("1")
            else:
                partieAdresse.append("0")
        while len(partieAdresse) != 8:
            partieAdresse.append("0")
        partieAdresse.reverse()
        adresseBinaire.append("".join(partieAdresse))

    return ".".join(adresseBinaire)

# Réseau Diffusion
def calculRéseauDiffusion_Ludo(ip, masque):
    ipDecoupe = ip.split(".", 3)
    masqueDecoupe = masque.split(".", 3)
    binaryFullIP = []

    for n in range(0, len(ipDecoupe)):
        segmentIp = list(ipDecoupe[n])
        segmentMasque = list(masqueDecoupe[n])
        segmentBinaryIP = []
        for x in range(0, len(segmentMasque)):
            if segmentMasque[x] == "1":
                segmentBinaryIP.append(segmentIp[x])
            else:
                segmentBinaryIP.append("0")
        result = 0
        for y in range(0, len(segmentBinaryIP)):
            calculatedSegment = int(segmentBinaryIP[y]) * (2 ** ((len(segmentBinaryIP) - 1) - y))
            result = result + abs(calculatedSegment)
        binaryFullIP.append(str(result))

    IPFinal = ".".join(binaryFullIP)
    return IPFinal

# Broadcast
def calculRéseauBroadcast_Ludo(ip, masque):
    ipDecoupe = ip.split(".", 3)
    masqueDecoupe = masque.split(".", 3)
    fullIP = []

    for n in range(0, len(ipDecoupe)):
        segmentIp = list(ipDecoupe[n])
        segmentMasque = list(masqueDecoupe[n])
        segmentBinaryIP = []

        for x in range(0, len(segmentMasque)):
            if segmentMasque[x] == "1":
                segmentBinaryIP.append(segmentIp[x])
            else:
                segmentBinaryIP.append("1")
        result = 0

        for y in range(0, len(segmentBinaryIP)):
            calculatedSegment = int(segmentBinaryIP[y]) * (2 ** ((len(segmentBinaryIP) - 1) - y))
            result = result + calculatedSegment
        fullIP.append(str(abs(result)))
    IPFinal = ".".join(fullIP)
    return IPFinal


# Calcul sous-réseaux
def calculSousRéseau(ip, masque, nbrRes):
    resMax = 0
    n = 0
    newMasque = []
    PAS = 0
    octectPAS = 0

    while (resMax <= int(nbrRes)):
        resMax = (2 ** n) - 1
        n = n + 1

    splitMasque = masque.split(".", 3)

    for numb in range(0, len(splitMasque)):
        segmentMasque = list(splitMasque[numb])
        newMasqueSeg = []

        for x in range(0, len(segmentMasque)):
            if segmentMasque[x] == "0" and n > 1:
                newMasqueSeg.append("1")
                n -= 1

                posPAS = (len(segmentMasque) - 1) - x
                PAS = 2 ** posPAS
                octectPAS = numb + 1

            else:
                newMasqueSeg.append(segmentMasque[x])

        newMasque.append(("".join(newMasqueSeg)))

    newMasque = ".".join(newMasque)

    bc = calculRéseauBroadcast_Ludo(ip, masque)
    ip_net = calculRéseauDiffusion_Ludo(ip, masque)

    print(f"Adresse du réseau : {ip_net}, Adresse Broadcast du réseau : {bc}")
    print(f"Le Pas vaut {PAS} et se trouve sur l'octet n° {octectPAS}\n")

    for res in range(0, int(nbrRes)):
        sousResIP = ip_net
        sousResBC = calculRéseauBroadcast_Ludo(calculBinaire(sousResIP), newMasque)

        splitIp = sousResIP.split(".", 3)

        sousResFirstIP = splitIp
        sousResFirstIP[octectPAS - 1] = str(int(sousResFirstIP[octectPAS - 1]) + 1)
        sousResFirstIP = ".".join(sousResFirstIP)

        sousResLastIP = sousResBC.split(".", 3)
        sousResLastIP[octectPAS - 1] = str(int(sousResLastIP[octectPAS - 1]) - 1)
        sousResLastIP = ".".join(sousResLastIP)

        print(f"sous réseau n° {res + 1} : Adresse sous réseau : {sousResIP}; Adresse de Broadcast : {sousResBC}; 1ère IP : {sousResFirstIP}; Dernière IP : {sousResLastIP}.\n")

        splitIp = ip_net.split(".", 3)
        splitIp[octectPAS - 1] = str(int(splitIp[octectPAS - 1]) + PAS)
        ip_net = ".".join(splitIp)


# ======================================================
# INTERFACE GRAPHIQUE (TKINTER)
# ======================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Projet Réseau - Authentification & Calcul IP")
        self.geometry("840x800")
        self.resizable(False, False)

        self.bg_color = "#2E2E2E"
        self.fg_color = "#FFFFFF"
        self.fg_colorV = "#32CD32"
        self.entry_bg = "#4B4B4B"
        self.button_bg = "#5A5A5A"

        self.configure(bg=self.bg_color)
        init_db()
        self.current_pw = get_password()
        self.create_login_ui()

    def create_label(self, text, size=11, bold=False, master=None):
        style = ("Arial", size, "bold" if bold else "normal")
        if master is None:
            master = self
        return tk.Label(master, text=text, font=style, bg=self.bg_color, fg=self.fg_color)

    def create_entry(self, show=None, master=None):
        if master is None:
            master = self
        return tk.Entry(master, width=40, bg=self.entry_bg, fg=self.fg_color, insertbackground=self.fg_color, show=show)

    def create_button(self, text, command, master=None):
        if master is None:
            master = self
        return tk.Button(master, text=text, bg=self.button_bg, fg=self.fg_color, relief="flat", width=18, command=command)

    # ======================================================
    # AUTHENTIFICATION
    # ======================================================
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
                self.create_main_ui()
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
                self.create_main_ui()
            else:
                messagebox.showerror("Erreur", "Le mot de passe ne peut pas être vide.")

        self.create_button("Valider", save_new_pw).pack(pady=15)

    # ======================================================
    # UI PRINCIPALE
    # ======================================================
    def create_main_ui(self):
        for widget in self.winfo_children():
            widget.destroy()

        self.create_label("=== Calcul d'adresse réseau ===", 13, True).pack(pady=12)

        # Toggle top : Classful / Classless
        mode_frame = tk.Frame(self, bg=self.bg_color)
        mode_frame.pack(pady=6)
        self.class_mode = tk.StringVar(value="classful")
        tk.Radiobutton(mode_frame, text="Classful", variable=self.class_mode, value="classful",
                       bg=self.bg_color, fg=self.fg_colorV, selectcolor=self.button_bg,
                       command=self.refresh_ui).pack(side="left", padx=8)
        tk.Radiobutton(mode_frame, text="Classless", variable=self.class_mode, value="classless",
                       bg=self.bg_color, fg=self.fg_colorV, selectcolor=self.button_bg,
                       command=self.refresh_ui).pack(side="left", padx=8)

        # Toggle bottom : Calcul / Subnets / Vérification
        calc_frame = tk.Frame(self, bg=self.bg_color)
        calc_frame.pack(pady=6)
        self.calc_mode = tk.StringVar(value="calcul")

        tk.Radiobutton(calc_frame, text="Calcul", variable=self.calc_mode, value="calcul",
                       bg=self.bg_color, fg=self.fg_colorV, selectcolor=self.button_bg,
                       command=self.refresh_ui).pack(side="left", padx=8)

        tk.Radiobutton(calc_frame, text="Subnets", variable=self.calc_mode, value="subnets",
                       bg=self.bg_color, fg=self.fg_colorV, selectcolor=self.button_bg,
                       command=self.refresh_ui).pack(side="left", padx=8)

        tk.Radiobutton(calc_frame, text="Vérification", variable=self.calc_mode, value="verification",
                       bg=self.bg_color, fg=self.fg_colorV, selectcolor=self.button_bg,
                       command=self.refresh_ui).pack(side="left", padx=8)

        # Frames
        self.input_frame = tk.Frame(self, bg=self.bg_color)
        self.input_frame.pack(pady=8)

        self.action_frame = tk.Frame(self, bg=self.bg_color)
        self.action_frame.pack(pady=4)

        self.output = scrolledtext.ScrolledText(self, width=100, height=30,
                                                bg="#1E1E1E", fg="#00FF00",
                                                insertbackground="#DCDCDC")
        self.output.pack(pady=10)

        self.refresh_ui()

    # ======================================================
    # UI dynamique selon les toggles
    # ======================================================
    def refresh_ui(self):
        for w in self.input_frame.winfo_children():
            w.destroy()
        for w in self.action_frame.winfo_children():
            w.destroy()

        mode = self.class_mode.get()
        calc = self.calc_mode.get()

        # Entrée IP/masque
        if mode == "classful":
            self.create_label("Adresse IP :", master=self.input_frame).grid(row=0, column=0, sticky="w", padx=4, pady=3)
            self.ip_entry = self.create_entry(master=self.input_frame)
            self.ip_entry.grid(row=0, column=1, pady=3, padx=4)

            self.create_label("Masque :", master=self.input_frame).grid(row=1, column=0, sticky="w", padx=4, pady=3)
            self.mask_entry = self.create_entry(master=self.input_frame)
            self.mask_entry.grid(row=1, column=1, pady=3, padx=4)
        else:
            self.create_label("Adresse IP /CIDR :", master=self.input_frame).grid(row=0, column=0, sticky="w", padx=4, pady=3)
            self.ip_entry = self.create_entry(master=self.input_frame)
            self.ip_entry.grid(row=0, column=1, pady=3, padx=4)

        # -------- MODE CALCUL --------
        if calc == "calcul":
            btn = self.create_button("Calculer", self.action_calcul, master=self.action_frame)
            btn.pack()
            # self.output.delete("1.0", tk.END) # Si besoin de refresh après toggle
            return

        # -------- MODE SUBNETS --------
        if calc == "subnets":
            self.create_label("Nombre de sous-réseaux (1-100) :", master=self.input_frame).grid(
                row=2, column=0, sticky="w", padx=4, pady=3
            )
            self.subnet_count_entry = self.create_entry(master=self.input_frame)
            self.subnet_count_entry.grid(row=2, column=1, pady=3, padx=4)

            btn = self.create_button("Calculer sous-réseaux", self.action_subnets, master=self.action_frame)
            btn.pack()
            # self.output.delete("1.0", tk.END) # Si besoin de refresh après toggle
            return

        # -------- MODE VERIFICATION --------
        if calc == "verification":
            self.create_label("Adresse SR à vérifier :", master=self.input_frame).grid(
                row=2, column=0, sticky="w", padx=4, pady=3
            )
            self.sr_entry = self.create_entry(master=self.input_frame)
            self.sr_entry.grid(row=2, column=1, pady=3, padx=4)

            btn = self.create_button("Vérifier appartenance", self.action_verify, master=self.action_frame)
            btn.pack()
            # self.output.delete("1.0", tk.END) # Si besoin de refresh après toggle
            return

    # ======================================================
    # ACTIONS
    # ======================================================

    # ---- Calcul simple ----
    def action_calcul(self):
        mode = self.class_mode.get()

        if mode == "classful":
            ip = self.ip_entry.get().strip()
            masque = self.mask_entry.get().strip()

            if not checkElements(ip, "l'adresse IP"):
                return
            if not checkElements(masque, "le masque"):
                return

        else:  # classless
            ip_input = self.ip_entry.get().strip()
            if "/" not in ip_input:
                messagebox.showerror("Erreur", "Format invalide. Exemple : 192.168.10.10/24")
                return
            try:
                ip_part, bits = ip_input.split("/")
                bits = int(bits)

                if bits not in range(8, 31):
                    messagebox.showerror("Erreur ", "Le masque doit avoir une valeur comprise entre 8 et 30.")
                    return

                masque = cidr_to_mask(bits)
                ip = ip_part
            except:
                messagebox.showerror("Erreur", "Format invalide.")
                return

        reseau, broadcast = calcul_reseau_broadcast(ip, masque)

        out = f"Adresse réseau : {reseau}\nAdresse Broadcast : {broadcast}"
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, out)

    # ---- Subnets ----
    def action_subnets(self):
        mode = self.class_mode.get()

        if mode == "classful":
            ip = self.ip_entry.get().strip()
            masque = self.mask_entry.get().strip()
            if not checkElements(ip, "l'adresse IP"):
                return
            if not checkElements(masque, "le masque"):
                return

            nbr = self.subnet_count_entry.get().strip()
            if not nbr.isdigit() or int(nbr) < 1 or int(nbr) > 100:
                messagebox.showerror("Erreur", "Nombre de sous-réseaux invalide (1-100).")
                return

            nbr = int(nbr)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                calculSousRéseau(calculBinaire(ip), calculBinaire(masque), nbr)
            out = buf.getvalue()

        else:
            ip_input = self.ip_entry.get().strip()
            if "/" not in ip_input:
                messagebox.showerror("Erreur", "Format invalide. Exemple : 192.168.10.10/24")
                return
            try:
                ip_part, bits = ip_input.split("/")
                bits = int(bits)
                if bits < 1 or bits > 31:
                    messagebox.showerror("Erreur", "Le masque doit être entre 1 et 31 bits.")
                    return
            except:
                messagebox.showerror("Erreur", "Format incorrect. Exemple : 192.168.10.10/24")
                return
            if not checkElements(ip_part, "l'adresse IP"):
                return

            nbr = self.subnet_count_entry.get().strip()
            if not nbr.isdigit() or int(nbr) < 1 or int(nbr) > 100:
                messagebox.showerror("Erreur", "Nombre de sous-réseaux invalide (1-100).")
                return
            nbr = int(nbr)

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                masque_str = bits
                calculSousRéseau(calculBinaire(ip_part), toBinary(masque_str), nbr)
            out = buf.getvalue()

        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, out)

    # ---- Verification ----
    def action_verify(self):
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
                messagebox.showerror("Erreur", "Veuillez entrer l'adresse IP avec le masque (ex: 192.168.10.10/24)")
                return
            try:
                ip_part, bits = ip_input.split("/")
                bits = int(bits)
                masque = cidr_to_mask(bits)
                ip = ip_part
            except:
                messagebox.showerror("Erreur", "Format incorrect. Exemple : 192.168.10.10/24")
                return
            if not checkElements(ip, "l'adresse IP"):
                return

        sr = self.sr_entry.get().strip()
        if not checkElements(sr, "l'adresse SR"):
            return

        reseau, broadcast = calcul_reseau_broadcast(ip, masque)

        ip_int = ip_to_int(sr)
        net_int = ip_to_int(reseau)
        bc_int = ip_to_int(broadcast)

        if net_int <= ip_int <= bc_int:
            msg = f"L’adresse {sr} se trouve dans le réseau, car elle est comprise entre {reseau} et {broadcast}."
        else:
            msg = f"L’adresse {sr} NE se trouve PAS dans le réseau. Le réseau va de {reseau} à {broadcast}."

        out = f"Adresse réseau : {reseau}\nAdresse Broadcast : {broadcast}\n\n{msg}\n"
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, out)


if __name__ == "__main__":
    app = App()
    app.mainloop()
