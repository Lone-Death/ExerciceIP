import sqlite3
import os

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
        print("Base de données initialisée avec le mot de passe par défaut : 4221")
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

# ✅ Fonction qui gère l'authentification
def password_system():
    init_db()
    current_password = get_password()

    while True:
        entered = input("Veuillez entrer le mot de passe pour procéder : ")

        if entered == current_password:
            print("✅ Mot de passe correct.")
            choice = input("Voulez-vous modifier le mot de passe ? (Y/N) : ").strip().lower()

            if choice == 'y':
                new_pass = input("Entrez le nouveau mot de passe : ").strip()
                if new_pass:
                    update_password(new_pass)
                    print("Mot de passe mis à jour avec succès.")
                else:
                    print("Mot de passe non modifié (vide).")
            else:
                print("Accès autorisé sans modification du mot de passe.")
            return True  # indique à main.py que le mot de passe est correct

        else:
            print("❌ Mot de passe incorrect, veuillez réessayer.\n")

# Seulement si on exécute ce fichier directement
if __name__ == "__main__":
    password_system()
