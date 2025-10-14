import decimal
from password_system import password_system  # ✅ Import du système de mot de passe


# =========================
# VARIABLE(S) IMPORTANTE(S)
# =========================

# --- Variable qui décide du mode de calcul ---
isClassFull = False

# =========================
# FONCTIONS CLASSLESS
# =========================

# --- Divise et renvoie l'adresse IP en deux à la présence de '/' -> est vérifier dans checkElement ---
def splitElements(element):
    if "/" in element:
        masque = element.split("/", 1)[1]
        element = element.split("/", 1)[0]
    return masque, element

# --- Créée le masque en binaire en classless (uniquement pour le masque) ---
def toBinary(masque):
    masqueBinary = []
    while len(masqueBinary) < 4:
        segment = []
        #découpage en ségments
        for x in range(0, 8):
            if int(masque) > 0:
                segment.append("1")
                masque = int(masque) - 1
            else:
                segment.append("0")
        #Donne un point tant qu'il le peut
        if len(masqueBinary) != 3:
            masqueBinary.append(("".join(segment) + "."))
        else:
            masqueBinary.append("".join(segment))

    return("".join(masqueBinary))


# --- Vérification des éléments IP et masque ---
def checkElements(element, type):

    if "." not in element:
        print(f"Erreur : {type} n'est pas conforme. Veuillez séparer les nombres avec un point.")
        return False
    # Si on est en classless
    if isClassFull == False:
        if "/" in element:
            # Séparation du masque et de l'adresse IP
            masque, element = splitElements(element)

            # Vérifications de la partie masque
            # présence de lettres
            if masque.isdigit() == False:
                print("Erreur : " + type + " n'est pas conforme. Veuillez ne mettre que des chiffres et aucun espace après le '/'. Ne mettez qu'un seul '/'.")
                return False

            # s'il n'est pas entre 8 et 30
            if int(masque) not in range(8, 31):
                print("Erreur : " + type + " n'est pas conforme. Veuillez le masque doit avoir une valeur comprise entre 8 et 30.")
                return False

        # Lors d'un oublie du '/'
        else:
            print("Erreur : " + type + " Vous avez oublier le '/' entre la partie adresse IP et le masque.")
            return False

    adresseDecoupe = element.split(".")

    if len(adresseDecoupe) != 4:
        print(f"Erreur: {type} n'est pas conforme. Veuillez vérifier sa taille/nombre de points.")
        return False

    for x in range(3):
        # Vérifie que chaque partie est bien numérique
        if not adresseDecoupe[x].isdigit():
            print(f"Erreur: {type} n'est pas conforme. Veuillez utiliser uniquement des chiffres.")
            return False

        val = int(adresseDecoupe[x])

        # Vérifie les bornes 0-255
        if val < 0 or val > 255:
            print(f"Erreur: {type} n'est pas conforme. Chaque nombre doit être entre 0 et 255.")
            return False

        # Vérifications spécifiques IP
        if type == "l'adresse IP":
            if x == 0 and (val < 1 or val > 223):
                print("Erreur: l'adresse IP n'est pas conforme. Le premier numéro doit être compris entre 1 et 223.")
                return False
            if x == 0 and val == 127:
                print("Erreur: l'adresse IP n'est pas conforme. Adresse IP réservée, donc refusée.")
                return False

    # ✅ Vérification spécifique du masque corrigée
    if type == "le masque":
        masque_bits = "".join([format(int(part), "08b") for part in adresseDecoupe])
        if "01" in masque_bits:
            print("Erreur: le masque n'est pas conforme. Les bits du masque doivent être continus (ex: 11111111.11111110.00000000.00000000)")
            return False
        if int(adresseDecoupe[0]) != 255:
            print("Erreur: le masque n'est pas conforme. Le premier numéro doit être 255.")
            return False
        if int(adresseDecoupe[3]) > 252:
            print("Erreur: le masque n'est pas conforme. Un masque ne peut pas se terminer par 253 ou plus.")
            return False

    return True

# =========================
# FONCTION CLASSFULL
# =========================

# --- Conversion en binaire (fonctionne pour adresse IP [classfull et classless] et masque [classfull uniquement])---
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
        if len(adresseBinaire) < 6:
            adresseBinaire.append(".")
    return "".join(adresseBinaire)

# =========================
# FONCTIONS DE CALCUL DE RÉSEAU
# =========================

# --- Calcul adresse réseau de diffusion ---
def calculRéseauDiffusion(ip, masque):
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
            result = result + calculatedSegment
        binaryFullIP.append(str(abs(result)))
        if len(binaryFullIP) < 6:
            binaryFullIP.append(".")
    IPFinal = "".join(binaryFullIP)
    print(IPFinal)

# --- Calcul adresse réseau de broadcast ---
def calculRéseauBroadcast(ip, masque):
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
                segmentBinaryIP.append("1")
        result = 0
        for y in range(0, len(segmentBinaryIP)):
            calculatedSegment = int(segmentBinaryIP[y]) * (2 ** ((len(segmentBinaryIP) - 1) - y))
            result = result + calculatedSegment
        binaryFullIP.append(str(abs(result)))
        if len(binaryFullIP) < 6:
            binaryFullIP.append(".")
    IPFinal = "".join(binaryFullIP)
    print(IPFinal)

# --- Programme principal ---
def programFinal(ip, masque=""):
    # Lance le programme selon le mode
    if isClassFull:
            print("Adresse de diffusion")
            calculRéseauDiffusion(calculBinaire(ip), calculBinaire(masque))
            print("Adresse Broadcast")
            calculRéseauBroadcast(calculBinaire(ip), calculBinaire(masque))
    else:
            masque, ip = splitElements(ip)
            print("Adresse de diffusion")
            calculRéseauDiffusion(calculBinaire(ip), toBinary(masque))
            print("Adresse Broadcast")
            calculRéseauBroadcast(calculBinaire(ip), toBinary(masque))


# --- Lancement du programme ---
if __name__ == "__main__":
    #password_system()
    #print("\n=== Authentification réussie ===\n")
        while True:
            ip_input = input("Entrez l'adresse IP : ").strip()
            if checkElements(ip_input, "l'adresse IP"):
                break
            print("Veuillez réessayer.\n")

        while isClassFull:
            mask_input = input("Entrez le masque : ").strip()
            if checkElements(mask_input, "le masque"):
                break
            print("Veuillez réessayer.\n")
        else:
            mask_input = ""

        programFinal(ip_input, mask_input)