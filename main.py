import decimal
from password_system import password_system  # ✅ Import du système de mot de passe

# =========================
# VARIABLE(S) IMPORTANTE(S)
# =========================

# --- Variable qui décide du mode de calcul ---
isClassFull = True

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

    for x in range(0, len(adresseDecoupe)):
        # Vérifie que chaque partie est bien numérique
        if not adresseDecoupe[x].isdigit():
            print(f"Erreur: {type} n'est pas conforme. Veuillez utiliser uniquement des chiffres.")
            return False
            break

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

    return ".".join(adresseBinaire)

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
            result = result + abs(calculatedSegment)
        binaryFullIP.append(str(result))

    IPFinal = ".".join(binaryFullIP)
    return IPFinal

# --- Calcul adresse réseau de broadcast ---
def calculRéseauBroadcast(ip, masque):
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

# AJOUT : --- Calcul des sous réseaux ---
def calculSousRéseau(ip, masque, nbrRes):
    #Variables importantes
    resMax = 0 #Réseaux possibles au max
    n = 0 #Facteur exposant
    newMasque = [] #Masque créer pour la création de sous réseaux.
    PAS = 0 #PAS
    octectPAS = 0 #Octet sur lequel le PAS se situe.

    #Calcul de n -> nombres de bits à changer
    while (resMax <= int(nbrRes)):
        resMax = (2 ** n) - 1
        n = n + 1

    #Division du masque
    splitMasque = masque.split(".", 3)

    #Création d'un nouveau masque
    for numb in range(0, len(splitMasque)):
        segmentMasque = list(splitMasque[numb])
        newMasqueSeg = []

        #Ajout par segments. Ajouts des nouveaux bits.
        for x in range(0, len(segmentMasque)):
            #Ajout des nouveaux bits
            if segmentMasque[x] == "0" and n > 1:
                newMasqueSeg.append("1")
                n = n - 1

                posPAS = (len(segmentMasque) - 1) - x #Position du Pas dans l'octect pour le calculer
                PAS = 2 ** posPAS #calcul du PAS
                octectPAS = numb + 1 # octet sur lequel le PAS est situé.

            else :
                newMasqueSeg.append(segmentMasque[x])

        #rassemble le tout
        newMasque.append(("".join(newMasqueSeg)))

    # nouveau masque final (en binaire)
    newMasque = ".".join(newMasque)

    #Afficher les résultats importants
    bc = calculRéseauBroadcast(ip, masque)
    ip = calculRéseauDiffusion(ip, masque)

    print(f"Adresse du réseau : {ip}, Adresse Broadcast du réseau : {bc}")
    print(f"Le Pas vaut {PAS} et se trouve sur l'octet n° {octectPAS}\n")

    #Ressort un "tableau" de sous réseaux
    for res in range(0, int(nbrRes)):

        sousResIP = ip #Sous réseau adresse IP

        sousResBC = calculRéseauBroadcast(calculBinaire(sousResIP), newMasque) # Sous réseau adresse Broadcast

        splitIp = sousResIP.split(".", 3) #découpe de l'adress Ip du sous réseaux pour modifications

        # première adresse IP
        sousResFirstIP = splitIp
        sousResFirstIP[octectPAS - 1] = str(int(sousResFirstIP[octectPAS - 1])+ 1)
        sousResFirstIP = ".".join(sousResFirstIP)

        #dernière adresse IP
        sousResLastIP = sousResBC.split(".", 3)
        sousResLastIP[octectPAS - 1] = str(int(sousResLastIP[octectPAS - 1])- 1)
        sousResLastIP = ".".join(sousResLastIP)

        #Phrase affichant les résultats
        print(f"sous réseau n° {res + 1} : Adresse sous réseau : {sousResIP}; Adresse de Broadcast : {sousResBC}; 1ère IP : {sousResFirstIP}; Dernière IP : {sousResLastIP}.\n")

        #Modifie l'adresse IP pour continuer la boucle.
        splitIp = ip.split(".", 3)
        splitIp[octectPAS - 1] = str(int(splitIp[octectPAS - 1]) + PAS)
        ip = ".".join(splitIp)

# --- Programme principal ---
def programFinal(ip, sousRes, masque=""):
    # Lance le programme selon le mode

    if isClassFull:
        calculSousRéseau(calculBinaire(ip), calculBinaire(masque), sousRes)
    else:
        masque, ip = splitElements(ip)
        calculSousRéseau(calculBinaire(ip), toBinary(masque), sousRes)

"192.168.1.53/24"
"255.255.255.0"


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

        while True:
            sr_input = input("Entrez le nombre de sous réseau : ").strip()
            #Vérifications du nombre de sous réseaux
            if not sr_input.isdigit():
                print("N'écrivez que des nombres, s'il vous plaît.")
                print("Veuillez réessayer.\n")

            elif sr_input in range(1, 101):
                print("Erreur : Le nombre de sous réseaux doit être compris entre 1 et 100.")
                print("Veuillez réessayer.\n")
            else: break
        programFinal(ip_input, sr_input, mask_input)