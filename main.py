import decimal

def checkElements(element, type):
    # Check valeur qui vérifie si l'élément est valide
    elementValid = True
    partieReseau = True

    # Si l'adresse est séparée par des points
    if "." not in element:
        print("Erreur : " + type + " n'est pas conforme. Veuillez séparer les nombres avec un point.")
        elementValid = False
    else:
        adresseDecoupe = element.split(".", 3)

    # Si le résultat est d'une longueur différente que prévu.
    if len(adresseDecoupe) != 4:
        print("Erreur: " + type + " n'est pas conforme. Veuillez vérifier sa taille.")
        elementValid = False

    # Si l'élément est correcte jusqu'ici
    if(elementValid):
        # Pour chaque segments...
        for x in range(0, len(adresseDecoupe)):

            # Vérifie si le premier nombre de l'IP est entre 0 et 223
            if type == "l'adresse IP" and x == 0 and int(adresseDecoupe[x]) not in range(1, 224):
                print("Erreur: " + type + " n'est pas conforme. Le premier numéro doit être compris entre 1 et 223.")
                elementValid = False
                break

            # Vérifie si le premier nombre de l'IP ne vaut pas 127
            if type == "l'adresse IP" and x == 0 and int(adresseDecoupe[x]) == 127:
                print("Erreur: " + type + " n'est pas conforme. Adresse IP réservée, donc refusée.")
                elementValid = False
                break

            # Si le premier numéro du masque est différent de 255
            if type == "le masque" and x == 0 and int(adresseDecoupe[x]) != 255:
                print("Erreur: " + type + " n'est pas conforme. Le premier numéro doit être 255.")
                elementValid = False
                break

            # Si un nombre du masque est précéder par un 0
            if type == "le masque" and int(adresseDecoupe[x]) != 0 and partieReseau == False:
                print(
                    "Erreur: " + type + " n'est pas conforme. Un masque ne peut pas avoir des chiffres autre que 0 après un 0.")
                elementValid = False
                break

            # Si un nombre du masque vaut autre chose que 255
            if type == "le masque" and int(adresseDecoupe[x]) != 255:
                partieReseau = False

            # Si le dernier nombre du masque est 255
            if type == "le masque" and x == (len(adresseDecoupe) - 1) and int(adresseDecoupe[x]) > 252:
                print("Erreur: " + type + " n'est pas conforme. Un masque ne peut pas se terminer par 253 et au delà")
                elementValid = False
                break

            # Vérifie s'il y a des lettres
            if adresseDecoupe[x].isdigit() == False:
                print(
                    "Erreur: " + type + " n'est pas conforme. Veuillez, n'utiliser que des chiffres et pas d'espaces.")
                elementValid = False
                break

            # Vérifie que le nombre du segment soit entre 0 et 255
            if int(adresseDecoupe[x]) not in range(256):
                print("Erreur: " + type + " n'est pas conforme. Veuillez vérifier les numéros.")
                elementValid = False
                break

    # Retourne un boolean en fonction de s'il y a une erreur ou pas
    if(elementValid):
        return True
    else: return False

def calculBinaire(element):
    #Données par rapport aux paramètres -> découpe l'IP et le masque
    adresseDecoupe = element.split(".", 3)

    #Encadré de l'adresse IP et du masque en binaire
    adresseBinaire = []

    #pour chaque partie de code L'IP
    for n in adresseDecoupe:
        partieAdresse = []
        #Tant qu'on peut diviser par 2
        while int(n) > 0 :
            n = int(n) / 2
            #donne le nombre juste après la virgule.
            d = decimal.Decimal(n)
            positive_result = abs(d.as_tuple().exponent)

            #si le nombre après la virgule vaut 0 -> on écrit 1, si pas on écrit 0
            if positive_result != 0 :
                partieAdresse.append("1")
            else:
                partieAdresse.append("0")
        #Si le résultat n'est pas un octet.
        while len(partieAdresse) != 8:
            partieAdresse.append("0")

        #Ajout de la partie du binaire dans un tableau.
        partieAdresse.reverse()
        adresseBinaire.append("".join(partieAdresse))
        if len(adresseBinaire) < 6:
            adresseBinaire.append(".")
    return "".join(adresseBinaire)

def calculRéseauDiffusion(ip, masque):
    #découpe des variables
    ipDecoupe = ip.split(".", 3)
    masqueDecoupe = masque.split(".", 3)
    #variable du résultat
    binaryFullIP = []

    #découpe en segments
    for n in range(0, len(ipDecoupe)):
        segmentIp = list(ipDecoupe[n])
        segmentMasque = list(masqueDecoupe[n])
        #variable pour un segment du résultat
        segmentBinaryIP = []
        #Création du segment
        for x in range(0, len(segmentMasque)):
            if segmentMasque[x] == "1":
                 segmentBinaryIP.append(segmentIp[x])
            else :
                segmentBinaryIP.append("0")
            #calcul de l'adresse finale
            result = 0
            for y in range(0, len(segmentBinaryIP)):
                calculatedSegment = int(segmentBinaryIP[y]) * (2**((len(segmentBinaryIP)-1)-y))
                result = result + calculatedSegment
        # ajout du segment au résultat
        binaryFullIP.append(str(abs(result)))
        if len(binaryFullIP) < 6:
            binaryFullIP.append(".")
    # Donne le résultat final correctement
    IPFinal = "".join(binaryFullIP)
    print(IPFinal)

def calculRéseauBroadcast(ip, masque):
    #découpe des variables
    ipDecoupe = ip.split(".", 3)
    masqueDecoupe = masque.split(".", 3)
    #variable du résultat
    binaryFullIP = []

    #découpe en segments
    for n in range(0, len(ipDecoupe)):
        segmentIp = list(ipDecoupe[n])
        segmentMasque = list(masqueDecoupe[n])
        #variable pour un segment du résultat
        segmentBinaryIP = []
        #Création du segment
        for x in range(0, len(segmentMasque)):
            if segmentMasque[x] == "1":
                 segmentBinaryIP.append(segmentIp[x])
            else :
                segmentBinaryIP.append("1")
            #calcul de l'adresse finale
            result = 0
            for y in range(0, len(segmentBinaryIP)):
                calculatedSegment = int(segmentBinaryIP[y]) * (2**((len(segmentBinaryIP)-1)-y))
                result = result + calculatedSegment
        # ajout du segment au résultat
        binaryFullIP.append(str(abs(result)))
        if len(binaryFullIP) < 6:
            binaryFullIP.append(".")
    #Donne le résultat final correctement
    IPFinal = "".join(binaryFullIP)
    print(IPFinal)

def programFinal(ip, masque):
    # Lance le programme
    if(checkElements(ip, "l'adresse IP") and checkElements(masque, "le masque")):
        print("Adresse de diffusion")
        calculRéseauDiffusion(calculBinaire(ip), calculBinaire(masque))
        print("Adresse Broadcast")
        calculRéseauBroadcast(calculBinaire(ip), calculBinaire(masque))

programFinal("192.168.1.53", "255.255.255.0")
"255.255.255.0"
"192.168.1.53"
