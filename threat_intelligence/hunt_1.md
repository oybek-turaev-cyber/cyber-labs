# Sherlock / Threat Intelligence Exercise

**Title: SalineBreeze-1**

**Date: 15/09/2025**

**Objective:**
Le but de la chasse est identifier la source d’un accès non autorisé par le groupe de **Salt Typhoon**, et analyser leur actions malveillants.

**Environment / Tools Used:**

* HTB Sherlocks: Threat Intelligence
* OSINT, MITTRE

**Investigation Steps (short):**

1. Analyser les informations disponiblees dans MITTRE de ce groupe de `Salt Typhoon`.
2. Trouver les informations avec les blogs par: **Picus Security, TrendMicro, Kaspersky Labs.**
3. Finaliser ce que nous devons faire pour notre entreprise.

**Findings:**

1. Le pays d'origine de ce groupe est Chine, et donc il est APT et parrainé par l'Etat.
2. Ce group est active depuis 2019.
3. Le cible de ce groupe est le Reseau: particulièrement, l'infrastructure reseau et principaux fournisseurs de services de telecommunications et d'Internet (FAI).
4. Alors, ils ont son logiciel: précisément, malware: il s'appelle `JumbledPath` >> il est écrit en la langage: GO.
5. Le malware est pour le systeme d'exploitation: Linux, car il est ELF binary et fonctionne dans l'architecture: `x86-64`
6. Le malware est écrit en langage: GO.
7. Le logiciel, malware est pour les produits de l'entreprise de Cisco.
8. Ce logiciel peut effacer les logs dans Linux / MAC (.bash_history, auth.log, lastlog, wtmp, andbtmp)
    - Technique: `T1070.002` (Indicator Removal: Clear Linux or Mac System Logs).

9. Le Decembre 20, 2024, le groupe de **Picus Security** a annoncé que le CVE-2022-3236 (`Sophos Firewall`) est utilise par cet APT, Salt Typhoon.
    - Il a son malware: "GhostSpider" >> backdoor
    - FBI/NSA ont aidé à proteger cet APT par les conseils.
10. Pour persister dans le systeme, il a modifié la clé de Registry:
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
    - Par le logiciel mefiant: `crowdoor.exe`.
11. Le technique s'appelle: Modify Registry `T1112` dans MITTRE.

12. Le **TrendMicro** a publié également un blog: `Earth Estries` >> ce nom correspond au meme groupe d'APT.
13. Le logiciel malware, `GhostSpider` est multi-backdoor et il fonctionne avec son protocol par TSL.
    - Il communique avec son C2 efficacement.
14. Parmi d'autres sites Web, seul celui-ci a un domain TLD different:
    - `telcom.grishamarkovgf8936.workers.dev`.
    - Pour le trouver: tu dois regarder le fichier: `IoCs` par *TrendMicro*.
15. Pour faire la première requête de `GET` au C2, il a utilisé le fichier:
    - `index.php`.

16. Le 30 Septembre, 2022, un blog a été publié sur `Securelist` par `Kaspersky`
    - Le titre de l'APT par `Kaspersky` est: **GhostEmperor**.
17. Le logiciel malware: `Demodex` est analysé par `Kaspersky` pour comprendre mieux.
18. Le logiciel a été le type de `Rootkit` malware.
19. Payload a été fait encrypte par AES.
20. IOCTL: `0x220300` a été utilisé pour cacher les actions de l'attaquant.

- **FAIRE**: Continuer d'apprendre ses méthodes et techniques!

**Key Learning / Takeaway:**
- IOCTL >> Input/Output Control >> il a beaucoup de fonctions qui fonctionnent avec les pilotes (drivers)
    - Simplement, `un code qui permet à une application d’ordonner à un pilote d’effectuer une action spécifique.`
    - **C’est un moyen pour un programme de parler directement à un pilote de périphérique (driver) pour lui demander une action spéciale.**

    - Lire/écrire un fichier → ça passe par les fonctions classiques.
    - Mais si tu veux dire à ton disque dur : “Donne-moi ta géométrie exacte” ou à ta carte réseau : “Passe en mode promiscuous” → tu envoies une commande IOCTL.
    - Donc:
        - C’est une commande spéciale envoyée par un programme → au driver → qui l’exécute.
        - Très utilisé pour interagir avec le matériel (disques, USB, réseau).
        - En cybersécurité, c’est important car des malwares exploitent des IOCTL vulnérables pour obtenir des privilèges kernel.

**Voilà:**
- **Voilà, ça y est, c'est fini:** `https://labs.hackthebox.com/achievement/sherlock/2118023/979`
