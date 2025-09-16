# Sherlock / Threat Hunting Exercise

**Title: ElectricBreeze-1**

**Date: 16/09/2025**

**Objective:**
Le but de l’exercice est d'identifier la source d’un accès non autorisé par l'APT: **Volt Typhoon** et analyser ses actions maveillants.

**Environment / Tools Used:**

* HTB Sherlocks
* MITRE ATT&CK, OSINT

**Investigation Steps (short):**

1. Analyser tous les informations et techniques de l'APT avec MITRE ATT&CK
2. Utiliser OSINT données
3. Savoir et relier les points ce que l'attaquant peut faire quelque chose de maveillants pour notre entreprise.

**Findings:**
1. L'APT **Volt Typhoon** est actif depuis 2021
2. Ce groupe utilise deux technique pour obtenir les privilégiés: `LSASS Memory Access`: `T1003.001` et `NTDS`: `T1003.003`
3. Avec NTDS, son cible est de creer la copie de la base de données du domaine: `Active Directory`
4. `SYSTEM` est le ruche de registre est requise par l’acteur de la menace pour décrypter la base de données ciblée: `Active Directory`
5. Le malware, `VersaMem` a été utilisé en June 2024: `pour la capture d'informations d'identification.`
    - L'entreprise, **Versa Director** a été cible de l'APT
    - Cet entreprise fait `SD-WAN`
6. Ce malware >> **Web Shell** conçu pour être déployé sur les serveurs Versa Director après exploitation
    - Il a été le fichier: `JAR`
    - Cela a été **Zero-Day Exploitation**
7. Il a stocké les informations capturées dans cet emplacement: `/tmp/.temp.data`
8. Selon l'article par **Lumen/Black Lotus Labs**, la promière fois, ce fichier, `VersaTest.png` a été téléchargé sur **VirusTotal** le 7 Juin, 2024.
9. Le hachage (SHA256) de ce fichier: `VersaTest.png` est: `4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37`
10. Le type du fichier du malware est **JAR** (Java Archive File)
11. Selon **VirusTotal**: sur les infos de **Manifest**: il a été créé par `Apache Maven 3.6.0`
12. Pour ce malware et vulnérabilité, ce CVE est créé: **CVE-2024-39717**
13. L'APT a utilisé la technique: **LOTL** (Living Off The Land) pour **defense evasion** pour
    cacher ses actions utilisant les logiciel et proces normaux de Windows
14. Dans le document de **CISA**, on a trouvé que les données des événement de connexion a été écrit dans ce fichier:
    - `user.dat` >> `C:\users\public\documents\user.dat` avec cette commande:
    - `Get-EventLog security -instanceid 4624 - after [year-month-date] | fl * | Out-File 'C:\users\public\documents\user.dat'`

**Key Learning / Takeaway:**
- Je dois réfléchir bien pour comprendre entierement les techniques de l'APT.
- Je finaliserai bientôt!

