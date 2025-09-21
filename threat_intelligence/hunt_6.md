# Sherlock / Threat Hunting Exercise

**Title: Constellation**

**Date: 20/09/2025**

**Objective:**
Le but de l’exercice est d'identifier la source d’un menace interne et  d'analyser les URLs et PDF suspects.

**Environment / Tools Used:**

* HTB Sherlocks
* OSINT, MITRE ATT&CK

**Investigation Steps (short):**
1. L'analyse de URLs
2. L'analyse de Metadata
3. DFIR & Incident Response

**Findings:**
1. Pour trouver la première date quand l'employée a connecté, on a utilisé l'outil: `unfurl`: grâce à `snowflakes` de **Discord**
    - on a trouvé la date: `2023-09-16 16:03:37`
    - Pour cela, on a utilisé le premier ligne dans le fichier: `IOC.txt`

2. Le fichier s'appelé: `NDA_Instructions.pdf`

3. Le fichier a été envoyé le `2023-09-27 05:27:02`

4. L'employée a cherché sur l'Internet: `how to zip a folder using tar in linux`

5. Quand on a analysé le deuxieme ligne par **unfurl**: on a trouvé que l'employée a cherché originalement cette phrase:
    - `How to archive a folder using tar i`

6. Cette recherche Google se passé le: `2023-09-27 05:31:45`

7. Le nom du group Hacker: `AntiCorp Gr04p` (trouvé dans le fichier PDF)

8. L'envoyeur était: `Karen Riley` (trouvé dans le fichier PDF)

9. La date quand ce fichier PDF a été evnoyé le: `2054-01-17 21:45:22` UTC mais la date original était en CET (22:45:22) >> on a fait la conversion.

10. On a trouvé l'email: `"CyberJunkie@AntiCorp.Gr04p"`
    - Quand on recherché `AntiCorp Gr04p` sur l'Internet, on a trouvé le compte de LinkedIn: **Abdullah Al Sajjad** qui était un agent de ce group.

11. La ville de cette personne dans LinkedIn était: `Bahawalpur`, Punjab, Pakistan.

**Key Learning / Takeaway:**
- DFIR (Digital Forensics and Incident Response) >>
- **unfurl** >> l'outil magique pour analyser l'URL davantage
- Discord Snowflakes - ils sont des information de la date

- Voilà, ça y est, c'est fini: `https://labs.hackthebox.com/achievement/sherlock/2118023/572`

