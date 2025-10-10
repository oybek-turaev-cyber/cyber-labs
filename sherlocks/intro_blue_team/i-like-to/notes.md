# Sherlock / SOC / CTI / DFIR / IR Exercice

## Title: I-like-to

## Date: 09/10/2025

## Objective:
Le but de la chasse est d'analyser le CVE **MOVEit** dans notre systeme Windows et d'identifier leur actions malveillants pour aider à notre equipe de SOC. On a toute les sources **triage** avec les artefacts nécessaires.

La vulnerabilité: `MOVEit`: **TODO**

## Environment / Tools Used:
* HTB Sherlocks:
* OSINT, MITTRE

## Investigation Steps:
1. Analyser les informations disponiblees dans MITTRE de ce groupe de `Salt Typhoon`.
2. Trouver les informations avec les blogs par: **Picus Security, TrendMicro, Kaspersky Labs.**
3. Finaliser ce que nous devons faire pour notre entreprise.

## Findings:
1. On doit trouver le fichier: `ASPX` téléchargé par l'attaquant:
    - Pour trouver cette information, on a la source: **$MFT**
    - Ma solution: 1-> `convertir $MFT à CSV par MFTECmd.exe`; 2-> `Ouvrir cela par Timeline Explorer`
        - `.\MFTECmd.exe -f '$MFT' --csv C:\Users\vboxuser\Desktop\ --csvf mtf_parsed.csv`
    - Quand on a analysé avec `Timeline Explorer` et a recherché les fichiers: `.aspx`
    - On a trouvé qu'il y a un fichier: `move.aspx` téléchargé par l'attaquant à location: `MOVEitTransfer\wwwroot`
    - C'est suspect pour nous.
    - Voilà, la preuve:
    ![Le fichier malveillant](images/1.png)

2. On doit trouver l'IP addresse de l'attaquant:
    - Pour trouver cette information, on a la source pour utiliser: `I-like-to-27a787c5.vmem`
        - Ce fichier est `dumped` mais on ne peut utiliser cela avec **Volatility3** car il n'a pas `.vmss` partie de fichier.
    - Donc, on peut utiliser l'outil: **strings** pour trouver quelque information avec le fichier (script) malveillant **move.aspx**.
    - On a utilisé cette commande: `strings I-like-to-27a787c5.vmem | grep "move.aspx"`
        - Il nous a donné l'information de l'IP addresse de l'attaquant: `10.255.254.3`
    - Voilà, la preuve:
    ![L'IP Addresse de l'attaquant](images/2.png)

3. On doit trouver *User Agent* utilisé par l'attaquant
    - On a la source: `Web Service Logs` et on peut utiliser cela:
    - Quand on a analysé le fichier: `u_ex230712`, on a trouvé que l'attaquant utilisé le logiciel: `Ruby` pour demander les info avec `GET` methode
    - Voilà, la preuve:
    ![User Agent](images/3.png)

4. Maintenant, on doit trouver le temps téléchargé du fichier: `move.aspx`
    - Quand on a analysé la source: `$MFT` avec le mot clé: `move.aspx`
    - On a trouvé qu'il est créé le `2023/07/12 11:24:30`
    - Voilà, la preuve:
    ![Le temps téléchargé du fichier malveillant](images/4.png)

5. On doit trouver la taille du fichier téléchargé par l'attaquant:
    - Ma méthode: Convertir le `$MFT` au `jason` fichier en utilisant `PowerShell`
        - `$mft=Get-Content "$MFT" | ConvertFrom-Json`
        - `$mft | Where-Object {$_.FileName -eq "movit.asp"} | Select-Object FileName, FileSize`
    - On connaît que `.asp` est l'ancienne version par rapport à l'autre.
    - Ensuite, j'ai obtenu la taille du fichier: `1362`
    - Voilà, la preuve:
    ![La taille](images/5.png)

6. On doit trouver l'outil utilisé par l'attaquant pour faire une énumération initiale:
    - Quand on a analysé le logs Web Server: `u_ex230712`, on a trouvé l'outil qui utilisé souvent pour faire les fins des énumérations initiales
    - Cet outil: `Nmap`
    - Voilà, la preuve:
    ![L'outil utilisé pour énumérations initiales](images/6.png)


















## Key Learning / Takeaway:
1. Les fichiers: **.aspx** >> webshell >> ils peuvent contenir script pour le framework Microsoft: **ASP.NET**
    - *une page web générée à l'aide du framework Microsoft ASP.NET exécuté sur des serveurs web*
2.


## Voilà:
- **Voilà, ça y est, c'est fini:**
