# Sherlock / Threat Hunting Exercise

**Title: Teamwork**

**Date: 19/09/2025**

**Objective:**
Le but de l’exercice (ex: identifier la source d’un accès non autorisé, analyser les logs suspects, etc.)`

**Environment / Tools Used:**

* HTB Sherlocks
* \[Splunk / ELK / Sysmon / Zeek / autre outil utilisé]

**Investigation Steps (short):**

1. `[Ex: Revue des logs de sécurité Windows → détection d’un logon anormal sur DC01]`
2. `[Ex: Corrélation avec événement PowerShell → script obfusqué]`
3. `[Ex: Extraction IOC → adresse IP malveillante]`

**Findings:**

* `[Ex: Compromission confirmée via technique DCsync]`
* `[Ex: Attaquant a escaladé les privilèges → Domain Admin]`

**Flags Captured:**

* `FLAG{xxxxxxx}`

**Key Learning / Takeaway:**

* `[Ex: Importance de surveiller les événements 4624 & 4672 pour les logons privilégiés]`
* `[Ex: Technique ATT&CK repérée : T1003.006 – DCsync]`



