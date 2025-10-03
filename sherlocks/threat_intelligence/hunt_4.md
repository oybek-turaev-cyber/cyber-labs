# Sherlock / Threat Hunting Exercise

**Title: UFO-1**

**Date: 17/09/2025**

**Objective:**
Le but de l’exercice est d'analyser les actions malveillantes par l'**APT44** ou **Sandworm Team**

**Environment / Tools Used:**

* HTB Sherlocks
* MITRE ATT&CK, OSINT

**Investigation Steps (short):**

1. Utiliser le framework MITRE ATT&CK pour analyser toutes les techniques de ce groupe
2. Relier les points pour notre entreprise de voir si le groupe peut montre quelque chose d'malveillante à nous!

**Findings:**
1. Le groupe de **Sandworm Team** est actif depuis 2009
2. Pendant la campagne d'attaque de 2016: ce groupe a utilisé deux techniques pour obtenir les
   information d'identification avec le tactic: `Accès aux informations d'identification`
   - L'une était `LSASS Memory`(T1003.001) et l'autre était `Brute Force` (T1110).
3. Pendant l'attaque, `VBS` scripts sont utilisés: `ufn.vbs` et `remote.vbs`
4. Pour garder la persévérance (persistence) >> il a modifié le serveur d'application: et a utilisé Neo-REGEORG `Web Shell` (T1505.003) sur un serveur connecté à Internet.
5. Le malware s'appele: `Neo-REGEORG`
6. Le binaire, `scilc.exe` a été abusé dans le systeme de SCADA pour pour exécuter les instructions.
7. Le command était: `C:\sc\prog\exec\scilc.exe -do pack\scil\s1.txt`
8. L'outil, **CaddyWiper** a été utilisé pour détruire et effacer les données.( to wipe the data) et les fichiers liés aux capacités OT, ainsi que les lecteurs mappés (mapped drivers) et les partitions de lecteurs physiques.
9. Le malware, `CaddyWiper` peut exécuter le `Native API`(T1106) et donc il peut utiliser les APIs tel que: `SeTakeOwnershipPrivilege`
10. Le malware, **NotPetya** fonctionne comme `ransomware` et il a des fonctionnalités comme un ver (worm).
11. **MS17-010** c'est la vulnérabilité pour indiquer: `EternalBlue` et `EternalRomance`
12. Le malware appelé **AcidRain** a été utilisé pour cibler les `modems` et `routeurs`
13. Il est trouvé que l'équipe Sandworm Team a utilisé le port non-standarde pour se connecter à `SSH`: le port: `6789`
14. Il est clair que l'**APT28** a assisté au groupe **Sandworm Team**.

**Key Learning / Takeaway:**
1. **VBS** script >> `Visual Basic Scripting` est seulement créé pour le systeme de Windows. Avec l'hôte `Wscript.exe`, le script est exécuté pour performer les tâches administratives.

2. Les malwares: `CaddyWiper`, `NotPetya`, `AcidRain` sont très intéressant d'en apprendre davantage.

**Voilà:** ça y est, c'est fini: `https://labs.hackthebox.com/achievement/sherlock/2118023/840`
