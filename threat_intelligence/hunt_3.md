# Sherlock / Threat Hunting Exercise

**Title: Dream Job-1**

**Date:17/09/2025**

**Objective:**
Le but de l’exercice est d'enquête sur une campagne de cyberespionnage appelé **Operation Dream Job** et recueillir des informations de cette opération.

**Environment / Tools Used:**

* HTB Sherlocks
* MITRE ATT&CK, OSINT, autre outil utilisé

**Investigation Steps (short):**

1. Utiliser MITRE pour recueillir les informations de ce groupe.
2. Trouver toute les actions malveillantes.
3. Finaliser ce que l'attaquant peut faire sur notre entreprise.

**Findings:**
1. Il est **Lazarus Group** qui mené l'opération Dream Job.
2. La première fois il a été vu en `September, 2019`.
3. Il y a deux campagnes associées de ce groupe: L'une s'appele `Operation North Start` et L'autre s'appele `Operation Interception`.
4. Deux processus Windows sont utilisé pour lancer le malware: L'un est `Regsvr32` et l'autre est `Rundll32`
    - Cette technique s'apple **LOLBAS** >> (System Binary Proxy Execution)
5. La technique, `Internal Spearphishing` de **Lateral Movement** est utilisé par ce groupe!
6. L'ID pour cette technique est `Internal Spearphishing` (T1534)
7. Ils ont utilisé le RAT (Remote Access Trojan) appelé **DRATzarus**.
8. Le malware, `DRATzarus` a utilisé **Native API** pour s'exécuter dans le systeme.
9. La malware a utilisé la technique, **Time Based Evasion** pour détecter l'environement de Virtual Machine ou Sandbox.
10. Le hachage ci-dessous donne le nom du programme: **IEXPLORE.EXE**
    - `7bb93be636b332d0a142ff11aedb5bf0ff56deabba3aa02520c85bd99258406f`
11. Le temps créé de ce fichier associé avec cet hachage: est `2020-05-12 19:26:17`
    - `adce894e3ce69c9822da57196707c7a15acee11319ccc963b84d83c23c3ea802`
12. Le nom du fichier associé avec le duexième hachage (au dessus): est `BAE_HPC_SE.iso` il faut utiliser le
    graph ayant compte sur VirusTotal pour trouver cette information.
13. Quand on a analysé le troisième hachage, on a trouvé que le fichier, `Salary_Lockheed_Martin_job_opportunities_confidential.doc`. Ce fichier a correspondé à la technique de l'attaquant.
14. Le 03/08/2022, cet URL a été contactée: `https://markettrendingcenter.com/lk_job_oppor.docx`

**Key Learning / Takeaway:**
1. `System Binary Proxy Execution` >> c'est privilège quand le binary program signé par Microsoft
   est utilisé pour lancer le malware et il peut éviter la detection d'Anti-Virus.

2. `Native API` >> La technique est utilisé pour changer le comportement des processus natives Windows: kernel, mémoire, périphériques matériels (hardware devices) et les processus.

3. `Virtualization/Sandbox Evasion` >> l'attaquant peut analyser l'environement pour savois si il y a des artefacts de Virtual Machine ou Sandbox. Par conséquence, il peut modifier son but and comportement si il trouve les données de VME / Wireshark ou d'autres outils.

Voilà, ça y est, c'est fini: `https://labs.hackthebox.com/achievement/sherlock/2118023/865`
