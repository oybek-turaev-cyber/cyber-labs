# Sherlock: SOC & DFIR Exercice

## Title: Brutus

## Date: 03/10/2025

## Objective:
Le but de cet exercice est d'analyser **Unix auth.log** et **wtmp logs**. Notre serveur **Confluence** est exploité par la technique: **brute-forcing**.
On doit identifier la source d’un accès non autorisé par le groupe et leur techniques pour: **Privilege Escalation**, **Persistence**, **Exécution de Commandes**. En général, on analysera leur actions malveillants.

## Environment / Tools Used:
* HTB Sherlocks: Intro-to-Blue-Team Track
* Unix, auth.log,

## Investigation Steps:
1. Analyser les informations disponiblees dans MITTRE de ce groupe de `Salt Typhoon`.
2. Trouver les informations avec les blogs par: **Picus Security, TrendMicro, Kaspersky Labs.**
3. Finaliser ce que nous devons faire pour notre entreprise.

## Findings:
1. On doit trouver l'IP address de l'attaquant:
    - Quand on a analysé la source: `auth.log`, on a trouvé les tentatives plusiers avec l'IP: `65.2.161.68`
    - À `06:31:31` heure, ça c'est passé.
    - La raison est que ces tentatives ont généré beaucoup de message d'échec (Failure Messages)
    - Donc, c'est la signé de **l'attaque** de **brute force**
    - Voilà, la preuve:
    ![Drapeau #1: IP addresse de l'attaqunt](images/1.png)

2. Il y a un compte compromis, on doit trouver ça.
    - Quand on a analysé la source: `auth.log`
    - On a trouvé que le compte de l'utilisateur: **root** est exploité: il y a les preuves de message d'échec et le message: `Accepted Password`
    - À `06:32:444` heure, ça c'est passé.
    - Voilà, la preuve:
    ![Drapeau #2: Le compte compromis](images/2.png)

3.



## Key Learning / Takeaway:**
1. **auth.log** montre et enregistre `événement d'authentication: successful/failed logins` et également `l'usage de sudo, les tentatives SSH`
2. **wtmp** montre et enregistre `logins / logouts / reboots` et `c'est qui fait login et quand`

## Voilà:
- **Voilà, ça y est, c'est fini:**
