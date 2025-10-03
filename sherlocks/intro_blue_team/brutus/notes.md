# Sherlock: SOC & DFIR Exercice

## Title: Brutus

## Date: 03/10/2025

## Objective:
Le but de cet exercice est d'analyser **Unix auth.log** et **wtmp logs**. Notre serveur **Confluence** est exploité par la technique: **brute-forcing**.
On doit identifier la source d’un accès non autorisé par le groupe et leur techniques pour: **Privilege Escalation**, **Persistence**, **Exécution de Commandes**. En général, on analysera leur actions malveillants.

## Environment / Tools Used:
* HTB Sherlocks: Intro-to-Blue-Team Track
* Unix, auth.log,

## Investigation Steps (short):
1. Analyser les informations disponiblees dans MITTRE de ce groupe de `Salt Typhoon`.
2. Trouver les informations avec les blogs par: **Picus Security, TrendMicro, Kaspersky Labs.**
3. Finaliser ce que nous devons faire pour notre entreprise.

## Findings:
1. On doit trouver l'IP address de l'attaquant:
    - Quand on a analysé source: `auth.log`, on a trouvé les tentatives plusiers avec l'IP: `65.2.161.68`
    - La raison est que ces tentatives ont généré beaucoup de message d'échec (Failure Messages)
    - Voilà, la preuve:
    ![Drapeau #1: IP addresse de l'attaqunt](images/1.png)
2.



## Key Learning / Takeaway:**

## Voilà:
- **Voilà, ça y est, c'est fini:**
