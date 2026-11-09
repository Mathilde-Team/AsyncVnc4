# Consommateur en aval (pluginvnc2)

Le plugin GTK4 `pluginvnc2` consomme ce fork. Son code source vit désormais
dans l'organisation : dépôt **Mathilde-Team/Gcm4**, dossier
`plugins/pluginvnc2/vnc_tab.py` (plus un simple `pluginvnc2.zip` hors org).
État vérifié dans ce fichier le 08/11/2026. Points de couplage à connaître
si tu modifies ce dépôt :

- `pluginvnc2` gère déjà le repli automatique si le paramètre `shared` de
  `connect()` n'existe pas encore (détection par `TypeError`) — ne pas
  retirer ce paramètre sans vérifier ce repli côté `vnc_tab.py`.
- `pluginvnc2` ne câble PAS `send_qemu_extended_key_event()` (aucune trace
  de `qemu` dans `vnc_tab.py`, vérifié le 08/11/2026). Depuis
  **2026-09-02** le format est vérifié contre le code source QEMU
  officiel (✅, plus ⚠️) donc un futur câblage côté GTK4 peut s'appuyer
  dessus avec la même confiance que xvp ci-dessous — sous réserve du
  test contre un vrai serveur QEMU/Proxmox, seul point encore non
  couvert (voir section dédiée plus haut).
- **xvp est câblé** depuis le correctif Gcm4 #104 : menu d'alimentation
  (extinction/redémarrage/reset) qui appelle
  `send_xvp_shutdown()`/`_reboot()`/`_reset()` avec `confirm=True` après
  confirmation utilisateur côté GTK4, comme exigé depuis le 2026-09-06
  (voir « Confirmation avant commande xvp destructive » dans
  `features.md`).
- **`listen()` est câblé** : l'onglet a un mode « ÉCOUTE » distinct
  (`opener: "listen"`, choix du port, affichage « en attente d'une
  connexion entrante »), exactement le mode à part dans l'UI que ce
  document prévoyait.
- **VeNCrypt est câblé** : `vnc_tab.py` construit un `ssl_context`
  optionnel (sans CA privée : dictionnaire vide, magasin système ; avec :
  `ssl.create_default_context` ne faisant confiance qu'à cette CA,
  vérification certificat ET nom d'hôte) et le passe à
  `connect()`/`listen()`.
- **Extended Clipboard est câblé** : l'émission distingue « extended »
  (serveur confirmé → `send_clipboard_update()`, Notify puis Provide,
  UTF-8), « legacy » (ClientCutText historique si Latin-1) et
  « unsupported » (rien n'est envoyé), avec le garde-fou
  `clipboard_ext_supported` (détails ci-dessous).
- **RSA-AES (RA2/RA2_256, ajouté le 2026-09-15)** reste absent de
  `vnc_tab.py` (vérifié le 08/11/2026). Un câblage exigerait un champ
  `username` (le sous-type « mot de passe seul » existe aussi côté
  RSA-AES, donc ce n'est pas garanti nécessaire selon le serveur visé,
  mais un serveur configuré comme celui utilisé pour vérifier ce
  correctif — `-RequireUsername=1` — l'exige). Contrairement à VeNCrypt,
  aucun paramètre `ssl_context`/CA ne serait nécessaire ici (RSA-AES ne
  s'appuie pas sur `ssl`/des autorités de certification) ; en revanche,
  `Client.rsa_aes_server_key_fingerprint` (une chaîne
  `%02x-%02x-...`, disponible après une connexion réussie) est
  directement du même type de donnée que ce que `HostKeyStore` sait déjà
  gérer pour l'auth Apple ARD — un épinglage RSA-AES côté `pluginvnc2`
  réutiliserait vraisemblablement la même mécanique de stockage/
  confirmation utilisateur, pas une nouvelle à inventer.
- Le repli de version de protocole ne demande AUCUNE adaptation côté
  `pluginvnc2` : entièrement interne à `Client.create()`, transparent
  pour l'appelant. Le seul ajout visible est le champ informatif
  `Client.protocol_version` (tuple `(3, 3)`/`(3, 7)`/`(3, 8)`), que
  `pluginvnc2` peut ignorer sans risque ou afficher en diagnostic s'il
  veut un jour.
- **Extended Clipboard** (ajouté le 2026-09-13) — côté réception, aucune
  adaptation requise : `Enc.EXTENDED_CLIPBOARD` est inclus dans
  `Enc.default()`, donc `client.clipboard.text` reçoit déjà le texte
  UTF-8 étendu dès lors que `pluginvnc2` utilise `connect()` tel quel.
  Côté émission, l'appel à `client.send_clipboard_update(text)` (pas
  `send_clipboard_provide()` seul, qui suppose qu'un `Request` a déjà été
  reçu — voir `features.md`) suppose `client.clipboard_ext_supported`,
  qui ne passe à `True` qu'après le premier message du serveur :
  `vnc_tab.py` gère ce garde-fou (retombée silencieuse sur le
  ClientCutText historique Latin-1, ou rien). Aucun nouveau paramètre
  sur `connect()`/`listen()`/`Client.create()`, contrairement à
  VeNCrypt ci-dessus.

- Depuis **2026-09-06**, `asyncvnc2.py` importe `loguru` (nouvelle
  dépendance tierce, absente jusqu'ici) pour la journalisation d'audit
  de `send_xvp()`/`send_qemu_extended_key_event()`/
  `send_set_desktop_size()` (voir section dédiée ci-dessus).
  `pluginvnc2` doit donc désormais lister `loguru` dans ses propres
  dépendances s'il ne l'avait pas déjà (à vérifier côté `pluginvnc2`) ;
  sans configuration de sink explicite côté `pluginvnc2`, ces logs
  sortent sur `stderr` par défaut (comportement loguru standard), donc
  rien ne casse si `pluginvnc2` ne fait rien — mais il ne les verra pas
  dans ses propres fichiers de logs tant qu'il n'appelle pas
  `logger.add(...)` à son propre démarrage.

Voir `features.md` de ce paquet pour l'état complet
encodage-par-encodage/extension-par-extension (créé le 2026-09-01, mis à
jour la même journée avec xvp, `listen()` puis le repli de version, puis
le 2026-09-02 avec la vérification source de
`send_qemu_extended_key_event()` puis avec le nettoyage de style partiel
ci-dessus) — ce fichier `CLAUDE.md` reste la référence pour le
« pourquoi » et les détails de vérification.

