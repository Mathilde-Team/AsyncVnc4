# Journal des versions

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Les numéros suivent [SemVer](https://semver.org/lang/fr/), et la version de `pyproject.toml` est égale au tag.

## [Non publié]

### Ajouté
- **Licence** (#72) : ajout de `NOTICE`, qui reprend l'avis des projets amont (asyncvnc de Barney Gale, asyncvnc2 d'Andrew Shirayev, tous deux sous GPLv3) et décrit les régimes de licence. `asyncvnc2.py` reste en `GPL-3.0-only`, le reste du code passe en `GPL-3.0-or-later`. En-têtes SPDX, `license` et `license-files` dans `pyproject.toml`, `test_licence.py`. La sauvegarde `asyncvnc2.py.orig`, que rien n'utilisait, est retirée du dépôt.
- **ZYWRLE complet** (#22) : décodage des tuiles à perte de QEMU. Une tuile Raw d'un rectangle ZYWRLE contient une tuile ZRLE imbriquée (coefficients d'ondelettes), reconstruite par `_zywrle_synthesize()`, port octet par octet de `ZYWRLE_SYNTHESIZE` (libvncserver). Le niveau (3 - qualité // 3) est déduit de `jpeg_quality`, désormais conservé par `Video`. Vérifié contre QEMU 10.2.1 (`test_live_qemu_zywrle.py`, job « Serveur réel »). `Enc.ZYWRLE` reste hors `Enc.default()` (à perte).
- **Couverture bloquante, palier 1** (#54) : `[tool.coverage]` dans `pyproject.toml` (branches activées, `fail_under = 51`, seuil déclaré une seule fois) ; le job Qualité lance `coverage run` puis `coverage report`. La couverture passe de 34,89 % à 51,32 % (lignes + branches).
- **Couverture bloquante, palier 3** (#54) : tests des négociations VeNCrypt (refus, ordre de préférence des 8 sous-types, contexte TLS anonyme ou vérifiant, montée TLS doublée) et RSA-AES (serveur RA2/RA2_256 en mémoire avec clés RSA et AES-EAX réels : identifiant et mot de passe, mot de passe seul, empreinte, hachage ou aléa du serveur incorrects, clé hors limites), de la montée TLS réelle en boucle locale (certificat auto-signé), d'`EncList`, du clavier, de la souris et des champs ARD/MSLogonII. La couverture passe de 76 % à 88,21 % ; `fail_under = 88`.
- **`test_reseau_local.py`** (27 tests) : un serveur RFB minimal sur 127.0.0.1 dialogue avec les vrais `connect()` et `listen()`, en TCP brut et en WebSocket. Les tests couvrent les versions 3.3/3.7/3.8, les versions mineures inconnues et majeures récentes, l'authentification VNC (DES) réussie ou refusée, les refus avec motif, SetPixelFormat, SetEncodings (qualité JPEG, compression) et une image Raw relue pixel par pixel. La poignée de main WebSocket est vérifiée contre le vecteur de la RFC 6455 §1.3.
- **Tests contre TigerVNC Xvnc** (#27) : `test_live_xvnc.py` (chaque encodage relu contre la couleur de `xsetroot`, `listen()` + `vncconfig -connect`), lancé par le job « Serveur réel ».
- **`scripts/scenario_listen_nat.sh`** (#27) : `listen()` à travers un NAT + pare-feu à états réel (espaces de noms réseau, `MASQUERADE`), lancement manuel avec sudo.

### Corrigé
- **Tight en mode `bgra`/`abgr`** (#27) : les TPIXEL (3 octets, toujours R, G, B) étaient lus dans l'ordre du mode client, rouge et bleu inversés (remplissage, JPEG/PNG, blocs de base).
- **`screenshot()` bloqué avec TigerVNC** (#27) : après une mise à jour qui ne contient que `ExtendedDesktopSize`, la capture redemande en incrémental au lieu de boucler sur des demandes complètes.

### Corrigé
- **ZYWRLE** (#22) : les subencodings 17-126 levés contre QEMU (`lossy=on`) venaient d'une désynchronisation du flux (tuile imbriquée lue comme du Raw) ; ils disparaissent avec le décodage de la tuile imbriquée.

## [0.1.0] - 2026-10-22

Première version publiée sous forme de release GitHub.

### Ajouté
- **Workflow de release** (#57) : `.github/workflows/release.yml` publie une release GitHub au push d'un tag `vX.Y.Z` sur `main` (tag = version de `pyproject.toml`, notes tirées de la section `## [X.Y.Z]` de ce journal, archive des sources jointe).
