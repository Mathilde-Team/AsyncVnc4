# asyncvnc2_patched — fonctionnalités

Fork maison d'`asyncvnc2` (client RFB pur Python) + 5 patches appliqués
directement dans `asyncvnc2.py` (voir `CLAUDE.md` pour le détail
avant/après et le niveau de vérification de chacun), **plus xvp, la
reconnexion inversée (`listen()`), le repli de version de protocole,
VeNCrypt (sous-types TLSNone/TLSVnc, puis X509None/X509Vnc) et
RFB-sur-WebSockets** ajoutés dans des sessions ultérieures le même
jour (voir sections « Client requests », « Transport » et
« Authentification »). Fichier unique, livré séparément du plugin
GTK4 qui le consomme (`pluginvnc2.zip`).

Légende : ✅ vérifié (exécution réelle ou RFC officielle) — ⚠️ implémenté
mais non confirmé contre une source fraîche — 🔲 non implémenté.

## Encodages (ordre de priorité de `Enc.default()`)

| Encodage | Statut |
|---|---|
| Tight / Tight PNG | ✅ (fork d'origine, 21/21 déjà testé contre TigerVNC/x11vnc réels) |
| ZRLE / TRLE / Zlib | ✅ (fork d'origine) |
| Hextile / ZlibHex | ✅ (fork d'origine) |
| CoRRE (4) | ✅ **2026-09-01** — décodage testé contre un flux fabriqué à la main, garde-fou 255×255 vérifié |
| RRE (3) | ✅ **2026-09-01** — décodage testé contre un flux fabriqué à la main |
| Copy | ✅ (fork d'origine) |
| Curseur (Rich Cursor / X Cursor / Cursor With Alpha) | ✅ (fork d'origine) |
| Desktop Size / Extended Desktop Size | ✅ (fork d'origine) |
| Last Rect / Fence / Continuous Updates | ✅ (fork d'origine) |
| ZYWRLE (17) | ✅ **2026-10-24 (issue #22) : décodage complet, testé contre un vrai QEMU 10.2.1** (`-vnc :N,lossy=on`, qualités 0/4/7 → niveaux 3/2/1, PSNR 21,1 / 26,0 / 55,9 dB contre le `screendump` du moniteur ; qualité 9 et ZRLE seul : identiques au pixel près). Format (QEMU `ui/vnc-enc-zrle.c.inc`, libvncclient `zrle.c`) : dans une tuile Raw (subencoding 0), le serveur envoie une **tuile ZRLE imbriquée complète** dont les pixels sont les coefficients d'ondelettes PLHarr ; le niveau vaut 3 - qualité JPEG // 3 et n'est jamais transmis. `_zywrle_synthesize()` est un port octet par octet de `ZYWRLE_SYNTHESIZE` (libvncserver), validé contre le C compilé (vecteurs SHA-256 dans `ZywrleTests`). Les subencodings 17-126 vus le 2026-09-09 (QEMU 8.2.2) étaient une désynchronisation du flux (tuile imbriquée lue comme du Raw), toujours refusés (`ValueError`). `Enc.ZYWRLE` reste opt-in (hors `Enc.default()`) car à perte. Test réel : `test_live_qemu_zywrle.py` (job CI « Serveur réel »). Détail : `docs/sessions/session-25-2026-10-24.md` ; historique : `docs/sessions/session-11-2026-09-09.md` |

## Authentification

| Fonctionnalité | Statut |
|---|---|
| VNC Auth (DES) | ✅ (fork d'origine) |
| Apple ARD | ✅ (fork d'origine) |
| Mot de passe VNC Auth non-ASCII (repli Latin-1) | ✅ **2026-09-01** — encodage testé avec un mot de passe accentué réel |
| Troncature ARD silencieuse | ✅ **2026-09-01** — corrigée en `ValueError` explicite, testée aux deux bornes (63/64 octets) |
| VeNCrypt / TLS anonyme (19) — sous-types TLSNone/TLSVnc | ✅ **2026-09-02**, **test réel contre un vrai serveur + bug trouvé et corrigé le 2026-09-08** — format vérifié contre la spec communautaire officielle (`rfbproto.rst` du dépôt `rfbproto/rfbproto`, section VeNCrypt) **et** contre l'implémentation de référence TigerVNC (`CSecurityVeNCrypt.cxx`/`CSecurityTLS.cxx`) — une divergence réelle entre un tout premier brouillon de spec de 2010 et le comportement actuel a été débusquée et corrigée en cours de session, voir `CLAUDE.md` ; négociation de version 0.2, sélection de sous-type et bascule TLS testées de bout en bout sur un vrai socket TCP loopback avec un faux serveur généré à la main (certificat auto-signé `openssl`), pour les deux sous-types TLSNone (aucune authentification après TLS) et TLSVnc (VNC Authentication standard réutilisée telle quelle, désormais sur le flux chiffré). **2026-09-08 : premier test contre un vrai serveur tiers (TigerVNC/Xvnc 1.13.1 réel, backend GnuTLS)** — a révélé un vrai bug : le contexte SSL par défaut ne proposait aucune suite cryptographique anonyme (`ADH`/`AECDH`), retirées par défaut depuis OpenSSL 1.1.0+, alors que TigerVNC implémente ces sous-types avec de vraies suites anonymes (aucun certificat échangé), contrairement au faux serveur du 2026-09-02 qui utilisait un certificat auto-signé avec des suites authentifiées normales. Corrigé (`set_ciphers('ADH:AECDH:ALL:!eNULL:@SECLEVEL=0')` + `maximum_version = TLSv1_2`, suites anonymes placées en tête de liste — un ordre de préférence, pas juste une présence, s'est révélé nécessaire : voir `CLAUDE.md` pour le détail de la bissection) et revérifié : TLSVnc et TLSNone fonctionnent désormais avec le contexte par défaut contre le vrai TigerVNC, sans régression du scénario 2026-09-02 (revérifié isolément sur la seule couche TLS) ni de X509None/X509Vnc (branche de code distincte) |
| VeNCrypt — sous-types X509None/X509Vnc | ✅ **2026-09-05**, **confirmé contre un vrai serveur le 2026-09-08** — vraie chaîne de certification (CA racine + certificat serveur signé, SAN `IP:127.0.0.1`+`DNS:localhost`) générée avec `openssl` dans ce sandbox, contrairement au certificat auto-signé anonyme utilisé pour TLSNone/TLSVnc ci-dessus ; testé de bout en bout sur un vrai socket TCP loopback pour X509None (aucune authentification après TLS) et X509Vnc (VNC Authentication standard réutilisée telle quelle, mais désormais avec en plus une vraie vérification du certificat serveur) ; **rejet réel confirmé avec une CA non liée** (`ssl.SSLCertVerificationError` authentique, preuve qu'une vraie vérification a bien lieu — contrairement à TLSNone/TLSVnc) ; ordre de préférence testé quand plusieurs sous-types sont offerts à la fois (X509Vnc > X509None > TLSVnc > TLSNone, le plus fort en premier) ; comportement par défaut (`ssl_context=None` → `ssl.create_default_context()`, magasin de CA système) testé à la fois en échec sûr (CA de test absente du magasin système) et en réussite (magasin simulé par `unittest.mock`, pour confirmer que le bon code s'exécute réellement et pas seulement qu'il est présent dans le fichier) ; non-régression de TLSNone/TLSVnc revérifiée. Un piège a été débusqué et corrigé en cours de session — voir `CLAUDE.md` § »VeNCrypt X509None/X509Vnc« — sur le comportement réel de `server_hostname=None` (le cas de `listen()`, qui n'a pas de nom d'hôte cible à vérifier). **2026-09-08 : testé pour de vrai contre TigerVNC/Xvnc réel** — X509Vnc (choisi par priorité quand les 4 sous-types sont offerts, avec vraie vérification de certificat + vrai mot de passe) et X509None (offert seul, sans mot de passe) tous deux réussis sans aucune modification de code nécessaire (contrairement à TLSNone/TLSVnc ci-dessus) |
| VeNCrypt — sous-types TLSPlain/X509Plain | ✅ **2026-09-14** — découverts en inspectant les types de sécurité qu'un vrai `Xtigervnc` 1.13.1 propose réellement (`-help` → `SecurityTypes ... Plain, TLSPlain, X509Plain ...`), absents jusqu'ici de ce fichier. Format vérifié contre `rfbproto.rst` (section VeNCrypt, « Plain subtype » : `U32` longueur-identifiant + `U32` longueur-mot-de-passe + identifiant + mot de passe, envoyés après la poignée de main TLS/X.509) **et** contre le client de référence TigerVNC (`CSecurityPlain.cxx`) — identiques. Réutilise les paramètres `username`/`password` déjà acceptés par `Client.create()` (jusqu'ici seulement pour l'authentification Apple, type 33) ; encodage UTF-8 (pas de contrainte de taille de clé cryptographique comme pour le DES de VNC Auth). Ordre de préférence étendu à six sous-types : X509Vnc > X509Plain > X509None > TLSVnc > TLSPlain > TLSNone (le degré de chiffrement d'abord, puis « nécessite une authentification » avant « aucune », puis — entre Vnc et Plain — la méthode qui n'expose jamais le mot de passe en clair même après déchiffrement TLS avant celle qui l'expose directement au serveur). **Testé pour de vrai contre TigerVNC/Xvnc 1.13.1 dès le départ** (contrairement à TLSNone/TLSVnc/X509None/X509Vnc, testés d'abord contre un faux serveur fabriqué à la main) : `SSecurityPlain` de TigerVNC délègue la vérification du mot de passe à PAM (ou Windows), donc un vrai utilisateur Linux + un service PAM (`PAMService`, config `common-auth`/`common-account` fournie par le paquet Debian/Ubuntu) ont été configurés dans ce sandbox spécifiquement pour ce test. Quatre scénarios vérifiés de bout en bout : identifiant+mot de passe corrects → connexion réussie ; mauvais mot de passe → `PermissionError` réelle (`rfb::AuthFailureException` du serveur, remontée par le code `SecurityResult` déjà existant, inchangé) ; identifiant inexistant → même rejet ; ni identifiant ni mot de passe fournis → `ValueError` levée avant tout envoi réseau. Effet de bord bénin observé et sans rapport avec ce patch : un avertissement asyncio (« returning from eof_received() has no effect when using ssl ») apparaît à la fermeture d'une connexion TLS refusée — comportement générique d'`asyncio`/`ssl` sur une coupure abrupte, pas spécifique à Plain. Aucun test unitaire ajouté à `test_asyncvnc2.py` : VeNCrypt dans son ensemble en est délibérément exclu depuis le 2026-09-07 (nécessiterait un faux serveur TLS complet, périmètre plus lourd que le reste de cette suite) — voir `docs/sessions/session-16-2026-09-14.md` pour le détail complet |
| Ancien type de sécurité "TLS" isolé (18, distinct de VeNCrypt, obsolète) | 🔲 non implémenté — supplanté par VeNCrypt en pratique ; **2026-09-16 : confirmé infaisable proprement** (pas seulement « valeur incertaine ») — voir la ligne dédiée dans « Prochaines étapes suggérées » ci-dessous pour le détail → [issue #33](https://github.com/MathildeDec/AsyncVnc4/issues/33) (P4-bloquée, Track C) |
| SASL, MSLogon, UltraVNC MSLogonII | ⚠️ **2026-09-16 : MSLogonII (113) implémenté** (voir ligne dédiée ci-dessous) ; **2026-09-16 (suite) : SASL (20) implémenté pour les mécanismes `PLAIN`/`ANONYMOUS` uniquement** (voir ligne dédiée ci-dessous) ; MSLogon original reste non commencé — voir « Prochaines étapes suggérées » → [issues #23](https://github.com/MathildeDec/AsyncVnc4/issues/23) (MSLogon, P4), [#25](https://github.com/MathildeDec/AsyncVnc4/issues/25) (SASL+, P4), [#31](https://github.com/MathildeDec/AsyncVnc4/issues/31) (test MSLogonII, P2), [#32](https://github.com/MathildeDec/AsyncVnc4/issues/32) (test SASL, P2) |
| MSLogonII (113) | ⚠️ **2026-09-16** — format vérifié contre `rfbproto.rst`, section « MSLogonII Authentication » (seule source disponible — extension originaire d'UltraVNC/Windows, sans serveur de référence installable dans ce sandbox Linux pour la confirmer). Échange Diffie-Hellman 64 bits (`generator`/`modulus`/`public-value`, 8 octets chacun, exponentiation modulaire via `pow()` natif Python — aucune bibliothèque cryptographique dédiée nécessaire), puis chiffrement DES-CBC des champs nom d'utilisateur (256 octets) et mot de passe (64 octets), chacun UTF-8/NUL-terminé/complété d'octets aléatoires (`_pack_mslogonii_field()`, même motif que `pack_ard()` pour Apple ARD, tailles de champ différentes). Réutilise le même bit-reversal DES que VNC Authentication (2 ci-dessus), la spec l'indique explicitement comme identique ; l'IV (le secret partagé lui-même, non inversé) suit la spec à la lettre. Classé en dernier de l'ordre de préférence de négociation (après RSA-AES) : neuf, jamais testé contre un vrai serveur, et sa clé DH 64 bits est qualifiée par la spec elle-même de cassable « immédiatement » — n'apporte donc pas de confidentialité réelle contre un attaquant actif, seulement un nom d'utilisateur en plus de VNC Auth. Deux points d'ambiguïté de la spec, non tranchables sans un vrai serveur MSLogonII contre lequel vérifier : l'ordre exact des trois champs Diffie-Hellman lus (« generator, modulus, public-value », dans cet ordre au tableau) et la lecture de « encrypt the username and password using DES in CBC mode, respectively » comme deux chiffrements CBC indépendants (chacun redémarrant avec le secret partagé comme IV) plutôt qu'un seul flux continu sur les deux champs concaténés — les deux choix sont documentés en commentaire dans le code. **Vérifié par un round-trip auto-cohérent fabriqué à la main** (un « serveur » recalculant le même secret Diffie-Hellman à partir de la valeur publique du client et déchiffrant les deux champs, nom d'utilisateur et mot de passe accentués/non-ASCII inclus) — confirme que le code est internement cohérent avec sa propre lecture de la spec, mais **ne prouve pas l'interopérabilité avec un vrai serveur MSLogonII** (aucun disponible dans ce sandbox). Pas de test unitaire committé dans `test_asyncvnc2.py` : même choix que pour le reste de VeNCrypt/RSA-AES/Apple ARD (poignée de main complète volontairement non testée unitairement, y compris `pack_ard()` lui-même, qui n'a jamais eu de test dédié) — voir `docs/sessions/session-20-2026-09-16.md` pour le détail complet |
| SASL (20) — mécanismes PLAIN/ANONYMOUS seulement | ✅ **2026-10-10 (issue #32) : testé contre un vrai QEMU 10.2** (Cyrus SASL, sasldb), via les nouveaux sous-types VeNCrypt **X509SASL (263)** et **TLSSASL (264)**. PLAIN fonctionne en X509SASL (connexion et capture) ; mauvais mot de passe et utilisateur inconnu : QEMU ferme la connexion, remontée en `PermissionError`. Hors X509SASL (SASL seul, TLSSASL anonyme), QEMU exige un mécanisme qui chiffre (min_ssf=56) et retire PLAIN : `ConnectionError` explicite (au lieu d'une `IncompleteReadError`) ou `ValueError` listant les mécanismes (ex. `DIGEST-MD5`). `test_live_qemu_sasl.py` (7 tests, job CI « Serveur réel »). ANONYMOUS reste non vérifié contre un serveur réel. Historique : ⚠️ **2026-09-16** — ré-examen d'un rejet trop rapide de la session précédente (voir `docs/sessions/session-21-2026-09-16c.md`) : le tramage RFB de SASL (`rfbproto.rst`, section « SASL » — mechlist, client-start, server-start, complete-flag) est en fait un protocole générique de messages longueur-préfixée, **documenté indépendamment de toute bibliothèque SASL** ; seule la production du contenu opaque `clientout-data`/`serverout-data` dépend en général d'une bibliothèque tierce (`sasl_client_start`/`sasl_client_step`) — mais `PLAIN` (RFC 4616) et `ANONYMOUS` (RFC 4505) sont chacun définis par leur propre RFC autonome, sans aucun défi du serveur (une seule étape), donc calculables directement sans dépendance supplémentaire. `_sasl_negotiate()` implémente ces deux mécanismes uniquement : `PLAIN` choisi en priorité si offert avec des identifiants (`username`/`password`, réutilisant les paramètres déjà acceptés par `Client.create()`), `ANONYMOUS` sinon (message de trace optionnel = nom d'utilisateur fourni ou chaîne vide). Tout autre mécanisme offert par le serveur (`DIGEST-MD5`, `GSSAPI`, `CRAM-MD5`, etc., qui nécessiteraient une vraie bibliothèque SASL et souvent une infrastructure Kerberos) est refusé explicitement (`ValueError` listant les mécanismes offerts) avant tout envoi réseau — même principe que pour ZYWRLE (subencodings 17-126) et le type de sécurité 18 isolé : refuser de deviner un format/protocole non documenté plutôt que l'implémenter partiellement en silence. Un `complete-flag` à 0 (échange multi-étapes, non prévu par `PLAIN`/`ANONYMOUS`) est également refusé plutôt que deviné. Ni l'un ni l'autre mécanisme ne négocie de couche de confidentialité/intégrité (SSF nul par construction, RFC 4422) : pas de `sasl_encode`/`sasl_decode` à implémenter pour ces deux-là — propriété des mécanismes, pas une limite de cette implémentation. Classé en toute dernière position de l'ordre de préférence de négociation (après MSLogonII) : `PLAIN` envoie le mot de passe directement sur le fil sans aucune couche de chiffrement propre à ce type de sécurité (contrairement aux sous-types VeNCrypt `TLSSASL`/`X509SASL` de la spec, qui enveloppent SASL dans du TLS déjà négocié — hors périmètre de cette session). **Aucun serveur SASL de référence installable dans ce sandbox** (même limite que MSLogonII ci-dessus) — vérifié par un round-trip auto-cohérent fabriqué à la main uniquement (7 tests unitaires ajoutés, `SaslNegotiateTests`, couvrant le choix de mécanisme, le format des deux messages, et les trois cas de rejet) — ne prouve pas l'interopérabilité avec un vrai serveur SASL, seulement la cohérence interne de l'implémentation avec sa propre lecture de la spec |
| RSA-AES (RA2, RA2_256) | ✅ **2026-09-15** — découverts le 2026-09-14 en inspectant `Xtigervnc -help` (à l'occasion du travail sur VeNCrypt Plain), implémentés le lendemain. Contrairement à VeNCrypt, ce n'est pas une extension de l'infrastructure TLS déjà en place : échange de clés RSA (le client génère sa propre paire, de même taille que celle du serveur, `CSecurityRSAAES.cxx` de TigerVNC à l'appui) puis chiffrement **AES-EAX construit dans ce fichier** (`_eax_seal`/`_eax_open`/`_omac`, `cryptography` n'ayant pas de classe EAX native, contrairement à AESGCM/AESCCM/AESSIV/AESOCB3/ChaCha20Poly1305 — vérifié le 2026-09-15) qui enveloppe ensuite **toute la connexion**, SecurityResult inclus, via `_EAXReader`/`_EAXWriter` (même principe que `_WebSocketWriter` déjà existant). Format croisé entre `rfbproto.rst` et le code source TigerVNC (`CSecurityRSAAES.cxx/.h` + `common/rdr/AESInStream/AESOutStream.cxx`) — plusieurs détails ne sont pas fixés sans ambiguïté par la seule prose de la spec (taille réelle de la clé de session, ordre exact des préimages des deux hachages, cadrage EAX) et viennent de cette seconde source. **Un vrai bug trouvé et corrigé par l'exécution réelle** : la clé de session était tronquée à 16 octets sans condition, alors que la variante 256 bits doit utiliser les 32 octets complets du SHA-256 (RA2/AES-128 fonctionnait dès le premier essai, RA2_256 échouait immédiatement avec un jeton EAX invalide — signal net et sans ambiguïté). **Testé pour de vrai contre TigerVNC/Xvnc 1.13.1** pour les deux variantes, avec un vrai utilisateur Linux + PAM (`-RequireUsername=1`, sans quoi ce serveur bascule sur une vérification façon VNC Auth nécessitant `-Password`/`-PasswordFile`, un piège distinct trouvé en cours de route) et une clé RSA serveur générée pour l'occasion (`-RSAKey`) : poignée de main complète, **lecture réelle du framebuffer au travers du chiffrement**, écriture clavier chiffrée, rejet correct (mauvais mot de passe, utilisateur inexistant, identifiants manquants). Empreinte de la clé serveur façon RealVNC exposée (`Client.rsa_aes_server_key_fingerprint`) pour un épinglage éventuel côté application appelante — cette bibliothèque n'en stocke ni n'en compare aucune elle-même (voir `docs/reference/downstream-consumer.md`). 6 tests unitaires ajoutés pour les primitives EAX elles-mêmes (fonctions pures, testables sans serveur — contrairement à la poignée de main complète, volontairement non testée unitairement, même choix que pour le reste de VeNCrypt). **Non implémenté, délibérément** : RA2ne/RA2ne_256 (ne chiffrent que la poignée de main, pas la session — annule justement l'intérêt de RA2) et RA2r/RA2r_256 (une seconde ronde de dérivation de clé, propriété marginale pour ce fork) — voir `docs/sessions/session-17-2026-09-15.md` pour le détail complet |

## Robustesse / anti-DoS

| Fonctionnalité | Statut |
|---|---|
| Plafonds anti-DoS (Tight ×2, ZlibHex ×2, curseurs ×3) | ✅ **2026-09-01** — `_check_alloc_size()` testé, tous les appelants vérifiés un par un |

## Client requests

| Fonctionnalité | Statut |
|---|---|
| `shared` flag (ClientInit) | ✅ **2026-09-01** — signature vérifiée (`inspect.signature()` sur `connect()`/`Client.create()`/`Video.create()`) |
| `send_set_desktop_size()` (RFC officielle) | ✅ **2026-09-01** — format binaire vérifié octet par octet (1 écran implicite : 24 octets ; 2 écrans explicites : 40 octets). **2026-09-06** : journalisation d'audit ajoutée (`logger.info()`, width/height/nombre d'écrans) — voir « Journalisation d'audit » ci-dessous |
| `send_qemu_extended_key_event()` (extension QEMU) | ✅ **2026-09-02** — format vérifié contre le code source QEMU officiel (`github.com/qemu/qemu`, `ui/vnc.c`, commit `a925240509d1b4b656cc480f1cc79ba4d7c8bc08`) : message-type 255, submessage-type 0, down-flag U16, keysym U32, keycode U32, 12 octets au total, network byte order — implémentation déjà conforme, aucune correction nécessaire ; vérifié octet par octet dans ce sandbox contre 3 messages reconstruits à la main d'après cette lecture de source. **2026-09-06** : journalisation d'audit ajoutée (`logger.info()`, down/keysym/keycode) — voir « Journalisation d'audit » ci-dessous. **2026-09-09 : premier test réel contre un vrai QEMU 8.2.2** (`qemu-system-x86_64`, aucun Proxmox disponible dans ce sandbox, mais même code serveur `ui/vnc.c`) — preuve visuelle via un secteur de boot BIOS écrit pour l'occasion (attend une touche, l'affiche telle quelle), capturé avant/après avec `screenshot()` de ce même fichier : keysym/keycode cohérents (chiffres, lettres) → caractère exact reçu à chaque fois, chaîne complète confirmée de bout en bout. Trois constats supplémentaires, voir la docstring de la fonction et `CLAUDE.md` pour le détail complet : `keycode=0` est silencieusement ignoré (pas de repli sur le keysym seul, reconfirmé 2 fois) ; **si le serveur cible a un layout clavier explicite (`-k <layout>`), `keycode` est intégralement ignoré** (confirmé à la fois en lisant `ext_key_event()` dans `ui/vnc.c` et en relançant le test avec `-k en-us`) — perte silencieuse de l'intérêt principal de l'extension dans ce cas, sans moyen pour le client de le détecter ; un keysym/keycode délibérément incohérents (touche lettre) donne un résultat qui n'est ni l'un ni l'autre pris isolément (hypothèse la plus probable, non confirmée à 100% : synthèse d'un Shift côté serveur quand le keysym est une majuscule ASCII A-Z) — toujours garder les deux mutuellement cohérents en usage réel |
| xvp (`send_xvp_shutdown()` / `_reboot()` / `_reset()`, `Enc.XVP`) | ✅ format (format vérifié contre la spec RFB officielle, `rfbproto.rst`, sections « xvp Client/Server Message », message type 250 bidirectionnel, pseudo-encoding -309 ; décodage `XVP_INIT`/`XVP_FAIL` testé contre un flux serveur fabriqué à la main, encodage des 3 requêtes vérifié octet par octet) — 🔲 extension non trouvée supportée par un vrai serveur à ce jour. **2026-09-06** : `send_xvp()` journalise désormais chaque envoi en `logger.warning()` (code numérique + nom lisible XVP_SHUTDOWN/_REBOOT/_RESET) — voir « Journalisation d'audit » ci-dessous. **2026-09-06 (2)** : nouveau paramètre `confirm: bool = False` sur `send_xvp()`/`send_xvp_shutdown()`/`_reboot()`/`_reset()` — `PermissionError` levée avant tout envoi si `confirm=True` n'est pas passé explicitement — voir « Confirmation avant commande xvp destructive » ci-dessous. **2026-09-09 : premier test réel contre un vrai serveur (`Xtigervnc`/`Xvnc` 1.13.1, installé via `apt` dans ce sandbox)** — corrige une hypothèse non vérifiée de ce fichier (« TigerVNC la supporte côté serveur ») : **TigerVNC ne supporte PAS xvp** (jamais de `XVP_INIT` reçu, y compris après plusieurs `FramebufferUpdate`) ; xvp est en réalité une extension du logiciel tiers `xvp` (« Xen VNC Proxy », un proxy distinct de tout serveur VNC/Xvnc classique), pas une fonctionnalité native de Xvnc. Constat plus important pour tout appelant : **envoyer un message xvp (type 250) à ce serveur ferme la connexion RFB entière** (`Xvnc` journalise `unknown message type 250` et `closing ... : unknown message type`), contrairement à ce qu'affirmait la docstring précédente de `send_xvp()` (« ignorera simplement le message ») — comportement générique de ce serveur face à un message-type inconnu (non spécifique à xvp), reproduit à l'identique sur 2 instances `Xvnc` distinctes. Docstrings de `send_xvp()`/`process_xvp()` corrigées en conséquence (la prudence recommandée — attendre `xvp_supported == True` avant d'envoyer — est reformulée en précaution nécessaire, pas simplement souhaitable). Aucun changement de format binaire (les 4 octets envoyés restent conformes à la spec, vérifiés depuis le 2026-09-01) ; non-régression vérifiée (import, signatures, `dir()` à 66 symboles, `ruff check` à 60 signalements préexistants, 13 tests toujours au vert). Détail complet : `docs/sessions/session-10-2026-09-09.md` |

## Journalisation d'audit des commandes poussées au serveur distant

| Fonctionnalité | Statut |
|---|---|
| `logger` (loguru) sur `send_xvp()` / `send_qemu_extended_key_event()` / `send_set_desktop_size()` | ✅ **2026-09-06** — comblait un écart identifié lors de l'audit `PATTERNS.md` du 2026-09-06 (`switch-capture::log_outbound_command`) : `asyncvnc2.py` n'importait `logging` nulle part, donc un envoi contesté ou raté ne laissait aucune trace locale. `send_xvp()` journalise en `logger.warning()` (commande potentiellement destructive : code numérique + nom lisible XVP_SHUTDOWN/XVP_REBOOT/XVP_RESET), les deux autres en `logger.info()` (paramètres complets : width/height/nombre d'écrans pour `send_set_desktop_size()`, down/keysym/keycode pour `send_qemu_extended_key_event()`). Aucun format binaire modifié — vérifié par exécution réelle dans ce sandbox : un faux `writer` capture les octets envoyés (comparés octet par octet aux valeurs attendues, inchangées) pendant qu'un sink `loguru` capture les messages émis, pour les trois fonctions ; cas d'erreur `send_xvp(code invalide)` vérifié pour confirmer qu'il lève toujours `ValueError` **avant** tout log ou écriture (pas de trace trompeuse pour une commande jamais réellement envoyée). Pas de nouvelle dépendance : `loguru` est déjà utilisé ailleurs dans l'écosystème du projet (voir `CLAUDE.md` du dépôt `switch-capture`) mais c'est la première fois qu'il est importé dans `asyncvnc2.py` — aucune configuration de sink ajoutée ici (fichier bibliothèque, pas point d'entrée applicatif), donc `pluginvnc2` ou tout autre appelant doit configurer `loguru` lui-même pour voir ces logs sortir quelque part (voir « Dépendant en aval ») |

## Confirmation avant commande xvp destructive

| Fonctionnalité | Statut |
|---|---|
| `confirm: bool = False` sur `send_xvp()` / `send_xvp_shutdown()` / `_reboot()` / `_reset()` | ✅ **2026-09-06** — comblait le premier écart « 🟠 Moyenne » identifié lors de l'audit `PATTERNS.md` du même jour : aucun garde-fou n'existait avant l'envoi d'une commande xvp destructive. Choix retenu parmi les deux options envisagées dans `features.md` (documenter que la responsabilité revient à l'appelant final vs. exposer un paramètre optionnel de confirmation) : **la seconde**, matérialisée par un unique point de contrôle dans `send_xvp()` (les trois wrappers `send_xvp_shutdown()`/`_reboot()`/`_reset()` le relaient simplement) — sans `confirm=True` explicite, une `PermissionError` est levée **avant** tout appel à `.write()` et avant le `logger.warning()` d'audit normal (un refus génère son propre `logger.warning()` distinct, mentionnant `REFUSÉ`, pour qu'un envoi bloqué laisse quand même une trace). Volontairement pas de confirmation interactive : cette bibliothèque bas niveau n'a aucune notion d'UI, donc `confirm=True` reste la responsabilité de l'appelant final (`pluginvnc2` ou autre) une fois sa propre confirmation utilisateur obtenue — voir « Dépendant en aval ». **Vérifié par exécution réelle** dans ce sandbox : appel sans `confirm` → `PermissionError` + aucune écriture socket + log `REFUSÉ` ; appel avec `confirm=True` → écriture socket inchangée (mêmes 4 octets qu'avant ce patch) + log d'audit normal ; code xvp invalide → `ValueError` toujours prioritaire sur la vérification de `confirm` (aucun changement de comportement pour ce cas déjà couvert) ; non-régression des trois wrappers vérifiée un par un |

## Transport / autres extensions

| Fonctionnalité | Statut |
|---|---|
| Reconnexion inversée (`listen()`, port 5500 par défaut) | ✅ **2026-09-01** — testé par exécution réelle dans ce sandbox : vrai socket TCP loopback, un script jouant le rôle du serveur VNC distant (ProtocolVersion/Security-None/SecurityResult/ServerInit fabriqués à la main) se connecte au listener, le `Client` obtenu est vérifié utilisable (dimensions + nom de bureau lus correctement) ; le protocole RFB lui-même après connexion est identique au mode normal (déjà couvert par les autres vérifications de ce fichier), donc pas de nouveau format de message à risque ici — seule l'orchestration TCP (accept, puis fermeture du listener) était nouvelle et a nécessité une correction en cours de route (voir `CLAUDE.md`) |
| Repli de version de protocole (3.3/3.7/3.8, `Client.protocol_version`) | ✅ **2026-09-01** — format vérifié contre la spec RFB officielle (RFC 6143 §7.1.1/§7.1.2/§7.1.3 + Appendix A, différences 3.3/3.7 documentées) ; **7 scénarios testés de bout en bout sur de vrais sockets TCP loopback** avec un serveur fabriqué à la main pour chacun : 3.8+None et 3.8+VNC Auth (régression, inchangés), 3.7+None (SecurityResult correctement sauté), 3.3+None et 3.3+VNC Auth (négociation U32 unilatérale du serveur, sans octet de sélection client), un minor 3.x inconnu (replié sur 3.3 comme l'exige la RFC), et un major > 3 façon RealVNC Enterprise ("RFB 004.001") traité comme 3.8 plutôt que 3.3 — ce dernier point confirmé par un rapport de bug tiers réel (SikuliX) qui avait dû corriger exactement ce cas |
| WebSockets | ✅ **2026-09-03/04, topologie reverse complète confirmée le 2026-09-10** — format vérifié contre RFC 6455 (poignée de main HTTP d'upgrade §4.1/§4.2, format de trame §5.2, masquage §5.3, ping/pong §5.5.2). Côté `connect()` (rôle client) : d'abord testé sur un faux serveur fabriqué à la main, **puis contre un vrai processus `websockify`** (le proxy de référence utilisé par noVNC), en `ws://` clair et en `wss://` (TLS) — un bug de fermeture propre à WebSocket+TLS a été trouvé et corrigé au passage (voir `CLAUDE.md`). Côté `listen(websocket=True)` (rôle serveur, ajouté le **2026-09-04**) : **testé contre un vrai client WebSocket tiers** (bibliothèque Python `websockets`, indépendante de ce fork), qui joue le rôle d'un serveur VNC distant initiant une reconnexion inversée à travers un proxy WebSocket ; **2026-09-10** : la topologie "reverse" complète (un vrai proxy relayant une connexion TCP entrante vers une connexion WS sortante) restait non couverte — testée avec succès contre un vrai `websocat`, après avoir confirmé par exécution réelle que `websockify` ne peut structurellement pas jouer ce rôle précis (voir la ligne dédiée dans « Prochaines étapes suggérées » et `docs/sessions/session-12-2026-09-10.md`). Non-régression vérifiée dans les trois cas (`connect()`/`listen()` sans `websocket=True` inchangés, et `listen(websocket=True)` contre la bibliothèque `websockets` reconfirmé) |
| Extended Clipboard | ✅ **2026-09-13** — format vérifié contre `rfbproto.rst` (« Extended Clipboard Pseudo-Encoding », pseudo-encodage `0xC0A1E5CE`) **et** contre deux implémentations de référence indépendantes : le code source de QEMU (`github.com/qemu/qemu`, `ui/vnc.h`+`ui/vnc-clipboard.c`+`ui/vnc.c`) et le binaire `Xtigervnc` 1.13.1 lui-même (extension originaire de TigerVNC) — identiques, aucun écart trouvé. `Enc.EXTENDED_CLIPBOARD` ajouté (inclus dans `Enc.default()`, comme `Enc.XVP`) ; réception (`process_extended_clipboard()` — Caps/Notify/Peek/Request/Provide, seul le format *text* décodé en UTF-8, rtf/html/dib/files correctement sautés sans désynchroniser le flux) et émission (`send_clipboard_caps/notify/request/provide()`) implémentées, gardées par `clipboard_ext_supported` (`PermissionError` sinon — contrairement à `xvp_supported`/`send_xvp()`, ce garde-fou est ici appliqué, pas seulement documenté : la lecture du code source QEMU a montré que la connexion est tuée si on l'ignore). **Testé pour de vrai contre un vrai TigerVNC/Xvnc 1.13.1 et un vrai QEMU 8.2.2** le même jour — voir `docs/sessions/session-14-2026-09-13.md` pour le détail complet (méthode, traces serveur). Constat principal : **un `Provide` non précédé d'un `Notify` du même émetteur est silencieusement ignoré par les deux serveurs**, chacun pour une raison mécanique différente (TigerVNC : sa propre Caps déclare une taille max de 0 octet pour du texte non sollicité ; QEMU : sa structure interne n'associe les données à l'émetteur qu'après un `Notify` de ce même émetteur) — `send_clipboard_update()` ajouté en conséquence (Notify puis Provide enchaînés), recommandé sur `send_clipboard_provide()` seul (réservé à la réponse à un `Request` déjà reçu). Round-trip confirmé de bout en bout : côté TigerVNC, avec un vrai `xclip` comme consommateur/producteur du presse-papiers X réel (texte accentué + CJK relu identique dans les deux sens) ; côté QEMU, en relais entre deux connexions simultanées (A fournit, B reçoit, texte identique). 21 tests committés (voir « Suite de tests committée » ci-dessous). **2026-09-13 (2) : `send_clipboard_caps()` revérifiée contre un vrai TigerVNC/Xvnc 1.13.1** — `handleClipboardCaps()` (`common/rfb/SConnection.cxx`) confirme que ce serveur tient réellement compte des tailles que nous déclarons (`vlog.debug` distingue explicitement "(only notify)" si la taille déclarée pour un format est 0, contre "(automatically send up to X)" sinon) : par défaut (sans jamais envoyer notre propre Caps), TigerVNC assume l'hypothèse générale de la spec (20 Mio pour le texte) et **fournit directement** (`Provide`) un nouveau contenu de presse-papiers X sans jamais nous demander — reconfirmé identique à la ligne ci-dessus. En envoyant nous-mêmes `send_clipboard_caps(max_text_size=0)`, le même changement de presse-papiers X déclenche cette fois un `Notify` (aucune donnée), et le texte n'arrive qu'après un `send_clipboard_request()` explicite de notre part — comportement différent, mesuré sur le même serveur, seule variable changée étant notre propre Caps. Effet secondaire non expliqué mais sans conséquence, noté pour mémoire : dans ce mode, TigerVNC envoie deux `Notify` de suite pour un même changement (le premier annonçant `formats=0x0000`, vide, le second `formats=0x0001`, avec le bit texte) — `process_extended_clipboard()` gère les deux sans erreur ni effet de bord (un `Notify` sans aucun format posé ne modifie aucun état). Non implémenté : formats rtf/html/dib/files (correctement ignorés, jamais décodés) |
| Ultra (LZO) | ✅ **2026-10-10 (issue #24)** — décodeur LZO1X pur Python (`_lzo1x_decompress()`, automate de `lzo1x_decompress_safe`), aucune dépendance ajoutée : `python-lzo` exige liblzo2 au build. Vérifié contre la vraie liblzo2 (vecteurs `python-lzo`, niveaux 1 et 9, 612 entrées aléatoires) puis **contre un vrai x11vnc 0.9.17** (libvncserver, `ultra.c`) : image identique au Raw. Opt-in (`Enc.ULTRA`, hors `Enc.default()`) : UltraVNC lui-même (Windows) non testé → [issue #24](https://github.com/MathildeDec/AsyncVnc4/issues/24) |

## Audit 2026-09-06 : conformité au catalogue PATTERNS.md (motifs non métier)

Comparaison section par section contre `PATTERNS.md` (catalogue de motifs
d'architecture/tests/sécurité extrait d'un projet GTK4/CLI totalement
différent, `switch-capture`/`project-skeleton`) — détail complet et
justification de chaque section applicable/non applicable dans
`CLAUDE.md`, § « Audit de conformité au catalogue PATTERNS.md ». Résumé :
la quasi-totalité du catalogue ne s'applique pas (architecture CLI/GTK4
vs bibliothèque protocolaire asyncio à fichier unique), un motif est déjà
respecté de fait (fermeture unique de `_WebSocketWriter`/`listen()`), et
trois écarts avaient été documentés ci-dessous en « Prochaines étapes
suggérées » — deux comblés le jour même (journalisation d'audit, puis
confirmation avant commande xvp destructive), voir « Journalisation
d'audit » et « Confirmation avant commande xvp destructive » ci-dessus.

## Prochaines étapes suggérées (par urgence)

**🟠 Moyenne**
- ~~VeNCrypt (TLSNone/TLSVnc, et depuis le **2026-09-05**
  X509None/X509Vnc) : test réel contre un serveur qui l'exige
  effectivement~~ ✅ **2026-09-08** — testé contre un vrai TigerVNC
  (`Xvnc` 1.13.1, installé via `apt` dans ce sandbox). X509Vnc/X509None
  ont fonctionné sans aucune modification de code. TLSNone/TLSVnc ont
  en revanche révélé un vrai bug (suites cryptographiques anonymes
  absentes du contexte SSL par défaut), corrigé et revérifié — voir la
  ligne VeNCrypt du tableau ci-dessus et `CLAUDE.md` pour le détail
  complet du diagnostic (bissection, effet de bord d'un mécanisme anti
  brute-force de TigerVNC qui a d'abord faussé les mesures). RealVNC
  Enterprise, mentionné comme second candidat possible, reste non
  essayé faute de disponibilité dans ce sandbox — non bloquant, l'
  objectif (une implémentation VeNCrypt tierce réelle et indépendante
  de ce fork) est atteint avec TigerVNC seul.
- ~~ZYWRLE : test réel contre TigerVNC en qualité ZYWRLE pour confirmer
  qu'aucun changement client n'est nécessaire (hypothèse actuelle, pas
  vérifiée)~~ ⚠️ **2026-09-09** — testé, mais contre un vrai QEMU 8.2.2
  plutôt que TigerVNC : **TigerVNC/Xvnc 1.13.1 n'implémente pas du tout
  ZYWRLE** (absence totale de la chaîne « ywrle » dans son binaire,
  confirmé par `strings`), donc aucun test possible contre ce serveur
  précis comme envisagé initialement. Contre QEMU (qui l'implémente
  réellement), **l'hypothèse « aucun changement client nécessaire » est
  infirmée** : `Enc.ZYWRLE` ajouté et partage le décodage de `Enc.ZRLE`
  pour les tuiles au format standard, mais une fois le vrai chemin lossy
  de QEMU engagé, le serveur envoie des octets de subencoding dans la
  plage 17-126 réservée par la RFC, qu'aucun décodeur conforme ne peut
  décoder sans deviner un format non documenté — voir la ligne dédiée
  ci-dessus et `docs/sessions/session-11-2026-09-09.md`. Objectif
  partiellement atteint : un vrai gap a été trouvé et documenté (pas
  silencieusement laissé en hypothèse non vérifiée), mais pas corrigé —
  `Enc.ZYWRLE` reste opt-in uniquement, exclu de `Enc.default()`.
  ✅ **2026-10-24 (issue #22)** : corrigé — tuile imbriquée, voir la
  ligne ZYWRLE ci-dessus et `docs/sessions/session-25-2026-10-24.md`.
- xvp : ~~test réel contre un serveur qui supporte l'extension (TigerVNC
  la supporte côté serveur)~~ ✅ **2026-09-09** — testé contre un vrai
  `Xtigervnc`/`Xvnc` 1.13.1 (installé via `apt`). Résultat inattendu :
  **TigerVNC ne supporte pas xvp** (hypothèse précédente de ce fichier
  corrigée) et **ferme la connexion** en réponse à un message xvp non
  reconnu — voir la ligne dédiée ci-dessus et
  `docs/sessions/session-10-2026-09-09.md` pour le détail complet.
  L'objectif initial (« confirmer que le format fonctionne contre un
  vrai serveur ») n'est donc que partiellement atteint : le format reste
  conforme à la spec, mais aucun vrai serveur supportant réellement xvp
  n'a pu être trouvé pour confirmer le scénario nominal (`XVP_INIT` reçu,
  commande honorée) — seul le logiciel tiers `xvp` (Xen VNC Proxy) est
  connu pour implémenter cette extension, non installé ici (valeur
  ajoutée incertaine, à confirmer avant d'y investir du temps).
- ~~`send_qemu_extended_key_event()` : test réel contre un vrai
  Proxmox/QEMU~~ ✅ **2026-09-09** — testé contre un vrai QEMU 8.2.2
  (`qemu-system-x86_64`, installé via `apt` dans ce sandbox ; aucun
  Proxmox disponible ici, mais même code serveur `ui/vnc.c`). Cas
  nominal (keysym/keycode cohérents) confirmé de bout en bout par
  preuve visuelle. Trois comportements réels supplémentaires découverts
  et documentés (voir ligne dédiée ci-dessus, docstring de la fonction
  et `CLAUDE.md`) : `keycode=0` silencieusement ignoré, `-k <layout>`
  côté serveur fait perdre tout l'intérêt de l'extension, keysym/keycode
  incohérents à éviter. Proxmox lui-même (au-delà du QEMU nu testé ici)
  reste non essayé faute de disponibilité dans ce sandbox — non
  bloquant, Proxmox utilise le même `ui/vnc.c` pour sa console VNC.

**🟢 Faible**
- ~~Suite de tests committée~~ ✅ **2026-09-07** — `test_asyncvnc2.py`
  ajouté (`unittest`/`IsolatedAsyncioTestCase`, aucune nouvelle
  dépendance), 13 tests rejouant mécaniquement les scénarios déjà
  vérifiés à la main pour RRE, CoRRE (dont le garde-fou 255×255 et sa
  frontière légale à 255×255 pile), `send_set_desktop_size()` (écran
  implicite 24 octets / explicite 40 octets), `send_qemu_extended_key_event()`
  (12 octets, bornes hautes U32) et `send_xvp()` (4 octets avec
  `confirm=True`, `PermissionError` sans confirm et aucune écriture
  socket dans ce cas, priorité de `ValueError` sur un code invalide même
  sans confirm, relais correct par les 3 wrappers `_shutdown`/`_reboot`/
  `_reset`). Lancer avec `python3 -m unittest test_asyncvnc2 -v` (needs
  `numpy`, `loguru`, `cryptography`, `keysymdef` installés — mêmes
  dépendances que `asyncvnc2.py` lui-même). Voir « Journalisation
  d'audit » et « Confirmation avant commande xvp destructive »
  ci-dessus pour le contexte des scénarios `send_xvp`/`send_set_desktop_size`/
  QEMU couverts. Volontairement pas de test pour Tight/ZRLE/Hextile/
  VeNCrypt/WebSockets etc. (non demandé, périmètre plus large que ce
  qui était identifié dans l'audit `PATTERNS.md` du 2026-09-06) — voir
  `CLAUDE.md` pour le détail de la session. **2026-09-09 : 3 tests
  ajoutés pour `Enc.ZYWRLE`** (dispatch identique à `Enc.ZRLE` pour une
  tuile standard, `ValueError` sur la plage de subencoding 17-126,
  absence de `Enc.ZYWRLE` dans `Enc.default()`) — 16 tests au total,
  toujours sans serveur réel ni nouvelle dépendance ; voir la ligne
  ZYWRLE ci-dessus et `docs/sessions/session-11-2026-09-09.md`.
  **2026-09-13 : 21 tests ajoutés pour Extended Clipboard** (Caps/Notify/
  Peek/Request/Provide, `PermissionError` des 4 `send_clipboard_*()`
  sans `clipboard_ext_supported`, formats sur le fil, messages tronqués/
  corrompus → `ValueError`, dépassement du plafond anti zip-bomb,
  non-régression du chemin Latin-1 d'origine, absence de désynchronisation)
  — 37 tests au total, toujours sans serveur réel ni nouvelle dépendance ;
  voir la ligne Extended Clipboard ci-dessus et
  `docs/sessions/session-14-2026-09-13.md`. **2026-09-15 : 6 tests
  ajoutés pour les primitives AES-EAX** (`_eax_seal`/`_eax_open`/
  `_eax_increment_counter`, cf. RSA-AES ci-dessus) : aller-retour
  chiffrement/déchiffrement pour les deux tailles de clé, détection
  d'une falsification du chiffré/du tag/de l'en-tête, incrément du
  compteur avec retenue — fonctions pures, testables sans serveur,
  contrairement à la poignée de main RSA-AES complète (volontairement
  non testée unitairement, même choix que pour le reste de VeNCrypt) —
  43 tests au total ; voir la ligne RSA-AES ci-dessus et
  `docs/sessions/session-17-2026-09-15.md`. **2026-09-16 (suite) : 7
  tests ajoutés pour SASL** (`SaslNegotiateTests` : choix de mécanisme
  PLAIN/ANONYMOUS, format des deux messages octet par octet, rejet
  explicite d'un mécanisme non pris en charge, d'une mechlist vide et
  d'un échange multi-étapes) — **50 tests au total**, toujours sans
  serveur réel ni nouvelle dépendance ; voir la ligne SASL ci-dessus et
  `docs/sessions/session-21-2026-09-16c.md`.
- ~~WebSockets côté `listen()` : testé contre un vrai client WebSocket
  tiers (bibliothèque `websockets`), mais pas encore contre un vrai
  `websockify` en topologie "reverse" complète (proxy relayant une
  connexion WS entrante vers notre port d'écoute)~~ ✅ **2026-09-10** —
  testé contre un vrai `websocat` (`tcp-listen:` → `ws://`, binaire
  officiel précompilé, outil indépendant de ce fork) : faux « serveur
  VNC distant » fabriqué à la main → TCP brut → `websocat` → WebSocket
  réelle → `listen(websocket=True)`, `Client` obtenu utilisable de bout
  en bout (dimensions/nom/version de protocole corrects). **`websockify`
  s'est en réalité révélé structurellement incapable de ce rôle** : son
  propre `--help` ne propose que des adresses d'écoute WS/HTTP et des
  cibles TCP/Unix/sous-processus, jamais l'inverse — confirmé aussi par
  exécution réelle de l'invocation qui figurait jusque-là en commentaire
  dans le code (`--wait` n'est pas une option reconnue, et sans elle une
  adresse seule échoue avec "Too few arguments"). Docstrings/commentaires
  du code corrigés en conséquence — **zéro ligne de code exécutable
  modifiée** (diff complet vérifié) ; non-régression confirmée (`listen()`
  TCP brut, `listen(websocket=True)` contre `websockets`, 16 tests,
  `dir()` à 66 symboles, `ruff check` à 60 signalements préexistants).
  Voir `docs/sessions/session-12-2026-09-10.md` pour le détail complet.
- ~~SASL, MSLogon, UltraVNC MSLogonII, Ultra (LZO) — valeur réelle
  incertaine, à confirmer avant d'y investir du temps~~ **2026-09-16 :
  investissement confirmé par l'utilisateur, avancé partiellement.**
  **MSLogonII (113) implémenté** — voir la ligne dédiée dans
  « Authentification » ci-dessus pour le détail complet (format,
  ambiguïtés de spec tranchées et documentées, vérification par
  round-trip auto-cohérent fabriqué à la main). **SASL (20) délibérément
  pas commencé cette session** : contrairement à MSLogonII, `rfbproto.rst`
  décrit SASL comme un protocole multi-étapes générique dont le nombre
  d'échanges dépend du mécanisme choisi par le serveur (`DIGEST-MD5`,
  `GSSAPI`, `ANONYMOUS`, etc.) — implémenter ne serait-ce qu'un seul
  mécanisme demanderait une bibliothèque SASL tierce (`cyrus-sasl` et
  souvent une infrastructure Kerberos pour `GSSAPI`), périmètre bien
  au-delà d'une seule tâche et non tranché par la confirmation obtenue
  cette session (qui portait sur l'idée générale « backlog valeur
  incertaine », pas sur SASL spécifiquement). **Réexaminé le 2026-09-16
  (suite)** : SASL (20) **implémenté pour les mécanismes `PLAIN`/
  `ANONYMOUS` seulement**, chacun défini par sa propre RFC autonome
  sans échange défi-réponse ni bibliothèque tierce requise — le tramage
  RFB générique lui-même n'a jamais nécessité `cyrus-sasl`, seule la
  production du contenu de mécanismes plus complexes (`DIGEST-MD5`/
  `GSSAPI`) en a besoin ; ceux-ci restent refusés explicitement. Voir la
  ligne dédiée dans « Authentification » ci-dessus et
  `docs/sessions/session-21-2026-09-16c.md`. **MSLogon (l'original,
  distinct de MSLogonII) reste également non commencé** : contrairement
  à MSLogonII, il n'a pas de section dédiée dans `rfbproto.rst`
  (extension UltraVNC plus ancienne, jamais formellement documentée
  dans la spec communautaire) — même blocage que le type de sécurité
  « TLS » (18) ci-dessous. **Ultra (LZO)** (encodage d'image, pas type
  de sécurité — voir « Transport / autres extensions » ci-dessus) non
  plus commencé : nécessiterait une dépendance de décompression LZO,
  absente de la bibliothèque standard Python, pour un encodage
  spécifique à UltraVNC sans serveur de référence dans ce sandbox.
  MSLogon/MSLogonII et Ultra (LZO) restent des extensions spécifiques à
  UltraVNC (Windows), sans serveur de référence installable dans ce
  sandbox Linux. SASL et MSLogonII sont en outre confirmés absents des
  types de sécurité qu'offre réellement `Xtigervnc` 1.13.1 (`-help` ne
  les liste pas, contrairement à `Plain`/`TLSPlain`/`X509Plain` — voir
  la ligne VeNCrypt du 2026-09-14 ci-dessus) — donc pas testables contre
  ce serveur non plus, MSLogonII y compris malgré son implémentation.
  Voir `docs/sessions/session-20-2026-09-16.md` pour le détail complet.
- Ancien type de sécurité « TLS » isolé (18) — **2026-09-16 : confirmé
  infaisable proprement, pas seulement « valeur incertaine ».**
  `rfbproto.rst` le liste uniquement dans le tableau « Other registered
  security types » (numéro + nom), sans aucune section dédiée décrivant
  un format sur le fil — contrairement à VeNCrypt (19), SASL (20) ou
  MSLogonII (113, implémenté cette session) qui en ont chacun une.
  Implémenter ce type sans aucune source de format reviendrait à
  deviner un protocole entier, pas seulement un détail non documenté
  (contrairement à ZYWRLE, où seul le format d'une tuile dans un
  encodage par ailleurs bien spécifié restait flou) — contraire au
  principe déjà établi dans ce fichier de ne jamais deviner un format
  non documenté. Reste non implémenté, cette fois pour une raison plus
  forte que la seule « valeur ajoutée incertaine » d'origine — voir
  `docs/sessions/session-20-2026-09-16.md`.
- ~~RSA-AES (RA2, RA2ne, RA2_256, RA2ne_256) : découvert le 2026-09-14,
  implémentation hors périmètre d'une seule tâche~~ ✅ **2026-09-15** —
  RA2/RA2_256 implémentés et testés contre un vrai TigerVNC/Xvnc 1.13.1
  (poignée de main RSA + chiffrement AES-EAX construit dans ce fichier,
  un vrai bug de taille de clé de session trouvé et corrigé en cours de
  route). RA2ne/RA2ne_256/RA2r/RA2r_256 restent non implémentés,
  délibérément (voir la ligne dédiée dans « Authentification »
  ci-dessus). Voir `docs/sessions/session-17-2026-09-15.md`.
- ~~Extended Clipboard : non commencé, valeur réelle incertaine~~ ✅
  **2026-09-13** — implémenté et testé contre deux serveurs réels
  indépendants (TigerVNC/Xvnc 1.13.1 et QEMU 8.2.2), qui exigent tous
  deux un `Notify` avant tout `Provide` pour l'accepter (raisons
  mécaniques différentes) — voir la ligne dédiée dans « Transport /
  autres extensions » ci-dessus et `docs/sessions/session-14-2026-09-13.md`
  pour le détail complet.
- Reconnexion inversée (`listen()`) : ✅ **2026-10-10 (issue #27)** —
  testée contre un vrai serveur qui initie la connexion, `x11vnc
  -connect_or_exit` (libvncserver) : RFB 3.8 et 3.3, sans mot de passe et
  avec VNC Authentication, mauvais mot de passe rejeté
  (`test_live_x11vnc.py`, job CI « Serveur réel »). Reste non vérifié : la
  traversée d'un vrai NAT/pare-feu, le sandbox et les runners ne testant
  qu'en loopback.
- ~~Repli de version de protocole : test réel contre un authentique
  serveur 3.3~~ ✅ **2026-10-10 (issue #28)** — x11vnc 0.9.17
  (libvncserver) avec `-rfbversion 3.3` / `3.7` envoie réellement
  `RFB 003.003` / `RFB 003.007` (vérifié sur le socket) et conduit la
  sécurité propre à chaque version. Repli 3.3 (type de sécurité imposé
  par le serveur) et 3.7 (sans SecurityResult après None) réussis, avec
  et sans VNC Authentication, mauvais mot de passe rejeté
  (`PermissionError`), capture d'écran lue dans chaque cas. Aucune
  modification de code nécessaire. Ce n'est pas un « très vieux » serveur
  natif 3.3 (iLO/iDRAC), mais une implémentation tierce indépendante du
  flux 3.3, ce qui manquait aux 7 scénarios fabriqués à la main.
- Nettoyage style (`ruff check`/`ruff format`) — **2026-09-02** : sous-ensemble
  sûr appliqué et vérifié (tri des imports, 3 corrections lint triviales,
  un `Optional` implicite rendu explicite ; zéro changement de
  comportement, revérifié par exécution réelle et comparaison de
  signatures avant/après). **2026-09-07** : même traitement étendu au code
  WebSockets ajouté depuis (sessions 2026-09-03/04), qui avait fait
  apparaître 4 nouveaux signalements `ruff check` absents lors du
  nettoyage précédent — voir « Nettoyage style — code WebSockets » ci-dessous
  pour le détail (2 corrigés, 2 délibérément non touchés). **2026-09-11** :
  la modernisation des annotations de type (`Dict`/`List`/`Set`/`Tuple` →
  minuscules, `Optional[X]` → `X | None`, 58 signalements) a été appliquée
  — mais **sur l'hypothèse non confirmée** d'une version Python minimale
  ≥ 3.10, en tension avec le principe posé le 2026-09-07 selon lequel
  cette décision revient à qui déploie ce fichier. Zéro changement de
  comportement (tests/signatures/`Enc.default()` identiques avant/après),
  patch réversible — voir `docs/sessions/session-13-2026-09-11.md`.
  **2026-09-16 : hypothèse confirmée** — `requires-python = ">=3.10"`
  désormais formellement acté dans `pyproject.toml` (nouveau,
  accompagne la migration vers `uv`), à la demande explicite de
  l'utilisateur ; ce n'est plus une hypothèse en tension mais une
  contrainte déclarée du projet. **2026-09-16 (2) : `ruff check`
  intégralement propre (0 signalement)** — les 2 derniers signalements
  préexistants (`S110`/`BLE001` sur `_WebSocketWriter.close()`, voir
  « Nettoyage style — code WebSockets » ci-dessous) corrigés. **2026-09-16
  (3) : `ruff format` complet appliqué** — sur choix explicite de
  l'utilisateur (options proposées, voir
  `docs/sessions/session-19-2026-09-16b.md`), après le premier essai du
  2026-09-11 (~1900 lignes de diff, jugé trop large pour un lot
  silencieux à l'époque). `quote-style = "single"` configuré dans
  `pyproject.toml` pour préserver la convention de guillemets simples du
  projet (le défaut de `ruff format` bascule en guillemets doubles) —
  diff final ramené à 1143+107 lignes, relu en entier, purement
  formel. 43 tests toujours au vert, `ruff check` toujours à 0
  signalement, `ruff format --check` désormais idempotent.

## Nettoyage style — code WebSockets (2026-09-07)

| Fonctionnalité | Statut |
|---|---|
| `ruff check` (règles par défaut) sur `_WebSocketWriter.close()`/`wait_closed()` et `_ws_pump()` | ✅ **2026-09-07** — 2 des 4 nouveaux signalements apparus depuis l'ajout des WebSockets (2026-09-03/04) corrigés : `PIE790` (`pass` redondant dans `_WebSocketWriter.wait_closed()`, déjà précédé d'un `if ... raise` dans le même bloc `except`) et `F841` (variable `exc` capturée puis jamais utilisée dans `except (IncompleteReadError, ConnectionError, OSError)` de `_ws_pump()`). Zéro changement de comportement : **vérifié par exécution réelle** dans ce sandbox avec de faux lecteurs/écrivains fabriqués à la main reproduisant les 4 scénarios concernés (fermeture WS normale, fermeture WS où l'envoi de la trame de clôture échoue, coupure réseau pendant `_ws_pump()`, annulation explicite de la tâche) — même script de vérification rejoué à l'identique contre la version d'avant patch, résultats strictement identiques ; `ruff check` repasse de 62 à 60 signalements ; 13 tests de `test_asyncvnc2.py` toujours au vert ; signatures publiques (`connect()`/`listen()`/`Client.create()`) et `dir(asyncvnc2)` inchangés. Les 2 signalements restants sur ce même code (`S110`/`BLE001`, sur le `except Exception: ...` de `_WebSocketWriter.close()`) sont **délibérément non touchés** — voir juste en dessous. |
| `S110`/`BLE001` sur `_WebSocketWriter.close()` (`except Exception:`) | ✅ **2026-09-16** — corrigé, sur demande explicite de la session (« correction de toutes les erreurs ruff »), après avoir été volontairement laissé de côté depuis le 2026-09-07 (raisonnement d'origine ci-dessous, conservé pour mémoire). `except Exception: pass` remplacé par `except (OSError, RuntimeError, ssl.SSLError) as exc:` + `logger.debug()` — exactement les deux options envisagées ci-dessous (restreindre le type capturé **et** journaliser), combinées. Comportement fonctionnel inchangé (aucune exception ne remonte plus qu'avant), mais **non revérifié contre un vrai transport cassé reproduisant les trois familles d'erreurs** — seule la non-régression des 43 tests existants a été confirmée, voir `docs/sessions/session-18-2026-09-16.md`. Raisonnement d'origine (2026-09-07, pour mémoire) : contrairement à `PIE790`/`F841` ci-dessus, corriger ces deux signalements change le comportement ou le design (ajouter un `logger.debug()` dans le chemin de fermeture, ou restreindre le type d'exception capturé), pas juste la forme. Le commentaire déjà présent dans le code documentait pourquoi une exception large était capturée puis ignorée ici (la connexion peut déjà être à moitié fermée, le close WebSocket n'est qu'une politesse protocolaire) — périmètre resté délibérément hors scope jusqu'à cette session, faute de demande explicite. |

## Dépendant en aval

Ce fork est consommé par le plugin GTK4 `pluginvnc2` (paquet séparé,
`pluginvnc2.zip`) — voir son `features.md`/`CLAUDE.md` pour ce qui est
réellement câblé côté GTK4 (aujourd'hui : rien des extensions ci-dessus
marquées 🔲, et pas non plus xvp, `listen()`, QEMU Extended Key Event,
VeNCrypt, WebSockets ou Extended Clipboard malgré leur statut ✅ ici —
ils viennent d'être ajoutés ou vérifiés dans ce paquet, `pluginvnc2` n'en
a pas encore connaissance. WebSockets, en particulier, demanderait une adaptation de
`vnc_tab.py` pour exposer un nouveau champ "utiliser WebSocket" (et
éventuellement un chemin d'URL) dans le formulaire de connexion, en
plus de faire passer `websocket=True` à `connect()` — mais aucune
adaptation du protocole RFB lui-même, entièrement transparent une fois
le tunnel établi. Le pendant `listen(websocket=True)` (rôle serveur,
pour la reconnexion inversée à travers un proxy WebSocket) demanderait
la même case à cocher, réutilisable dans le mode "écouter une connexion
entrante" déjà nécessaire pour `listen()` (voir plus bas) plutôt qu'un
écran séparé.
Extended Clipboard ne demande, côté appelant, aucun paramètre
supplémentaire pour la partie réception : `Enc.EXTENDED_CLIPBOARD` est
inclus dans `Enc.default()`, donc un `pluginvnc2` qui utilise déjà
`connect()`/`Enc.default()` tel quel bénéficierait transparemment du
texte étendu (UTF-8) dans `client.clipboard.text`, sans rien changer —
seule l'émission (`send_clipboard_update()`) demanderait un appel
explicite côté GTK4 (par ex. quand l'utilisateur colle du texte dans la
fenêtre distante), avec la même prudence Notify-avant-Provide que
documentée ci-dessus.
VeNCrypt en particulier (TLSNone/TLSVnc et, depuis le **2026-09-05**,
X509None/X509Vnc) ne demande, côté appelant, qu'un paramètre optionnel
de plus (`ssl_context`, à `None` par défaut) sur
`connect()`/`listen()`/`Client.create()` — aucune adaptation d'UI
nécessaire pour le cas nominal, X509None/X509Vnc y compris,
contrairement à `listen()`. `Client.create()` a par ailleurs gagné un
second paramètre optionnel, `server_hostname` (utile uniquement pour
X509None/X509Vnc, ignoré sinon) — mais `connect()`/`listen()` le
renseignent eux-mêmes (`host` pour `connect()`, `None` pour `listen()`,
qui n'a pas de cible à vérifier), donc `pluginvnc2` n'a rien de plus à
câbler pour en bénéficier tant qu'il passe par `connect()`/`listen()`
plutôt que par `Client.create()` directement. `listen()`
en particulier demande une adaptation de `vnc_tab.py` côté GTK4 : le
mode reconnexion inversée change le sens d'établissement de la
connexion, donc l'UI qui suppose aujourd'hui "on compose vers un hôte"
devrait proposer un mode "écouter une connexion entrante" séparé plutôt
que de réutiliser tel quel le formulaire de connexion existant). Le
repli de version de protocole, lui, ne demande AUCUNE adaptation côté
`pluginvnc2` — il est entièrement interne à `Client.create()`/`connect()`/
`listen()` et totalement transparent pour l'appelant (le seul ajout
visible est le champ informatif `Client.protocol_version`, que
`pluginvnc2` peut ignorer sans risque).

## Suivi des issues GitHub (ouvertes au 2026-09-20)

Issues de session fermées : [#1](https://github.com/MathildeDec/AsyncVnc4/issues/1)–[#21](https://github.com/MathildeDec/AsyncVnc4/issues/21)

### Tableau récapitulatif des issues restantes

| Issue | Priorité | Track | Ordre | Titre | Statut |
|-------|----------|-------|-------|-------|--------|
| [#22](https://github.com/MathildeDec/AsyncVnc4/issues/22) | 🔴 P1-Haute | A — Code/Features | 1/4 | ZYWRLE — décoder les tuiles lossy (subencodings 17-126) | Fait (2026-10-24, PR vers dev) |
| [#34](https://github.com/MathildeDec/AsyncVnc4/issues/34) | 🔴 P1-Haute | A — Code/Features | 2/4 | Intégration des extensions dans pluginvnc2 (downstream) | Faisable maintenant |
| [#27](https://github.com/MathildeDec/AsyncVnc4/issues/27) | 🟡 P2-Moyenne | B — Tests serveurs réels | 1/6 | `listen()` — test contre vrai serveur VNC / NAT | Hors sandbox |
| [#28](https://github.com/MathildeDec/AsyncVnc4/issues/28) | 🟡 P2-Moyenne | B — Tests serveurs réels | 2/6 | Repli de version — test contre un vrai serveur 3.3 | Hors sandbox |
| [#31](https://github.com/MathildeDec/AsyncVnc4/issues/31) | 🟡 P2-Moyenne | B — Tests serveurs réels | 5/6 | MSLogonII — test contre un vrai serveur UltraVNC/Windows | Hors sandbox |
| [#32](https://github.com/MathildeDec/AsyncVnc4/issues/32) | ✅ Fait | B — Tests serveurs réels | 6/6 | SASL — testé contre QEMU 10.2 (X509SASL + PLAIN) | — |
| [#35](https://github.com/MathildeDec/AsyncVnc4/issues/35) | 🟡 P2-Moyenne | C — Investigation | 4/4 | Annotations de type — version Python minimale | Fait le 2026-10-13 : `>=3.9` |
| [#26](https://github.com/MathildeDec/AsyncVnc4/issues/26) | ⚪ P3-Faible | A — Code/Features | 3/4 | RSA-AES — variantes RA2ne/RA2ne_256/RA2r/RA2r_256 | Différé volontairement |
| [#29](https://github.com/MathildeDec/AsyncVnc4/issues/29) | ⚪ P3-Faible | B — Tests serveurs réels | 3/6 | VeNCrypt — test contre RealVNC Enterprise | Non bloquant |
| [#30](https://github.com/MathildeDec/AsyncVnc4/issues/30) | ⚪ P3-Faible | B — Tests serveurs réels | 4/6 | xvp — test contre un vrai serveur (xvp/Xen VNC Proxy) | Valeur incertaine |
| [#23](https://github.com/MathildeDec/AsyncVnc4/issues/23) | ⛔ P4-Bloquée | C — Investigation | 1/4 | MSLogon original — non implémenté (pas de spec) | Bloqué : spec manquante |
| [#24](https://github.com/MathildeDec/AsyncVnc4/issues/24) | ✅ Fait | C — Investigation | 4/4 | Ultra (LZO) — décodeur pur Python, vérifié contre x11vnc | — |
| [#25](https://github.com/MathildeDec/AsyncVnc4/issues/25) | ⛔ P4-Bloquée | A — Code/Features | 4/4 | SASL — mécanismes supplémentaires (DIGEST-MD5, GSSAPI) | Bloqué : cyrus-sasl |
| [#33](https://github.com/MathildeDec/AsyncVnc4/issues/33) | ⛔ P4-Bloquée | C — Investigation | 3/4 | Type de sécurité « TLS » isolé (18) — infaisable sans spec | Wontfix recommandé |

### Pistes de travail parallèle

Les issues sont organisées en **3 tracks indépendants** qui peuvent être
menés en parallèle sans conflit de fichiers :

#### Track A — Code / Features (`asyncvnc2.py` + `pluginvnc2`)

Issues #22, #34, #26, #25 (ordre suggéré). Touchent des sections
différentes du code, parallélisables entre elles.

#### Track B — Tests contre de vrais serveurs (hors sandbox)

Issues #27, #28, #29, #30, #31, #32 (ordre suggéré). Chaque test
nécessite un serveur ou une topologie indépendante — aucun conflit.

#### Track C — Investigation / Vérification

Issues #23, #24, #33, #35 (ordre suggéré). Recherche de specs,
dépendances ou confirmation d'environnement. Indépendantes entre elles.
