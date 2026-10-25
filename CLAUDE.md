# CLAUDE.md — asyncvnc2_patched

Fichier court, à lire à chaque démarrage de session. Le détail (raisonnement,
décisions de conception, vérifications) vit ailleurs — voir « Où chercher
quoi » en bas de page.

## État courant

Fork maison d'`asyncvnc2` (client RFB pur Python) + 23 patches, tous
vérifiés soit par exécution réelle, soit contre une spec/source faisant
autorité (RFC 6143, `rfbproto.rst`, code source QEMU). Les extensions
les plus délicates (VeNCrypt, `send_qemu_extended_key_event()`, xvp,
ZYWRLE, Extended Clipboard) ont depuis été confirmées — ou leurs
limites révélées — contre de vrais serveurs tiers (TigerVNC/Xvnc les
2026-09-08, 2026-09-09, 2026-09-13 et 2026-09-14, QEMU 8.2.2 les
2026-09-09 et 2026-09-13) : un vrai bug de suites cryptographiques a
été trouvé et corrigé sur VeNCrypt, le test xvp du 2026-09-09 a révélé
que TigerVNC ne supporte pas cette extension et ferme la connexion en
réponse à un message xvp non reconnu, le test ZYWRLE du 2026-09-09 a
révélé une désynchronisation du flux (subencodings 17-126) une fois le
chemin lossy de QEMU engagé — cause trouvée et corrigée le 2026-10-24,
issue #22 — et le test Extended Clipboard du
2026-09-13 a révélé qu'un `Provide` non précédé d'un `Notify` du même
émetteur est silencieusement ignoré par TigerVNC **et** par QEMU,
chacun pour une raison mécanique différente — dans les quatre cas,
docstrings corrigées en conséquence (aucun changement de format
binaire pour xvp ; `Enc.ZYWRLE` ajouté mais exclu de `Enc.default()`
pour ZYWRLE ; `send_clipboard_update()` ajouté pour Extended Clipboard,
voir `docs/sessions/session-14-2026-09-13.md`). **2026-09-13 (2)** :
`send_clipboard_caps()` revérifiée contre le même TigerVNC — confirmée
avoir un effet réel (pas seulement un format sur le fil correct) : avec
`max_text_size=0`, ce serveur passe de « fournit directement » à
« notifie puis attend notre `Request` », voir
`docs/sessions/session-15-2026-09-13.md`. **2026-09-14** : VeNCrypt
étendu aux sous-types `TLSPlain`/`X509Plain` (`_VENCRYPT_TLS_PLAIN`/
`_VENCRYPT_X509_PLAIN`, patch 18) — découverts en inspectant les types
de sécurité qu'`Xtigervnc` 1.13.1 propose réellement, jamais mentionnés
dans ce fichier auparavant. Testés pour de vrai dès le départ (un vrai
utilisateur Linux + PAM configurés dans ce sandbox pour l'occasion, la
vérification de mot de passe étant déléguée à PAM par TigerVNC) : cas
nominal, mauvais mot de passe, utilisateur inexistant et identifiants
manquants tous vérifiés — voir `docs/sessions/session-16-2026-09-14.md`.
**2026-09-15** : RSA-AES (RA2/RA2_256, security types 5/129, patch 19)
implémenté — contrairement à VeNCrypt, pas un TLS enveloppé : échange
de clés RSA puis chiffrement AES-EAX construit dans ce fichier
(`cryptography` n'a pas de classe EAX native), qui enveloppe ensuite
toute la connexion. Format croisé entre `rfbproto.rst` et le code
source TigerVNC (`CSecurityRSAAES.cxx` + `AESInStream`/`AESOutStream.cxx`).
**Un vrai bug trouvé et corrigé par l'exécution réelle** : clé de
session tronquée à 16 octets sans condition, alors que la variante 256
bits doit utiliser les 32 octets complets du SHA-256 (RA2/128 marchait
du premier coup, RA2_256 échouait immédiatement — signal net). Testé
pour de vrai contre TigerVNC/Xvnc 1.13.1 pour les deux variantes :
poignée de main complète, lecture réelle du framebuffer déchiffré,
écriture clavier chiffrée, rejets corrects. RA2ne/RA2ne_256/RA2r/RA2r_256
délibérément non implémentés (voir `docs/features-backlog.md`). 6 tests
unitaires ajoutés pour les primitives EAX elles-mêmes (fonctions pures,
contrairement au reste de RSA-AES/VeNCrypt) — voir
`docs/sessions/session-17-2026-09-15.md`.

Le dernier point 🟢 directement testable dans ce sandbox — la topologie
WebSocket « reverse » complète de `listen(websocket=True)` (un proxy
relayant une connexion TCP entrante vers une connexion WS sortante) —
a été vérifié le 2026-09-10 : `websockify` (pressenti à tort dans les
commentaires du code comme le proxy à utiliser pour ce rôle précis)
s'est révélé **structurellement incapable** de ce sens de relais
(confirmé par son propre `--help` et par exécution réelle de
l'invocation erronée qui figurait en commentaire) ; un vrai `websocat`
(outil tiers indépendant, binaire officiel précompilé) comble ce rôle
et le test de bout en bout a réussi. Docstrings/commentaires corrigés
en conséquence — **zéro ligne de code exécutable modifiée** (diff
vérifié), donc toujours 16 patches.

Suite de tests committée (`test_asyncvnc2.py`, 50 tests, aucune
nouvelle dépendance) depuis le 2026-09-07.

**2026-09-11 : modernisation des annotations de type appliquée, mais
sous hypothèse non confirmée.** `ruff check` passe de 60 à 2
signalements (`Dict`/`List`/`Set`/`Tuple` → minuscules, `Optional[X]`
→ `X | None`, import `typing` devenu mort supprimé) — 93 lignes
touchées, zéro changement de comportement vérifié (tests, signatures,
`Enc.default()` identiques avant/après). **Contredit un principe posé
le 2026-09-07** (« décision de version minimale qui revient à qui
déploie ce fichier, pas à trancher unilatéralement ») : appliqué quand
même, sur l'hypothèse Python ≥ 3.10, pour ne pas rester bloqué sans
confirmation possible dans l'immédiat — mais reste réversible et **à
confirmer**. Voir `docs/sessions/session-13-2026-09-11.md` pour le
détail et le rollback. Ne pas considérer ce point clos tant que la
version minimale n'est pas confirmée par qui déploie ce fichier.

Détail complet des 23 patches et de leur statut : @docs/features-backlog.md

**2026-10-10** : repli de version (#28) et connexion inversée (#27)
testés contre un vrai serveur tiers, x11vnc/libvncserver (`-rfbversion
3.3`/`3.7`, `-connect_or_exit`) : 10 tests dans `test_live_x11vnc.py`, job
CI « Serveur réel (x11vnc) », aucune modification de code. Voir
`docs/sessions/session-22-2026-10-10.md`.

**2026-10-24** (#27) : `listen()` testé contre TigerVNC Xvnc
(`vncconfig -connect`) et à travers un NAT + pare-feu réel monté en espaces de
noms réseau (`scripts/scenario_listen_nat.sh`, manuel, root). Deux bugs
corrigés au passage : ordre R,G,B des TPIXEL Tight en mode `bgra`/`abgr`, et
`screenshot()` bloqué avec TigerVNC (réponse `ExtendedDesktopSize` seule à une
demande non incrémentale). `test_live_xvnc.py` dans le job « Serveur réel ».
Reste une vraie box Internet, procédure dans
`docs/sessions/session-26-2026-10-24.md`.

**2026-10-10 (2)** : encodage Ultra (9) implémenté (#24) : décodeur LZO1X
pur Python `_lzo1x_decompress()`, vérifié contre liblzo2 et contre un vrai
x11vnc (image identique au Raw). Opt-in, hors `Enc.default()`. Voir
`docs/sessions/session-23-2026-10-10.md`.

**2026-10-10 (3)** : SASL testé contre un vrai QEMU 10.2 (#32). Ajout des
sous-types VeNCrypt X509SASL (263) et TLSSASL (264) ; PLAIN ne fonctionne
qu'en X509SASL. `test_live_qemu_sasl.py`. Voir
`docs/sessions/session-24-2026-10-10.md`.

## Prochaine feature / prochaine session

Plus aucun point 🟠 Moyenne restant. Les huit derniers 🟢 traités
(2026-09-09, 2026-09-10, 2026-09-13 deux fois, 2026-09-14, 2026-09-15,
puis 2026-09-16 deux fois pour MSLogonII et SASL) :

- **SASL — mécanismes PLAIN/ANONYMOUS (patch 23)** — voir le paragraphe
  dédié dans « État courant » ci-dessus et
  `docs/sessions/session-21-2026-09-16c.md` pour le détail complet.
- **MSLogonII (patch 22)** — voir la ligne dédiée plus bas et
  `docs/sessions/session-20-2026-09-16.md`.
- **RSA-AES — RA2/RA2_256 (patch 19)** — la piste ouverte (puis
  volontairement écartée) la session précédente : un type de sécurité à
  part entière, pas une extension de VeNCrypt (échange de clés RSA puis
  chiffrement AES-EAX construit dans ce fichier, `cryptography` n'ayant
  pas de classe EAX native). Format croisé entre `rfbproto.rst` et le
  code source TigerVNC (`CSecurityRSAAES.cxx` + `AESInStream`/
  `AESOutStream.cxx`) : plusieurs détails (taille réelle de la clé de
  session, ordre des préimages de hachage, cadrage EAX) viennent de la
  seconde source, la prose de la spec seule ne les fixant pas sans
  ambiguïté. **Un vrai bug trouvé et corrigé par l'exécution réelle** :
  clé de session tronquée à 16 octets sans condition — correct pour
  AES-128 (RA2), faux pour AES-256 (RA2_256, qui doit utiliser les 32
  octets complets du SHA-256) ; RA2 fonctionnait du premier coup,
  RA2_256 échouait immédiatement (jeton EAX invalide, signal net et sans
  ambiguïté), ce qui a permis de trouver l'erreur tout de suite. **Testé
  pour de vrai contre TigerVNC/Xvnc 1.13.1** pour les deux variantes
  (vrai utilisateur Linux + PAM + clé RSA serveur générée pour
  l'occasion) : poignée de main complète, lecture réelle du framebuffer
  déchiffré, écriture clavier chiffrée, rejets corrects (mauvais mot de
  passe, utilisateur inexistant, identifiants manquants). Empreinte de
  la clé serveur façon RealVNC exposée pour un épinglage éventuel côté
  application appelante, non stockée/comparée par cette bibliothèque
  elle-même. RA2ne/RA2ne_256/RA2r/RA2r_256 délibérément non implémentés.
  6 tests unitaires ajoutés pour les primitives EAX elles-mêmes
  (fonctions pures, testables sans serveur) — voir
  `docs/features-backlog.md` et `docs/sessions/session-17-2026-09-15.md`
  pour le détail complet.
- **VeNCrypt — sous-types TLSPlain/X509Plain (patch 18)** — découverts
  en inspectant `Xtigervnc -help` (qui les propose réellement, aux
  côtés de `RA2`/`RA2ne`/`RA2_256`/`RA2ne_256`, eux aussi jamais
  mentionnés dans ce fichier avant cette date mais laissés de côté :
  échange de clés RSA propre, pas une extension de l'infrastructure TLS
  déjà en place, hors périmètre d'une seule session). Réutilise les
  paramètres `username`/`password` déjà acceptés (auth Apple, type 33) ;
  format vérifié contre `rfbproto.rst` **et** `CSecurityPlain.cxx`
  (TigerVNC). Ordre de préférence étendu à six sous-types : X509Vnc >
  X509Plain > X509None > TLSVnc > TLSPlain > TLSNone. **Testé pour de
  vrai contre TigerVNC/Xvnc 1.13.1 dès le départ** (vrai utilisateur
  Linux + PAM configurés dans ce sandbox, la vérification du mot de
  passe étant déléguée à PAM par ce serveur) : identifiants corrects,
  mauvais mot de passe, utilisateur inexistant, identifiants manquants
  — les quatre vérifiés. Aucun test unitaire ajouté (VeNCrypt en est
  délibérément exclu depuis le 2026-09-07, voir ci-dessous) — voir
  `docs/features-backlog.md` et `docs/sessions/session-16-2026-09-14.md`
  pour le détail complet.
- **`send_clipboard_caps()`, revérifiée contre un vrai serveur** — la
  seule limite encore notée pour Extended Clipboard (patch 17) juste
  en dessous. `handleClipboardCaps()` lu dans `common/rfb/SConnection.cxx`
  (TigerVNC) montrait que ce serveur tient compte des tailles déclarées
  par le client (« only notify » si 0, « automatically send up to X »
  sinon) — confirmé par exécution réelle sur le même TigerVNC/Xvnc
  1.13.1 : `send_clipboard_caps(max_text_size=0)` fait bien passer ce
  serveur de « fournit directement » (comportement par défaut, déjà
  observé le 2026-09-13) à « notifie puis attend notre `Request` » —
  seule variable changée entre les deux mesures. Aucun changement de
  code nécessaire (la fonction faisait déjà ce qu'il fallait) — voir
  `docs/features-backlog.md` et `docs/sessions/session-15-2026-09-13.md`
  pour le détail complet.
- **Extended Clipboard** — testé contre deux serveurs réels indépendants,
  TigerVNC/Xvnc 1.13.1 et QEMU 8.2.2. `Enc.EXTENDED_CLIPBOARD` ajouté
  (inclus dans `Enc.default()`, sûr à annoncer comme `Enc.XVP`) ;
  réception (`process_extended_clipboard()`, texte UTF-8 seul décodé,
  rtf/html/dib/files correctement sautés sans désynchroniser) et
  émission (`send_clipboard_caps/notify/request/provide/update()`)
  implémentées. Les deux serveurs ignorent silencieusement un `Provide`
  non précédé d'un `Notify` du même émetteur (raisons mécaniques
  différentes) — `send_clipboard_update()` ajouté en conséquence comme
  raccourci recommandé. Round-trip complet confirmé dans les deux sens
  contre TigerVNC (presse-papiers X réel via `xclip`) et en relais à
  deux connexions contre QEMU. Voir `docs/features-backlog.md` et
  `docs/sessions/session-14-2026-09-13.md` pour le détail complet.
- **ZYWRLE (17)** — **décodage complet depuis le 2026-10-24 (issue
  #22)**, vérifié contre un vrai QEMU 10.2.1 (`lossy=on`, niveaux 1 à 3).
  Une tuile ZYWRLE est un octet de subencoding 0 suivi d'une tuile ZRLE
  imbriquée complète (coefficients d'ondelettes) ; le niveau vaut
  3 - qualité JPEG // 3 (jamais transmis). Les subencodings 17-126 vus
  le 2026-09-09 (QEMU 8.2.2) étaient une désynchronisation (tuile
  imbriquée lue comme du Raw), pas un format : ils restent refusés
  (`ValueError`). `_zywrle_synthesize()` est un port octet par octet de
  `ZYWRLE_SYNTHESIZE` (libvncserver), validé contre le C compilé.
  `Enc.ZYWRLE` reste exclu de `Enc.default()` parce qu'il est à perte.
  Voir `docs/sessions/session-25-2026-10-24.md` (l'historique est dans
  `docs/sessions/session-11-2026-09-09.md`).
- **xvp** — testé contre un vrai TigerVNC/Xvnc 1.13.1. Résultat : ce
  serveur ne supporte PAS xvp et ferme la connexion en réponse à un
  message xvp non reconnu (docstrings corrigées en conséquence) — voir
  `docs/features-backlog.md` et `docs/sessions/session-10-2026-09-09.md`
  pour le détail complet.
- **WebSockets, `listen()` en topologie reverse complète** — testé
  contre un vrai `websocat` (`tcp-listen:` → `ws://`) ; `websockify`
  s'est révélé structurellement incapable de ce rôle de proxy
  (confirmé par exécution réelle — voir « État courant » ci-dessus).
  Docstrings/commentaires corrigés, **zéro changement de code
  exécutable** — voir `docs/features-backlog.md` et
  `docs/sessions/session-12-2026-09-10.md` pour le détail complet.

Priorité 🟢 Faible restante : voir la liste complète dans
`docs/features-backlog.md` § « Prochaines étapes suggérées » (repli de
version contre un vrai serveur 3.3, `listen()` contre une vraie box
Internet (NAT simulé testé le 2026-10-24), MSLogon original/Ultra(LZO)/type de sécurité 18 non commencés
(aucune source de format documentée indépendamment d'un serveur/
bibliothèque de référence, même blocage pour les trois) — **MSLogonII
(113) et SASL (mécanismes PLAIN/ANONYMOUS) implémentés le 2026-09-16**,
voir plus bas —, RA2ne/RA2ne_256/RA2r/
RA2r_256 délibérément non implémentés (voir « État courant » ci-dessus),
câblage côté `pluginvnc2` des extensions déjà validées ici — Extended
Clipboard, VeNCrypt Plain et RSA-AES y compris désormais). La
modernisation des annotations de type, elle, est appliquée depuis le
2026-09-11 sur une hypothèse de version Python (≥ 3.10) restée non
confirmée jusqu'au **2026-09-16**, où elle est désormais formellement
actée (`requires-python = ">=3.10"` dans `pyproject.toml`, voir
« Commandes de qualité » ci-dessous) ; `ruff format` complet est
désormais appliqué (voir plus bas), n'est plus une décision en
suspens.

## Commandes de qualité

```bash
uv sync                                          # crée .venv/, installe numpy/loguru/cryptography/keysymdef + ruff (dev)
uv run python3 -m unittest test_asyncvnc2 -v     # 62 tests
uv run coverage run -m unittest test_asyncvnc2 test_reseau_local test_decodage_video  # 126 tests (27 sur socket locale, 37 décodeurs hors ligne, issue #54)
uv run coverage report                           # lignes + branches, échoue sous fail_under (pyproject.toml)
uv run python3 -m unittest test_loguru_regles -v # 25 tests, règles de journalisation (issue #55)
uv run python3 scripts/audit_debug_sorties.py    # 0 fonction non conforme (référence : 0)
uv run ruff check asyncvnc2.py test_asyncvnc2.py # 0 signalement
```

**2026-09-16 : migration vers `uv`** (voir
`docs/sessions/session-18-2026-09-16.md`) — il n'y avait en réalité
aucun `poetry` préexistant à remplacer : `pyproject.toml`/`uv.lock`
n'avaient jamais été ajoutés jusqu'ici, décision délibérée du
2026-09-11 pour ne pas figer une version Python minimale sans
confirmation. À la demande explicite de cette session, cette question
est désormais tranchée (**2026-10-13, issue #35 : abaissé à `>=3.9`**, voir plus bas) : `requires-python = ">=3.10"` est acté dans
`pyproject.toml`, reprenant l'hypothèse déjà appliquée en code depuis
le 2026-09-11 (`Dict`/`List` → minuscules, `Optional[X]` → `X | None`)
mais jamais formalisée. Vérifié par exécution réelle dans ce sandbox :
`uv lock` (13 paquets), `uv sync` (`.venv` créé, 8 paquets installés,
versions plus récentes que celles déjà présentes dans ce sandbox —
numpy 2.5.3, cryptography 50.0.1 — aucune incompatibilité constatée),
`uv run` pour les tests (43/43) et pour `ruff check` (0 signalement).
`.gitignore` ajouté (`.venv/`, `.ruff_cache/`, `__pycache__/` —
`uv.lock` volontairement pas ignoré, à committer comme l'aurait été
`poetry.lock`).

**2026-09-16 : `ruff check` intégralement propre (0 signalement)** —
les 2 signalements `BLE001`/`S110` sur `_WebSocketWriter.close()`,
volontairement non corrigés depuis le 2026-09-07 (voir
`docs/features-backlog.md` § « Nettoyage style — code WebSockets »),
sont désormais traités : `except Exception: pass` remplacé par
`except (OSError, RuntimeError, ssl.SSLError) as exc:` suivi d'un
`logger.debug()`. Choix des trois types justifié en commentaire dans
le code (transport TCP déjà fermé / event loop qui referme entre-temps
/ session TLS déjà en cours de fermeture) — comportement fonctionnel
inchangé (aucune exception ne remonte plus à l'appelant qu'avant, seule
une trace `debug` est ajoutée), mais **pas revérifié contre un vrai
transport cassé dans les trois cas** (à la différence du reste de ce
fichier) faute de scénario reproduisant facilement les trois familles
d'erreurs sans un vrai serveur à moitié fermé — voir
`docs/sessions/session-18-2026-09-16.md`. Les 2 signalements `C408`
dans `test_asyncvnc2.py` (jamais audité par `ruff` jusqu'ici) corrigés
en parallèle (`dict(...)` → littéral, purement syntaxique). 43 tests
toujours au vert.

**2026-09-16 (4) : SASL (security type 20), mécanismes `PLAIN`/
`ANONYMOUS` seulement.** Ré-examen d'un rejet trop rapide de la session
précédente : le tramage RFB de SASL (`rfbproto.rst`, mechlist/
client-start/server-start) est en fait documenté indépendamment de
toute bibliothèque SASL, et `PLAIN` (RFC 4616) / `ANONYMOUS` (RFC 4505)
sont chacun définis par leur propre RFC autonome sans échange
défi-réponse — seuls ces deux mécanismes sont implémentés
(`_sasl_negotiate()`), tout autre (`DIGEST-MD5`/`GSSAPI`, qui
nécessiteraient réellement `cyrus-sasl`) est refusé explicitement par
`ValueError` plutôt que deviné. Classé en toute dernière position de
l'ordre de préférence de négociation (après MSLogonII) : `PLAIN` envoie
le mot de passe en clair sur le fil, sans couche de chiffrement propre à
ce type de sécurité. **Aucun serveur SASL de référence installable dans
ce sandbox** (même limite que MSLogonII) — vérifié par un round-trip
auto-cohérent fabriqué à la main, 7 tests unitaires ajoutés
(`SaslNegotiateTests`, 50 tests au total). Voir
`docs/sessions/session-21-2026-09-16c.md`.

**2026-09-16 (3) : `ruff format` complet appliqué** — sur choix
explicite de l'utilisateur entre plusieurs options proposées (voir
`docs/sessions/session-19-2026-09-16b.md`). `[tool.ruff.format]
quote-style = "single"` ajouté à `pyproject.toml` pour préserver la
convention de guillemets simples déjà en place partout dans le fichier
(le style par défaut de `ruff format` bascule en guillemets doubles,
ce qui aurait été un changement de convention non demandé) — ce
réglage ramène le diff de 1504+409 lignes à 1143+107 lignes sur
`asyncvnc2.py`/`test_asyncvnc2.py`. Diff intégral relu en entier (pas
d'échantillonnage) : uniquement des retours à la ligne, reformatage de
littéraux multi-lignes et alignement de commentaires — aucun
changement de contenu de chaîne, de valeur ou de logique. Vérifié par
exécution réelle : 43/43 tests toujours au vert, `ruff check` toujours
à 0 signalement, `ruff format --check` désormais stable (idempotent)
sur les deux fichiers.

## Outils disponibles en session

En plus du réseau sortant déjà autorisé vers `github.com`/
`raw.githubusercontent.com`/`pypi.org` etc. (voir la config réseau du
sandbox — déjà utilisé pour récupérer `rfbproto.rst` en direct depuis
`rfbproto/rfbproto` le 2026-09-16, cf. MSLogonII ci-dessus), **Context7
peut être interrogé au besoin** pour de la documentation à jour de
bibliothèques tierces (`cryptography`, `numpy`, etc.) si une question
de version/API précise se pose et que la doc locale ou la mémoire ne
suffit pas — pense à le solliciter plutôt que de deviner un détail
d'API sur une bibliothèque dont le comportement a pu changer entre
versions.

## Où chercher quoi

- `docs/features-backlog.md` — table de statut par fonctionnalité
  (encodages, authentification, transport, robustesse) + backlog priorisé.
  Importé ci-dessus, pas besoin de l'ouvrir séparément pour l'état général.
- `docs/sessions/session-NN-YYYY-MM-DD.md` — historique détaillé d'une
  session donnée (raisonnement, bugs trouvés, méthode de vérification).
  À rouvrir seulement si besoin de contexte précis sur cette session.
- `docs/reference/patch-history.md` — table récapitulative des 23 patches
  avec leur numéro, et comment réappliquer un patch à la main sur une
  version divergente du fork.
- `docs/reference/downstream-consumer.md` — ce que le plugin GTK4
  `pluginvnc2` (paquet séparé) consomme réellement de ce fork, et ce qui
  resterait à câbler côté UI pour chaque extension.

## Instructions reçues dans le chat (issue #44)

Toute instruction reçue dans le chat (Perplexity Computer, Claude Code ou autre) devient une issue. Une phrase ne reste pas en l'air.

- Avant de commencer le travail, créer l'issue dans le dépôt concerné, en citant l'instruction mot pour mot avec sa date.
- Une demande qui touche plusieurs dépôts donne une issue par dépôt, chacune liée aux autres.
- Une question posée dans le chat sans réponse immédiate devient elle aussi une issue, ou un commentaire « Question pour Mathilde » sur l'issue existante.
- La PR ferme ou cite l'issue (`Closes #n`). Une instruction abandonnée est fermée avec sa raison (« not planned »).
- En fin de session, vérifier que chaque instruction du chat a son issue, ouverte ou fermée.

## Version Python minimale : 3.9 (issue #35, 2026-10-13)

Demande de Mathilde : garder la compatibilité Python 3.9 si possible, car AsyncVnc4 sera utilisé par Gcm4, y compris sur RHEL/Rocky 9 (python3 système 3.9).

- `from __future__ import annotations` en tête de chaque module : les annotations `X | None` restent des chaînes, jamais évaluées.
- Interdit dans le code exécuté : `X | Y` hors annotation (`isinstance(x, A | B)`, alias de type), `match`, `zip(strict=)`, `itertools.pairwise`, `int.bit_count`, `aiter` / `anext`, `dataclass(slots=, kw_only=)`, `asyncio.timeout`, `asyncio.TaskGroup`.
- Le job CI « Python 3.9 (tests, vermin) » le vérifie : suite unittest sous 3.9, puis `vermin -t=3.9-`.
- `requires-python = ">=3.9"` et ruff `target-version = "py39"`.

## Journalisation loguru (issue #55, SOCLE §8, 2026-10-22)

- `from loguru import logger` uniquement ; `import logging` interdit ; format `{}` (jamais `%s`).
- `logger.debug()` à l'entrée de chaque fonction non triviale et avant chaque sortie (`return`, `raise` volontaire, fin implicite) ; `logger.trace()` sur les chemins chauds (par rectangle, tuile, message chiffré ou événement clavier/souris).
- Avant chaque `raise` volontaire : l'exception exacte est journalisée (`_erreur = X(...)`, journal, `raise _erreur`), avec la cause d'origine quand elle existe.
- Chaque `except` journalise la cause exacte.
- Jamais de secret ni de contenu saisi : mot de passe, identifiant, clé d'hôte → `bool()` ; clés, presse-papiers, texte tapé → `len()` ; keysym/keycode jamais journalisés (enregistreur de frappes).
- Contrôle : `test_loguru_regles.py` (règles AST) et `scripts/audit_debug_sorties.py` ; la référence `scripts/audit_debug_sorties.baseline` (0) ne peut que baisser.
