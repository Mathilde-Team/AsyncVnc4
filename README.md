# asyncvnc2

Client RFB/VNC asynchrone pur Python, fork d'`asyncvnc2` (Tight/Hextile/ZlibHex, curseur, resize, Fence/ContinuousUpdates) + 23 patches vérifiés.

Pensé comme la bibliothèque VNC pour [Gcm4](https://github.com/MathildeDec/Gcm4) (Gnome Connection Manager 4) — consommée par le plugin `pluginvnc2` (`plugins/pluginvnc2/vnc_tab.py`).

```python
import asyncio
import asyncvnc2

async def main():
    async with asyncvnc2.connect("192.168.1.10", password="secret") as client:
        print(client.name, client.width, "x", client.height)
        client.keyboard.write("hello")
        frame = await client.capture()

asyncio.run(main())
```

## État du projet

50 tests unitaires, `ruff check` à 0 signalement, `ruff format` idempotent. 23 patches appliqués, tous vérifiés par exécution réelle ou contre une spec faisant autorité (RFC 6143, `rfbproto.rst`, code source QEMU/TigerVNC).

Détail complet dans [`CLAUDE.md`](./CLAUDE.md), [`docs/features-backlog.md`](./docs/features-backlog.md) et [`docs/sessions/`](./docs/sessions/).

### Fonctionnalités implémentées

| Catégorie | Fonctionnalités |
|-----------|----------------|
| Encodages | Tight, ZRLE, Hextile, CoRRE, RRE, Copy, Curseur, ZYWRLE (à perte, opt-in) |
| Authentification | VNC Auth, Apple ARD, VeNCrypt (6 sous-types), RSA-AES (RA2/RA2_256), MSLogonII, SASL (PLAIN/ANONYMOUS) |
| Transport | WebSockets (client + serveur), reconnexion inversée (`listen()`), repli 3.3/3.7/3.8 |
| Extensions | xvp, Extended Clipboard, QEMU Extended Key Event, `send_set_desktop_size()` |
| Sécurité | Plafonds anti-DoS, journalisation d'audit, confirmation avant commandes destructives |

## Installation

```bash
uv sync          # environnement isolé
uv run pytest test_asyncvnc2.py -v
uv run ruff check asyncvnc2.py test_asyncvnc2.py
```

Dépendances : `numpy`, `loguru`, `cryptography`, `keysymdef`. Python >= 3.9 (python3 système de RHEL/Rocky 9 compris, issue #35), vérifié en CI.

## Suivi des issues

- **Sessions fermées :** [#1](https://github.com/MathildeDec/AsyncVnc4/issues/1)–[#21](https://github.com/MathildeDec/AsyncVnc4/issues/21)
- **Travaux restants :** [#22](https://github.com/MathildeDec/AsyncVnc4/issues/22)–[#35](https://github.com/MathildeDec/AsyncVnc4/issues/35) (14 issues ouvertes)
- **Tableau récapitulatif :** [`docs/features-backlog.md`](./docs/features-backlog.md) § Suivi des issues GitHub

## Écosystème

Ce dépôt fait partie de l'écosystème Gcm4 :

- **[Gcm4](https://github.com/MathildeDec/Gcm4)** — Application principale (gestionnaire de connexions GTK4)
- **AsyncVnc4** (ce dépôt) — Bibliothèque cliente VNC
- **[AsyncRdp4](https://github.com/MathildeDec/AsyncRdp4)** — Bibliothèque cliente RDP

Roadmap d'intégration : [Gcm4 #106](https://github.com/MathildeDec/Gcm4/issues/106)
Tableau de bord : [Gcm4 #107](https://github.com/MathildeDec/Gcm4/issues/107)
Annonce du projet : [Gcm4 #102](https://github.com/MathildeDec/Gcm4/issues/102)

## Licence

GPL-3.0 — le fichier `LICENSE` est celui de l'original (`asyncvnc` de Barney Gale, dont ce dépôt dérive via `asyncvnc2` d'andrews239). Le relicence en MIT est impossible : l'œuvre dérivée d'un programme GPL-3.0 reste GPL-3.0 (exception assumée dans l'audit du socle, `.github#1`).
