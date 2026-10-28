# SPDX-License-Identifier: GPL-3.0-or-later
"""Licence du dépôt (issue #72) : GPLv3, amont en GPL-3.0 seule, NOTICE.

``asyncvnc2.py`` dérive d'asyncvnc (Barney Gale) via asyncvnc2 (Andrew
Shirayev), publiés sous GPLv3 sans « ou version ultérieure » : il garde
``GPL-3.0-only``. Le reste du code de l'équipe est en ``GPL-3.0-or-later``.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

RACINE = Path(__file__).resolve().parent
AMONT = {'asyncvnc2.py'}
MOTIF = re.compile(r'^# SPDX-License-Identifier: (\S+)$')


def _fichiers_de_code() -> list[str]:
    """Liste les fichiers Python et shell suivis par git."""
    sortie = subprocess.run(
        ['git', 'ls-files', '*.py', '*.sh'],
        cwd=RACINE,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return sortie.split()


def _identifiant(chemin: str) -> str | None:
    """Renvoie l'identifiant SPDX des trois premières lignes du fichier."""
    lignes = (RACINE / chemin).read_text(encoding='utf-8').splitlines()[:3]
    for ligne in lignes:
        trouve = MOTIF.match(ligne)
        if trouve:
            return trouve.group(1)
    return None


class TestLicence(unittest.TestCase):
    """Fichiers de licence, métadonnées et en-têtes SPDX."""

    def test_license_est_le_texte_gplv3(self) -> None:
        """LICENSE contient le texte officiel de la GPLv3."""
        texte = (RACINE / 'LICENSE').read_text(encoding='utf-8')
        self.assertIn('GNU GENERAL PUBLIC LICENSE', texte.splitlines()[0])
        self.assertIn('Version 3, 29 June 2007', texte)

    def test_notice_conserve_les_avis_amont(self) -> None:
        """NOTICE cite les deux auteurs amont et les deux régimes."""
        texte = (RACINE / 'NOTICE').read_text(encoding='utf-8')
        for attendu in (
            'Barney Gale',
            'https://github.com/barneygale/asyncvnc',
            'Andrew Shirayev',
            'https://github.com/andrews239/asyncvnc2',
            'SPDX-License-Identifier: GPL-3.0-only',
            'SPDX-License-Identifier: GPL-3.0-or-later',
        ):
            self.assertIn(attendu, texte)

    def test_pyproject_declare_les_deux_regimes(self) -> None:
        """pyproject.toml déclare l'expression SPDX et les fichiers de licence."""
        texte = (RACINE / 'pyproject.toml').read_text(encoding='utf-8')
        self.assertIn('license = "GPL-3.0-only AND GPL-3.0-or-later"', texte)
        self.assertIn('license-files = ["LICENSE", "NOTICE"]', texte)

    def test_chaque_fichier_de_code_porte_le_bon_regime(self) -> None:
        """Chaque fichier .py et .sh porte l'identifiant SPDX de son régime."""
        fichiers = _fichiers_de_code()
        self.assertIn('asyncvnc2.py', fichiers)
        ecarts = {}
        for chemin in fichiers:
            attendu = 'GPL-3.0-only' if chemin in AMONT else 'GPL-3.0-or-later'
            trouve = _identifiant(chemin)
            if trouve != attendu:
                ecarts[chemin] = trouve
        self.assertEqual(ecarts, {})

    def test_pas_de_copie_orig_suivie(self) -> None:
        """Aucune sauvegarde ``*.orig`` n'est suivie par git."""
        sortie = subprocess.run(
            ['git', 'ls-files', '*.orig'],
            cwd=RACINE,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertEqual(sortie.split(), [])


if __name__ == '__main__':
    unittest.main()
