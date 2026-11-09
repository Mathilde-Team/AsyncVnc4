# SPDX-License-Identifier: GPL-3.0-or-later
"""Le garde-fou doit refuser un total combiné trompeusement supérieur à 95 %."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verifier_couverture import main, verifier_couverture


class ControleCouvertureTests(unittest.TestCase):
    def test_deux_seuils_independants(self):
        for lignes, branches, attendu in (
            (95, 95, True),
            (100, 94, False),
            (94, 100, False),
            (0, 0, False),
        ):
            with self.subTest(lignes=lignes, branches=branches):
                self.assertEqual(
                    verifier_couverture(
                        {
                            'covered_lines': lignes,
                            'num_statements': 100,
                            'covered_branches': branches,
                            'num_branches': 100,
                        },
                        95,
                    ),
                    attendu,
                )

    def test_pas_arrondi_a_95(self):
        self.assertFalse(
            verifier_couverture(
                {
                    'covered_lines': 9499,
                    'num_statements': 10000,
                    'covered_branches': 100,
                    'num_branches': 100,
                },
                95,
            )
        )

    def test_aucune_ligne_ou_branche_a_mesurer(self):
        self.assertTrue(
            verifier_couverture(
                {'covered_lines': 0, 'num_statements': 0, 'covered_branches': 0, 'num_branches': 0},
                95,
            )
        )

    def test_lecture_du_seuil_unique_et_code_retour(self):
        with tempfile.TemporaryDirectory() as dossier:
            rapport = Path(dossier) / 'coverage.json'
            rapport.write_text(
                json.dumps(
                    {
                        'totals': {
                            'covered_lines': 96,
                            'num_statements': 100,
                            'covered_branches': 96,
                            'num_branches': 100,
                        }
                    }
                ),
                encoding='utf-8',
            )
            with (
                patch('sys.argv', ['verifier_couverture', str(rapport)]),
                patch('scripts.verifier_couverture.Coverage') as couverture,
            ):
                couverture.return_value.get_option.return_value = 97
                self.assertEqual(main(), 1)
                couverture.return_value.get_option.assert_called_once_with('report:fail_under')
                couverture.return_value.get_option.return_value = 95
                self.assertEqual(main(), 0)

    def test_rapport_absent_ou_invalide(self):
        with tempfile.TemporaryDirectory() as dossier:
            rapport = Path(dossier) / 'coverage.json'
            with patch('sys.argv', ['verifier_couverture', str(rapport)]):
                self.assertEqual(main(), 2)
                rapport.write_text('{', encoding='utf-8')
                self.assertEqual(main(), 2)
                rapport.write_text('{}', encoding='utf-8')
                self.assertEqual(main(), 2)
