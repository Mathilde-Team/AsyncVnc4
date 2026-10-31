# SPDX-License-Identifier: GPL-3.0-or-later
"""Garde-fous hors réseau de la publication du tag exact depuis GitHub."""

import json
import unittest
from pathlib import Path


class PublicationSurTag(unittest.TestCase):
    def setUp(self):
        self.workflows = Path(__file__).resolve().parents[1] / '.github' / 'workflows'

    def test_tag_explicite_et_ascendance_main(self):
        texte = (self.workflows / 'release.yml').read_text(encoding='utf-8')
        self.assertIn('  workflow_dispatch:', texte)
        self.assertIn('      TAG: ${{ inputs.tag || github.ref_name }}', texte)
        self.assertIn('          ref: refs/tags/${{ env.TAG }}', texte)
        self.assertIn('          fetch-depth: 0', texte)
        self.assertIn('merge-base --is-ancestor', texte)
        self.assertIn('refs/tags/${TAG}^{commit}', texte)
        self.assertNotIn('${GITHUB_REF_NAME}', texte)
        self.assertNotIn('${GITHUB_SHA}', texte)
        self.assertIn('          draft: false', texte)
        self.assertIn('          tag_name: ${{ env.TAG }}', texte)
        self.assertIn('          fail_on_unmatched_files: true', texte)

    def test_repli_github_et_garde_main_conserves(self):
        for nom in ('ci.yml', 'guard-main.yml', 'release.yml'):
            texte = (self.workflows / nom).read_text(encoding='utf-8')
            repli = 'fromJSON(vars.RUNS_ON_LINUX || \'"ubuntu-latest"\')'
            direct = any(
                ligne.strip()
                in (
                    'runs-on: ubuntu-latest',
                    'runs-on: ubuntu-24.04',
                    'runs-on: ubuntu-26.04',
                )
                for ligne in texte.splitlines()
            )
            self.assertTrue(repli in texte or direct)
        garde = (self.workflows / 'guard-main.yml').read_text(encoding='utf-8')
        self.assertIn('Garde : PR vers main doit venir de dev', garde)
        self.assertIn('!= "dev"', garde)
        ci = (self.workflows / 'ci.yml').read_text(encoding='utf-8')
        regle = json.loads(
            (self.workflows.parent / 'branch-protection' / 'dev.json').read_text(encoding='utf-8')
        )['required_status_checks']
        contextes = [check['context'] for check in regle.get('checks', [])]
        contextes.extend(regle.get('contexts', []))
        self.assertTrue(contextes)
        for contexte in contextes:
            self.assertIn(contexte, ci + '\n' + garde)
        self.assertIn('run: python3 tests/test_workflow_release.py', ci)


if __name__ == '__main__':
    unittest.main()
