# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests contre un vrai serveur TigerVNC : Xvnc et `vncconfig -connect` (issue #27).

`listen()` reçoit une connexion inversée initiée par un vrai Xvnc
(`vncconfig -connect`, le scénario cité par l'issue), et `connect()` est vérifié
contre le même serveur avec chaque encodage. La couleur posée par `xsetroot`
sert de vérité terrain : elle a révélé deux défauts corrigés le 2026-10-24
(capture jamais terminée avec ExtendedDesktopSize, rouge et bleu inversés en
Tight) -- voir docs/sessions/session-26-2026-10-24.md.

La traversée d'un vrai NAT/pare-feu est rejouée par
`scripts/scenario_listen_nat.sh` (espaces de noms réseau, droits root : hors CI).

Requiert `Xvnc`, `vncconfig` et `xsetroot`. Sans eux, la suite est sautée, sauf
si `ASYNCVNC_LIVE=1` (job CI dédié) : l'absence devient alors un échec.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import time
import unittest

import asyncvnc2
from asyncvnc2 import Enc, EncList

OUTILS = all(shutil.which(o) for o in ('Xvnc', 'vncconfig', 'xsetroot'))
EXIGE = os.environ.get('ASYNCVNC_LIVE') == '1'
COULEUR = '#2080c0'
ATTENDU = (0x20, 0x80, 0xC0, 255)


def _port_libre() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@unittest.skipUnless(OUTILS or EXIGE, 'Xvnc/vncconfig absents (ASYNCVNC_LIVE=1 pour exiger)')
class TestXvnc(unittest.TestCase):
    """Un Xvnc pour toute la classe ; fond uni posé par xsetroot."""

    @classmethod
    def setUpClass(cls):
        if not OUTILS:
            raise AssertionError('ASYNCVNC_LIVE=1 mais Xvnc, vncconfig ou xsetroot est absent')
        cls.port = _port_libre()
        cls.affichage = f':{cls.port % 1000 + 200}'
        cls.xvnc = subprocess.Popen(
            ['Xvnc', cls.affichage, '-geometry', '320x240', '-depth', '24',
             '-SecurityTypes', 'None', '-rfbport', str(cls.port), '-interface', '127.0.0.1',
             '-nolisten', 'tcp'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )  # fmt: skip
        fin = time.monotonic() + 15
        while True:
            pose = subprocess.run(
                ['xsetroot', '-display', cls.affichage, '-solid', COULEUR],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if pose.returncode == 0:
                break
            if time.monotonic() > fin:
                cls.xvnc.terminate()
                raise AssertionError("Xvnc n'a pas démarré")
            time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.xvnc.terminate()
        cls.xvnc.wait(10)

    async def _deux_captures(self, cm):
        async with cm as client:
            premiere = await asyncio.wait_for(client.screenshot(), 15)
            seconde = await asyncio.wait_for(client.screenshot(), 15)
            return client.video.mode, premiere, seconde

    def _verifier(self, resultat):
        mode, premiere, seconde = resultat
        self.assertEqual(mode, 'bgra')  # format par défaut de Xvnc : rgb888 petit-boutiste
        for image in (premiere, seconde):
            self.assertEqual(image.shape, (240, 320, 4))
            self.assertEqual(tuple(int(v) for v in image[120, 160]), ATTENDU)
            self.assertTrue((image == image[0, 0]).all())

    def _connect(self, encodings=None, qualite=None):
        cm = asyncvnc2.connect(
            '127.0.0.1',
            self.port,
            encodings=EncList(encodings) if encodings else None,
            jpeg_quality=qualite,
        )
        return asyncio.run(asyncio.wait_for(self._deux_captures(cm), 40))

    def test_encodages_par_defaut(self):
        # Avant le correctif : délai dépassé (mise à jour « taille seule » sans suite).
        self._verifier(self._connect())

    def test_encodages_par_defaut_avec_qualite_jpeg(self):
        self._verifier(self._connect(qualite=5))

    def test_chaque_encodage(self):
        for encodage in (Enc.TIGHT, Enc.ZRLE, Enc.HEXTILE, Enc.ZLIB, Enc.RRE, Enc.RAW):
            with self.subTest(encodage=encodage.name):
                # Avant le correctif, Tight rendait (192, 128, 32) : rouge et bleu inversés.
                self._verifier(self._connect([encodage]))

    def test_inverse_vncconfig_connect(self):
        port = _port_libre()

        async def scenario():
            ecoute = asyncio.ensure_future(self._deux_captures(asyncvnc2.listen('127.0.0.1', port)))
            await asyncio.sleep(0.5)  # listener ouvert avant que Xvnc compose
            proc = await asyncio.create_subprocess_exec(
                'vncconfig', '-display', self.affichage, '-connect', f'127.0.0.1:{port}'
            )
            self.assertEqual(await proc.wait(), 0)
            return await ecoute

        self._verifier(asyncio.run(asyncio.wait_for(scenario(), 40)))


if __name__ == '__main__':
    unittest.main()
