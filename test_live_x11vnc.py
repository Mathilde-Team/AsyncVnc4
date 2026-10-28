# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests contre un vrai serveur VNC tiers : x11vnc (libvncserver).

Issues #28 (repli de version, serveur 3.3 réel) et #27 (connexion inversée
initiée par un vrai serveur, `x11vnc -connect_or_exit`). Contrairement à
`test_asyncvnc2.py`, aucun serveur n'est fabriqué à la main : x11vnc écrit
lui-même `RFB 003.003`, `003.007` ou `003.008` et conduit la sécurité.

Requiert `x11vnc`, `Xvfb` et `xsetroot`. Sans eux, la suite est sautée, sauf si
`ASYNCVNC_LIVE=1` (job CI dédié) : l'absence devient alors un échec.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

import numpy as np

import asyncvnc2

OUTILS = all(shutil.which(o) for o in ('x11vnc', 'Xvfb', 'xsetroot'))
EXIGE = os.environ.get('ASYNCVNC_LIVE') == '1'
MOT_DE_PASSE = 'secret12'


def _port_libre() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _attendre_port(port: int, delai: float = 10.0) -> None:
    fin = time.monotonic() + delai
    while time.monotonic() < fin:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"x11vnc n'écoute pas sur {port}")


@unittest.skipUnless(OUTILS or EXIGE, 'x11vnc/Xvfb absents (ASYNCVNC_LIVE=1 pour exiger)')
class TestX11vnc(unittest.TestCase):
    """Un Xvfb pour toute la classe, un x11vnc par test."""

    @classmethod
    def setUpClass(cls):
        if not OUTILS:
            raise AssertionError('ASYNCVNC_LIVE=1 mais x11vnc, Xvfb ou xsetroot est absent')
        cls.tmp = tempfile.TemporaryDirectory()
        cls.display = f':{_port_libre() % 1000 + 100}'
        cls.xvfb = subprocess.Popen(
            ['Xvfb', cls.display, '-screen', '0', '320x240x24', '-nolisten', 'tcp'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1)
        cls.pwfile = os.path.join(cls.tmp.name, 'passwd')
        subprocess.run(
            ['x11vnc', '-storepasswd', MOT_DE_PASSE, cls.pwfile], check=True, capture_output=True
        )

    @classmethod
    def tearDownClass(cls):
        cls.xvfb.terminate()
        cls.xvfb.wait(5)
        cls.tmp.cleanup()

    def setUp(self):
        self.serveurs: list[subprocess.Popen] = []

    def tearDown(self):
        for p in self.serveurs:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()

    def _x11vnc(self, *args: str) -> None:
        securite = [] if '-rfbauth' in args else ['-nopw']
        self.serveurs.append(
            subprocess.Popen(
                ['x11vnc', '-display', self.display, '-quiet', *securite, *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )

    def _serveur(self, *args: str) -> int:
        port = _port_libre()
        self._x11vnc('-rfbport', str(port), '-forever', '-shared', *args)
        _attendre_port(port)
        return port

    async def _session(self, cm) -> tuple[tuple, tuple]:
        async with cm as client:
            image = await asyncio.wait_for(client.screenshot(), 15)
            return client.protocol_version, image.shape

    def _connect(self, port: int, password: str | None = None):
        return asyncio.run(
            asyncio.wait_for(
                self._session(asyncvnc2.connect('127.0.0.1', port, password=password)), 20
            )
        )

    def _intro(self, port: int) -> bytes:
        with socket.create_connection(('127.0.0.1', port), timeout=5) as s:
            return s.recv(12)

    # --- #28 : repli de version contre un vrai serveur -----------------

    def test_serveur_3_8(self):
        port = self._serveur()
        self.assertEqual(self._intro(port), b'RFB 003.008\n')
        self.assertEqual(self._connect(port), ((3, 8), (240, 320, 4)))

    def test_serveur_3_3_sans_authentification(self):
        port = self._serveur('-rfbversion', '3.3')
        self.assertEqual(self._intro(port), b'RFB 003.003\n')
        self.assertEqual(self._connect(port), ((3, 3), (240, 320, 4)))

    def test_serveur_3_3_authentification_vnc(self):
        port = self._serveur('-rfbversion', '3.3', '-rfbauth', self.pwfile)
        self.assertEqual(self._connect(port, MOT_DE_PASSE), ((3, 3), (240, 320, 4)))

    def test_serveur_3_3_mauvais_mot_de_passe(self):
        port = self._serveur('-rfbversion', '3.3', '-rfbauth', self.pwfile)
        with self.assertRaises(PermissionError):
            self._connect(port, 'mauvais1')

    def test_serveur_3_7_authentification_vnc(self):
        port = self._serveur('-rfbversion', '3.7', '-rfbauth', self.pwfile)
        self.assertEqual(self._intro(port), b'RFB 003.007\n')
        self.assertEqual(self._connect(port, MOT_DE_PASSE), ((3, 7), (240, 320, 4)))

    def test_serveur_3_7_mauvais_mot_de_passe(self):
        port = self._serveur('-rfbversion', '3.7', '-rfbauth', self.pwfile)
        with self.assertRaises(PermissionError):
            self._connect(port, 'mauvais1')

    # --- #24 : encodage Ultra (LZO) servi par libvncserver --------------

    def _capture(self, port: int, encodings: list) -> tuple[np.ndarray, list]:
        rects: list = []
        original = asyncvnc2.Video.process_ultra

        async def espion(video, reader, x, y, w, h):
            rects.append((x, y, w, h))
            return await original(video, reader, x, y, w, h)

        async def scenario():
            async with asyncvnc2.connect('127.0.0.1', port, encodings=encodings) as client:
                return np.asarray(await asyncio.wait_for(client.screenshot(), 30)).copy()

        asyncvnc2.Video.process_ultra = espion
        try:
            return asyncio.run(scenario()), rects
        finally:
            asyncvnc2.Video.process_ultra = original

    def test_ultra_identique_au_raw(self):
        # Contenu non uniforme (motif de xsetroot) : une image noire ne
        # prouverait rien sur le décodage LZO des correspondances.
        subprocess.run(
            [
                'xsetroot',
                '-display',
                self.display,
                '-mod',
                '7',
                '5',
                '-fg',
                'orange',
                '-bg',
                'navy',
            ],
            check=True,
        )
        port = self._serveur()
        ultra, rects = self._capture(port, [asyncvnc2.Enc.ULTRA])
        raw, _ = self._capture(port, [asyncvnc2.Enc.RAW])
        self.assertTrue(rects, "le serveur n'a envoyé aucun rectangle Ultra")
        self.assertGreaterEqual(sum(w * h for _, _, w, h in rects), 320 * 240)
        self.assertGreater(len(np.unique(ultra[..., :3].reshape(-1, 3), axis=0)), 1)
        self.assertTrue(np.array_equal(ultra[..., :3], raw[..., :3]))

    # --- #27 : connexion inversée initiée par un vrai serveur ----------

    def _inverse(self, *args: str, password: str | None = None):
        port = _port_libre()

        async def scenario():
            session = asyncio.create_task(
                self._session(asyncvnc2.listen('127.0.0.1', port, password=password))
            )
            await asyncio.sleep(0.5)  # listener ouvert avant que x11vnc compose
            self._x11vnc('-connect_or_exit', f'127.0.0.1:{port}', '-rfbport', '0', *args)
            return await asyncio.wait_for(session, 20)

        return asyncio.run(scenario())

    def test_inverse_3_8(self):
        self.assertEqual(self._inverse(), ((3, 8), (240, 320, 4)))

    def test_inverse_3_3(self):
        self.assertEqual(self._inverse('-rfbversion', '3.3'), ((3, 3), (240, 320, 4)))

    def test_inverse_authentification_vnc(self):
        self.assertEqual(
            self._inverse('-rfbauth', self.pwfile, password=MOT_DE_PASSE), ((3, 8), (240, 320, 4))
        )

    def test_inverse_mauvais_mot_de_passe(self):
        with self.assertRaises(PermissionError):
            self._inverse('-rfbauth', self.pwfile, password='mauvais1')


if __name__ == '__main__':
    unittest.main()
