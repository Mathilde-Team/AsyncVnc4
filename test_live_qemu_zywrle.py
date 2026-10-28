# SPDX-License-Identifier: GPL-3.0-or-later
"""ZYWRLE contre un vrai serveur : le VNC intégré de QEMU (issue #22).

QEMU n'envoie de rectangles ZYWRLE (17) que si le client a annoncé une qualité JPEG
0-8 et que le serveur tourne avec ``-vnc ...,lossy=on`` ; le niveau d'ondelettes
(3 - qualité // 3) n'est jamais transmis. Le contenu affiché est fabriqué par un
secteur d'amorçage de 47 octets (mode VGA 13h, motif ``(x*y + (x^y)) >> 1``) pour
que les coefficients d'ondelettes soient réellement non nuls. La vérité terrain est
le ``screendump`` du moniteur QEMU, indépendant du VNC.

Requiert `qemu-system-x86_64`. Sans lui, la suite est sautée, sauf si
`ASYNCVNC_LIVE=1`.
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
from asyncvnc2 import Enc, EncList

OUTIL = shutil.which('qemu-system-x86_64') is not None
EXIGE = os.environ.get('ASYNCVNC_LIVE') == '1'

# Assemblé avec nasm depuis : mov ax,0x13 / int 0x10 / es=0xA000 / pour y<200, x<320 :
# al = (x*y + (x^y)) >> 1 ; stosb / hlt. Voir docs/sessions/session-25-2026-10-24.md.
SECTEUR = bytes.fromhex(
    'b81300cd10b800a08ec031ff31d231c989c80fafc289cb31d301d8d1e8aa4181f9400172eb4281fac80072e2f4ebfd'
)


def _port_libre() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _lire_ppm(chemin: str) -> np.ndarray:
    """Lit le PPM binaire (P6, 8 bits) produit par ``screendump``."""
    with open(chemin, 'rb') as f:
        donnees = f.read()
    champs: list[bytes] = []
    pos = 0
    while len(champs) < 4:
        while donnees[pos : pos + 1].isspace():
            pos += 1
        if donnees[pos : pos + 1] == b'#':
            pos = donnees.index(b'\n', pos) + 1
            continue
        fin = pos
        while not donnees[fin : fin + 1].isspace():
            fin += 1
        champs.append(donnees[pos:fin])
        pos = fin
    largeur, hauteur = int(champs[1]), int(champs[2])
    pixels = donnees[pos + 1 : pos + 1 + largeur * hauteur * 3]
    return np.frombuffer(pixels, 'B').reshape(hauteur, largeur, 3)


def _psnr(a: np.ndarray, b: np.ndarray) -> float:
    eqm = float(((a.astype(int) - b.astype(int)) ** 2).mean())
    return float('inf') if eqm == 0 else 10 * np.log10(255**2 / eqm)


@unittest.skipUnless(OUTIL or EXIGE, 'QEMU absent (ASYNCVNC_LIVE=1 pour exiger)')
class TestQemuZywrle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dossier = tempfile.TemporaryDirectory()
        image = os.path.join(cls.dossier.name, 'amorce.img')
        with open(image, 'wb') as f:
            f.write(SECTEUR.ljust(510, b'\x00') + b'\x55\xaa')
            f.write(b'\x00' * (1474560 - 512))
        cls.moniteur = os.path.join(cls.dossier.name, 'moniteur.sock')
        cls.port = _port_libre()
        cls.qemu = subprocess.Popen(
            [
                'qemu-system-x86_64', '-M', 'pc', '-m', '32', '-no-reboot', '-display', 'none',
                '-drive', f'file={image},format=raw,if=floppy',
                '-vnc', f'127.0.0.1:{cls.port - 5900},lossy=on',
                '-monitor', f'unix:{cls.moniteur},server,nowait',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )  # fmt: skip
        cls.reference = cls._attendre_motif()

    @classmethod
    def tearDownClass(cls):
        cls.qemu.terminate()
        cls.qemu.wait(10)
        cls.dossier.cleanup()

    @classmethod
    def _screendump(cls) -> np.ndarray:
        chemin = os.path.join(cls.dossier.name, 'ecran.ppm')
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(cls.moniteur)
            s.settimeout(5)
            s.recv(65536)  # bannière du moniteur
            s.sendall(f'screendump {chemin}\n'.encode())
            fin = time.monotonic() + 5
            while not os.path.exists(chemin) and time.monotonic() < fin:
                time.sleep(0.1)
            time.sleep(0.3)
        return _lire_ppm(chemin)

    @classmethod
    def _attendre_motif(cls) -> np.ndarray:
        """Attend que le secteur d'amorçage ait dessiné son motif (640x400, varié)."""
        fin = time.monotonic() + 30
        while time.monotonic() < fin:
            if os.path.exists(cls.moniteur):
                try:
                    ecran = cls._screendump()
                except (OSError, ValueError, IndexError):
                    ecran = None
                if (
                    ecran is not None
                    and ecran.shape == (400, 640, 3)
                    and len(np.unique(ecran.reshape(-1, 3), axis=0)) > 32
                ):
                    return ecran
            time.sleep(0.5)
        raise AssertionError("le motif du secteur d'amorçage n'est jamais apparu")

    def _capture(self, encodings: list, qualite: int | None) -> np.ndarray:
        async def session():
            async with asyncvnc2.connect(
                '127.0.0.1', self.port, encodings=EncList(encodings), jpeg_quality=qualite
            ) as client:
                for _ in range(2):
                    image = await asyncio.wait_for(client.screenshot(), 20)
                return image[..., :3]

        return asyncio.run(asyncio.wait_for(session(), 60))

    def test_zrle_sans_perte_identique_au_screendump(self):
        image = self._capture([Enc.ZRLE], None)
        self.assertTrue(np.array_equal(image, self.reference))

    def test_zywrle_qualite_9_retombe_sans_perte(self):
        # QEMU désactive les ondelettes à la qualité 9 (et envoie du ZRLE, 16).
        image = self._capture([Enc.ZYWRLE, Enc.ZRLE], 9)
        self.assertTrue(np.array_equal(image, self.reference))

    def test_zywrle_niveaux_1_2_3_coherents(self):
        # Avant le correctif, chaque capture levait ValueError (subencoding 17-126,
        # désynchronisation). Mesuré le 2026-10-24 (QEMU 10.2.1) : 55,9 / 26,0 / 21,1 dB.
        psnr = {
            q: _psnr(self._capture([Enc.ZYWRLE, Enc.ZRLE], q), self.reference) for q in (7, 4, 0)
        }
        self.assertGreater(psnr[7], 45, psnr)  # niveau 1
        self.assertGreater(psnr[4], 22, psnr)  # niveau 2
        self.assertGreater(psnr[0], 17, psnr)  # niveau 3
        self.assertGreater(psnr[7], psnr[4], psnr)
        self.assertGreater(psnr[4], psnr[0], psnr)


if __name__ == '__main__':
    unittest.main()
