"""
Tests hors ligne des décodeurs de Video (issue #54, palier 2 de couverture).

Chaque test fabrique à la main les octets d'un rectangle RFB, les fournit à
un StreamReader asyncio puis vérifie les pixels obtenus. Aucun serveur VNC,
aucun réseau.
"""

from __future__ import annotations

import asyncio
import struct
import sys
import unittest
import zlib
from unittest import mock

import numpy as np

import asyncvnc2
from asyncvnc2 import (
    Enc,
    Video,
    _rle_packedbits,
    _rle_rle,
    _tight_decode_image,
    _tight_gradient_filter,
    _tight_palette_filter,
)


def lecteur(donnees: bytes) -> asyncio.StreamReader:
    """StreamReader pré-rempli puis fermé (doit être créé dans une boucle)."""
    r = asyncio.StreamReader()
    r.feed_data(donnees)
    r.feed_eof()
    return r


def video(donnees: bytes | None = None, **champs) -> Video:
    """Video minimal ; sans données, pas de lecteur (utilisable hors boucle)."""
    valeurs = {
        'reader': None if donnees is None else lecteur(donnees),
        'writer': None,
        'decompress': zlib.decompressobj(),
        'name': 'test',
        'width': 32,
        'height': 32,
        'mode': 'rgba',
    }
    valeurs.update(champs)
    return Video(**valeurs)


def entete(x, y, w, h, encodage) -> bytes:
    """En-tête de rectangle FramebufferUpdate (encodage signé S32)."""
    return struct.pack('>HHHHi', x, y, w, h, encodage)


def rouge_vert_bleu(pixel) -> tuple:
    return tuple(int(v) for v in pixel[:3])


def zlib_flux(donnees: bytes, flux=None) -> tuple[bytes, object]:
    """Compresse avec un flux zlib persistant (Z_SYNC_FLUSH, comme les serveurs)."""
    flux = flux or zlib.compressobj()
    return flux.compress(donnees) + flux.flush(zlib.Z_SYNC_FLUSH), flux


def longueur_tight(n: int) -> bytes:
    """Longueur « compacte » Tight sur 1 à 3 octets."""
    octets = [n & 0x7F]
    if n > 0x7F:
        octets[0] |= 0x80
        octets.append((n >> 7) & 0x7F)
        if n > 0x3FFF:
            octets[1] |= 0x80
            octets.append(n >> 14)
    return bytes(octets)


class _Asynchrone(unittest.TestCase):
    def lancer(self, coro):
        return asyncio.run(coro)


class TestTight(_Asynchrone):
    def test_fill(self):
        async def scenario():
            v = video(entete(1, 2, 3, 2, Enc.TIGHT.value) + b'\x80' + b'\x0a\x14\x1e')
            self.assertFalse(await v.read())
            return v

        v = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[2, 1]), (10, 20, 30))
        self.assertEqual(rouge_vert_bleu(v.data[3, 3]), (10, 20, 30))
        self.assertEqual(int(v.data[3, 3, 3]), 255)

    def test_controle_invalide(self):
        async def scenario():
            v = video(b'\xa0')
            await v.process_tight(v.reader, 0, 0, 1, 1)

        with self.assertRaisesRegex(ValueError, 'compression-control'):
            self.lancer(scenario())

    def test_jpeg_sans_pillow(self):
        async def scenario():
            v = video(b'\x90' + longueur_tight(4) + b'abcd')
            await v.process_tight(v.reader, 0, 0, 1, 1)

        with (
            mock.patch.dict(sys.modules, {'PIL': None}),
            self.assertRaisesRegex(RuntimeError, 'Pillow'),
        ):
            self.lancer(scenario())

    def test_jpeg_longueur_au_dela_du_plafond(self):
        async def scenario():
            v = video(b'\x90' + longueur_tight(0x3FFFFF))
            await v.process_tight(v.reader, 0, 0, 1, 1)

        with (
            mock.patch.object(asyncvnc2, '_MAX_ALLOC_BYTES', 1000),
            self.assertRaisesRegex(ValueError, 'plafond'),
        ):
            self.lancer(scenario())

    def test_copie_brute_petite_taille_sans_zlib(self):
        # 2x1 pixels = 6 octets (< 12) : envoyés tels quels, sans longueur.
        async def scenario():
            v = video(b'\x00' + bytes([1, 2, 3, 4, 5, 6]))
            await v.process_tight(v.reader, 0, 0, 2, 1)
            return v

        v = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[0, 1]), (4, 5, 6))

    def test_copie_compressee_et_reinitialisation_du_flux(self):
        pixels = bytes(range(48))  # 4x4 pixels RGB
        comp, _ = zlib_flux(pixels)

        async def scenario():
            # ctl 0x11 : réinitialise le flux 0 (bit 0), flux 1 (bits 4-5), sans filtre.
            v = video(b'\x11' + longueur_tight(len(comp)) + comp)
            await v.process_tight(v.reader, 0, 0, 4, 4)
            return v

        v = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[3, 3]), (45, 46, 47))

    def test_filtre_palette_deux_couleurs(self):
        # 8x2 pixels, 1 bit par pixel : 1 octet par ligne, 2 octets (< 12) en clair.
        palette = b'\x00\x00\x00' + b'\xff\x00\x00'

        async def scenario():
            v = video(b'\x40' + b'\x01' + b'\x01' + palette + b'\xf0\x0f')
            await v.process_tight(v.reader, 0, 0, 8, 2)
            return v

        v = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[0, 0]), (255, 0, 0))
        self.assertEqual(rouge_vert_bleu(v.data[0, 7]), (0, 0, 0))
        self.assertEqual(rouge_vert_bleu(v.data[1, 7]), (255, 0, 0))

    def test_filtre_palette_trois_couleurs_compressee(self):
        palette = b'\x01\x01\x01' + b'\x02\x02\x02' + b'\x03\x03\x03'
        indices = bytes([0, 1, 2, 0] * 4)  # 4x4, 1 octet par pixel = 16 octets (>= 12)
        comp, _ = zlib_flux(indices)

        async def scenario():
            v = video(b'\x40\x01\x02' + palette + longueur_tight(len(comp)) + comp)
            await v.process_tight(v.reader, 0, 0, 4, 4)
            return v

        v = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[2, 2]), (3, 3, 3))

    def test_filtre_gradient(self):
        # 2x2 : différences nulles => toutes les prédictions donnent 0, sauf le 1er pixel.
        brut = bytes([10, 20, 30]) + bytes(9)

        async def scenario():
            v = video(b'\x40\x02' + longueur_tight(len(brut)) + zlib_flux(brut)[0])
            await v.process_tight(v.reader, 0, 0, 2, 2)
            return v

        v = self.lancer(scenario())
        # pixel (0,1) = gauche ; (1,0) = haut ; (1,1) = gauche + haut - haut-gauche
        for py, px in ((0, 0), (0, 1), (1, 0), (1, 1)):
            self.assertEqual(rouge_vert_bleu(v.data[py, px]), (10, 20, 30))

    def test_filtre_inconnu(self):
        async def scenario():
            v = video(b'\x40\x07')
            await v.process_tight(v.reader, 0, 0, 1, 1)

        with self.assertRaisesRegex(ValueError, 'filter-id'):
            self.lancer(scenario())

    def test_tight_png_meme_decodeur(self):
        async def scenario():
            v = video(entete(0, 0, 1, 1, Enc.TIGHT_PNG.value) + b'\x80' + b'\x01\x02\x03')
            await v.read()
            return v

        v = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[0, 0]), (1, 2, 3))


class TestFiltresTight(unittest.TestCase):
    def test_gradient_bornes_0_et_255(self):
        # Ligne 1 : 250 puis +10 (prédiction 250, résultat 4 modulo 256).
        # Ligne 2 : la prédiction gauche + haut - haut-gauche sort de [0, 255].
        brut = bytes([250, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0])
        sortie = _tight_gradient_filter(brut, 2, 2)
        self.assertEqual(sortie[0:3], bytes([250, 0, 0]))
        self.assertEqual(sortie[3:6], bytes([4, 0, 0]))
        self.assertEqual(len(sortie), 12)

    def test_gradient_prediction_negative_bornee_a_zero(self):
        # haut-gauche = 200, gauche = haut = 0 => prédiction -200 ramenée à 0.
        brut = bytes([200, 0, 0, 56, 0, 0, 56, 0, 0, 7, 0, 0])
        sortie = _tight_gradient_filter(brut, 2, 2)
        self.assertEqual(sortie[9], 7)

    def test_palette_un_bit_et_huit_bits(self):
        pal2 = [b'\x00\x00\x00', b'\x09\x09\x09']
        self.assertEqual(_tight_palette_filter(b'\x80', 2, 1, pal2), b'\x09\x09\x09\x00\x00\x00')
        pal3 = pal2 + [b'\x05\x05\x05']
        self.assertEqual(_tight_palette_filter(b'\x02', 1, 1, pal3), b'\x05\x05\x05')

    def test_decodage_image_avec_pillow_simule(self):
        image = mock.Mock()
        image.convert.return_value = np.zeros((1, 4, 3), 'B')  # forme à corriger
        faux_pil = mock.Mock()
        faux_pil.Image.open.return_value = image
        with mock.patch.dict(sys.modules, {'PIL': faux_pil, 'PIL.Image': faux_pil.Image}):
            sortie = _tight_decode_image(b'png', 2, 2)
        self.assertEqual(sortie.shape, (2, 2, 3))


class TestHextileEtZlibHex(_Asynchrone):
    def test_hextile_fond_premier_plan_et_sous_rectangles(self):
        # Tuile 4x4 : fond (bit 2) + premier plan (bit 4) + 2 sous-rectangles (bit 8).
        fond = b'\x01\x01\x01\xff'
        devant = b'\x02\x02\x02\xff'
        corps = bytes([2 | 4 | 8]) + fond + devant + b'\x02' + b'\x00\x00' + b'\x33\x00'

        async def scenario():
            v = video(entete(0, 0, 4, 4, Enc.HEXTILE.value) + corps)
            await v.read()
            return v

        v = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[0, 0]), (2, 2, 2))
        self.assertEqual(rouge_vert_bleu(v.data[3, 3]), (2, 2, 2))  # 2e sous-rect : (3, 3), 1x1
        self.assertEqual(rouge_vert_bleu(v.data[2, 2]), (1, 1, 1))

    def test_hextile_sous_rectangles_colores_et_tuile_brute(self):
        # 20x4 => deux tuiles (16 + 4). 1re : brute (bit 1). 2e : fond + sous-rect coloré.
        brute = bytes(range(16)) * (16 * 4 // 16) * 4  # 16x4x4 = 256 octets
        brute = brute[: 16 * 4 * 4]
        fond = b'\x05\x05\x05\xff'
        coloree = bytes([2 | 8 | 16]) + fond + b'\x01' + b'\x09\x09\x09\xff' + b'\x11' + b'\x00'

        async def scenario():
            v = video(bytes([1]) + brute + coloree)
            await v.process_hextile(v.reader, 0, 0, 20, 4)
            return v

        v = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[1, 17]), (9, 9, 9))
        self.assertEqual(rouge_vert_bleu(v.data[0, 16]), (5, 5, 5))

    def test_hextile_sans_fond(self):
        async def scenario():
            v = video(b'\x00')
            await v.process_hextile(v.reader, 0, 0, 2, 2)

        with self.assertRaisesRegex(ValueError, 'background'):
            self.lancer(scenario())

    def test_zlibhex_trois_sortes_de_tuiles(self):
        # 48x1 => trois tuiles 16x1 : ZlibRaw (0x20), Zlib (0x40 + fond), Raw (0x01) ;
        # puis 16x1 de plus en Hextile simple qui réutilise le fond.
        brut = b'\x07\x07\x07\xff' * 16
        comp_brut, _ = zlib_flux(brut)
        fond = b'\x08\x08\x08\xff'
        comp_tuile, _ = zlib_flux(fond)
        donnees = (
            b'\x20'
            + struct.pack('>H', len(comp_brut))
            + comp_brut
            + bytes([0x40 | 2])
            + struct.pack('>H', len(comp_tuile))
            + comp_tuile
            + b'\x01'
            + b'\x09\x09\x09\xff' * 16
            + b'\x00'
        )

        async def scenario():
            v = video(entete(0, 0, 64, 1, Enc.ZLIBHEX.value) + donnees, width=64)
            await v.read()
            return v

        v = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[0, 0]), (7, 7, 7))
        self.assertEqual(rouge_vert_bleu(v.data[0, 20]), (8, 8, 8))
        self.assertEqual(rouge_vert_bleu(v.data[0, 40]), (9, 9, 9))
        self.assertEqual(rouge_vert_bleu(v.data[0, 60]), (8, 8, 8))


class TestRleZrle(_Asynchrone):
    def test_packedbits_palette_puis_reutilisation(self):
        async def scenario():
            palette: list = []
            # 2 couleurs, 1 bit : ligne 0b10 => [c1, c0]
            r = lecteur(b'\x01\x01\x01' + b'\x02\x02\x02' + b'\x80' + b'\x40')
            premier = await _rle_packedbits(r, 2, 1, 2, palette)
            # subencoding 127 : réutilise la palette précédente
            second = await _rle_packedbits(r, 2, 1, 127, palette)
            return premier, second

        premier, second = self.lancer(scenario())
        self.assertEqual(premier, b'\x02\x02\x02\x01\x01\x01')
        self.assertEqual(second, b'\x01\x01\x01\x02\x02\x02')

    def test_packedbits_deux_et_quatre_bits(self):
        async def scenario():
            pal4 = b''.join(bytes([i] * 3) for i in range(4))
            pal5 = b''.join(bytes([i] * 3) for i in range(5))
            r = lecteur(pal4 + b'\xe4' + pal5 + b'\x41')
            a = await _rle_packedbits(r, 4, 1, 4, [])
            b = await _rle_packedbits(r, 2, 1, 5, [])
            return a, b

        a, b = self.lancer(scenario())
        self.assertEqual(a, b'\x03' * 3 + b'\x02' * 3 + b'\x01' * 3 + b'\x00' * 3)
        self.assertEqual(b, b'\x04' * 3 + b'\x01' * 3)

    def test_rle_simple_et_palette(self):
        async def scenario():
            # 128 : RLE simple, couleur + longueur (255 + 1, plus 1 => 257 pixels)
            r = lecteur(b'\x0a\x0b\x0c' + b'\xff\x01')
            simple = await _rle_rle(r, 257, 1, 128, [])
            palette: list = []
            # 130 : palette de 2 ; index 1 seul, puis index 0 + RLE (128) longueur 2
            r = lecteur(b'\x01\x01\x01\x02\x02\x02' + b'\x01' + b'\x80\x01')
            pal = await _rle_rle(r, 3, 1, 130, palette)
            # 129 : réutilise la palette
            r = lecteur(b'\x00\x01')
            reprise = await _rle_rle(r, 2, 1, 129, palette)
            return simple, pal, reprise

        simple, pal, reprise = self.lancer(scenario())
        self.assertEqual(simple, b'\x0a\x0b\x0c' * 257)
        self.assertEqual(pal, b'\x02\x02\x02' + b'\x01\x01\x01' * 2)
        self.assertEqual(reprise, b'\x01\x01\x01' + b'\x02\x02\x02')

    def test_rle_trop_de_pixels(self):
        async def scenario():
            await _rle_rle(lecteur(b'\x0a\x0b\x0c\x05'), 2, 1, 128, [])

        with self.assertRaisesRegex(ValueError, 'Too many pixels'):
            self.lancer(scenario())

    def test_trle_tuiles_brute_unie_et_rle(self):
        # TRLE 3x1 : une tuile, subencoding 0 (brut, 3 octets/pixel)
        async def scenario():
            v = video(entete(0, 0, 3, 1, Enc.TRLE.value) + b'\x00' + bytes(range(9)))
            await v.read()
            v2 = video(entete(0, 0, 2, 2, Enc.TRLE.value) + b'\x01' + b'\x04\x05\x06')
            await v2.read()
            v3 = video(entete(0, 0, 2, 1, Enc.TRLE.value) + b'\x80' + b'\x07\x08\x09\x01')
            await v3.read()
            v4 = video(
                entete(0, 0, 2, 1, Enc.TRLE.value) + b'\x02' + b'\x01' * 3 + b'\x02' * 3 + b'\x40'
            )
            await v4.read()
            return v, v2, v3, v4

        v, v2, v3, v4 = self.lancer(scenario())
        self.assertEqual(rouge_vert_bleu(v.data[0, 2]), (6, 7, 8))
        self.assertEqual(rouge_vert_bleu(v2.data[1, 1]), (4, 5, 6))
        self.assertEqual(rouge_vert_bleu(v3.data[0, 1]), (7, 8, 9))
        self.assertEqual(rouge_vert_bleu(v4.data[0, 0]), (1, 1, 1))  # bits 0b01
        self.assertEqual(rouge_vert_bleu(v4.data[0, 1]), (2, 2, 2))

    def test_trle_sous_encodage_reserve(self):
        async def scenario():
            v = video(b'\x20')
            await v.process_xrle(v.reader, 0, 0, 1, 1, 16)

        with self.assertRaisesRegex(ValueError, 'réservée'):
            self.lancer(scenario())


class TestCurseurs(_Asynchrone):
    def test_rich_cursor(self):
        # 2x1, mode bgra : pixels B,G,R,A ; masque 0b10 (seul le 1er pixel opaque)
        pixels = b'\x03\x02\x01\x00' + b'\x06\x05\x04\x00'

        async def scenario():
            v = video(entete(1, 0, 2, 1, Enc.CURSOR.value) + pixels + b'\x80', mode='bgra')
            await v.read()
            return v

        v = self.lancer(scenario())
        c = v.cursor
        self.assertEqual((c.x, c.y, c.width, c.height), (1, 0, 2, 1))
        self.assertEqual(rouge_vert_bleu(c.data[0, 0]), (1, 2, 3))
        self.assertEqual(int(c.data[0, 0, 3]), 255)
        self.assertEqual(int(c.data[0, 1, 3]), 0)

    def test_x_cursor(self):
        async def scenario():
            corps = b'\xff\x00\x00' + b'\x00\x00\xff' + b'\x80' + b'\xc0'
            v = video(entete(0, 0, 2, 1, Enc.X_CURSOR.value) + corps)
            await v.read()
            return v

        c = self.lancer(scenario()).cursor
        self.assertEqual(rouge_vert_bleu(c.data[0, 0]), (255, 0, 0))
        self.assertEqual(rouge_vert_bleu(c.data[0, 1]), (0, 0, 255))
        self.assertTrue((c.data[0, :, 3] == 255).all())

    def test_cursor_with_alpha(self):
        async def scenario():
            corps = struct.pack('>i', 0) + b'\x01\x02\x03\x80'
            v = video(entete(0, 0, 1, 1, Enc.CURSOR_WITH_ALPHA.value) + corps)
            await v.read()
            return v

        c = self.lancer(scenario()).cursor
        self.assertEqual(tuple(int(b) for b in c.data[0, 0]), (1, 2, 3, 128))

    def test_cursor_with_alpha_sous_encodage_refuse(self):
        async def scenario():
            v = video(struct.pack('>i', 7))
            await v.process_cursor_with_alpha(0, 0, 1, 1)

        with self.assertRaisesRegex(ValueError, 'sub-encoding 7'):
            self.lancer(scenario())

    def test_curseurs_vides(self):
        async def scenario():
            curseurs = []
            for enc, corps in (
                (Enc.CURSOR, b''),
                (Enc.X_CURSOR, b''),
                (Enc.CURSOR_WITH_ALPHA, struct.pack('>i', 0)),
            ):
                v = video(entete(0, 0, 0, 0, enc.value) + corps)
                await v.read()
                curseurs.append(v.cursor)
            return curseurs

        for c in self.lancer(scenario()):
            self.assertEqual(c.data.shape, (0, 0, 4))

    def test_curseur_trop_grand(self):
        async def scenario():
            v = video()
            await v.process_cursor(0, 0, 100, 100)

        with (
            mock.patch.object(asyncvnc2, '_MAX_ALLOC_BYTES', 10),
            self.assertRaisesRegex(ValueError, 'Rich Cursor'),
        ):
            self.lancer(scenario())


class TestTailleEcran(_Asynchrone):
    @staticmethod
    def ecran(identifiant, x, y, w, h, drapeaux=0) -> bytes:
        return struct.pack('>IHHHHI', identifiant, x, y, w, h, drapeaux)

    def test_extended_desktop_size_redimensionne(self):
        corps = (
            b'\x02\x00\x00\x00' + self.ecran(1, 0, 0, 640, 480) + self.ecran(2, 640, 0, 640, 480)
        )

        async def scenario():
            v = video(entete(0, 0, 1280, 480, Enc.EXTENDED_DESKTOP_SIZE.value) + corps)
            v.data = np.zeros((32, 32, 4), 'B')
            await v.read()
            return v

        v = self.lancer(scenario())
        self.assertEqual((v.width, v.height), (1280, 480))
        self.assertIsNone(v.data)
        self.assertEqual([s.id for s in v.screens], [1, 2])
        self.assertEqual(v.screens[1].x, 640)

    def test_extended_desktop_size_refus_garde_la_taille(self):
        # raison 1 (réponse à notre SetDesktopSize), statut 3 (refus) : pas de redimensionnement.
        async def scenario():
            v = video(entete(1, 3, 800, 600, Enc.EXTENDED_DESKTOP_SIZE.value) + b'\x00' * 4)
            await v.read()
            return v

        v = self.lancer(scenario())
        self.assertEqual((v.width, v.height), (32, 32))
        self.assertEqual(v.screens, [])

    def test_desktop_size_et_last_rect(self):
        async def scenario():
            v = video(
                entete(0, 0, 100, 50, Enc.DESKTOP_SIZE.value)
                + entete(0, 0, 0, 0, Enc.LAST_RECT.value)
            )
            self.assertFalse(await v.read())
            self.assertTrue(await v.read())
            return v

        v = self.lancer(scenario())
        self.assertEqual((v.width, v.height), (100, 50))

    def test_encodage_h264_refuse(self):
        async def scenario():
            v = video(entete(0, 0, 1, 1, asyncvnc2._H264_ENCODING))
            await v.read()

        with self.assertRaises(NotImplementedError):
            self.lancer(scenario())


class TestLectureImage(unittest.TestCase):
    def test_as_rgba_selon_le_mode(self):
        for mode, attendu in (
            ('rgba', (1, 2, 3, 4)),
            ('abgr', (4, 3, 2, 1)),
            ('bgra', (3, 2, 1, 4)),
            ('argb', (2, 3, 4, 1)),
        ):
            with self.subTest(mode=mode):
                v = video(width=2, height=1, mode=mode)
                self.assertEqual(v.as_rgba().shape, (1, 2, 4))  # tampon vide : zéros
                self.assertFalse(v.as_rgba().any())
                v.data = np.array([[[1, 2, 3, 4], [0, 0, 0, 0]]], 'B')
                self.assertEqual(tuple(int(b) for b in v.as_rgba()[0, 0]), attendu)

    def test_detect_screens(self):
        v = video(width=8, height=4)
        self.assertEqual(v.detect_screens(), [])
        v.data = np.zeros((4, 8, 4), 'B')
        v.data[0:4, 0:4, 3] = 255  # écran gauche 4x4
        v.data[0:2, 5:8, 3] = 255  # écran droit 3x2
        ecrans = sorted((s.x, s.y, s.width, s.height) for s in v.detect_screens())
        self.assertEqual(ecrans, [(0, 0, 4, 4), (5, 0, 3, 2)])


if __name__ == '__main__':
    unittest.main()
