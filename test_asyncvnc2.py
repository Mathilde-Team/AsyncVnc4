"""
Suite de tests pour asyncvnc2.py, limitée aux formats binaires déjà vérifiés
octet par octet en session interactive (voir features.md/CLAUDE.md) :
RRE, CoRRE, send_set_desktop_size(), send_xvp() (+ garde-fou confirm),
send_qemu_extended_key_event() et Extended Clipboard
(process_extended_clipboard()/send_clipboard_*(), cf. Enc.EXTENDED_CLIPBOARD).
Rejoue mécaniquement les scénarios déjà exécutés à la main pour qu'une
régression future soit détectée automatiquement, sans avoir besoin d'un vrai
serveur VNC.

Lancer avec : python3 -m unittest test_asyncvnc2 -v
"""

from __future__ import annotations

import asyncio
import hashlib
import unittest
import zlib

import numpy as np
from loguru import logger

import asyncvnc2
from asyncvnc2 import (
    CLIPBOARD_ACTION_CAPS,
    CLIPBOARD_ACTION_NOTIFY,
    CLIPBOARD_ACTION_PEEK,
    CLIPBOARD_ACTION_PROVIDE,
    CLIPBOARD_ACTION_REQUEST,
    CLIPBOARD_FORMAT_RTF,
    CLIPBOARD_FORMAT_TEXT,
    XVP_REBOOT,
    XVP_RESET,
    XVP_SHUTDOWN,
    Client,
    Clipboard,
    Enc,
    Keyboard,
    Mouse,
    Screen,
    UpdateType,
    Video,
    _lzo1x_decompress,
    _zywrle_synthesize,
)


def make_video(**overrides) -> Video:
    """
    Construit un Video minimal utilisable pour les tests, sans passer par
    Video.create() (qui a besoin d'une vraie négociation ServerInit/
    SetPixelFormat). Video est un @dataclass ordinaire -- l'instancier
    directement est suffisant pour exercer le décodage RRE/CoRRE, qui
    n'utilise que self.writer et self._update_rect().
    """
    fields = {
        'reader': None,
        'writer': _FakeWriter(),
        'decompress': None,
        'name': 'test',
        'width': 64,
        'height': 64,
        'mode': 'rgba',
    }
    fields.update(overrides)
    return Video(**fields)


def make_client(**overrides) -> Client:
    """
    Construit un Client minimal utilisable pour les tests. send_xvp(),
    send_set_desktop_size() et send_qemu_extended_key_event() vivent sur
    Client (pas Video) et n'utilisent que self.writer -- pas besoin d'une
    vraie négociation Client.create().
    """
    writer = _FakeWriter()
    video = make_video(writer=writer)
    fields = {
        'reader': None,
        'writer': writer,
        'clipboard': Clipboard(writer=writer),
        'keyboard': Keyboard(writer=writer),
        'mouse': Mouse(writer=writer),
        'video': video,
        'host_key': None,
    }
    fields.update(overrides)
    return Client(**fields)


class _FakeWriter:
    """Capture les octets écrits par writer.write() sans socket réel."""

    def __init__(self):
        self.sent = bytearray()

    def write(self, data: bytes):
        self.sent.extend(data)


def _reader_from(data: bytes) -> asyncio.StreamReader:
    """Construit un vrai asyncio.StreamReader pré-rempli avec `data`, pour
    exercer le code de décodage (read_int/readexactly) sans socket réel."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


class RRETests(unittest.IsolatedAsyncioTestCase):
    """process_rre() -- 1 fond + N sous-rectangles, champs 2 octets (RFC 6143 §7.7.4)."""

    async def test_background_only(self):
        video = make_video(width=4, height=3)
        bg = bytes([10, 20, 30, 255])
        stream = (0).to_bytes(4, 'big') + bg  # n=0 sous-rectangle
        await video.process_rre(_reader_from(stream), x=0, y=0, width=4, height=3)
        expected = np.ndarray((3, 4, 4), 'B', bg * 12)
        self.assertTrue((video.data[0:3, 0:4, :] == expected).all())

    async def test_one_subrectangle_2byte_fields(self):
        video = make_video(width=10, height=10)
        bg = bytes([0, 0, 0, 255])
        colour = bytes([255, 0, 0, 255])
        # sous-rectangle à (2,3), 4x5, avec des champs 2 octets (>255, pour
        # bien distinguer RRE de CoRRE si jamais les deux étaient confondus)
        sub = (
            colour
            + (2).to_bytes(2, 'big')
            + (3).to_bytes(2, 'big')
            + (4).to_bytes(2, 'big')
            + (5).to_bytes(2, 'big')
        )
        stream = (1).to_bytes(4, 'big') + bg + sub
        await video.process_rre(_reader_from(stream), x=0, y=0, width=10, height=10)
        # fond partout sauf le sous-rectangle
        self.assertTrue((video.data[0, 0, :] == np.frombuffer(bg, 'B')).all())
        self.assertTrue((video.data[3:8, 2:6, :] == np.frombuffer(colour, 'B')).all())


class CoRRETests(unittest.IsolatedAsyncioTestCase):
    """process_corre() -- comme RRE mais champs 1 octet, garde-fou 255x255."""

    async def test_one_subrectangle_1byte_fields(self):
        video = make_video(width=20, height=20)
        bg = bytes([1, 2, 3, 255])
        colour = bytes([9, 9, 9, 255])
        sub = colour + bytes([2, 3, 4, 5])  # sx, sy, sw, sh en 1 octet chacun
        stream = (1).to_bytes(4, 'big') + bg + sub
        await video.process_corre(_reader_from(stream), x=0, y=0, width=20, height=20)
        self.assertTrue((video.data[0, 0, :] == np.frombuffer(bg, 'B')).all())
        self.assertTrue((video.data[3:8, 2:6, :] == np.frombuffer(colour, 'B')).all())

    async def test_255x255_limit_enforced(self):
        video = make_video(width=256, height=100)
        with self.assertRaises(ValueError):
            await video.process_corre(_reader_from(b''), x=0, y=0, width=256, height=100)

    async def test_255x255_boundary_allowed(self):
        # 255x255 est la limite légale (pas 256) -- ne doit PAS lever.
        video = make_video(width=255, height=255)
        bg = bytes([0, 0, 0, 255])
        stream = (0).to_bytes(4, 'big') + bg
        await video.process_corre(_reader_from(stream), x=0, y=0, width=255, height=255)
        self.assertTrue((video.data[0, 0, :] == np.frombuffer(bg, 'B')).all())


class TightOrdreDesOctetsTests(unittest.IsolatedAsyncioTestCase):
    """
    TPIXEL (Tight) vaut toujours rouge, vert, bleu (rfbproto.rst § Tight Encoding),
    quel que soit le format de pixel ; le tampon, lui, suit l'ordre du format négocié.
    En 'bgra' (format par défaut de TigerVNC Xvnc et de x11vnc), rouge et bleu
    sortaient inversés jusqu'au 2026-10-24 (issue #27, trouvé contre un vrai Xvnc).
    """

    @staticmethod
    def _rect_tight(largeur: int, hauteur: int, corps: bytes) -> bytes:
        return (
            (0).to_bytes(2, 'big') * 2
            + largeur.to_bytes(2, 'big')
            + hauteur.to_bytes(2, 'big')
            + Enc.TIGHT.value.to_bytes(4, 'big', signed=True)
            + corps
        )

    async def _decoder(self, mode: str, largeur: int, hauteur: int, corps: bytes):
        video = make_video(width=largeur, height=hauteur, mode=mode)
        video.reader = _reader_from(self._rect_tight(largeur, hauteur, corps))
        await video.read()
        return video

    async def test_remplissage_dans_chaque_mode(self):
        for mode in ('rgba', 'bgra', 'argb', 'abgr'):
            with self.subTest(mode=mode):
                video = await self._decoder(mode, 2, 2, bytes([0x80, 0x20, 0x80, 0xC0]))
                rgba = video.as_rgba(0, 0, 2, 2)
                self.assertEqual(tuple(int(v) for v in rgba[1, 1]), (0x20, 0x80, 0xC0, 255))
                octets = video.data[0, 0]
                self.assertEqual(int(octets[mode.index('r')]), 0x20)
                self.assertEqual(int(octets[mode.index('b')]), 0xC0)

    async def test_compression_de_base_sans_filtre(self):
        # ctl 0x00 (flux 0, pas de filtre) ; 2x1 pixels = 6 octets < 12 : envoyés tels quels.
        pixels = bytes([1, 2, 3, 250, 251, 252])
        for mode in ('rgba', 'bgra'):
            with self.subTest(mode=mode):
                video = await self._decoder(mode, 2, 1, bytes([0x00]) + pixels)
                rgba = video.as_rgba(0, 0, 2, 1)
                self.assertEqual(rgba[0, :, :3].tobytes(), pixels)


def _lcg_octets(n: int, graine: int) -> np.ndarray:
    """Octets pseudo-aléatoires reproductibles (même suite que le générateur des vecteurs C)."""
    x = (np.arange(n, dtype=np.uint64) * np.uint64(2654435761) + np.uint64(graine)) & np.uint64(
        0xFFFFFFFF
    )
    x = (x * np.uint64(1103515245) + np.uint64(12345)) & np.uint64(0xFFFFFFFF)
    return ((x >> np.uint64(16)) & np.uint64(0xFF)).astype(np.uint8)


class ZywrleTests(unittest.IsolatedAsyncioTestCase):
    """
    Enc.ZYWRLE (17), issue #22 -- voir docs/sessions/session-25-2026-10-24.md.

    Format (QEMU ``ui/vnc-enc-zrle.c.inc``, libvncclient ``zrle.c``) : une tuile
    ZYWRLE est un octet de subencoding 0 suivi d'une tuile ZRLE imbriquée complète
    (n'importe quel subencoding) dont les pixels sont des coefficients d'ondelettes ;
    le niveau (1-3) vaut 3 - qualité JPEG // 3, jamais transmis. Vérifié ici :
      1) _zywrle_synthesize() identique octet par octet à ``ZYWRLE_SYNTHESIZE`` de
         libvncserver compilé (empreintes SHA-256 des sorties C, entrées
         reproductibles) ;
      2) décodage de bout en bout via Video.read() (tuile imbriquée Raw, unie,
         palette) et niveau déduit de la qualité ;
      3) sans qualité annoncée ou en ZRLE (16), une tuile 0 reste du Raw ;
      4) un subencoding 17-126 reste refusé (ValueError) ;
      5) Enc.default() n'annonce PAS ZYWRLE (opt-in, encodage avec perte).
    Le test contre un vrai QEMU est dans test_live_qemu_zywrle.py.
    """

    #: (largeur, hauteur, niveau, graine, sha256 de la sortie du C de libvncserver).
    VECTEURS_C = (
        (64, 64, 3, 1, '2454d82291abffb98ccb4a617aa9070300969b4da8cf85aa06e3049965dc980c'),
        (64, 64, 2, 2, '2461f9242759c57cbab849a8e16df6da30999185b420e427b10bebdcbcc9e82c'),
        (64, 64, 1, 3, '67159a1653b563b33119cdaa4e2144f4f4c6949435c54ab411a3c02e126ab32f'),
        (37, 21, 1, 4, 'a9d0416a4f99d0579cd34c0cbfad24f9ba0419a5c9e2409ee561e63b72d561bd'),
        (13, 64, 3, 5, '39b7a4ddac59d3f681d531e4d0cedcae0c1c31b9d9d6ef82ef70454fcb9d159f'),
        (64, 50, 2, 6, '3461c725e387f6b630c94d27d69e2a2d0219ee4d626a7adf8bb7bcd31726e098'),
        (9, 9, 3, 7, '9510a8baf83ce499f9790770c93bad20eeb9eca409b928324e225080b708bc31'),
        (5, 3, 3, 8, 'aed184345b181368313957ac0f37299a6f21dbcc392784ced265fde06f953899'),
        (1, 1, 1, 9, '67853ea2543ddf539279d7b78c09224b6c11b0f63a79125b0ea313097ee5e5cd'),
        (64, 8, 3, 10, '486541e75983c639859d8c8190c82989c19ee52075e8bb7116897812def7c461'),
    )

    #: Dégradé 4x4 passé par ``ZYWRLE_ANALYZE`` (C, niveau 1) puis ``ZYWRLE_SYNTHESIZE``.
    COEFFS_4X4 = bytes.fromhex(
        '000000000000000000000000000000000000000000000000'
        '000000000000000000000000e7bc5a50da5aabfc280a1df6'
    )
    PIXELS_4X4 = bytes.fromhex(
        '001cd0001cd0a505b9a505b9001cd0001cd0a505b9a505b9'
        '0093e30093e3b19d89b19d890093e30093e3b19d89b19d89'
    )

    @staticmethod
    def _zrle_rect_stream(
        encoding_value: int, tile: bytes, width: int = 4, height: int = 3
    ) -> bytes:
        compressor = zlib.compressobj()
        compressed = compressor.compress(tile) + compressor.flush()
        header = (0).to_bytes(2, 'big') * 2 + width.to_bytes(2, 'big') + height.to_bytes(2, 'big')
        return (
            header
            + encoding_value.to_bytes(4, 'big', signed=True)
            + len(compressed).to_bytes(4, 'big')
            + compressed
        )

    async def _decoder(self, encoding_value, tile, width, height, qualite):
        video = make_video(width=width, height=height, decompress=zlib.decompressobj())
        video.jpeg_quality = qualite
        video.reader = _reader_from(self._zrle_rect_stream(encoding_value, tile, width, height))
        await video.read()
        return video.data[0:height, 0:width, :3]

    def test_synthese_identique_au_code_c_de_reference(self):
        for largeur, hauteur, niveau, graine, empreinte in self.VECTEURS_C:
            entree = _lcg_octets(largeur * hauteur * 3, graine).reshape(hauteur, largeur, 3)
            sortie = _zywrle_synthesize(entree, niveau)
            self.assertEqual(sortie.shape, entree.shape)
            self.assertEqual(
                hashlib.sha256(np.ascontiguousarray(sortie).tobytes()).hexdigest(),
                empreinte,
                f'{largeur}x{hauteur} niveau {niveau}',
            )

    def test_synthese_tuile_trop_petite_inchangee(self):
        entree = _lcg_octets(3 * 7 * 3, 11).reshape(3, 7, 3)
        self.assertIs(_zywrle_synthesize(entree, 2), entree)
        self.assertIs(_zywrle_synthesize(entree, 0), entree)

    async def test_tuile_zywrle_imbriquee_raw(self):
        tile = bytes([0, 0]) + self.COEFFS_4X4  # ZYWRLE (0) + tuile imbriquée Raw (0)
        image = await self._decoder(Enc.ZYWRLE.value, tile, 4, 4, 7)  # qualité 7 -> niveau 1
        self.assertEqual(image.tobytes(), self.PIXELS_4X4)

    async def test_tuile_zywrle_imbriquee_unie_et_palette(self):
        coeff = bytes([5, 250, 7])
        attendu = _zywrle_synthesize(
            np.ndarray((1, 1, 3), 'B', coeff * 1).repeat(8, 0).repeat(8, 1), 3
        )
        image = await self._decoder(Enc.ZYWRLE.value, bytes([0, 1]) + coeff, 8, 8, 0)
        self.assertTrue((image == attendu).all())
        # Palette de 2 couleurs (subencoding 2) : 1 bit par pixel, lignes de 8 pixels.
        palette = bytes([1, 2, 3, 200, 100, 50])
        bits = bytes([0b10101010, 0b01010101] * 4)
        coeffs = np.array(
            [[[1, 2, 3], [200, 100, 50]][((b >> (7 - k)) & 1)] for b in bits for k in range(8)], 'B'
        ).reshape(8, 8, 3)
        image = await self._decoder(Enc.ZYWRLE.value, bytes([0, 2]) + palette + bits, 8, 8, 4)
        self.assertTrue((image == _zywrle_synthesize(coeffs, 2)).all())
        # RLE simple (subencoding 128) : une couleur, longueur 64 codée 63.
        image = await self._decoder(
            Enc.ZYWRLE.value, bytes([0, 128]) + coeff + bytes([63]), 8, 8, 0
        )
        self.assertTrue((image == attendu).all())

    async def test_niveau_deduit_de_la_qualite(self):
        coeffs = _lcg_octets(8 * 8 * 3, 21).reshape(8, 8, 3)
        tile = bytes([0, 0]) + coeffs.tobytes()
        vus = set()
        for qualite in range(9):
            image = await self._decoder(Enc.ZYWRLE.value, tile, 8, 8, qualite)
            attendu = _zywrle_synthesize(coeffs, 3 - qualite // 3)
            self.assertTrue((image == attendu).all(), f'qualité {qualite}')
            vus.add(image.tobytes())
        self.assertEqual(len(vus), 3)

    async def test_tuile_0_reste_du_raw_sans_ondelettes(self):
        coeffs = _lcg_octets(8 * 8 * 3, 31)
        tile = bytes([0]) + coeffs.tobytes()
        for encoding_value, qualite in (
            (Enc.ZRLE.value, 0),
            (Enc.ZYWRLE.value, None),
            (Enc.ZYWRLE.value, 9),
        ):
            image = await self._decoder(encoding_value, tile, 8, 8, qualite)
            self.assertEqual(image.tobytes(), coeffs.tobytes(), (encoding_value, qualite))

    async def test_zywrle_decodes_like_zrle_for_a_standard_raw_tile(self):
        pixel = bytes([11, 22, 33])
        tile = bytes([0]) + pixel * (4 * 3)  # subencoding=0 (Raw), tuile 4x3
        expected = np.ndarray((3, 4, 3), 'B', pixel * 12)
        for encoding_value in (Enc.ZRLE.value, Enc.ZYWRLE.value):
            video = make_video(width=4, height=3, decompress=zlib.decompressobj())
            video.reader = _reader_from(self._zrle_rect_stream(encoding_value, tile))
            await video.read()
            self.assertTrue(
                (video.data[0:3, 0:4, :3] == expected).all(),
                f'échec pour raw_encoding={encoding_value}',
            )

    async def test_reserved_subencoding_range_raises_valueerror(self):
        # subencoding=28 : la valeur vue le 2026-09-09 contre QEMU 8.2.2, qui était en fait
        # une désynchronisation (tuile imbriquée lue comme du Raw). Toujours refusée, que
        # ce soit au premier niveau ou dans une tuile imbriquée.
        for tile, qualite in ((bytes([28]), None), (bytes([0, 28]), 0)):
            video = make_video(width=4, height=3, decompress=zlib.decompressobj())
            video.jpeg_quality = qualite
            video.reader = _reader_from(self._zrle_rect_stream(Enc.ZYWRLE.value, tile))
            with self.assertRaises(ValueError):
                await video.read()

    def test_default_encodings_excludes_zywrle(self):
        self.assertNotIn(Enc.ZYWRLE, list(Enc.default()))
        self.assertIn(Enc.ZRLE, list(Enc.default()))


def _lzo_source(nom: str) -> bytes:
    """Données d'origine des vecteurs LZO (mêmes expressions qu'à la génération)."""
    return {
        'court': b'abc',
        'repetitions': b'abcd' * 64,
        'zeros_longs': bytes(1000),
        'melange': b''.join([b'RFB', bytes(300), b'x' * 40, bytes(range(256)), b'\x01\x02' * 200]),
        'pixels': bytes((i * 7) & 0xFF for i in range(4 * 64 * 16)),
    }[nom]


class Lzo1xTests(unittest.TestCase):
    """
    _lzo1x_decompress() (issue #24, encodage Ultra). Vecteurs produits par la
    vraie liblzo2 via python-lzo (`lzo.compress(data, niveau, False)`, niveau
    1 = lzo1x_1, celui de LibVNCServer ; 9 = lzo1x_999, autres codes de
    correspondance). Vérifié aussi sur 612 entrées aléatoires (0 à 70 000
    octets) le 2026-10-10, voir docs/sessions/session-23-2026-10-10.md.
    """

    VECTEURS = (
        ('court', 1, '14616263110000'),
        ('court', 9, '14616263110000'),
        (
            'repetitions',
            1,
            '05616263646162636420c31c0000026162636461626364616263646162636461626364110000',
        ),
        ('repetitions', 9, '156162636420db0c00110000'),
        ('zeros_longs', 1, '02000000000020000000b610000c000000000000000000000000000000110000'),
        ('zeros_longs', 9, '120020000000c90000110000'),
        (
            'melange',
            1,
            '0352464200000020000901007820060000000006000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff010201020102010201020102010201020102010201020120004c44000a02010201020102010201020102110000',
        ),
        (
            'melange',
            9,
            '155246420020000b0100782006000000f0000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff010220006e0400110000',
        ),
        (
            'pixels',
            1,
            '00f300070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c200000000000000000000000000000d9fc030c979ea5acb3bac1c8cfd6dde4ebf2f9110000',
        ),
        (
            'pixels',
            9,
            '00ee00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f92000000000000000e6fc0320000000000000e5fc03110000',
        ),
    )

    def test_vecteurs_liblzo2(self):
        for nom, niveau, compresse in self.VECTEURS:
            attendu = _lzo_source(nom)
            with self.subTest(nom=nom, niveau=niveau):
                self.assertEqual(_lzo1x_decompress(bytes.fromhex(compresse), len(attendu)), attendu)

    def test_taille_inattendue_refusee(self):
        nom, _, compresse = self.VECTEURS[2]
        with self.assertRaises(ValueError):
            _lzo1x_decompress(bytes.fromhex(compresse), len(_lzo_source(nom)) + 1)
        with self.assertRaises(ValueError):
            _lzo1x_decompress(bytes.fromhex(compresse), len(_lzo_source(nom)) - 1)

    def test_flux_tronque_refuse(self):
        for nom, _, compresse in self.VECTEURS:
            flux = bytes.fromhex(compresse)
            with self.subTest(nom=nom), self.assertRaises(ValueError):
                _lzo1x_decompress(flux[: len(flux) // 2], len(_lzo_source(nom)))

    def test_reference_avant_le_debut_refusee(self):
        # 0x40 (M2, distance 1) en tout premier code : rien à recopier encore.
        with self.assertRaises(ValueError):
            _lzo1x_decompress(bytes([0x40, 0x00, 0x11, 0x00, 0x00]), 4)


class UltraTests(unittest.IsolatedAsyncioTestCase):
    """Rectangle Ultra (9) : U32 taille + pixels bruts en LZO1X (ultra.c)."""

    @staticmethod
    def _ultra_rect(width: int, height: int, compresse: bytes) -> bytes:
        header = (0).to_bytes(2, 'big') * 2 + width.to_bytes(2, 'big') + height.to_bytes(2, 'big')
        return (
            header
            + Enc.ULTRA.value.to_bytes(4, 'big')
            + len(compresse).to_bytes(4, 'big')
            + compresse
        )

    async def test_rectangle_ultra_decode(self):
        nom, _, compresse = next(v for v in Lzo1xTests.VECTEURS if v[0] == 'pixels')
        pixels = _lzo_source(nom)  # 4096 octets = 32x32 pixels x 4
        video = make_video(width=32, height=32)
        video.reader = _reader_from(self._ultra_rect(32, 32, bytes.fromhex(compresse)))
        await video.read()
        attendu = np.ndarray((32, 32, 4), 'B', pixels)
        self.assertTrue((video.data[0:32, 0:32, :3] == attendu[..., :3]).all())

    async def test_rectangle_ultra_taille_incoherente(self):
        _, _, compresse = next(v for v in Lzo1xTests.VECTEURS if v[0] == 'pixels')
        video = make_video(width=32, height=16)
        video.reader = _reader_from(self._ultra_rect(32, 16, bytes.fromhex(compresse)))
        with self.assertRaises(ValueError):
            await video.read()

    def test_ultra_hors_des_encodages_par_defaut(self):
        self.assertEqual(Enc.ULTRA.value, 9)
        self.assertNotIn(Enc.ULTRA, list(Enc.default()))


class SendSetDesktopSizeTests(unittest.IsolatedAsyncioTestCase):
    """send_set_desktop_size() -- message client type 251 (RFC officielle)."""

    async def test_implicit_single_screen_24_bytes(self):
        client = make_client()
        await client.send_set_desktop_size(1920, 1080)
        sent = bytes(client.writer.sent)
        self.assertEqual(len(sent), 24)
        self.assertEqual(sent[0], 251)
        self.assertEqual(sent[1], 0)  # padding
        self.assertEqual(int.from_bytes(sent[2:4], 'big'), 1920)
        self.assertEqual(int.from_bytes(sent[4:6], 'big'), 1080)
        self.assertEqual(sent[6], 1)  # 1 écran implicite
        self.assertEqual(sent[7], 0)  # padding
        screen = sent[8:24]
        self.assertEqual(int.from_bytes(screen[0:4], 'big'), 0)  # id
        self.assertEqual(int.from_bytes(screen[4:6], 'big'), 0)  # x
        self.assertEqual(int.from_bytes(screen[6:8], 'big'), 0)  # y
        self.assertEqual(int.from_bytes(screen[8:10], 'big'), 1920)
        self.assertEqual(int.from_bytes(screen[10:12], 'big'), 1080)
        self.assertEqual(int.from_bytes(screen[12:16], 'big'), 0)  # flags

    async def test_explicit_two_screens_40_bytes(self):
        client = make_client()
        screens = [
            Screen(0, 0, 1280, 1080, id=1, flags=0),
            Screen(1280, 0, 1280, 1080, id=2, flags=0),
        ]
        await client.send_set_desktop_size(2560, 1080, screens=screens)
        sent = bytes(client.writer.sent)
        self.assertEqual(len(sent), 40)
        self.assertEqual(sent[6], 2)  # 2 écrans explicites


class SendQemuExtendedKeyEventTests(unittest.IsolatedAsyncioTestCase):
    """send_qemu_extended_key_event() -- extension QEMU, 12 octets (ui/vnc.c)."""

    async def test_key_down_12_bytes(self):
        client = make_client()
        await client.send_qemu_extended_key_event(down=True, keysym=0x61, keycode=30)
        sent = bytes(client.writer.sent)
        self.assertEqual(len(sent), 12)
        self.assertEqual(sent[0], 255)  # message-type QEMU
        self.assertEqual(sent[1], 0)  # submessage-type EXT_KEY_EVENT
        self.assertEqual(int.from_bytes(sent[2:4], 'big'), 1)  # down-flag U16
        self.assertEqual(int.from_bytes(sent[4:8], 'big'), 0x61)  # keysym U32
        self.assertEqual(int.from_bytes(sent[8:12], 'big'), 30)  # keycode U32

    async def test_key_up_high_u32_values(self):
        client = make_client()
        await client.send_qemu_extended_key_event(down=False, keysym=0xFFFFFFFF, keycode=0xFFFFFFFF)
        sent = bytes(client.writer.sent)
        self.assertEqual(int.from_bytes(sent[2:4], 'big'), 0)  # down-flag = False
        self.assertEqual(int.from_bytes(sent[4:8], 'big'), 0xFFFFFFFF)
        self.assertEqual(int.from_bytes(sent[8:12], 'big'), 0xFFFFFFFF)


class JournalSansFrappeTests(unittest.IsolatedAsyncioTestCase):
    """Issue #55 (SOCLE §8) : aucune frappe ni aucun secret dans les journaux, même en TRACE.

    Un keysym/keycode ou le texte tapé dans le journal ferait de la bibliothèque
    un enregistreur de frappes (mot de passe saisi dans la session distante).
    """

    def setUp(self):
        self.messages: list[str] = []
        self.sink_id = logger.add(lambda m: self.messages.append(str(m)), level='TRACE')

    def tearDown(self):
        logger.remove(self.sink_id)

    def _journal(self) -> str:
        return '\n'.join(self.messages)

    async def test_qemu_extended_key_event_sans_keysym_ni_keycode(self):
        client = make_client()
        await client.send_qemu_extended_key_event(down=True, keysym=0x1234ABCD, keycode=0x5A5A)
        journal = self._journal()
        self.assertIn('send_qemu_extended_key_event', journal)
        for fuite in ('0x1234abcd', str(0x1234ABCD), '1234abcd', str(0x5A5A), '0x5a5a'):
            self.assertNotIn(fuite, journal.lower())

    async def test_keyboard_write_sans_texte_tape(self):
        client = make_client()
        client.keyboard.write('Zq9!xW')
        journal = self._journal()
        self.assertIn('Keyboard.write() appelée | len(text)=6', journal)
        self.assertNotIn('Zq9!xW', journal)
        for touche in 'Zq9!xW':
            self.assertNotIn(f"'{touche}'", journal)

    async def test_clipboard_et_mot_de_passe_jamais_journalises(self):
        client = make_client()
        client.clipboard.write('presse-papiers-confidentiel')
        with self.assertRaises(PermissionError):
            await asyncvnc2._sasl_negotiate(
                _reader_from((5).to_bytes(4, 'big') + b'PLAIN'),
                _FakeWriter(),
                'alice-identifiant',
                'mot-de-passe-confidentiel',
            )
        journal = self._journal()
        for secret in (
            'presse-papiers-confidentiel',
            'alice-identifiant',
            'mot-de-passe-confidentiel',
        ):
            self.assertNotIn(secret, journal)
        self.assertIn('identifiant=True mot_de_passe=True', journal)


class SendXvpTests(unittest.IsolatedAsyncioTestCase):
    """send_xvp() -- message type 250 + garde-fou confirm=True (2026-09-06)."""

    async def test_refused_without_confirm(self):
        client = make_client()
        with self.assertRaises(PermissionError):
            await client.send_xvp(XVP_SHUTDOWN)
        self.assertEqual(len(client.writer.sent), 0)  # aucune écriture socket

    async def test_sent_with_confirm_4_bytes(self):
        client = make_client()
        await client.send_xvp(XVP_REBOOT, confirm=True)
        sent = bytes(client.writer.sent)
        self.assertEqual(sent, bytes([250, 0, 1, XVP_REBOOT]))

    async def test_invalid_code_raises_valueerror_before_confirm_check(self):
        client = make_client()
        # code invalide : ValueError, même sans confirm=True (priorité déjà
        # vérifiée manuellement -- on la rejoue ici automatiquement)
        with self.assertRaises(ValueError):
            await client.send_xvp(99)
        self.assertEqual(len(client.writer.sent), 0)

    async def test_wrapper_methods_relay_confirm(self):
        client = make_client()
        await client.send_xvp_reset(confirm=True)
        self.assertEqual(bytes(client.writer.sent), bytes([250, 0, 1, XVP_RESET]))


def _clipboard_message(flags: int, body_after_flags: bytes = b'') -> bytes:
    """Construit un ServerCutText étendu complet (type 3, longueur S32
    négative) tel qu'il arriverait sur le fil, pour alimenter Client.read()."""
    body = flags.to_bytes(4, 'big') + body_after_flags
    return bytes([3, 0, 0, 0]) + (-len(body)).to_bytes(4, 'big', signed=True) + body


def _provide_payload(
    text: str | None = None, extra_pairs: bytes = b'', extra_flags: int = 0
) -> tuple[int, bytes]:
    """Construit (flags, corps-après-flags) d'un Provide texte, avec des
    paires de formats supplémentaires optionnelles APRÈS le texte (le texte
    est le bit 0 -- le plus bas -- donc toujours la première paire dans un
    flux valide ; ceci vérifie qu'un format de bit plus élevé placé ensuite
    est bien ignoré sans désynchroniser)."""
    flags = CLIPBOARD_ACTION_PROVIDE | CLIPBOARD_FORMAT_TEXT | extra_flags
    inner = b''
    if text is not None:
        data = text.encode('utf-8') + b'\x00'
        inner += len(data).to_bytes(4, 'big') + data
    inner += extra_pairs
    return flags, zlib.compress(inner)


class ProcessExtendedClipboardTests(unittest.IsolatedAsyncioTestCase):
    """process_extended_clipboard() -- Caps/Notify/Peek/Request/Provide (rfbproto.rst
    "Extended Clipboard Pseudo-Encoding"), vérifié le 2026-09-13 contre un vrai
    TigerVNC/Xvnc 1.13.1 et un vrai QEMU 8.2.2 (voir docs/sessions/session-14)."""

    def test_pseudo_encoding_value_and_included_by_default(self):
        self.assertEqual(Enc.EXTENDED_CLIPBOARD.value, -1063131698)
        self.assertEqual(Enc.EXTENDED_CLIPBOARD.value & 0xFFFFFFFF, 0xC0A1E5CE)
        self.assertIn(Enc.EXTENDED_CLIPBOARD, list(Enc.default()))  # sûr à annoncer, cf. Enc.XVP

    async def test_caps_sets_supported_flag_and_stores_sizes(self):
        client = make_client()
        flags = CLIPBOARD_ACTION_CAPS | CLIPBOARD_FORMAT_TEXT
        client.reader = _reader_from(flags.to_bytes(4, 'big') + (0).to_bytes(4, 'big'))
        await client.process_extended_clipboard(8)
        self.assertTrue(client.clipboard_ext_supported)
        self.assertEqual(client.clipboard_ext_server_caps, {CLIPBOARD_FORMAT_TEXT: 0})

    async def test_caps_multiple_formats_sizes_in_bit_order(self):
        client = make_client()
        flags = CLIPBOARD_ACTION_CAPS | CLIPBOARD_FORMAT_TEXT | CLIPBOARD_FORMAT_RTF
        body = (
            flags.to_bytes(4, 'big')
            + (20 * 1024 * 1024).to_bytes(4, 'big')
            + (0).to_bytes(4, 'big')
        )
        client.reader = _reader_from(body)
        await client.process_extended_clipboard(len(body))
        self.assertEqual(
            client.clipboard_ext_server_caps,
            {CLIPBOARD_FORMAT_TEXT: 20 * 1024 * 1024, CLIPBOARD_FORMAT_RTF: 0},
        )

    async def test_notify_does_not_touch_clipboard_text(self):
        client = make_client()
        client.clipboard.text = 'inchangé'
        flags = CLIPBOARD_ACTION_NOTIFY | CLIPBOARD_FORMAT_TEXT
        client.reader = _reader_from(flags.to_bytes(4, 'big'))
        await client.process_extended_clipboard(4)
        self.assertFalse(client.clipboard_ext_supported)  # Notify seul ne confirme pas le support
        self.assertEqual(client.clipboard.text, 'inchangé')

    async def test_peek_and_request_do_not_crash_or_touch_state(self):
        client = make_client()
        for action in (CLIPBOARD_ACTION_PEEK, CLIPBOARD_ACTION_REQUEST):
            client.reader = _reader_from((action | CLIPBOARD_FORMAT_TEXT).to_bytes(4, 'big'))
            await client.process_extended_clipboard(4)  # ne doit pas lever

    async def test_provide_decodes_utf8_text_with_trailing_nul(self):
        client = make_client()
        flags, body = _provide_payload('café — 日本語')
        client.reader = _reader_from(flags.to_bytes(4, 'big') + body)
        await client.process_extended_clipboard(4 + len(body))
        self.assertEqual(client.clipboard.text, 'café — 日本語')

    async def test_provide_without_trailing_nul_still_decodes(self):
        # Défensif : la spec exige un NUL terminal à l'émission, mais certains
        # pairs pourraient s'en dispenser -- on ne doit pas planter pour autant.
        client = make_client()
        data = b'sans NUL'
        inner = len(data).to_bytes(4, 'big') + data
        compressed = zlib.compress(inner)
        flags = CLIPBOARD_ACTION_PROVIDE | CLIPBOARD_FORMAT_TEXT
        body = flags.to_bytes(4, 'big') + compressed
        client.reader = _reader_from(body)
        await client.process_extended_clipboard(len(body))
        self.assertEqual(client.clipboard.text, 'sans NUL')

    async def test_provide_extra_unsupported_format_is_skipped_not_decoded(self):
        # RTF après le texte dans le flux (bit 1 > bit 0) : doit être sauté
        # correctement (pas de désynchronisation) sans jamais être exposé/
        # décodé (non implémenté).
        rtf = b'{\\rtf1 fake}'
        extra_pairs = len(rtf).to_bytes(4, 'big') + rtf
        flags, body = _provide_payload(
            'texte seul décodé', extra_pairs=extra_pairs, extra_flags=CLIPBOARD_FORMAT_RTF
        )
        client = make_client()
        client.reader = _reader_from(flags.to_bytes(4, 'big') + body)
        await client.process_extended_clipboard(4 + len(body))
        self.assertEqual(client.clipboard.text, 'texte seul décodé')

    async def test_message_shorter_than_4_bytes_raises_valueerror(self):
        client = make_client()
        client.reader = _reader_from(b'')
        with self.assertRaises(ValueError):
            await client.process_extended_clipboard(2)

    async def test_truncated_provide_size_field_raises_valueerror(self):
        client = make_client()
        compressed = zlib.compress(b'\x00\x00')  # 2 octets : trop court pour une taille U32
        flags = CLIPBOARD_ACTION_PROVIDE | CLIPBOARD_FORMAT_TEXT
        body = flags.to_bytes(4, 'big') + compressed
        client.reader = _reader_from(body)
        with self.assertRaises(ValueError):
            await client.process_extended_clipboard(len(body))

    async def test_truncated_provide_data_raises_valueerror(self):
        client = make_client()
        inner = (1000).to_bytes(
            4, 'big'
        ) + b'trop court'  # annonce 1000 octets, n'en fournit pas assez
        compressed = zlib.compress(inner)
        flags = CLIPBOARD_ACTION_PROVIDE | CLIPBOARD_FORMAT_TEXT
        body = flags.to_bytes(4, 'big') + compressed
        client.reader = _reader_from(body)
        with self.assertRaises(ValueError):
            await client.process_extended_clipboard(len(body))

    async def test_oversized_decompressed_payload_raises_valueerror(self):
        original_cap = asyncvnc2._MAX_ALLOC_BYTES
        asyncvnc2._MAX_ALLOC_BYTES = 64  # plafond artificiellement bas pour ce test
        try:
            compressed = zlib.compress(b'A' * 10_000)
            flags = CLIPBOARD_ACTION_PROVIDE | CLIPBOARD_FORMAT_TEXT
            body = flags.to_bytes(4, 'big') + compressed
            client = make_client()
            client.reader = _reader_from(body)
            with self.assertRaises(ValueError):
                await client.process_extended_clipboard(len(body))
        finally:
            asyncvnc2._MAX_ALLOC_BYTES = original_cap

    async def test_invalid_zlib_stream_raises_valueerror(self):
        client = make_client()
        flags = CLIPBOARD_ACTION_PROVIDE | CLIPBOARD_FORMAT_TEXT
        body = flags.to_bytes(4, 'big') + b'ceci-n-est-pas-du-zlib'
        client.reader = _reader_from(body)
        with self.assertRaises(ValueError):
            await client.process_extended_clipboard(len(body))

    async def test_no_desync_two_consecutive_messages(self):
        # Un Caps étendu suivi d'un ServerCutText Latin-1 classique dans le
        # même flux : les deux doivent se décoder correctement l'un après
        # l'autre, sans que le premier ne consomme un octet de trop ou de
        # travers sur le second.
        client = make_client()
        caps_msg = _clipboard_message(
            CLIPBOARD_ACTION_CAPS | CLIPBOARD_FORMAT_TEXT, (0).to_bytes(4, 'big')
        )
        latin1_text = 'café'.encode('latin-1')
        latin1_msg = bytes([3, 0, 0, 0]) + len(latin1_text).to_bytes(4, 'big') + latin1_text
        client.reader = _reader_from(caps_msg + latin1_msg)
        self.assertEqual(await client.read(), UpdateType.CLIPBOARD)
        self.assertTrue(client.clipboard_ext_supported)
        self.assertEqual(await client.read(), UpdateType.CLIPBOARD)
        self.assertEqual(client.clipboard.text, 'café')


class ClientReadClipboardRegressionTests(unittest.IsolatedAsyncioTestCase):
    """Client.read() / UpdateType.CLIPBOARD -- non-régression du chemin Latin-1
    d'origine après le passage à une longueur S32 signée (2026-09-13)."""

    async def test_basic_latin1_positive_length_unaffected(self):
        client = make_client()
        text = 'café'.encode('latin-1')
        msg = bytes([3, 0, 0, 0]) + len(text).to_bytes(4, 'big') + text
        client.reader = _reader_from(msg)
        self.assertEqual(await client.read(), UpdateType.CLIPBOARD)
        self.assertEqual(client.clipboard.text, 'café')
        self.assertFalse(client.clipboard_ext_supported)


class SendClipboardTests(unittest.IsolatedAsyncioTestCase):
    """send_clipboard_caps/notify/request/provide/update() -- garde-fou
    clipboard_ext_supported et formats sur le fil, vérifiés le 2026-09-13
    contre un vrai TigerVNC/Xvnc 1.13.1 et un vrai QEMU 8.2.2."""

    async def test_all_send_methods_refused_without_ext_supported(self):
        client = make_client()
        for coro in (
            client.send_clipboard_caps(),
            client.send_clipboard_notify(),
            client.send_clipboard_request(),
            client.send_clipboard_provide('x'),
        ):
            with self.assertRaises(PermissionError):
                await coro
        self.assertEqual(len(client.writer.sent), 0)

    async def test_send_clipboard_notify_wire_format(self):
        client = make_client()
        client.clipboard_ext_supported = True
        await client.send_clipboard_notify()
        expected_flags = CLIPBOARD_ACTION_NOTIFY | CLIPBOARD_FORMAT_TEXT
        expected = (
            bytes([6, 0, 0, 0])
            + (-4).to_bytes(4, 'big', signed=True)
            + expected_flags.to_bytes(4, 'big')
        )
        self.assertEqual(bytes(client.writer.sent), expected)

    async def test_send_clipboard_request_wire_format(self):
        client = make_client()
        client.clipboard_ext_supported = True
        await client.send_clipboard_request()
        expected_flags = CLIPBOARD_ACTION_REQUEST | CLIPBOARD_FORMAT_TEXT
        expected = (
            bytes([6, 0, 0, 0])
            + (-4).to_bytes(4, 'big', signed=True)
            + expected_flags.to_bytes(4, 'big')
        )
        self.assertEqual(bytes(client.writer.sent), expected)

    async def test_send_clipboard_caps_wire_format(self):
        client = make_client()
        client.clipboard_ext_supported = True
        await client.send_clipboard_caps(max_text_size=1234)
        sent = bytes(client.writer.sent)
        self.assertEqual(sent[0], 6)
        length = int.from_bytes(sent[4:8], 'big', signed=True)
        self.assertEqual(length, -8)
        flags = int.from_bytes(sent[8:12], 'big')
        self.assertTrue(flags & CLIPBOARD_ACTION_CAPS)
        self.assertTrue(flags & CLIPBOARD_FORMAT_TEXT)
        self.assertEqual(int.from_bytes(sent[12:16], 'big'), 1234)

    async def test_send_clipboard_provide_round_trips_through_process(self):
        sender = make_client()
        sender.clipboard_ext_supported = True
        text = 'texte à relayer — 中文 — ✅'
        await sender.send_clipboard_provide(text)
        sent = bytes(sender.writer.sent)
        self.assertEqual(sent[0], 6)
        length = int.from_bytes(sent[4:8], 'big', signed=True)
        self.assertLess(length, 0)

        receiver = make_client()
        receiver.clipboard_ext_supported = True
        receiver.reader = _reader_from(sent[8 : 8 + (-length)])
        await receiver.process_extended_clipboard(-length)
        self.assertEqual(receiver.clipboard.text, text)

    async def test_send_clipboard_update_sends_notify_then_provide(self):
        # Ordre exigé en pratique par TigerVNC et QEMU (voir
        # send_clipboard_provide()) : Notify avant Provide, jamais l'inverse.
        client = make_client()
        client.clipboard_ext_supported = True
        await client.send_clipboard_update('bonjour')
        sent = bytes(client.writer.sent)
        first_flags = int.from_bytes(sent[8:12], 'big')
        self.assertEqual(first_flags, CLIPBOARD_ACTION_NOTIFY | CLIPBOARD_FORMAT_TEXT)
        second_length = int.from_bytes(sent[16:20], 'big', signed=True)
        second_flags = int.from_bytes(sent[20:24], 'big')
        self.assertLess(second_length, 0)
        self.assertEqual(second_flags, CLIPBOARD_ACTION_PROVIDE | CLIPBOARD_FORMAT_TEXT)


class EaxPrimitivesTests(unittest.IsolatedAsyncioTestCase):
    """
    _eax_seal()/_eax_open()/_eax_increment_counter() -- les primitives
    AES-EAX ajoutées pour RSA-AES (RA2/RA2_256, cf. _rsa_aes_negotiate()).
    Contrairement au reste de VeNCrypt/RSA-AES (délibérément non
    testé unitairement, cf. l'en-tête de ce fichier -- nécessiterait un
    vrai serveur), ces fonctions sont pures et déterministes : testables
    sans aucun serveur. La poignée de main RSA-AES complète, elle, a été
    testée le 2026-09-15 contre un vrai TigerVNC/Xvnc 1.13.1 pour RA2 et
    RA2_256, voir docs/sessions/session-17-2026-09-15.md -- c'est ce test
    réel, pas celui-ci, qui a débusqué le piège de troncature de clé de
    session que test_seal_open_round_trip_both_key_sizes revérifie
    désormais mécaniquement.
    """

    def test_seal_open_round_trip_both_key_sizes(self):
        for key_size in (16, 32):  # AES-128 (RA2) et AES-256 (RA2_256)
            key = bytes(range(key_size))
            nonce = bytes(16)
            header = (42).to_bytes(2, 'big')
            plaintext = b'un message de taille arbitraire, pas forcement multiple de 16'
            ciphertext, tag = asyncvnc2._eax_seal(key, nonce, header, plaintext)
            self.assertEqual(len(tag), 16)
            self.assertEqual(len(ciphertext), len(plaintext))
            decrypted = asyncvnc2._eax_open(key, nonce, header, ciphertext, tag)
            self.assertEqual(decrypted, plaintext)

    def test_open_rejects_tampered_ciphertext(self):
        key = bytes(range(16))
        nonce = bytes(16)
        header = (5).to_bytes(2, 'big')
        ciphertext, tag = asyncvnc2._eax_seal(key, nonce, header, b'texte original')
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with self.assertRaises(ValueError):
            asyncvnc2._eax_open(key, nonce, header, tampered, tag)

    def test_open_rejects_tampered_tag(self):
        key = bytes(range(16))
        nonce = bytes(16)
        header = (5).to_bytes(2, 'big')
        ciphertext, tag = asyncvnc2._eax_seal(key, nonce, header, b'texte original')
        tampered_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with self.assertRaises(ValueError):
            asyncvnc2._eax_open(key, nonce, header, ciphertext, tampered_tag)

    def test_open_rejects_wrong_header(self):
        # Le préfixe de longueur fait partie des données authentifiées :
        # rejouer le même chiffré+tag avec une longueur différente doit
        # échouer, pas juste être ignoré silencieusement.
        key = bytes(range(16))
        nonce = bytes(16)
        ciphertext, tag = asyncvnc2._eax_seal(key, nonce, (5).to_bytes(2, 'big'), b'texte original')
        with self.assertRaises(ValueError):
            asyncvnc2._eax_open(key, nonce, (6).to_bytes(2, 'big'), ciphertext, tag)

    def test_different_nonces_produce_different_ciphertexts(self):
        key = bytes(range(16))
        header = (4).to_bytes(2, 'big')
        plaintext = b'meme message'
        c1, t1 = asyncvnc2._eax_seal(key, bytes(16), header, plaintext)
        c2, t2 = asyncvnc2._eax_seal(key, (1).to_bytes(16, 'little'), header, plaintext)
        self.assertNotEqual(c1, c2)
        self.assertNotEqual(t1, t2)

    def test_increment_counter_little_endian_with_carry(self):
        counter = bytearray(16)
        asyncvnc2._eax_increment_counter(counter)
        self.assertEqual(bytes(counter), (1).to_bytes(16, 'little'))
        counter = bytearray(b'\xff' + bytes(15))  # octet de poids faible déjà à 0xff
        asyncvnc2._eax_increment_counter(counter)
        self.assertEqual(
            bytes(counter), (256).to_bytes(16, 'little')
        )  # retenue vers l'octet suivant


def _sasl_server_start_message(serverout: bytes, complete_flag: int) -> bytes:
    """Construit un message "SASL server start message" (rfbproto.rst,
    section SASL) tel qu'un vrai serveur l'enverrait : U32 longueur +
    serverout-data (bourrage NUL déjà inclus si besoin, à la charge de
    l'appelant, exactement comme pour clientout côté client) + U8
    complete-flag."""
    return len(serverout).to_bytes(4, 'big') + serverout + bytes([complete_flag])


class SaslNegotiateTests(unittest.IsolatedAsyncioTestCase):
    """
    _sasl_negotiate() -- security type 20, mécanismes PLAIN (RFC 4616) et
    ANONYMOUS (RFC 4505) uniquement (voir sa docstring pour le détail du
    tramage et des mécanismes volontairement non pris en charge).

    Comme pour MSLogonII (security type 113), aucun serveur SASL de
    référence n'est installable dans ce sandbox -- ces tests vérifient
    donc la cohérence interne du tramage envoyé/attendu contre la lecture
    de rfbproto.rst, via un "serveur" fabriqué à la main (round-trip
    auto-cohérent), pas contre une véritable implémentation SASL tierce.
    """

    async def test_plain_chosen_when_offered_with_credentials(self):
        # mechlist offrant PLAIN et ANONYMOUS : PLAIN doit être préféré dès
        # que des identifiants sont fournis (mécanisme authentifié, pas
        # seulement anonyme).
        mechlist = b'ANONYMOUS,PLAIN'
        server_bytes = (
            len(mechlist).to_bytes(4, 'big') + mechlist + _sasl_server_start_message(b'', 1)
        )
        reader = _reader_from(server_bytes)
        writer = _FakeWriter()
        await asyncvnc2._sasl_negotiate(reader, writer, 'mathilde', 's3cret')

        sent = bytes(writer.sent)
        mechname_length = int.from_bytes(sent[0:4], 'big')
        mechname = sent[4 : 4 + mechname_length]
        self.assertEqual(mechname, b'PLAIN')
        offset = 4 + mechname_length
        clientout_length = int.from_bytes(sent[offset : offset + 4], 'big')
        clientout_padded = sent[offset + 4 : offset + 4 + clientout_length]
        self.assertEqual(offset + 4 + clientout_length, len(sent))  # rien après
        clientout = clientout_padded[:-1]  # retrait du NUL de bourrage
        self.assertEqual(clientout_padded[-1], 0)
        # RFC 4616 : authzid (vide) NUL authcid NUL passwd
        self.assertEqual(clientout, b'\x00mathilde\x00s3cret')

    async def test_fermeture_avant_la_liste_de_mecanismes(self):
        # Comportement réel de QEMU 10.2 (issue #32) : aucun mécanisme commun
        # -> connexion fermée sans liste. Message explicite, pas IncompleteReadError.
        with self.assertRaises(ConnectionError) as ctx:
            await asyncvnc2._sasl_negotiate(_reader_from(b''), _FakeWriter(), 'u', 'p')
        self.assertIn('X509SASL', str(ctx.exception))

    async def test_fermeture_apres_plain_est_un_refus(self):
        # QEMU ferme la connexion sur mauvais mot de passe (vérifié 2026-10-10).
        mechlist = b'PLAIN'
        reader = _reader_from(len(mechlist).to_bytes(4, 'big') + mechlist)
        with self.assertRaises(PermissionError):
            await asyncvnc2._sasl_negotiate(reader, _FakeWriter(), 'alice', 'mauvais')

    async def test_anonymous_used_when_plain_not_offered(self):
        mechlist = b'ANONYMOUS'
        server_bytes = (
            len(mechlist).to_bytes(4, 'big') + mechlist + _sasl_server_start_message(b'', 1)
        )
        reader = _reader_from(server_bytes)
        writer = _FakeWriter()
        await asyncvnc2._sasl_negotiate(reader, writer, 'trace-info', None)

        sent = bytes(writer.sent)
        mechname_length = int.from_bytes(sent[0:4], 'big')
        self.assertEqual(sent[4 : 4 + mechname_length], b'ANONYMOUS')
        offset = 4 + mechname_length
        clientout_length = int.from_bytes(sent[offset : offset + 4], 'big')
        clientout_padded = sent[offset + 4 : offset + 4 + clientout_length]
        self.assertEqual(clientout_padded, b'trace-info\x00')  # RFC 4505 + bourrage NUL

    async def test_anonymous_with_no_username_sends_empty_message(self):
        mechlist = b'ANONYMOUS'
        server_bytes = (
            len(mechlist).to_bytes(4, 'big') + mechlist + _sasl_server_start_message(b'', 1)
        )
        reader = _reader_from(server_bytes)
        writer = _FakeWriter()
        await asyncvnc2._sasl_negotiate(reader, writer, None, None)

        sent = bytes(writer.sent)
        mechname_length = int.from_bytes(sent[0:4], 'big')
        offset = 4 + mechname_length
        clientout_length = int.from_bytes(sent[offset : offset + 4], 'big')
        clientout_padded = sent[offset + 4 : offset + 4 + clientout_length]
        self.assertEqual(clientout_padded, b'\x00')  # message vide + seul le bourrage NUL

    async def test_no_supported_mechanism_raises_valueerror(self):
        mechlist = b'DIGEST-MD5,GSSAPI'
        reader = _reader_from(len(mechlist).to_bytes(4, 'big') + mechlist)
        writer = _FakeWriter()
        with self.assertRaises(ValueError):
            await asyncvnc2._sasl_negotiate(reader, writer, 'mathilde', 's3cret')
        self.assertEqual(len(writer.sent), 0)  # aucune écriture avant l'échec

    async def test_empty_mechlist_raises_valueerror(self):
        reader = _reader_from((0).to_bytes(4, 'big'))
        writer = _FakeWriter()
        with self.assertRaises(ValueError):
            await asyncvnc2._sasl_negotiate(reader, writer, 'mathilde', 's3cret')

    async def test_plain_only_offered_without_credentials_falls_back_to_error(self):
        # PLAIN seul offert, mais ni username ni password fournis, et
        # ANONYMOUS absent de la liste -- aucun mécanisme utilisable.
        mechlist = b'PLAIN'
        reader = _reader_from(len(mechlist).to_bytes(4, 'big') + mechlist)
        writer = _FakeWriter()
        with self.assertRaises(ValueError):
            await asyncvnc2._sasl_negotiate(reader, writer, None, None)

    async def test_multi_step_exchange_rejected(self):
        # complete-flag=0 : le serveur attend une étape supplémentaire,
        # jamais prévue pour PLAIN/ANONYMOUS -- refusé explicitement
        # plutôt que deviné (même principe que pour ZYWRLE ci-dessus).
        mechlist = b'ANONYMOUS'
        server_bytes = (
            len(mechlist).to_bytes(4, 'big') + mechlist + _sasl_server_start_message(b'', 0)
        )
        reader = _reader_from(server_bytes)
        writer = _FakeWriter()
        with self.assertRaises(ValueError):
            await asyncvnc2._sasl_negotiate(reader, writer, None, None)


if __name__ == '__main__':
    unittest.main()
