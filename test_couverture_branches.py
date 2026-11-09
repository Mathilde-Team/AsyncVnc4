# SPDX-License-Identifier: GPL-3.0-or-later
"""Cas limites du protocole et de la vidéo, sans serveur externe (#54)."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import numpy as np

import asyncvnc2
from test_asyncvnc2 import _Ecrivain, _reader_from, make_client, make_video


class BornesVideoTests(unittest.TestCase):
    def test_rectangle_hors_image_et_dimensions_negatives(self):
        video = make_video()
        self.assertEqual(video.get_rect(-3, -4), (0, 0, 64, 64))
        self.assertEqual(video.get_rect(99, 99), (64, 64, 0, 0))
        self.assertEqual(video.get_rect(1, 2, -1, -2), (1, 2, 0, 0))

    def test_canal_alpha_en_premiere_position(self):
        video = make_video(mode='argb')
        video._update_rect(0, 1, 0, 1, np.array([[[1, 2, 3]]], dtype='B'))
        self.assertEqual(video.data[0, 0].tolist(), [255, 1, 2, 3])

    def test_compteur_eax_reboucle_apres_128_bits(self):
        compteur = bytearray(b'\xff' * 16)
        asyncvnc2._eax_increment_counter(compteur)
        self.assertEqual(compteur, bytearray(16))

    def test_prediction_gradient_superieure_a_255(self):
        # Bas-droite : gauche + haut - haut-gauche = 400, borné à 255.
        donnees = bytes([0, 0, 0, 200, 0, 0, 200, 0, 0, 7, 0, 0])
        self.assertEqual(
            asyncvnc2._tight_gradient_filter(donnees, 2, 2),
            bytes([0, 0, 0, 200, 0, 0, 200, 0, 0, 6, 0, 0]),
        )

    def test_lzo_marqueur_de_fin_invalide(self):
        with self.assertRaisesRegex(ValueError, 'marqueur de fin invalide'):
            asyncvnc2._lzo1x_decompress(b'\x12a\x12\x00\x00', 1)


class BranchesProtocoleTests(unittest.IsolatedAsyncioTestCase):
    async def test_lecteur_memoire_tronque(self):
        lecteur = asyncvnc2._BytesReader(b'a')
        with self.assertRaises(asyncio.IncompleteReadError) as erreur:
            await lecteur.readexactly(2)
        self.assertEqual(erreur.exception.partial, b'a')
        self.assertEqual(erreur.exception.expected, 2)

    async def test_longueur_tight_sur_deux_octets(self):
        self.assertEqual(await asyncvnc2._tight_read_length(_reader_from(b'\x81\x01')), 129)

    async def test_raw_pixel_recu_en_plusieurs_fragments(self):
        lecteur = AsyncMock()
        lecteur.read.side_effect = [b'\x01', b'\x02\x03\x04']
        video = make_video(width=1, height=1)
        await video.process_raw(lecteur, 0, 0, 1, 1)
        self.assertEqual(video.data[0, 0].tolist(), [1, 2, 3, 255])
        self.assertEqual(lecteur.read.await_count, 2)

    async def test_ultra_indexe(self):
        # LZO : un littéral (index de palette 1), puis marqueur de fin.
        compresse = b'\x12\x01\x11\x00\x00'
        lecteur = _reader_from(len(compresse).to_bytes(4, 'big') + compresse)
        video = make_video(mode='indexed8', width=1, height=1)
        video.palette = {1: (9, 8, 7)}
        await video.process_ultra(lecteur, 0, 0, 1, 1)
        self.assertEqual(video.data[0, 0].tolist(), [9, 8, 7, 255])

    async def test_aiguillage_rre_et_corre(self):
        for encodage in (asyncvnc2.Enc.RRE, asyncvnc2.Enc.CORRE):
            with self.subTest(encodage=encodage):
                rectangle = (
                    b'\x00\x00\x00\x00\x00\x01\x00\x01'
                    + encodage.value.to_bytes(4, 'big', signed=True)
                    + b'\x00\x00\x00\x00'
                    + b'\x09\x08\x07\x00'
                )
                video = make_video(reader=_reader_from(rectangle))
                self.assertFalse(await video.read())
                self.assertEqual(video.data[0, 0].tolist(), [9, 8, 7, 255])

    async def test_fence_acquitte_ne_declenche_pas_de_reponse(self):
        client = make_client(reader=_reader_from(b'\x00' * 8))
        await client.process_server_fence()
        self.assertEqual(bytes(client.writer.sent), b'')

    async def test_caps_presse_papiers_tronque_refuse(self):
        flags = asyncvnc2.CLIPBOARD_ACTION_CAPS | asyncvnc2.CLIPBOARD_FORMAT_TEXT
        client = make_client(reader=_reader_from(flags.to_bytes(4, 'big')))
        with self.assertRaisesRegex(ValueError, 'Caps tronqué'):
            await client.process_extended_clipboard(4)

    async def test_action_presse_papiers_inconnue_conserve_alignement(self):
        client = make_client(reader=_reader_from(b'\x00\x00\x00\x00excesfin'))
        await client.process_extended_clipboard(9)
        self.assertEqual(await client.reader.readexactly(3), b'fin')

    async def test_xvp_echec_ne_retire_pas_le_support_annonce(self):
        client = make_client(reader=_reader_from(b'\x00\x01\x00'))
        client.xvp_supported = True
        client.xvp_version = 1
        await client.process_xvp()
        self.assertTrue(client.xvp_supported)
        self.assertEqual(client.xvp_version, 1)

    async def test_pong_websocket_ignore(self):
        lecteur = _reader_from(
            asyncvnc2._ws_frame(b'pong', opcode=0xA)
            + asyncvnc2._ws_frame(b'donnee')
            + asyncvnc2._ws_frame(b'', opcode=0x8)
        )
        sortie = asyncio.StreamReader()
        ecrivain = _Ecrivain()
        await asyncvnc2._ws_pump(lecteur, ecrivain, sortie)
        self.assertEqual(await sortie.read(), b'donnee')
        self.assertEqual(bytes(ecrivain.sent), b'')

    async def test_sous_protocole_websocket_avec_entrees_vides(self):
        requete = (
            b'GET / HTTP/1.1\r\nUpgrade: websocket\r\n'
            b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
            b'Sec-WebSocket-Protocol: binary, , base64\r\n\r\n'
        )
        ecrivain = _Ecrivain()
        await asyncvnc2._ws_handshake_server(_reader_from(requete), ecrivain)
        self.assertIn(b'Sec-WebSocket-Protocol: binary\r\n', ecrivain.sent)
        self.assertIn(b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=', ecrivain.sent)

    async def test_capture_ignore_message_non_video(self):
        client = make_client()
        image = np.zeros((1, 1, 4), dtype='B')
        with (
            patch.object(
                client,
                'read',
                AsyncMock(side_effect=[asyncvnc2.UpdateType.CLIPBOARD, asyncvnc2.UpdateType.VIDEO]),
            ) as lecture,
            patch.object(asyncvnc2.Video, 'is_complete', return_value=True),
            patch.object(asyncvnc2.Video, 'as_rgba', return_value=image),
        ):
            self.assertIs(await client.screenshot(), image)
        self.assertEqual(lecture.await_count, 2)

    async def test_authentifications_exigeant_identifiants(self):
        for authentification in (33, 113):
            with self.subTest(authentification=authentification):
                lecteur = _reader_from(b'RFB 003.008\n\x01' + bytes([authentification]))
                with self.assertRaisesRegex(ValueError, 'requires username and password'):
                    await asyncvnc2.Client.create(lecteur, _Ecrivain())
