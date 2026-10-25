"""Tests de bout en bout sur une vraie socket locale, sans serveur VNC externe (issue #54).

Un petit serveur RFB asynchrone, écrit ici octet par octet d'après
rfbproto.rst (ProtocolVersion, Security, SecurityResult, ClientInit,
ServerInit, FramebufferUpdate), écoute sur 127.0.0.1. Il est rejoint par le
vrai ``connect()`` (TCP brut ou WebSocket) ou se connecte lui-même au vrai
``listen()`` (reconnexion inversée). Rien n'est simulé côté client : sockets,
poignée de main, authentification VNC (DES), décodage Raw, tout passe par le
code de ``asyncvnc2``.

La poignée de main WebSocket est aussi vérifiée contre le vecteur de la
RFC 6455 §1.3 (clé ``dGhlIHNhbXBsZSBub25jZQ==``), pour qu'une erreur
symétrique client/serveur ne puisse pas passer inaperçue.
"""

from __future__ import annotations

import asyncio
import contextlib
import unittest

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import asyncvnc2

# Format de pixel 32 bits « rgba » reconnu tel quel par le client (video_modes).
FORMAT_RGBA = asyncvnc2.video_definition['rgba']
# Format 16 bits inconnu de video_modes : le client doit envoyer SetPixelFormat.
FORMAT_16_BITS = b'\x10\x10\x00\x01\x00\x1f\x00\x3f\x00\x1f\x0b\x05\x00'


def _cle_des_vnc(mot_de_passe: str) -> bytes:
    """Clé DES de la VNC Authentication : 8 octets, bits de chaque octet inversés (rfbproto.rst)."""
    brut = mot_de_passe.encode('ascii')[:8].ljust(8, b'\x00')
    return bytes(int(f'{octet:08b}'[::-1], 2) for octet in brut)


def _reponse_vnc_attendue(mot_de_passe: str, defi: bytes) -> bytes:
    chiffreur = Cipher(algorithms.TripleDES(_cle_des_vnc(mot_de_passe)), modes.ECB()).encryptor()
    return chiffreur.update(defi) + chiffreur.finalize()


def _server_init(largeur: int, hauteur: int, nom: str, format_pixel: bytes = FORMAT_RGBA) -> bytes:
    nom_octets = nom.encode('utf-8')
    return (
        largeur.to_bytes(2, 'big')
        + hauteur.to_bytes(2, 'big')
        + format_pixel
        + b'\x00\x00\x00'
        + len(nom_octets).to_bytes(4, 'big')
        + nom_octets
    )


def _mise_a_jour_raw(x: int, y: int, pixels: np.ndarray) -> bytes:
    """FramebufferUpdate (type 0) avec un seul rectangle encodé Raw (encodage 0)."""
    hauteur, largeur, _ = pixels.shape
    return (
        b'\x00\x00'
        + (1).to_bytes(2, 'big')
        + x.to_bytes(2, 'big')
        + y.to_bytes(2, 'big')
        + largeur.to_bytes(2, 'big')
        + hauteur.to_bytes(2, 'big')
        + (0).to_bytes(4, 'big', signed=True)
        + pixels.astype('B').tobytes()
    )


class ServeurRfb:
    """Serveur RFB minimal : un scénario par test, observations exposées aux assertions."""

    def __init__(
        self,
        version: bytes = b'RFB 003.008\n',
        types_securite: bytes = b'\x01',
        mot_de_passe: str | None = None,
        resultat: int | None = None,
        raison_refus: str = '',
        format_pixel: bytes = FORMAT_RGBA,
        pixels: np.ndarray | None = None,
    ) -> None:
        self.version = version
        self.types_securite = types_securite
        self.mot_de_passe = mot_de_passe
        self.resultat = resultat
        self.raison_refus = raison_refus
        self.format_pixel = format_pixel
        self.pixels = pixels
        self.version_client = b''
        self.type_choisi: int | None = None
        self.partage: int | None = None
        self.set_pixel_format: bytes | None = None
        self.encodages: list[int] = []
        self.termine = asyncio.Event()

    async def dialoguer(self, reader: asyncio.StreamReader, writer) -> None:
        try:
            await self._dialoguer(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass  # le client a refermé la connexion (cas d'erreur attendus)
        finally:
            writer.close()
            self.termine.set()

    async def _dialoguer(self, reader: asyncio.StreamReader, writer) -> None:
        writer.write(self.version)
        await writer.drain()
        if not self.version.startswith(b'RFB '):
            return
        self.version_client = await reader.readexactly(12)
        # Version négociée = celle que le client renvoie (jamais > l'annonce).
        mineure = int(self.version_client[8:11])
        if mineure < 7:
            # 3.3 : le serveur impose un seul type (U32), sans choix du client.
            self.type_choisi = self.types_securite[0]
            writer.write(self.type_choisi.to_bytes(4, 'big'))
        else:
            writer.write(len(self.types_securite).to_bytes(1, 'big') + self.types_securite)
            if not self.types_securite:
                motif = self.raison_refus.encode('utf-8')
                writer.write(len(motif).to_bytes(4, 'big') + motif)
                await writer.drain()
                return
            self.type_choisi = (await reader.readexactly(1))[0]
        await writer.drain()
        resultat = 0
        if self.type_choisi == 2:
            defi = bytes(range(16))
            writer.write(defi)
            await writer.drain()
            reponse = await reader.readexactly(16)
            bonne = self.mot_de_passe is not None and reponse == _reponse_vnc_attendue(
                self.mot_de_passe, defi
            )
            resultat = 0 if bonne else 1
        if self.resultat is not None:
            resultat = self.resultat
        # 3.3/3.7 avec None : pas de SecurityResult (rfbproto.rst).
        sans_resultat = self.type_choisi == 1 and mineure < 8
        if not sans_resultat:
            writer.write(resultat.to_bytes(4, 'big'))
            if resultat not in (0, 1, 2):
                writer.write(self.raison_refus.encode('utf-8'))
            await writer.drain()
            if resultat != 0:
                return
        self.partage = (await reader.readexactly(1))[0]
        writer.write(_server_init(4, 3, 'bureau-test', self.format_pixel))
        await writer.drain()
        type_message = (await reader.readexactly(1))[0]
        if type_message == 0:  # SetPixelFormat : 3 octets de bourrage + 16 octets
            self.set_pixel_format = await reader.readexactly(19)
            type_message = (await reader.readexactly(1))[0]
        assert type_message == 2, type_message  # SetEncodings
        await reader.readexactly(1)
        nombre = int.from_bytes(await reader.readexactly(2), 'big')
        brut = await reader.readexactly(4 * nombre)
        self.encodages = [
            int.from_bytes(brut[i : i + 4], 'big', signed=True) for i in range(0, len(brut), 4)
        ]
        if self.pixels is not None:
            writer.write(_mise_a_jour_raw(0, 0, self.pixels))
            await writer.drain()
        await self.apres_poignee_de_main(reader, writer)

    async def apres_poignee_de_main(self, reader: asyncio.StreamReader, writer) -> None:
        """Garde la connexion ouverte jusqu'à ce que le client la ferme."""
        await reader.read()


class ServeurFaconTigerVnc(ServeurRfb):
    """
    Imite TigerVNC Xvnc (``VNCSConnectionST::framebufferUpdateRequest``) : toute
    demande NON incrémentale reçoit une mise à jour ne contenant que le
    pseudo-rectangle ExtendedDesktopSize ; les pixels ne partent qu'à la demande
    incrémentale suivante (issue #27).
    """

    def __init__(self, pixels: np.ndarray) -> None:
        super().__init__()
        self.image = pixels
        self.demandes: list[int] = []

    @staticmethod
    def _taille_seule() -> bytes:
        ecran = (0).to_bytes(4, 'big') + (0).to_bytes(4, 'big') + (4).to_bytes(2, 'big')
        ecran += (3).to_bytes(2, 'big') + (0).to_bytes(4, 'big')
        return (
            b'\x00\x00'
            + (1).to_bytes(2, 'big')
            + (0).to_bytes(4, 'big')
            + (4).to_bytes(2, 'big')
            + (3).to_bytes(2, 'big')
            + asyncvnc2.Enc.EXTENDED_DESKTOP_SIZE.value.to_bytes(4, 'big', signed=True)
            + b'\x01\x00\x00\x00'
            + ecran
        )

    async def apres_poignee_de_main(self, reader: asyncio.StreamReader, writer) -> None:
        while True:
            message = await reader.readexactly(10)
            assert message[0] == 3, message  # FramebufferUpdateRequest
            self.demandes.append(message[1])
            if message[1]:
                writer.write(_mise_a_jour_raw(0, 0, self.image))
            else:
                writer.write(self._taille_seule())
            await writer.drain()


@contextlib.asynccontextmanager
async def serveur_local(scenario: ServeurRfb, websocket: bool = False):
    """Démarre *scenario* sur 127.0.0.1 (port libre) ; rend le port."""

    async def accepter(reader, writer):
        if websocket:
            reader, writer = await asyncvnc2._ws_wrap_connection_server(reader, writer)
        await scenario.dialoguer(reader, writer)

    serveur = await asyncio.start_server(accepter, '127.0.0.1', 0)
    try:
        yield serveur.sockets[0].getsockname()[1]
    finally:
        serveur.close()
        await serveur.wait_closed()


def _image(largeur: int = 4, hauteur: int = 3) -> np.ndarray:
    valeurs = np.arange(largeur * hauteur * 4, dtype='B').reshape((hauteur, largeur, 4))
    valeurs[..., 3] = 255
    return valeurs


class ConnexionTcpTests(unittest.IsolatedAsyncioTestCase):
    async def _lire_premiere_image(self, client) -> None:
        mise_a_jour = await asyncio.wait_for(client.read(), 5)
        self.assertIs(mise_a_jour, asyncvnc2.UpdateType.VIDEO)

    async def test_rfb_38_sans_securite_et_image_raw(self):
        pixels = _image()
        scenario = ServeurRfb(pixels=pixels)
        async with (
            serveur_local(scenario) as port,
            asyncvnc2.connect('127.0.0.1', port, shared=False) as client,
        ):
            await self._lire_premiere_image(client)
            self.assertEqual((client.video.width, client.video.height), (4, 3))
            self.assertEqual(client.video.name, 'bureau-test')
            self.assertEqual(client.protocol_version, (3, 8))
            np.testing.assert_array_equal(client.video.as_rgba(0, 0, 4, 3), pixels)
        self.assertEqual(scenario.version_client, b'RFB 003.008\n')
        self.assertEqual(scenario.type_choisi, 1)
        self.assertEqual(scenario.partage, 0)
        self.assertIsNone(scenario.set_pixel_format)
        # Liste par défaut annoncée telle quelle (Raw, toujours supporté, n'a pas à y figurer).
        self.assertEqual(scenario.encodages, [e.value for e in asyncvnc2.EncList(None)])

    async def test_capture_redemande_en_incremental_facon_tigervnc(self):
        # Avant le correctif, screenshot() attendait indéfiniment après la mise à
        # jour « taille seule » ; une redemande non incrémentale bouclerait aussi.
        pixels = _image()
        scenario = ServeurFaconTigerVnc(pixels)
        async with serveur_local(scenario) as port, asyncvnc2.connect('127.0.0.1', port) as client:
            image = await asyncio.wait_for(client.screenshot(), 5)
            np.testing.assert_array_equal(image, pixels)
            self.assertEqual(client.video.screens[0].width, 4)
        self.assertEqual(scenario.demandes, [0, 1])

    async def test_qualite_jpeg_et_compression_annoncees(self):
        scenario = ServeurRfb()
        async with (
            serveur_local(scenario) as port,
            asyncvnc2.connect('127.0.0.1', port, jpeg_quality=7, compression_level=2) as client,
        ):
            self.assertEqual(client.video.width, 4)
            await asyncio.wait_for(self._attendre_encodages(scenario), 5)
        self.assertIn(-32 + 7, scenario.encodages)
        self.assertIn(-256 + 2, scenario.encodages)
        self.assertEqual(scenario.partage, 1)

    async def _attendre_encodages(self, scenario: ServeurRfb) -> None:
        while not scenario.encodages:
            await asyncio.sleep(0.01)

    async def test_format_inconnu_le_client_impose_rgba(self):
        scenario = ServeurRfb(format_pixel=FORMAT_16_BITS)
        async with serveur_local(scenario) as port, asyncvnc2.connect('127.0.0.1', port) as client:
            self.assertEqual(client.video.mode, 'rgba')
            await asyncio.wait_for(self._attendre_encodages(scenario), 5)
        self.assertEqual(scenario.set_pixel_format, b'\x00\x00\x00' + FORMAT_RGBA + b'\x00\x00\x00')

    async def test_authentification_vnc_reussie(self):
        scenario = ServeurRfb(types_securite=b'\x02', mot_de_passe='s3cret')
        async with (
            serveur_local(scenario) as port,
            asyncvnc2.connect('127.0.0.1', port, password='s3cret') as client,
        ):
            self.assertEqual(client.video.name, 'bureau-test')
        self.assertEqual(scenario.type_choisi, 2)

    async def test_authentification_vnc_refusee(self):
        scenario = ServeurRfb(types_securite=b'\x02', mot_de_passe='s3cret')
        async with serveur_local(scenario) as port:
            with self.assertRaisesRegex(PermissionError, '^Auth failed$'):
                async with asyncvnc2.connect('127.0.0.1', port, password='mauvais'):
                    self.fail('la connexion aurait dû être refusée')

    async def test_mot_de_passe_requis(self):
        scenario = ServeurRfb(types_securite=b'\x02', mot_de_passe='s3cret')
        async with serveur_local(scenario) as port:
            with self.assertRaisesRegex(ValueError, 'server requires password'):
                async with asyncvnc2.connect('127.0.0.1', port):
                    self.fail('connexion sans mot de passe acceptée')

    async def test_trop_de_tentatives(self):
        scenario = ServeurRfb(resultat=2)
        async with serveur_local(scenario) as port:
            with self.assertRaisesRegex(PermissionError, 'too many attempts'):
                async with asyncvnc2.connect('127.0.0.1', port):
                    self.fail('connexion acceptée malgré le refus')

    async def test_refus_avec_motif_du_serveur(self):
        # SecurityResult > 2 : interprété comme la longueur du motif qui suit.
        motif = 'compte verrouillé'
        scenario = ServeurRfb(resultat=len(motif.encode('utf-8')), raison_refus=motif)
        async with serveur_local(scenario) as port:
            with self.assertRaisesRegex(PermissionError, motif):
                async with asyncvnc2.connect('127.0.0.1', port):
                    self.fail('connexion acceptée malgré le refus')

    async def test_aucun_type_de_securite_motif_remonte(self):
        scenario = ServeurRfb(types_securite=b'', raison_refus='trop de connexions')
        async with serveur_local(scenario) as port:
            with self.assertRaisesRegex(ValueError, 'trop de connexions'):
                async with asyncvnc2.connect('127.0.0.1', port):
                    self.fail('connexion acceptée sans type de sécurité')

    async def test_types_de_securite_non_supportes(self):
        scenario = ServeurRfb(types_securite=b'\x10\x11')
        async with serveur_local(scenario) as port:
            with self.assertRaisesRegex(ValueError, 'unsupported auth types'):
                async with asyncvnc2.connect('127.0.0.1', port):
                    self.fail('types inconnus acceptés')

    async def test_rfb_37_sans_securite_sans_security_result(self):
        scenario = ServeurRfb(version=b'RFB 003.007\n')
        async with serveur_local(scenario) as port, asyncvnc2.connect('127.0.0.1', port) as client:
            self.assertEqual(client.protocol_version, (3, 7))
        self.assertEqual(scenario.version_client, b'RFB 003.007\n')

    async def test_rfb_33_authentification_imposee_par_le_serveur(self):
        scenario = ServeurRfb(version=b'RFB 003.003\n', types_securite=b'\x02', mot_de_passe='pw')
        async with (
            serveur_local(scenario) as port,
            asyncvnc2.connect('127.0.0.1', port, password='pw') as client,
        ):
            self.assertEqual(client.protocol_version, (3, 3))
        self.assertEqual(scenario.version_client, b'RFB 003.003\n')

    async def test_version_mineure_inconnue_traitee_comme_33(self):
        # rfbproto.rst, annexe A : toute version autre que 3.7/3.8 vaut 3.3.
        scenario = ServeurRfb(version=b'RFB 003.005\n')
        async with serveur_local(scenario) as port, asyncvnc2.connect('127.0.0.1', port) as client:
            self.assertEqual(client.protocol_version, (3, 3))

    async def test_version_majeure_recente_traitee_comme_38(self):
        scenario = ServeurRfb(version=b'RFB 005.000\n')
        async with serveur_local(scenario) as port, asyncvnc2.connect('127.0.0.1', port) as client:
            self.assertEqual(client.protocol_version, (3, 8))
        self.assertEqual(scenario.version_client, b'RFB 003.008\n')

    async def test_serveur_qui_n_est_pas_vnc(self):
        scenario = ServeurRfb(version=b'SSH-2.0-OpenSSH_9.6\r\n')
        async with serveur_local(scenario) as port:
            with self.assertRaisesRegex(ValueError, 'not a VNC server'):
                async with asyncvnc2.connect('127.0.0.1', port):
                    self.fail('un serveur SSH accepté comme VNC')

    async def test_version_illisible(self):
        scenario = ServeurRfb(version=b'RFB abc.def\n')
        async with serveur_local(scenario) as port:
            with self.assertRaisesRegex(ValueError, 'not a VNC server'):
                async with asyncvnc2.connect('127.0.0.1', port):
                    self.fail('version illisible acceptée')

    async def test_version_trop_ancienne(self):
        scenario = ServeurRfb(version=b'RFB 002.000\n')
        async with serveur_local(scenario) as port:
            with self.assertRaisesRegex(ValueError, 'unsupported RFB protocol version'):
                async with asyncvnc2.connect('127.0.0.1', port):
                    self.fail('RFB 2.0 accepté')


class WebSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_connexion_rfb_complete_sur_websocket(self):
        pixels = _image()
        scenario = ServeurRfb(pixels=pixels)
        async with (
            serveur_local(scenario, websocket=True) as port,
            asyncvnc2.connect('127.0.0.1', port, websocket=True, ws_path='/websockify') as client,
        ):
            mise_a_jour = await asyncio.wait_for(client.read(), 5)
            self.assertIs(mise_a_jour, asyncvnc2.UpdateType.VIDEO)
            np.testing.assert_array_equal(client.video.as_rgba(0, 0, 4, 3), pixels)
        self.assertEqual(scenario.type_choisi, 1)

    async def test_poignee_de_main_serveur_vecteur_rfc_6455(self):
        reponse = await self._poignee_de_main_brute(
            b'GET /chat HTTP/1.1\r\n'
            b'Host: server.example.com\r\n'
            b'Upgrade: websocket\r\n'
            b'Connection: Upgrade\r\n'
            b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
            b'Sec-WebSocket-Protocol: chat, binary\r\n'
            b'Sec-WebSocket-Version: 13\r\n\r\n'
        )
        self.assertTrue(reponse.startswith(b'HTTP/1.1 101'), reponse)
        # RFC 6455 §1.3 : réponse attendue pour la clé d'exemple.
        self.assertIn(b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=', reponse)
        self.assertIn(b'Sec-WebSocket-Protocol: binary', reponse)

    async def test_poignee_de_main_serveur_refuse_sans_upgrade(self):
        with self.assertRaises(ValueError):
            await self._poignee_de_main_brute(
                b'GET / HTTP/1.1\r\nHost: x\r\nSec-WebSocket-Key: abc=\r\n\r\n', lever=True
            )

    async def test_poignee_de_main_serveur_refuse_sans_cle(self):
        with self.assertRaises(ValueError):
            await self._poignee_de_main_brute(
                b'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n', lever=True
            )

    async def test_poignee_de_main_serveur_refuse_autre_methode(self):
        with self.assertRaises(ValueError):
            await self._poignee_de_main_brute(b'POST / HTTP/1.1\r\n\r\n', lever=True)

    async def _poignee_de_main_brute(self, requete: bytes, lever: bool = False) -> bytes:
        """Envoie *requete* à _ws_handshake_server sur une vraie socket ; rend la réponse HTTP."""
        erreurs: list[BaseException] = []

        async def accepter(reader, writer):
            try:
                await asyncvnc2._ws_handshake_server(reader, writer)
            except ValueError as exc:
                erreurs.append(exc)
            finally:
                writer.close()

        serveur = await asyncio.start_server(accepter, '127.0.0.1', 0)
        try:
            port = serveur.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            writer.write(requete)
            await writer.drain()
            reponse = await asyncio.wait_for(reader.read(), 5)
            writer.close()
        finally:
            serveur.close()
            await serveur.wait_closed()
        if lever and erreurs:
            raise erreurs[0]
        return reponse

    async def test_poignee_de_main_client_refuse_mauvaise_cle_accept(self):
        async def accepter(reader, writer):
            while (await reader.readline()) not in (b'\r\n', b''):
                pass
            writer.write(
                b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                b'Connection: Upgrade\r\nSec-WebSocket-Accept: faux=\r\n\r\n'
            )
            await writer.drain()

        serveur = await asyncio.start_server(accepter, '127.0.0.1', 0)
        try:
            port = serveur.sockets[0].getsockname()[1]
            with self.assertRaises(ValueError):
                async with asyncvnc2.connect('127.0.0.1', port, websocket=True):
                    self.fail('clé Sec-WebSocket-Accept fausse acceptée')
        finally:
            serveur.close()
            await serveur.wait_closed()

    async def test_poignee_de_main_client_refuse_statut_non_101(self):
        async def accepter(reader, writer):
            while (await reader.readline()) not in (b'\r\n', b''):
                pass
            writer.write(b'HTTP/1.1 404 Not Found\r\n\r\n')
            await writer.drain()

        serveur = await asyncio.start_server(accepter, '127.0.0.1', 0)
        try:
            port = serveur.sockets[0].getsockname()[1]
            with self.assertRaises(ValueError):
                async with asyncvnc2.connect('127.0.0.1', port, websocket=True):
                    self.fail('statut 404 accepté')
        finally:
            serveur.close()
            await serveur.wait_closed()

    def test_trames_longueurs_7_16_et_64_bits(self):
        # RFC 6455 §5.2 : longueur sur 7 bits (<=125), 16 bits (126) ou 64 bits (127).
        for taille, octet_longueur, entete in ((5, 5, 2), (300, 126, 4), (70000, 127, 10)):
            trame = asyncvnc2._ws_frame(b'x' * taille, mask=False)
            self.assertEqual(trame[0], 0x82)
            self.assertEqual(trame[1], octet_longueur)
            self.assertEqual(len(trame), entete + taille)
        masquee = asyncvnc2._ws_frame(b'abc')
        self.assertEqual(masquee[1], 0x80 | 3)
        cle = masquee[2:6]
        self.assertEqual(bytes(b ^ cle[i % 4] for i, b in enumerate(masquee[6:])), b'abc')


class ReconnexionInverseeTests(unittest.IsolatedAsyncioTestCase):
    async def _port_libre(self) -> int:
        serveur = await asyncio.start_server(lambda r, w: None, '127.0.0.1', 0)
        port = serveur.sockets[0].getsockname()[1]
        serveur.close()
        await serveur.wait_closed()
        return port

    async def _composer(self, port: int, scenario: ServeurRfb, websocket: bool = False) -> None:
        """Le « serveur VNC » compose vers le client en écoute (vncconfig -connect)."""
        for _ in range(200):
            try:
                reader, writer = await asyncio.open_connection('127.0.0.1', port)
                break
            except OSError:
                await asyncio.sleep(0.02)
        else:
            raise AssertionError('le client en écoute ne répond pas')
        if websocket:
            reader, writer = await asyncvnc2._ws_wrap_connection(
                reader, writer, '127.0.0.1', port, '/'
            )
        await scenario.dialoguer(reader, writer)

    async def test_listen_accepte_le_serveur_qui_compose(self):
        port = await self._port_libre()
        pixels = _image()
        scenario = ServeurRfb(pixels=pixels)
        tache = asyncio.ensure_future(self._composer(port, scenario))
        try:
            async with asyncvnc2.listen('127.0.0.1', port) as client:
                self.assertIs(await asyncio.wait_for(client.read(), 5), asyncvnc2.UpdateType.VIDEO)
                np.testing.assert_array_equal(client.video.as_rgba(0, 0, 4, 3), pixels)
        finally:
            await asyncio.wait_for(scenario.termine.wait(), 5)
            await tache

    async def test_listen_sur_websocket(self):
        port = await self._port_libre()
        scenario = ServeurRfb()
        tache = asyncio.ensure_future(self._composer(port, scenario, websocket=True))
        try:
            async with asyncvnc2.listen('127.0.0.1', port, websocket=True) as client:
                self.assertEqual(client.video.name, 'bureau-test')
        finally:
            await asyncio.wait_for(scenario.termine.wait(), 5)
            await tache


if __name__ == '__main__':
    unittest.main()
