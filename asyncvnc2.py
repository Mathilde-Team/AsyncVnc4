# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import hmac
import ssl
from asyncio import (
    CancelledError,
    IncompleteReadError,
    Queue,
    QueueFull,
    StreamReader,
    StreamWriter,
    get_running_loop,
    open_connection,
    sleep,
    start_server,
)
from base64 import b64encode
from contextlib import ExitStack, asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction
from hashlib import sha1, sha256
from itertools import product
from os import urandom
from zlib import compress, decompressobj
from zlib import error as zlib_error

import numpy as np
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from keysymdef import keysymdef  # type: ignore
from loguru import logger

# Keyboard keys
key_codes: dict[str, int] = {}
key_codes.update((name, code) for name, code, char in keysymdef)
key_codes.update((chr(char), code) for name, code, char in keysymdef if char)
key_codes['Del'] = key_codes['Delete']
key_codes['Esc'] = key_codes['Escape']
key_codes['Cmd'] = key_codes['Super_L']
key_codes['Alt'] = key_codes['Alt_L']
key_codes['Ctrl'] = key_codes['Control_L']
key_codes['Super'] = key_codes['Super_L']
key_codes['Shift'] = key_codes['Shift_L']
key_codes['Backspace'] = key_codes['BackSpace']

# Common screen aspect ratios
screen_ratios: set[Fraction] = {
    Fraction(3, 2),
    Fraction(4, 3),
    Fraction(16, 10),
    Fraction(16, 9),
    Fraction(32, 9),
    Fraction(64, 27),
}

# Colour channel orders
video_modes: dict[bytes, str] = {
    b'\x20\x18\x00\x01\x00\xff\x00\xff\x00\xff\x10\x08\x00': 'bgra',
    b'\x20\x18\x00\x01\x00\xff\x00\xff\x00\xff\x00\x08\x10': 'rgba',
    b'\x20\x18\x01\x01\x00\xff\x00\xff\x00\xff\x10\x08\x00': 'argb',
    b'\x20\x18\x01\x01\x00\xff\x00\xff\x00\xff\x00\x08\x10': 'abgr',
}

video_definition: dict[str, bytes] = {v: k for k, v in video_modes.items()}

#: Open H.264 encoding number (0x48323634 = ASCII "H264"). Intentionally NOT an
#: Enc member -- it must never be auto-advertised by EncList.default(), and there
#: is no verified wire format to decode it against. See Video.read() for details.
_H264_ENCODING = 0x48323634

#: Plafond défensif sur toute longueur/taille annoncée par le serveur avant
#: une allocation (Tight, ZlibHex, curseurs). 64 Mo est largement au-dessus
#: de tout besoin légitime -- juste assez pour éviter qu'un serveur hostile
#: ou buggé ne force une allocation démesurée.
_MAX_ALLOC_BYTES = 64 * 1024 * 1024


def _check_alloc_size(n: int, what: str):
    logger.trace('_check_alloc_size() appelée | n={} what={}', n, what)
    if n > _MAX_ALLOC_BYTES:
        _erreur = ValueError(f'{what}: taille annoncée ({n} octets) dépasse le plafond de sécurité')
        logger.debug('_check_alloc_size() lève | {!r}', _erreur)
        raise _erreur
    logger.trace('_check_alloc_size() terminée')


class Enc(Enum):
    """
    Supported encodings

    Default priority order is TIGHT, TIGHT_PNG, ZRLE, TRLE, ZLIB, HEXTILE, COPY, RAW.
    ZYWRLE (17) is a supported (lossy) member but deliberately NOT in this
    default list -- see Enc.ZYWRLE and Enc.default() docstrings.

    The remaining members are pseudo-encodings: they never "win" a rectangle
    like the ones above, they either shape the framebuffer/cursor state
    (CURSOR, X_CURSOR, CURSOR_WITH_ALPHA, DESKTOP_SIZE, EXTENDED_DESKTOP_SIZE,
    LAST_RECT) or just advertise a capability with no rectangle payload of
    their own (FENCE, CONTINUOUS_UPDATES, XVP, EXTENDED_CLIPBOARD).
    """

    #: Tight encoding (BasicCompression/FillCompression/JpegCompression).
    TIGHT = 7

    #: Tight encoding, PNG variant (reuses the Tight decoder as-is).
    TIGHT_PNG = -260

    #: ZRLE encoding.
    ZRLE = 16

    #: ZYWRLE encoding (17), lossy (Hitachi's wavelet extension of ZRLE, issue #22).
    #: Same envelope as ZRLE (4-byte zlib length, 64x64 tiles through the same zlib
    #: context); the difference is inside a Raw tile: subencoding byte 0 is followed by
    #: a *complete nested ZRLE tile* (any subencoding) whose pixels are PLHarr wavelet
    #: coefficients, rebuilt by _zywrle_synthesize() (byte-for-byte port of
    #: libvncserver's ZYWRLE_SYNTHESIZE). Sources: QEMU ``ui/vnc-enc-zrle.c.inc``
    #: (ZRLE_ENCODE_TILE calls itself with ``zywrle_level | 0x80``) and libvncclient
    #: ``zrle.c``. The wavelet level is never sent: both sides derive it from the JPEG
    #: quality the client advertised (level = 3 - quality // 3, quality 0-8; QEMU sends
    #: plain ZRLE (16) when no quality, quality 9 or ``lossy`` is off), so
    #: Video.create() keeps ``jpeg_quality``. The 17-126 subencodings seen on
    #: 2026-09-09 against QEMU 8.2.2 were a stream desync (the nested tile read as Raw
    #: pixels), not a tile format; they are still refused (ValueError). Verified
    #: 2026-10-24 against a real QEMU 10.2.1 (``lossy=on``, levels 1-3, see
    #: test_live_qemu_zywrle.py and docs/sessions/session-25-2026-10-24.md). Still
    #: opt-in (excluded from Enc.default()) because it is lossy.
    ZYWRLE = 17

    #: TRLE encoding.
    TRLE = 15

    #: Raw encoding with zlib compession.
    ZLIB = 6

    #: Hextile encoding.
    HEXTILE = 5

    #: zlib-compressed Hextile encoding (LibVNCServer/x11vnc).
    ZLIBHEX = 8

    #: Ultra encoding (9, UltraVNC/LibVNCServer) : en-tête U32 (taille
    #: compressée) puis les pixels bruts du rectangle compressés en LZO1X
    #: (`lzo1x_1_compress`, voir `src/libvncserver/ultra.c`). Décodé par
    #: `_lzo1x_decompress()`, pur Python. Vérifié 2026-10-10 contre un vrai
    #: x11vnc 0.9.17 (issue #24) : image 640x480 identique au Raw, 10
    #: rectangles Ultra en ~0,2 s. Exclu de Enc.default() (opt-in) : seule
    #: LibVNCServer a été testée, pas UltraVNC lui-même (Windows).
    ULTRA = 9

    #: CoRRE encoding (Compact RRE -- rectangles limités à 255x255).
    CORRE = 4

    #: RRE encoding (Rise-and-Run-length Encoding).
    RRE = 3

    #: CopyRect encoding.
    COPY = 1

    #: Raw encoding.
    RAW = 0

    #: Rich Cursor pseudo-encoding: client-side cursor rendering.
    CURSOR = -239

    #: X Cursor pseudo-encoding: older/simpler cousin of CURSOR.
    X_CURSOR = -240

    #: Cursor With Alpha pseudo-encoding: true per-pixel alpha, no bitmask.
    CURSOR_WITH_ALPHA = -314

    #: DesktopSize pseudo-encoding: server-initiated framebuffer resize.
    DESKTOP_SIZE = -223

    #: ExtendedDesktopSize pseudo-encoding: resize + multi-screen layout.
    EXTENDED_DESKTOP_SIZE = -308

    #: LastRect pseudo-encoding: marks the end of an update of unknown rectangle count.
    LAST_RECT = -224

    #: Fence pseudo-encoding: enables the ClientFence/ServerFence messages.
    FENCE = -312

    #: ContinuousUpdates pseudo-encoding: enables streaming without polling.
    CONTINUOUS_UPDATES = -313

    #: xvp pseudo-encoding: enables the xvp Client/Server Messages (remote
    #: shutdown/reboot/reset of the system whose framebuffer we're viewing).
    XVP = -309

    #: Extended Clipboard pseudo-encoding (0xC0A1E5CE as signed S32): switches
    #: ClientCutText/ServerCutText (message-types 6/3) to a signed-length
    #: format that, on a negative length, carries a UTF-8-capable
    #: Caps/Request/Peek/Notify/Provide envelope instead of plain Latin-1 text
    #: (rfbproto.rst "Extended Clipboard Pseudo-Encoding"; see
    #: CLIPBOARD_FORMAT_*/CLIPBOARD_ACTION_* below, Client.process_extended_clipboard()
    #: and Client.send_clipboard_*()). Safe to advertise by default like
    #: Enc.XVP above -- a server that doesn't recognise this pseudo-encoding
    #: just ignores it per spec (confirmed 2026-09-13 by reading QEMU's own
    #: SetEncodings dispatch, ui/vnc.c: an unrecognised encoding value simply
    #: doesn't match any case and is skipped). **2026-09-13 : tested for
    #: real** against both a real TigerVNC/Xvnc 1.13.1 (the extension's
    #: originating implementation) and a real QEMU 8.2.2 -- see
    #: docs/features-backlog.md and docs/sessions/session-14-2026-09-13.md.
    #: Only the *text* format (UTF-8) is decoded/encoded by this fork --
    #: rtf/html/dib/files are correctly skipped over on receive (so the
    #: stream never desyncs) but their content is discarded, not implemented.
    EXTENDED_CLIPBOARD = (
        -1063131698
    )  # 0xC0A1E5CE as S32 -- verified against rfbproto.rst + QEMU/TigerVNC sources

    @classmethod
    def default(cls):
        """
        Get a list of supported encodings expect RAW.

        Enc.ZYWRLE (17) is deliberately excluded here -- opt-in only via
        EncList([...]) + Enc.ZYWRLE or EncList() + Enc.ZYWRLE. Its decoding is
        complete since issue #22 (verified against a real QEMU 10.2.1), but it is a
        lossy encoding: a caller that only asks for a jpeg_quality hint (meant for
        Tight) must not silently get wavelet artefacts in ZRLE rectangles too.

        Enc.ULTRA (9) est exclu aussi, pour une autre raison : seul le
        serveur LibVNCServer a été testé, pas UltraVNC (voir Enc.ULTRA).
        """
        return filter(lambda x: x.value not in (0, cls.ZYWRLE.value, cls.ULTRA.value), cls)


class EncList(list):
    """
    A list of Supported encodings and the simple operations:

    "-" -- Exclude from the list

    "+" -- Add to list or rise priority

    EncList()         -- default encoding list

    EncList(Enc.ZLIB) -- encoding list with one encoding

    EncList([Enc.ZLIB,Enc.TRLE]) -- encoding list with two encodings

    EncList() - Enc.ZLIB -- default encoding list except Enc.ZLIB

    EncList() + Enc.ZLIB -- default encoding list with hi-priority of Enc.ZLIB
    """

    def __init__(self, iterable=None):
        logger.debug('EncList.__init__() appelée')
        if iterable is None:
            super().__init__(Enc.default())
            logger.debug('EncList.__init__() retourne')
            return
        super().__init__([])
        if isinstance(iterable, Enc):
            iterable = [iterable]
        try:
            for x in iterable:
                if isinstance(x, Enc):
                    if x not in self:
                        self.append(x)
                else:
                    logger.debug('EncList.__init__() élément hors Enc | type={}', type(x).__name__)
                    raise TypeError
        except TypeError as exc:
            _erreur = TypeError('Arg must be one of the None or the Enc or the iterable of Enc')
            logger.debug('EncList.__init__() lève | {!r} (cause : {!r})', _erreur, exc)
            raise _erreur
        logger.debug('EncList.__init__() terminée')

    def __add__(self, other):
        logger.debug('EncList.__add__() appelée')
        if isinstance(other, Enc):
            _resultat = EncList([other, *self])
            logger.debug('EncList.__add__() retourne | {} encodage(s)', len(_resultat))
            return _resultat
        _resultat = EncList([*other, *self])
        logger.debug('EncList.__add__() retourne | {} encodage(s)', len(_resultat))
        return _resultat

    def __sub__(self, other):
        logger.debug('EncList.__sub__() appelée')
        if isinstance(other, Enc):
            other = [other]
        a = filter(lambda x: x not in other, self)

        _resultat = EncList(a)
        logger.debug('EncList.__sub__() retourne | {} encodage(s)', len(_resultat))
        return _resultat


async def read_int(reader: StreamReader, length: int) -> int:
    """
    Reads, unpacks, and returns an integer of *length* bytes.
    """

    return int.from_bytes(await reader.readexactly(length), 'big')


async def read_text(reader: StreamReader, encoding: str) -> str:
    """
    Reads, unpacks, and returns length-prefixed text.
    """

    logger.trace('read_text() appelée | encoding={}', encoding)
    length = await read_int(reader, 4)
    data = await reader.readexactly(length)
    _resultat = data.decode(encoding)
    logger.trace('read_text() retourne | {} caractère(s)', len(_resultat))
    return _resultat


def pack_ard(data):
    logger.debug('pack_ard() appelée | len(data)={}', len(data))
    encoded = data.encode('utf-8')
    if len(encoded) > 63:
        _erreur = ValueError(
            f'Identifiant/mot de passe Apple ARD trop long : {len(encoded)} '
            f'octets UTF-8 (63 maximum, terminateur nul compris dans les 64 '
            f'octets du champ protocolaire)'
        )
        logger.debug('pack_ard() lève | {!r}', _erreur)
        raise _erreur
    data = encoded + b'\x00'
    data += urandom(64 - len(data))
    logger.debug('pack_ard() retourne | {} octet(s)', len(data))
    return data


def _pack_mslogonii_field(data: str, field_size: int, what: str) -> bytes:
    """
    Encode un champ nom d'utilisateur/mot de passe MSLogonII (security type
    113) : UTF-8, terminateur nul, complété par des octets aléatoires
    jusqu'à *field_size* -- rfbproto.rst, section "MSLogonII
    Authentication" ("Both fields should be encoded using UTF-8, NULL
    terminated and padded with random data so the length of each is 256
    and 64 bytes respectively"). Même motif que pack_ard() ci-dessus
    (Apple ARD), avec des tailles de champ différentes.
    """

    logger.debug(
        '_pack_mslogonii_field() appelée | len(data)={} field_size={} what={}',
        len(data),
        field_size,
        what,
    )
    encoded = data.encode('utf-8')
    if len(encoded) > field_size - 1:
        _erreur = ValueError(
            f'{what} MSLogonII trop long : {len(encoded)} octets UTF-8 '
            f'({field_size - 1} maximum, terminateur nul compris dans les '
            f'{field_size} octets du champ protocolaire)'
        )
        logger.debug('_pack_mslogonii_field() lève | {!r}', _erreur)
        raise _erreur
    data = encoded + b'\x00'
    data += urandom(field_size - len(data))
    logger.debug('_pack_mslogonii_field() retourne | {} octet(s)', len(data))
    return data


async def _sasl_negotiate(
    reader: StreamReader, writer: StreamWriter, username: str | None, password: str | None
) -> None:
    """
    Négocie l'authentification SASL (security type 20, rfbproto.rst section
    "SASL") pour les mécanismes ``PLAIN`` (RFC 4616) et ``ANONYMOUS``
    (RFC 4505) uniquement.

    Contrairement au reste des types de sécurité de ce fichier, SASL n'est
    *pas* un format binaire figé mais une correspondance de RFC 2222 dans le
    protocole RFB, où la charge utile opaque (*clientout-data*/
    *serverout-data*) est en principe produite par un appel à une
    bibliothèque tierce (`cyrus-sasl`, via `sasl_client_start`/
    `sasl_client_step`). Le tramage sur le fil lui-même (longueurs U32,
    séquence mechlist -> client-start -> [server-start ->
    client-step -> server-step]* -> SecurityResult) est en revanche
    entièrement documenté indépendamment de cette bibliothèque -- voir
    `rfbproto.rst`, section "SASL". Seuls PLAIN et ANONYMOUS sont
    implémentés ici, en clair, sans aucune dépendance supplémentaire : ce
    sont les deux mécanismes SASL les plus simples possibles, chacun
    intégralement défini par sa propre RFC autonome (pas de défi du
    serveur, un seul aller-retour). Tout autre mécanisme
    (`DIGEST-MD5`/`GSSAPI`/`CRAM-MD5`/etc.) nécessiterait une vraie
    bibliothèque SASL (et souvent une infrastructure Kerberos pour
    `GSSAPI`) -- refusé explicitement ici plutôt que deviné, même principe
    que pour le type de sécurité 18 isolé
    (voir `docs/features-backlog.md`).

    Ni PLAIN ni ANONYMOUS ne négocient de couche de confidentialité/
    intégrité (SSF, "security strength factor") au sens de RFC 4422 -- le
    SSF de ces deux mécanismes est nul par construction. Il n'y a donc
    jamais, pour ces deux mécanismes précisément, de `sasl_encode`/
    `sasl_decode` à appliquer aux messages RFB qui suivent le
    `SecurityResult` : ce n'est pas une limite de cette implémentation,
    c'est une propriété des mécanismes eux-mêmes.

    **Testé contre un vrai QEMU 10.2 le 2026-10-10 (issue #32)**, PLAIN
    avec une base sasldb, via le sous-type VeNCrypt X509SASL (263) : seul
    chemin où QEMU propose PLAIN (voir la ConnectionError ci-dessous et
    `test_live_qemu_sasl.py`). Connexion et capture réussies ; mauvais mot de
    passe et utilisateur inconnu : connexion fermée par QEMU, remontée en
    PermissionError. ANONYMOUS n'est proposé par QEMU dans aucun mode
    (SASL_SEC_NOANONYMOUS hors X509SASL ; en X509SASL, dépend de la
    configuration Cyrus) : non vérifié contre un serveur réel.
    """

    logger.debug(
        '_sasl_negotiate() appelée | identifiant={} mot_de_passe={}', bool(username), bool(password)
    )
    try:
        mechlist_length = await read_int(reader, 4)
    except IncompleteReadError as exc:
        # Vu contre un vrai QEMU 10.2 (2026-10-10, issue #32) : sans aucun
        # mécanisme utilisable, il ferme la connexion au lieu d'envoyer une
        # liste vide (trace : « no available SASL mechanisms »). Hors
        # VeNCrypt X509SASL (et socket Unix), QEMU exige un mécanisme qui
        # chiffre lui-même (min_ssf=56, NOPLAINTEXT, NOANONYMOUS) : PLAIN et
        # ANONYMOUS sont retirés en SASL seul **et** en TLSSASL (TLS anonyme).
        _erreur = ConnectionError(
            'SASL: le serveur a fermé la connexion avant la liste des mécanismes '
            "(aucun mécanisme commun ? QEMU ne propose PLAIN/ANONYMOUS qu'en "
            'VeNCrypt X509SASL : tls-creds-x509 + sasl=on)'
        )
        logger.debug('_sasl_negotiate() lève | {!r} (cause : {!r})', _erreur, exc)
        raise _erreur from exc
    mechlist = (await reader.readexactly(mechlist_length)).decode('ascii')
    mechanisms = set(mechlist.split(',')) if mechlist else set()
    if not mechanisms:
        # QEMU 4.2 (vérifié 2026-10-11) envoie une liste vide là où QEMU 10
        # ferme la connexion (voir ci-dessus) : même cause, même conseil.
        _erreur = ValueError(
            'SASL: server offered no mechanisms (QEMU ne propose PLAIN/ANONYMOUS '
            "qu'en VeNCrypt X509SASL : tls-creds-x509 + sasl=on)"
        )
        logger.debug('_sasl_negotiate() lève | {!r}', _erreur)
        raise _erreur

    if 'PLAIN' in mechanisms and username is not None and password is not None:
        # RFC 4616 : authzid NUL authcid NUL passwd -- authzid vide (on
        # n'autorise pas à agir pour une identité distincte de authcid).
        chosen_mechanism = 'PLAIN'
        clientout = b'\x00' + username.encode('utf-8') + b'\x00' + password.encode('utf-8')
    elif 'ANONYMOUS' in mechanisms:
        # RFC 4505 : message optionnel ("trace information", p.ex. une
        # adresse mail ou un identifiant informel) -- le nom d'utilisateur
        # fourni sert de trace s'il y en a un, sinon message vide (les deux
        # sont valides selon la RFC).
        chosen_mechanism = 'ANONYMOUS'
        clientout = (username or '').encode('utf-8')
    else:
        _erreur = ValueError(
            f'SASL: aucun mécanisme pris en charge parmi {sorted(mechanisms)} '
            '(seuls PLAIN et ANONYMOUS sont implémentés ici -- les autres '
            'nécessiteraient une vraie bibliothèque SASL)'
        )
        logger.debug('_sasl_negotiate() lève | {!r}', _erreur)
        raise _erreur

    mechname = chosen_mechanism.encode('ascii')
    # "If clientout-data is non-NULL, it should be extended by a single NUL
    # byte" -- clientout construit ci-dessus n'est jamais None (toujours au
    # moins b'' pour ANONYMOUS sans nom d'utilisateur), donc toujours
    # complété d'un octet NUL.
    clientout_padded = clientout + b'\x00'
    writer.write(
        len(mechname).to_bytes(4, 'big')
        + mechname
        + len(clientout_padded).to_bytes(4, 'big')
        + clientout_padded
    )

    try:
        serverout_length = await read_int(reader, 4)
    except IncompleteReadError as exc:
        # QEMU (vérifié 2026-10-10) refuse un mauvais mot de passe ou un
        # utilisateur inconnu en fermant la connexion, sans SecurityResult.
        _erreur = PermissionError(
            f'SASL {chosen_mechanism}: authentification refusée (connexion fermée par le serveur)'
        )
        logger.debug('_sasl_negotiate() lève | {!r} (cause : {!r})', _erreur, exc)
        raise _erreur from exc
    await reader.readexactly(serverout_length)  # serverout-data, ignorée (voir docstring)
    complete_flag = await read_int(reader, 1)
    if complete_flag != 1:
        # PLAIN et ANONYMOUS sont tous deux des mécanismes à une seule
        # étape (RFC 4616/4505 : aucun défi du serveur) -- un
        # complete-flag à 0 ici indiquerait un serveur attendant une étape
        # SASL client-step supplémentaire non prévue par ces deux
        # mécanismes et non implémentée ici, plutôt que de deviner un
        # échange non documenté pour ce cas.
        _erreur = ValueError(
            f'SASL: échange multi-étapes inattendu pour {chosen_mechanism} '
            '(seuls PLAIN/ANONYMOUS en une étape sont pris en charge ici)'
        )
        logger.debug('_sasl_negotiate() lève | {!r}', _erreur)
        raise _erreur
    logger.debug('_sasl_negotiate() terminée')


# VeNCrypt (security type 19) sub-types, per the only formal spec that was
# ever written for this extension (obtained directly from the original
# VeNCrypt implementation, published on the tigervnc-rfbproto mailing list --
# https://www.mail-archive.com/tigervnc-rfbproto@lists.sourceforge.net/msg00256.html --
# this text never made it into an RFC, but the "Plain subtype" wire format
# below *is* documented in rfbproto.rst itself, section "VeNCrypt", which
# this fork also cross-checked) -- this text never made it into an RFC or
# into rfbproto.rst itself for the None/Vnc families, but it is the same
# document TigerVNC's own CSecurityVeNCrypt.cxx implements against.
#
# Six sub-types are implemented here, in three families, crossed with two
# encryption tiers (TLS.../X509...):
# - TLSNone/TLSVnc ("anonymous" TLS): the server presents a self-signed/
#   ephemeral certificate that this client deliberately does not attempt to
#   validate (see _vencrypt_negotiate below) -- that lack of validation *is*
#   the whole meaning of "anonymous" here, matching the "TLS anonyme" wording
#   used for this feature in features.md.
# - X509None/X509Vnc (added 2026-09-05): the server instead presents a real
#   CA-signed certificate that this client *does* validate against a trust
#   store -- by default the system trust store (`ssl.create_default_context()`,
#   the same default a browser or `requests`/`httpx` would use), or an
#   explicit CA supplied by the caller via `ssl_context` (e.g. an internal/
#   private CA). This is what features.md used to describe as "would need a
#   way for the caller to supply a CA certificate, which nothing here
#   currently plumbs through" -- that plumbing is `ssl_context` itself
#   (already threaded through `connect()`/`listen()`/`Client.create()` for
#   TLSNone/TLSVnc) plus the new `server_hostname` parameter below, needed
#   because `loop.start_tls()` refuses to check a certificate's hostname
#   without being told what hostname to check it against.
# - TLSPlain/X509Plain (added 2026-09-14): a third, orthogonal suffix --
#   after the TLS/X509 handshake, the client sends a username and password
#   as plain length-prefixed byte strings (rfbproto.rst "Plain subtype";
#   cross-checked against TigerVNC's own client, CSecurityPlain.cxx --
#   identical field order and U32 lengths). Reuses the existing `username`/
#   `password` parameters already accepted by `Client.create()` for Apple
#   authentication (type 33) above -- no new parameter needed. Encoded as
#   UTF-8: unlike VNC Authentication's DES challenge-response (Latin-1,
#   truncated to 8 bytes -- see the dedicated comment on that block), Plain
#   has no such cryptographic key-size constraint, so the modern, unambiguous
#   choice is used instead, matching how this fork already encodes Extended
#   Clipboard text.
#
# In all three families, "None" means no further authentication after the
# TLS handshake (the SecurityResult below concludes the negotiation
# directly), "Vnc" means standard VNC Authentication is layered on top, now
# running over the encrypted stream instead of the underlying algorithm
# changing, and "Plain" means the username/password exchange above instead.
_VENCRYPT_TLS_NONE = 257
_VENCRYPT_TLS_VNC = 258
_VENCRYPT_TLS_PLAIN = 259
_VENCRYPT_X509_NONE = 260
_VENCRYPT_X509_VNC = 261
_VENCRYPT_X509_PLAIN = 262
# Sous-types SASL (2026-10-10, issue #32) : TLS (anonyme) ou X509, puis la
# négociation SASL du type de sécurité 20 (_sasl_negotiate) sur le flux
# chiffré. Numéros d'après QEMU (ui/vnc.h : VNC_AUTH_VENCRYPT_X509SASL = 263,
# VNC_AUTH_VENCRYPT_TLSSASL = 264). C'est la seule façon d'obtenir PLAIN
# d'un vrai QEMU : sans TLS, QEMU exige un mécanisme SASL qui chiffre
# lui-même (SSF >= 56, ex. DIGEST-MD5) et retire PLAIN de sa liste.
_VENCRYPT_X509_SASL = 263
_VENCRYPT_TLS_SASL = 264


async def _start_tls_client(
    reader: StreamReader,
    writer: StreamWriter,
    ssl_context: ssl.SSLContext,
    server_hostname: str | None = None,
) -> tuple[StreamReader, StreamWriter]:
    """
    Upgrades an already-connected plain-TCP asyncio stream pair to TLS, in
    place. Needed for the VeNCrypt security type (see _vencrypt_negotiate),
    which multiplexes: ProtocolVersion and the VeNCrypt version/sub-type
    negotiation itself happen in clear, then everything from that point on
    (including the rest of the security handshake) must go over TLS on the
    *same* TCP connection -- there is no separate port or new connection.

    asyncio has no public "StreamWriter.start_tls()"; the documented way to
    upgrade an existing connection is `loop.start_tls()`, which swaps the
    transport under an existing protocol instance in place. The StreamReader
    keeps working unmodified afterwards -- `loop.start_tls()` internally
    calls `protocol.connection_made(new_transport)`, and
    `StreamReaderProtocol.connection_made()` reacts to that by calling
    `self._stream_reader.set_transport(new_transport)` on the very same
    StreamReader object we already have. Only the StreamWriter needs to be
    rebuilt: it binds to a specific transport at construction time and has
    no way to swap it out itself, so a fresh StreamWriter is constructed
    around the new (TLS) transport instead, reusing the same reader,
    protocol and event loop.

    *server_hostname* (added for the X509None/X509Vnc VeNCrypt sub-types,
    see _vencrypt_negotiate) is forwarded as-is to `loop.start_tls()`, used
    to check the hostname/IP on the certificate the server presents --
    meaningful whenever `ssl_context.check_hostname` is true, which is the
    default for `ssl.create_default_context()` used below for X509None/
    X509Vnc. Passing `None` here (as `listen()` does, see its own
    docstring) does NOT raise, even with `check_hostname` true: verified by
    real execution in this sandbox that asyncio's `loop.start_tls()`
    (`SSLContext.wrap_bio()` under the hood) silently skips the hostname
    check in that case instead of raising -- unlike the synchronous
    `SSLContext.wrap_socket()` API, which does raise
    `ValueError("check_hostname requires server_hostname")` in the same
    situation (a genuinely different code path; the naive assumption that
    asyncio would raise the same error was wrong and corrected in this
    session, see CLAUDE.md). Certificate CHAIN verification against the
    trust store still applies regardless of `server_hostname` -- only the
    hostname-matching step is affected. Harmless to pass a real hostname
    for TLSNone/TLSVnc, where the default anonymous context explicitly
    disables check_hostname anyway; if a caller supplies their own
    ssl_context for those sub-types with check_hostname enabled instead,
    forwarding it here is the correct behaviour too, not just a no-op.
    """
    logger.debug(
        '_start_tls_client() appelée | tls={} server_hostname={}',
        ssl_context is not None,
        server_hostname,
    )
    loop = get_running_loop()
    transport = writer.transport
    protocol = transport.get_protocol()
    new_transport = await loop.start_tls(
        transport, protocol, ssl_context, server_side=False, server_hostname=server_hostname
    )
    new_writer = StreamWriter(new_transport, protocol, reader, loop)
    logger.debug('_start_tls_client() retourne | (reader, new_writer)')
    return reader, new_writer


async def _vencrypt_negotiate(
    reader: StreamReader,
    writer: StreamWriter,
    ssl_context: ssl.SSLContext | None,
    server_hostname: str | None = None,
) -> tuple[StreamReader, StreamWriter, int]:
    """
    Runs the VeNCrypt (security type 19) version and sub-type negotiation,
    then upgrades the connection to TLS and returns the new (reader, writer)
    pair together with the sub-type that was selected -- the caller
    (Client.create()) still has to finish authentication itself for the
    "Vnc" sub-types (by falling through into the existing VNC Authentication
    block over the now-encrypted stream) and the "Plain" sub-types (by
    sending a username/password directly, see the comment above
    _VENCRYPT_TLS_NONE) and, either way, to read the final SecurityResult
    the same as for any other RFB 3.7/3.8 security type.

    Byte format verified against the only formal VeNCrypt specification that
    exists -- see the comment above _VENCRYPT_TLS_NONE for the source -- not
    from memory. Only version 0.2 of the extension is implemented (0.1 was
    never documented and, per that same spec author, no known VNC
    implementation was ever found that supports 0.1 but not 0.2).

    *server_hostname* is the hostname/IP the caller believes it is talking
    to (typically the same `host` passed to `connect()`) -- only meaningful
    for the X509None/X509Vnc/X509Plain sub-types added 2026-09-05/2026-09-14,
    see below and the comment above _VENCRYPT_TLS_NONE. Ignored (well,
    harmlessly forwarded) for TLSNone/TLSVnc/TLSPlain.

    Sub-type preference order when several are offered: X509Vnc, X509Plain,
    X509None, TLSVnc, TLSPlain, TLSNone -- real certificate validation
    (X509*) is preferred over anonymous TLS (TLS*), and within each family,
    requiring further authentication ("Vnc" or "Plain") is preferred over no
    further authentication at all ("None"), same reasoning as the
    pre-existing outer `for auth_type in (33, 1, 2, 19)` preference a few
    lines up in Client.create(). Between "Vnc" and "Plain", "Vnc" is
    preferred: VNC Authentication's DES challenge-response never puts the
    actual password on the wire (even the now-encrypted one), whereas
    "Plain" sends it directly -- safe once TLS/X509 is already established,
    but a passive TLS-terminating intermediary (a corporate proxy, say)
    would see it in the clear where it would not for "Vnc". A server
    offering only a subset of these six behaves exactly as before this
    session -- this ordering is a pure addition, not a change to any
    previous choice.

    TLSNone/TLSVnc: only tested in this sandbox against a hand-written fake
    VeNCrypt server over a real loopback TLS socket (see CLAUDE.md) --
    **tested for real against TigerVNC/Xvnc on 2026-09-08**, see the
    dedicated VeNCrypt row in features-backlog.md.

    X509None/X509Vnc (added 2026-09-05): same hand-written-fake-server
    loopback methodology, this time with a real two-tier CA/server
    certificate chain generated with `openssl` in this sandbox, covering
    both a successful connection (client trusts the CA that signed the
    server certificate) and a rejected one (client trusts an unrelated CA
    instead -- confirms real validation actually happens, unlike TLSNone/
    TLSVnc above). **Tested for real against TigerVNC/Xvnc on 2026-09-08**,
    see features-backlog.md.

    TLSPlain/X509Plain (added 2026-09-14): **tested for real against
    TigerVNC/Xvnc 1.13.1 from the start** (a real Linux user + PAM `vnc`
    service configured in this sandbox specifically for this test, since
    TigerVNC's `SSecurityPlain` delegates password verification to PAM/
    Windows and refuses to run at all without one) -- see
    docs/sessions/session-16-2026-09-14.md for the full method. Correct
    username/password: connection succeeds end-to-end. Wrong password:
    a real `rfb::AuthFailureException` from the server, surfaced here as
    the existing SecurityResult failure-reason path (unchanged code).
    """
    logger.debug(
        '_vencrypt_negotiate() appelée | tls={} server_hostname={}',
        ssl_context is not None,
        server_hostname,
    )
    server_major = await read_int(reader, 1)
    server_minor = await read_int(reader, 1)
    if server_major != 0 or server_minor < 2:
        _erreur = ValueError(
            f'unsupported VeNCrypt version offered by server: {server_major}.{server_minor}'
        )
        logger.debug('_vencrypt_negotiate() lève | {!r}', _erreur)
        raise _erreur

    writer.write(bytes([0, 2]))
    if await read_int(reader, 1) != 0:
        _erreur = ValueError('server rejected VeNCrypt version 0.2')
        logger.debug('_vencrypt_negotiate() lève | {!r}', _erreur)
        raise _erreur

    n_subtypes = await read_int(reader, 1)
    if n_subtypes == 0:
        _erreur = ValueError('server advertised no VeNCrypt sub-types')
        logger.debug('_vencrypt_negotiate() lève | {!r}', _erreur)
        raise _erreur
    raw_subtypes = await reader.readexactly(4 * n_subtypes)
    subtypes = [
        int.from_bytes(raw_subtypes[i : i + 4], 'big') for i in range(0, len(raw_subtypes), 4)
    ]

    for candidate in (
        _VENCRYPT_X509_VNC,
        _VENCRYPT_X509_PLAIN,
        _VENCRYPT_X509_SASL,
        _VENCRYPT_X509_NONE,
        _VENCRYPT_TLS_VNC,
        _VENCRYPT_TLS_PLAIN,
        _VENCRYPT_TLS_SASL,
        _VENCRYPT_TLS_NONE,
    ):
        if candidate in subtypes:
            chosen = candidate
            break
    else:
        _erreur = ValueError(
            f'unsupported VeNCrypt sub-types offered by server: {subtypes} (only '
            f'TLSNone/TLSVnc/TLSPlain/TLSSASL/X509None/X509Vnc/X509Plain/X509SASL '
            f'are implemented)'
        )
        logger.debug('_vencrypt_negotiate() lève | {!r}', _erreur)
        raise _erreur

    writer.write(chosen.to_bytes(4, 'big'))

    # Point de divergence réel entre sources trouvé et corrigé dans cette
    # session : le tout premier brouillon de spec VeNCrypt (mailing-list
    # tigervnc-rfbproto, 2010, cité plus haut) décrivait ici un U32 de
    # statut (0=OK) suivi, en cas d'échec, d'une chaîne de raison
    # longueur-préfixée -- mais ni la spec communautaire actuelle
    # (rfbproto.rst, section VeNCrypt/"Subtypes with TLS or X509 prefix")
    # ni l'implémentation de référence ne suivent ce format : TigerVNC
    # (`CSecurityTLS::processMsg()`, `common/rfb/CSecurityTLS.cxx`) lit un
    # unique octet U8 et lève une erreur seulement s'il vaut 0 -- aucune
    # chaîne de raison n'est lue. C'est ce format à un octet qui est
    # implémenté ci-dessous ; l'ancien format U32+raison aurait
    # désynchronisé la lecture d'un octet dès la première connexion à un
    # vrai serveur (lu comme les 3 premiers octets de la poignée de main
    # TLS elle-même).
    if await read_int(reader, 1) == 0:
        _erreur = ValueError(
            'server failed to set up VeNCrypt TLS (TLS session initialisation failed)'
        )
        logger.debug('_vencrypt_negotiate() lève | {!r}', _erreur)
        raise _erreur

    if ssl_context is None:
        if chosen in (
            _VENCRYPT_X509_NONE,
            _VENCRYPT_X509_VNC,
            _VENCRYPT_X509_PLAIN,
            _VENCRYPT_X509_SASL,
        ):
            # X509None/X509Vnc/X509Plain: the server presents a
            # real CA-signed certificate, unlike TLSNone/TLSVnc below --
            # this is exactly the "X509" prefix's meaning. The safe default
            # is therefore to actually verify it, against the system trust
            # store, the same default a browser or `requests`/`httpx` would
            # use -- not to silently disable verification as done for the
            # anonymous sub-types just below.
            #
            # A caller whose server uses a private/internal CA (the common
            # case in practice: publicly-trusted CAs essentially never
            # certify VNC endpoints) needs to supply their own ssl_context,
            # e.g.:
            #     ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            #     ctx.load_verify_locations(cafile='ma-ca-interne.pem')
            #     await connect(host, ssl_context=ctx)
            # Passing an explicit ssl_context always takes priority over
            # this default, exactly as it already did for TLSNone/TLSVnc.
            ssl_context = ssl.create_default_context()
        else:
            # TLSNone/TLSVnc are the "anonymous" VeNCrypt sub-types: the
            # server presents a self-signed/ephemeral certificate that
            # there is, by construction, no CA to validate it against --
            # that lack of validation *is* what "anonymous" means here, as
            # opposed to the X509None/X509Vnc sub-types just above, which do
            # carry a real, verifiable certificate. Disabling verification
            # is therefore the correct default for these two sub-types
            # specifically, not a careless bypass -- a caller who wants
            # strict verification instead can always pass their own
            # ssl_context (which is exactly what selects X509None/X509Vnc's
            # verifying behaviour above, if the server also offers one of
            # those two).
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            # 2026-09-07, trouve par test reel contre un vrai serveur
            # TigerVNC (Xvnc, backend GnuTLS) : le contexte ci-dessus,
            # jusque-la, ne suffisait PAS a etablir une session TLSNone/
            # TLSVnc contre ce serveur reel -- echec immediat cote serveur
            # ("TLS Handshake failed: Insufficient credentials for that
            # request."), alors que le meme code fonctionnait contre un
            # faux serveur fabrique a la main lors de la verification du
            # 2026-09-02. Cause reelle : TigerVNC/GnuTLS implemente ces
            # deux sous-types "anonymes" avec de vraies suites Diffie-
            # Hellman anonymes (ADH/AECDH, aucun certificat echange du
            # tout), alors que le faux serveur de test utilisait un
            # certificat auto-signe avec des suites authentifiees
            # normales (CERT_NONE cote client desactive juste la
            # *verification* du certificat, ce qui est different d'une
            # suite reellement anonyme) -- deux implementations
            # differentes d'"anonyme" au sens VeNCrypt du terme.
            # OpenSSL 1.1.0+ retire les suites anonymes de sa liste de
            # suites par defaut (SECLEVEL 1 les exclut deja) ; sans
            # reactivation explicite, aucune suite commune n'existe entre
            # ce client et un serveur qui n'offre QUE de l'anonyme reel --
            # confirme en forcant manuellement `set_ciphers('ADH:AECDH:'
            # '@SECLEVEL=0')` + `maximum_version = TLSv1_2` (les suites
            # anonymes n'existent pas en TLS 1.3, protocole qui les a
            # retirees structurellement) : la connexion contre le meme
            # Xvnc reussit alors. Mais reactiver les suites anonymes ne
            # suffit pas a lui seul : `'DEFAULT:ADH:AECDH:@SECLEVEL=0'`
            # (suites anonymes ajoutees APRES la liste par defaut, pour ne
            # pas casser la non-regression contre un serveur qui
            # presenterait un certificat auto-signe avec des suites
            # authentifiees normales -- exactement le scenario deja
            # verifie le 2026-09-02) echoue tout aussi silencieusement que
            # l'absence totale de suites anonymes. Diagnostic par
            # bissection (`SSLContext.get_ciphers()` sur chaque variante,
            # plus repetition apres avoir decouvert que TigerVNC blackliste
            # temporairement une IP au bout de 5 echecs d'authentification
            # -- `-UseBlacklist=0` cote serveur de test le temps du
            # diagnostic, pour ne pas fausser les mesures) : la ou
            # `'DEFAULT:ADH:AECDH'` echoue, `'ADH:AECDH:DEFAULT'` (memes
            # suites, ordre inverse) reussit. Ce n'est donc pas une
            # question de PRESENCE des suites anonymes dans la liste, mais
            # de leur RANG : `set_ciphers()` restitue une liste ordonnee
            # selon l'ordre d'apparition des tokens dans la chaine, et
            # GnuTLS (backend de Xvnc) ne semble considerer qu'un prefixe
            # de la liste annoncee par le client avant de conclure "No
            # supported cipher suites have been found" -- avec `ADH-AES256
            # -GCM-SHA384` en position 3 (`'ADH:AECDH:HIGH'`) la connexion
            # reussit, avec la meme suite en position 18 (`'ALL:!eNULL'`,
            # ordre par defaut d'OpenSSL) elle echoue, a liste de suites
            # quasi identique par ailleurs (140 vs 141 entrees). Chaine
            # retenue : `'ADH:AECDH:ALL:!eNULL:@SECLEVEL=0'` -- suites
            # anonymes placees EN TETE (prioritaires pour un serveur
            # anonyme reel comme TigerVNC/GnuTLS), suivies de l'ensemble
            # des suites authentifiees normales pour prendre le relais
            # face a un serveur (reel ou fabrique a la main) qui
            # presenterait un certificat auto-signe avec des suites
            # classiques -- verifie sans regression dans les deux sens
            # (voir CLAUDE.md, entree du 2026-09-08). `!eNULL` exclut
            # uniquement les suites sans chiffrement (le "e" de eNULL) ;
            # les suites sans authentification (le "a" de aNULL, ADH/
            # AECDH) restent incluses -- seule l'authentification est
            # optionnelle ici, pas le chiffrement lui-meme. Un caller qui
            # fournit son propre `ssl_context` continue de
            # court-circuiter entierement ce bloc, comme avant.
            ssl_context.set_ciphers('ADH:AECDH:ALL:!eNULL:@SECLEVEL=0')
            ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2

    reader, writer = await _start_tls_client(reader, writer, ssl_context, server_hostname)
    logger.debug('_vencrypt_negotiate() retourne | (reader, writer, chosen={})', chosen)
    return reader, writer, chosen


# RSA-AES security types (5=RA2, 129=RA2_256 -- "RSA-AES-256"; rfbproto.rst
# "RSA-AES Security Type"/"RSA-AES-256 Security Type", added by TigerVNC in
# 2022). Unlike VeNCrypt above, this is not a wrapper around TLS: the RSA
# key exchange and the AES-EAX message framing that follows are both
# implemented from scratch here, since nothing in Python's standard library
# or in `cryptography` does either for us the way `ssl`/`start_tls()` does
# for VeNCrypt. Two sibling security types exist for each -- RA2ne/RA2ne_256
# ("only the handshake is encrypted, SecurityResult and everything after
# stays in the clear") and RA2r/RA2r_256 ("a second round of key derivation
# after the credentials, this time over AES-EAX instead of RSA") -- neither
# is implemented here: RA2ne trades away exactly the property that makes
# RA2 worth having in the first place, and RA2r's extra round buys a
# marginal property (forward secrecy for a hypothetical RSA key compromise
# discovered mid-session) at real extra complexity, for a fork that only
# needs to interoperate as a client, not to hedge against every possible
# server hardening choice. Confirmed real values by reading TigerVNC's own
# client, common/rfb/{CSecurityRSAAES.cxx,CSecurityRSAAES.h} and
# common/rdr/{AESInStream,AESOutStream}.cxx (2026-09-15) -- several details
# below (the AES key size actually being 128/256 rather than matching the
# RSA key size, the exact preimage byte layout for the two SHA1/SHA256
# hashes, the credentials format, and the EAX nonce/associated-data
# construction) are not fully pinned down by rfbproto.rst's prose alone and
# were taken from this reference implementation instead.
RSA_AES_MIN_KEY_LENGTH = 1024  # bits; TigerVNC's own client refuses shorter
RSA_AES_MAX_KEY_LENGTH = 8192  # bits; TigerVNC's own client refuses longer
RSA_AES_SUBTYPE_USERPASS = 1  # server wants both username and password
RSA_AES_SUBTYPE_PASS = 2  # server wants only a password
_EAX_TAG_SIZE = 16  # AES block size -- true for EAX regardless of AES-128 vs AES-256
_EAX_MAX_MESSAGE_SIZE = 8192  # matches TigerVNC's AESOutStream::MaxMessageSize exactly


def _omac(key: bytes, tweak: int, message: bytes) -> bytes:
    """
    One building block of AES-EAX: CMAC of a single all-zero 16-byte block
    with its last byte set to *tweak*, concatenated with *message* --
    OMAC_K^tweak(message) in the notation rfbproto.rst itself uses ("N =
    OMAC_K^0(Nonce)", etc.). *key* is the raw AES key (16 or 32 bytes).
    """
    logger.trace(
        '_omac() appelée | len(key)={} tweak={} len(message)={}', len(key), tweak, len(message)
    )
    mac = cmac.CMAC(algorithms.AES(key))
    mac.update(bytes(15) + bytes([tweak]) + message)
    _resultat = mac.finalize()
    logger.trace('_omac() retourne | {} octet(s)', len(_resultat))
    return _resultat


def _eax_seal(key: bytes, nonce: bytes, header: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts *plaintext* with AES-EAX, returning (ciphertext, 16-byte tag).
    *nonce* is the 16-byte message counter (see _EAXWriter below), *header*
    is the associated data (the 2-byte big-endian length prefix, for this
    fork's one and only use of EAX). `cryptography` has no built-in AESEAX
    class (unlike AESGCM/AESCCM/AESSIV/AESOCB3/ChaCha20Poly1305 -- checked
    2026-09-15), so this rebuilds the construction from CTR mode + CMAC
    exactly as the EAX paper defines it and as TigerVNC's own
    common/rdr/AESOutStream.cxx does it (via Nettle's EAX macros) --
    N=OMAC^0(nonce), H=OMAC^1(header), C=CTR_N(plaintext), tag=N⊕H⊕OMAC^2(C).
    """
    logger.trace(
        '_eax_seal() appelée | len(key)={} len(nonce)={} len(header)={} len(plaintext)={}',
        len(key),
        len(nonce),
        len(header),
        len(plaintext),
    )
    n_tag = _omac(key, 0, nonce)
    h_tag = _omac(key, 1, header)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(n_tag)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    c_tag = _omac(key, 2, ciphertext)
    tag = bytes(a ^ b ^ c for a, b, c in zip(n_tag, h_tag, c_tag))
    logger.trace(
        '_eax_seal() retourne | (len(ciphertext)={}, len(tag)={})', len(ciphertext), len(tag)
    )
    return ciphertext, tag


def _eax_open(key: bytes, nonce: bytes, header: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Inverse of _eax_seal(): verifies *tag* (constant-time, via
    hmac.compare_digest -- TigerVNC's own AESInStream.cxx uses a plain
    memcmp() here, but there is no reason for this fork to copy that
    particular shortcut when a safer comparison is one import away) and
    raises ValueError on mismatch, otherwise returns the decrypted
    plaintext.
    """
    logger.trace(
        '_eax_open() appelée | len(key)={} len(nonce)={} len(header)={} len(ciphertext)={} len(tag)={}',
        len(key),
        len(nonce),
        len(header),
        len(ciphertext),
        len(tag),
    )
    n_tag = _omac(key, 0, nonce)
    h_tag = _omac(key, 1, header)
    c_tag = _omac(key, 2, ciphertext)
    expected_tag = bytes(a ^ b ^ c for a, b, c in zip(n_tag, h_tag, c_tag))
    if not hmac.compare_digest(expected_tag, tag):
        _erreur = ValueError(
            "AES-EAX : jeton d'authenticité invalide (message corrompu ou mauvaise clé)"
        )
        logger.debug('_eax_open() lève | {!r}', _erreur)
        raise _erreur
    decryptor = Cipher(algorithms.AES(key), modes.CTR(n_tag)).decryptor()
    _resultat = decryptor.update(ciphertext) + decryptor.finalize()
    logger.trace('_eax_open() retourne | {} octet(s)', len(_resultat))
    return _resultat


def _eax_increment_counter(counter: bytearray) -> None:
    """
    Increments *counter* in place as a 128-bit little-endian unsigned
    integer -- the exact scheme rfbproto.rst specifies for the EAX message
    index ("16-byte little-endian message index increments from zero"),
    confirmed byte-for-byte against TigerVNC's own AESInStream.cxx/
    AESOutStream.cxx (both increment the lowest-address byte first,
    carrying into the next byte on overflow, stopping at the first byte
    that does *not* wrap to 0).
    """
    logger.trace('_eax_increment_counter() appelée | len(counter)={}', len(counter))
    for i in range(16):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i] != 0:
            break
    logger.trace('_eax_increment_counter() terminée')


class _EAXReader:
    """
    Enveloppe un `StreamReader` TCP brut pour déchiffrer et authentifier
    chaque message AES-EAX avant de le rendre disponible à `readexactly()`
    -- transparent pour tout le reste de ce fichier, qui ne s'en sert que
    via cette unique méthode (voir le commentaire au-dessus de
    RSA_AES_MIN_KEY_LENGTH pour le format exact et sa source). Contrairement
    à `_ws_wrap_connection()` (WebSockets), pas besoin d'une tâche de fond
    ni de `feed_data()` : chaque message EAX porte son propre préfixe de
    longueur explicite (2 octets), donc un simple aller-retour
    `readexactly()` sur le flux brut suffit à en lire un entier avant de le
    déchiffrer.
    """

    def __init__(self, raw_reader: StreamReader, key: bytes):
        logger.debug('_EAXReader.__init__() appelée | len(key)={}', len(key))
        self._raw = raw_reader
        self._key = key
        self._counter = bytearray(16)
        self._buffer = b''
        logger.debug('_EAXReader.__init__() terminée')

    async def readexactly(self, n: int) -> bytes:
        logger.trace('_EAXReader.readexactly() appelée | n={}', n)
        while len(self._buffer) < n:
            self._buffer += await self._read_one_message()
        result, self._buffer = self._buffer[:n], self._buffer[n:]
        logger.trace('_EAXReader.readexactly() retourne | {} octet(s)', len(result))
        return result

    async def _read_one_message(self) -> bytes:
        logger.trace('_EAXReader._read_one_message() appelée')
        header = await self._raw.readexactly(2)
        length = int.from_bytes(header, 'big')
        ciphertext_and_tag = await self._raw.readexactly(length + _EAX_TAG_SIZE)
        ciphertext, tag = ciphertext_and_tag[:length], ciphertext_and_tag[length:]
        plaintext = _eax_open(self._key, bytes(self._counter), header, ciphertext, tag)
        _eax_increment_counter(self._counter)
        logger.trace('_EAXReader._read_one_message() retourne | {} octet(s)', len(plaintext))
        return plaintext


class _EAXWriter:
    """
    Enveloppe un `StreamWriter` TCP brut pour que chaque `write()` soit
    automatiquement scindé en messages d'au plus `_EAX_MAX_MESSAGE_SIZE`
    octets (comme `AESOutStream::MaxMessageSize` côté TigerVNC), chiffrés
    et authentifiés en AES-EAX avant d'être réellement écrits sur le
    socket -- même principe et même API minimale que `_WebSocketWriter`
    ci-dessus (voir sa docstring), mais pour un chiffrement plutôt qu'un
    tunnel WebSocket.
    """

    def __init__(self, raw_writer: StreamWriter, key: bytes):
        logger.debug('_EAXWriter.__init__() appelée | len(key)={}', len(key))
        self._raw = raw_writer
        self._key = key
        self._counter = bytearray(16)
        logger.debug('_EAXWriter.__init__() terminée')

    def write(self, data: bytes) -> None:
        logger.trace('_EAXWriter.write() appelée | len(data)={}', len(data))
        data = bytes(data)
        for offset in range(0, len(data), _EAX_MAX_MESSAGE_SIZE):
            chunk = data[offset : offset + _EAX_MAX_MESSAGE_SIZE]
            header = len(chunk).to_bytes(2, 'big')
            ciphertext, tag = _eax_seal(self._key, bytes(self._counter), header, chunk)
            self._raw.write(header + ciphertext + tag)
            _eax_increment_counter(self._counter)
        logger.trace('_EAXWriter.write() terminée')

    async def drain(self) -> None:
        logger.trace('_EAXWriter.drain() appelée')
        await self._raw.drain()
        logger.trace('_EAXWriter.drain() terminée')

    def close(self) -> None:
        logger.debug('_EAXWriter.close() appelée')
        self._raw.close()
        logger.debug('_EAXWriter.close() terminée')

    async def wait_closed(self) -> None:
        logger.debug('_EAXWriter.wait_closed() appelée')
        await self._raw.wait_closed()
        logger.debug('_EAXWriter.wait_closed() terminée')


async def _rsa_aes_negotiate(
    reader: StreamReader,
    writer: StreamWriter,
    key_bits: int,
    username: str | None,
    password: str | None,
):
    """
    Runs the full RSA-AES (security type 5, `key_bits=128`) or RSA-AES-256
    (security type 129, `key_bits=256`) handshake and returns
    (new_reader, new_writer, server_key_fingerprint) -- from this point on
    the ENTIRE connection is wrapped in AES-EAX (unlike VeNCrypt, this is
    not optional/sub-typed here: only the fully-encrypted RA2/RA2_256
    variants are implemented, see the comment above RSA_AES_MIN_KEY_LENGTH).
    The caller (Client.create()) still has to read the final SecurityResult
    the same as for any other security type -- but over the now-returned,
    already-encrypted reader/writer, since unlike VeNCrypt's plain TLS
    upgrade, RSA-AES's own spec explicitly folds SecurityResult itself into
    the encrypted stream ("After that the server continues with the
    encrypted SecurityResult message").

    Byte format verified against rfbproto.rst ("RSA-AES Security Type"/
    "RSA-AES-256 Security Type") **and** against TigerVNC's own client
    (common/rfb/CSecurityRSAAES.cxx) -- several details below came from the
    latter, not the former (see the comment above RSA_AES_MIN_KEY_LENGTH).

    *key_bits* selects AES-128 + SHA-1 (128) or AES-256 + SHA-256 (256) for
    the session keys and the two integrity hashes exchanged during the
    handshake -- this is independent of the server's RSA key size (read off
    the wire, not chosen by the caller), which the client's own generated
    RSA key simply matches (`clientKeyLength = serverKeyLength` in
    TigerVNC's own client -- copied here for the same reason: nothing in
    the spec requires it, but every real server this fork can test against
    is that same TigerVNC).

    Server key verification: unlike Apple ARD authentication above (which
    accepts an already-known `host_key` to skip re-fetching/re-encrypting
    with it), this fork does not implement any cross-connection pinning
    storage for RSA-AES -- that is an application-level policy decision
    (see docs/reference/downstream-consumer.md), not something a low-level
    protocol client should decide on the caller's behalf. What this
    function DOES do is what TigerVNC's own client always does regardless
    of pinning: compute and return the same RealVNC-style fingerprint
    (`%02x-%02x-...` of the first 8 bytes of SHA-1(U32(server-key-length) +
    modulus + exponent) -- "so users can compare", straight from
    CSecurityRSAAES.cxx's own comment) via the returned tuple's third
    element, so a caller that DOES want pinning has something ready to
    compare and to store (see Client.rsa_aes_server_key_fingerprint).

    **Tested for real against TigerVNC/Xvnc 1.13.1 on 2026-09-15** -- see
    docs/sessions/session-17-2026-09-15.md for the full method (a real
    Linux user + PAM, reused from the VeNCrypt Plain work earlier the same
    day, since TigerVNC's `SSecurityRSAAES` also delegates password
    verification to `PlainUsers`/PAM).
    """
    logger.debug(
        '_rsa_aes_negotiate() appelée | key_bits={} identifiant={} mot_de_passe={}',
        key_bits,
        bool(username),
        bool(password),
    )
    hash_algorithm = sha1 if key_bits == 128 else sha256

    server_key_length = await read_int(reader, 4)
    if server_key_length < RSA_AES_MIN_KEY_LENGTH:
        _erreur = ValueError(f'server RSA-AES key too short ({server_key_length} bits)')
        logger.debug('_rsa_aes_negotiate() lève | {!r}', _erreur)
        raise _erreur
    if server_key_length > RSA_AES_MAX_KEY_LENGTH:
        _erreur = ValueError(f'server RSA-AES key too long ({server_key_length} bits)')
        logger.debug('_rsa_aes_negotiate() lève | {!r}', _erreur)
        raise _erreur
    server_key_size = (server_key_length + 7) // 8
    server_key_n_bytes = await reader.readexactly(server_key_size)
    server_key_e_bytes = await reader.readexactly(server_key_size)
    server_key_n = int.from_bytes(server_key_n_bytes, 'big')
    server_key_e = int.from_bytes(server_key_e_bytes, 'big')
    server_public_key = rsa.RSAPublicNumbers(server_key_e, server_key_n).public_key()

    # Empreinte façon RealVNC pour un éventuel épinglage côté appelant --
    # voir la docstring ci-dessus. Ne bloque jamais la connexion elle-même :
    # ce fork ne connaît aucune empreinte "de confiance" préalable, seule
    # l'application appelante peut savoir si celle-ci est acceptable.
    fingerprint_input = (
        server_key_length.to_bytes(4, 'big') + server_key_n_bytes + server_key_e_bytes
    )
    fingerprint_digest = sha1(fingerprint_input).digest()
    server_key_fingerprint = '-'.join(f'{b:02x}' for b in fingerprint_digest[:8])

    client_key_length = (
        server_key_length  # cf. docstring : imite TigerVNC, pas une exigence de la spec
    )
    client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=client_key_length)
    client_public_numbers = client_private_key.public_key().public_numbers()
    client_key_size = (client_key_length + 7) // 8
    client_key_n_bytes = client_public_numbers.n.to_bytes(client_key_size, 'big')
    client_key_e_bytes = client_public_numbers.e.to_bytes(client_key_size, 'big')
    writer.write(client_key_length.to_bytes(4, 'big') + client_key_n_bytes + client_key_e_bytes)
    await writer.drain()

    random_size = key_bits // 8
    client_random = urandom(random_size)
    encrypted_client_random = server_public_key.encrypt(client_random, padding.PKCS1v15())
    writer.write(len(encrypted_client_random).to_bytes(2, 'big') + encrypted_client_random)
    await writer.drain()

    encrypted_random_length = await read_int(reader, 2)
    if encrypted_random_length != client_key_size:
        _erreur = ValueError(
            f'server sent a {encrypted_random_length}-byte encrypted random number, '
            f'expected {client_key_size} to match our own key size'
        )
        logger.debug('_rsa_aes_negotiate() lève | {!r}', _erreur)
        raise _erreur
    encrypted_server_random = await reader.readexactly(encrypted_random_length)
    server_random = client_private_key.decrypt(encrypted_server_random, padding.PKCS1v15())
    if len(server_random) != random_size:
        _erreur = ValueError(
            'failed to decrypt the server random number (wrong size after decryption)'
        )
        logger.debug('_rsa_aes_negotiate() lève | {!r}', _erreur)
        raise _erreur

    # Clé de session = condensé complet pour 256 bits (SHA-256 fait déjà
    # 32 octets = 256 bits, aucune troncature) ; pour 128 bits, les 16
    # premiers octets du condensé SHA-1 (qui en fait 20) -- vérifié contre
    # CSecurityRSAAES::setCipher() (Nettle) qui construit ses deux clés
    # AES-128/AES-256 exactement ainsi, sans jamais tronquer à 16 dans le
    # cas 256 (piège trouvé par exécution réelle contre RA2_256 : une
    # première version de ce fork tronquait toujours à 16 octets par
    # erreur, ce qui échouait immédiatement avec un jeton EAX invalide dès
    # le premier message chiffré -- voir docs/sessions/session-17-2026-09-15.md).
    client_session_key = hash_algorithm(server_random + client_random).digest()[: key_bits // 8]
    server_session_key = hash_algorithm(client_random + server_random).digest()[: key_bits // 8]
    eax_reader = _EAXReader(reader, server_session_key)
    eax_writer = _EAXWriter(writer, client_session_key)

    server_key_blob = server_key_length.to_bytes(4, 'big') + server_key_n_bytes + server_key_e_bytes
    client_key_blob = client_key_length.to_bytes(4, 'big') + client_key_n_bytes + client_key_e_bytes
    client_hash = hash_algorithm(client_key_blob + server_key_blob).digest()
    eax_writer.write(client_hash)
    await eax_writer.drain()

    expected_server_hash = hash_algorithm(server_key_blob + client_key_blob).digest()
    received_server_hash = await eax_reader.readexactly(len(expected_server_hash))
    if not hmac.compare_digest(received_server_hash, expected_server_hash):
        _erreur = ValueError(
            'RSA-AES : hachage du serveur incorrect (négociation corrompue ou usurpée)'
        )
        logger.debug('_rsa_aes_negotiate() lève | {!r}', _erreur)
        raise _erreur

    subtype = (await eax_reader.readexactly(1))[0]
    if subtype not in (RSA_AES_SUBTYPE_USERPASS, RSA_AES_SUBTYPE_PASS):
        _erreur = ValueError(f'unknown RSA-AES subtype {subtype!r} requested by server')
        logger.debug('_rsa_aes_negotiate() lève | {!r}', _erreur)
        raise _erreur
    if password is None or (subtype == RSA_AES_SUBTYPE_USERPASS and username is None):
        _erreur = ValueError(
            'server requires username and password (RSA-AES)'
            if subtype == RSA_AES_SUBTYPE_USERPASS
            else 'server requires a password (RSA-AES)'
        )
        logger.debug('_rsa_aes_negotiate() lève | {!r}', _erreur)
        raise _erreur

    credentials = b''
    if subtype == RSA_AES_SUBTYPE_USERPASS:
        username_bytes = username.encode('utf-8')
        if len(username_bytes) > 255:
            _erreur = ValueError(
                'username is too long for RSA-AES (255 bytes max once UTF-8 encoded)'
            )
            logger.debug('_rsa_aes_negotiate() lève | {!r}', _erreur)
            raise _erreur
        credentials += bytes([len(username_bytes)]) + username_bytes
    else:
        credentials += b'\x00'
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 255:
        _erreur = ValueError('password is too long for RSA-AES (255 bytes max once UTF-8 encoded)')
        logger.debug('_rsa_aes_negotiate() lève | {!r}', _erreur)
        raise _erreur
    credentials += bytes([len(password_bytes)]) + password_bytes
    eax_writer.write(credentials)
    await eax_writer.drain()

    logger.debug(
        '_rsa_aes_negotiate() retourne | (eax_reader, eax_writer, len(server_key_fingerprint)={})',
        len(server_key_fingerprint),
    )
    return eax_reader, eax_writer, server_key_fingerprint


@dataclass
class Clipboard:
    """
    Shared clipboard.
    """

    writer: StreamWriter = field(repr=False)

    #: The clipboard text.
    text: str = ''

    def write(self, text: str):
        """
        Sends clipboard text to the server using the original, Latin-1-only
        ClientCutText format. See Client.send_clipboard_provide() for the
        UTF-8-capable Extended Clipboard alternative (Enc.EXTENDED_CLIPBOARD) --
        it requires the server to have confirmed support first, so it lives on
        Client rather than here; this method's behaviour is unchanged.
        """

        logger.trace('Clipboard.write() appelée | len(text)={}', len(text))
        data = text.encode('latin-1')
        self.writer.write(b'\x06\x00\x00\x00' + len(data).to_bytes(4, 'big') + data)
        logger.trace('Clipboard.write() terminée')


@dataclass
class Keyboard:
    """
    Virtual keyboard.
    """

    writer: StreamWriter = field(repr=False)

    @contextmanager
    def _write(self, key: str):
        # Rien sur la touche (ni nom ni longueur) : enregistreur de frappes sinon.
        logger.trace('Keyboard._write() appelée')
        data = key_codes[key].to_bytes(4, 'big')
        self.writer.write(b'\x04\x01\x00\x00' + data)
        try:
            yield
        finally:
            self.writer.write(b'\x04\x00\x00\x00' + data)
        logger.trace('Keyboard._write() terminée')

    @contextmanager
    def hold(self, *keys: str):
        """
        Context manager that pushes the given keys on enter, and releases them (in reverse order) on exit.
        """

        logger.trace('Keyboard.hold() appelée | len(keys)={}', len(keys))
        with ExitStack() as stack:
            for key in keys:
                stack.enter_context(self._write(key))
            yield
        logger.trace('Keyboard.hold() terminée')

    def press(self, *keys: str):
        """
        Pushes all the given keys, and then releases them in reverse order.
        """

        logger.trace('Keyboard.press() appelée | len(keys)={}', len(keys))
        with self.hold(*keys):
            pass
        logger.trace('Keyboard.press() terminée')

    def write(self, text: str):
        """
        Pushes and releases each of the given keys, one after the other.
        """

        logger.trace('Keyboard.write() appelée | len(text)={}', len(text))
        for key in text:
            with self.hold(key):
                pass
        logger.trace('Keyboard.write() terminée')


@dataclass
class Mouse:
    """
    Virtual mouse.
    """

    writer: StreamWriter = field(repr=False)
    buttons: int = 0
    x: int = 0
    y: int = 0

    def _write(self):
        logger.trace('Mouse._write() appelée')
        self.writer.write(
            b'\x05'
            + self.buttons.to_bytes(1, 'big')
            + self.x.to_bytes(2, 'big')
            + self.y.to_bytes(2, 'big')
        )
        logger.trace('Mouse._write() terminée')

    @contextmanager
    def hold(self, button: int = 0):
        """
        Context manager that presses a mouse button on enter, and releases it on exit.
        """

        logger.trace('Mouse.hold() appelée | button={}', button)
        mask = 1 << button
        self.buttons |= mask
        self._write()
        try:
            yield
        finally:
            self.buttons &= ~mask
            self._write()
        logger.trace('Mouse.hold() terminée')

    def click(self, button: int = 0):
        """
        Presses and releases a mouse button.
        """

        logger.trace('Mouse.click() appelée | button={}', button)
        with self.hold(button):
            pass
        logger.trace('Mouse.click() terminée')

    def middle_click(self):
        """
        Presses and releases the middle mouse button.
        """

        logger.trace('Mouse.middle_click() appelée')
        self.click(1)
        logger.trace('Mouse.middle_click() terminée')

    def right_click(self):
        """
        Presses and releases the right mouse button.
        """

        logger.trace('Mouse.right_click() appelée')
        self.click(2)
        logger.trace('Mouse.right_click() terminée')

    def scroll_up(self, repeat=1):
        """
        Scrolls the mouse wheel upwards.
        """

        logger.trace('Mouse.scroll_up() appelée | repeat={}', repeat)
        for _ in range(repeat):
            self.click(3)
        logger.trace('Mouse.scroll_up() terminée')

    def scroll_down(self, repeat=1):
        """
        Scrolls the mouse wheel downwards.
        """

        logger.trace('Mouse.scroll_down() appelée | repeat={}', repeat)
        for _ in range(repeat):
            self.click(4)
        logger.trace('Mouse.scroll_down() terminée')

    def move(self, x: int, y: int):
        """
        Moves the mouse cursor to the given co-ordinates.
        """

        logger.trace('Mouse.move() appelée | x={} y={}', x, y)
        self.x = x
        self.y = y
        self._write()
        logger.trace('Mouse.move() terminée')


@dataclass
class Screen:
    """
    Computer screen.
    """

    #: Horizontal position in pixels.
    x: int

    #: Vertical position in pixels.
    y: int

    #: Width in pixels.
    width: int

    #: Height in pixels.
    height: int

    #: Arbitrary server/client-assigned identifier (ExtendedDesktopSize only).
    id: int = 0

    #: Reserved flags (ExtendedDesktopSize only, currently always 0).
    flags: int = 0

    @property
    def slices(self) -> tuple[slice, slice]:
        """
        Object that can be used to crop the video buffer to this screen.
        """

        return slice(self.y, self.y + self.height), slice(self.x, self.x + self.width)

    @property
    def score(self) -> float:
        """
        A measure of our confidence that this represents a real screen. For screens with standard aspect ratios, this
        is proportional to its pixel area. For non-standard aspect ratios, the score is further multiplied by the ratio
        or its reciprocal, whichever is smaller.
        """

        logger.trace('Screen.score() appelée')
        value = float(self.width * self.height)
        ratios = {
            Fraction(self.width, self.height).limit_denominator(64),
            Fraction(self.height, self.width).limit_denominator(64),
        }
        if not ratios & screen_ratios:
            value *= min(ratios) * 0.5
        logger.trace('Screen.score() retourne | {}', value)
        return value


@dataclass
class Cursor:
    """
    Mouse cursor shape received from the server (Rich Cursor / X Cursor / Cursor With Alpha pseudo-encodings).
    """

    #: Horizontal hotspot position, relative to the cursor image.
    x: int

    #: Vertical hotspot position, relative to the cursor image.
    y: int

    #: Width in pixels.
    width: int

    #: Height in pixels.
    height: int

    #: RGBA image data (alpha is real per-pixel alpha, or derived from the server's transparency bitmask).
    data: np.ndarray


@dataclass
class StreamZReader:
    """
    aio StreamReader wrapper for zlib
    """

    reader: StreamReader = field(repr=False)
    decompress: object = field(repr=False)
    length: int
    _head: int = 0
    _buffer: bytes = b''
    _zbuffer: bytes = b''

    async def read(self, n: int = -1) -> bytes:
        """
        Read up to a maximum of n bytes.
        If n is not provided, or set to -1, read until EOF and return all read bytes.
        When n is provided, data will be returned as soon as it is available.
        """

        logger.trace('StreamZReader.read() appelée | n={}', n)
        if n == -1:
            try:
                self._zbuffer += await self.reader.readexactly(self.length)
            except IncompleteReadError as e:
                logger.trace(
                    'StreamZReader.read() lecture partielle | {} octet(s) sur {} attendus',
                    len(e.partial),
                    e.expected,
                )
                self._zbuffer += e.partial
            self.length = 0
            rdata = self._buffer[self._head :] + self.decompress.decompress(self._zbuffer)
            self._buffer = b''
            self._head = 0
            self._zbuffer = self.decompress.unconsumed_tail
            logger.trace('StreamZReader.read() retourne | {} octet(s)', len(rdata))
            return rdata

        if (n <= 0) or ((len(self._buffer) <= self._head) and (self.length <= 0)):
            logger.trace("StreamZReader.read() retourne | b''")
            return b''

        while (len(self._buffer) == self._head) and (self.length > 0):
            ndata = await self.reader.readexactly(self.length)
            self.length -= len(ndata)
            self._zbuffer += ndata
            self._buffer = self.decompress.decompress(self._zbuffer)
            self._head = 0
            self._zbuffer = self.decompress.unconsumed_tail
        rdata = self._buffer[self._head : self._head + n]
        self._head += len(rdata)
        logger.trace('StreamZReader.read() retourne | {} octet(s)', len(rdata))
        return rdata

    async def readexactly(self, n: int) -> bytes:
        """
        Read exactly n bytes.
        Raise an asyncio.IncompleteReadError if the end of the stream is reached before n can be read.
        """
        logger.trace('StreamZReader.readexactly() appelée | n={}', n)
        data = b''
        _n = n
        while _n > 0:
            ndata = await self.read(_n)
            if len(ndata) == 0:
                _erreur = IncompleteReadError(data, n)
                logger.debug('StreamZReader.readexactly() lève | {!r}', _erreur)
                raise _erreur
            data += ndata
            _n = n - len(data)
        logger.trace('StreamZReader.readexactly() retourne | {} octet(s)', len(data))
        return data


def _tile_1d_gen(tw: int, x: int, w: int):
    logger.trace('_tile_1d_gen() appelée | tw={} x={} w={}', tw, x, w)
    for cx in range(x, x + w - tw + 1, tw):
        yield (cx, tw)
    mod = w % tw
    if mod:
        yield (x + w - mod, mod)
    logger.trace('_tile_1d_gen() terminée')


def _tile_gen(tw: int, th: int, x: int, y: int, w: int, h: int):
    logger.trace('_tile_gen() appelée | tw={} th={} x={} y={} w={} h={}', tw, th, x, y, w, h)
    for cy, ch in _tile_1d_gen(th, y, h):
        for cx, cw in _tile_1d_gen(tw, x, w):
            yield (cx, cy, cw, ch)
    logger.trace('_tile_gen() terminée')


def _lzo1x_decompress(src: bytes, out_len: int) -> bytes:
    """
    Décompresse un flux LZO1X (format produit par `lzo1x_1_compress`, sans
    en-tête) -- utilisé par l'encodage Ultra (9) de LibVNCServer/UltraVNC.

    Implémentation pure Python de l'algorithme de `lzo1x_decompress_safe`
    (même automate que le noyau Linux, `lib/lzo/lzo1x_decompress_safe.c`,
    hors extension « bitstream version 1 » propre au noyau) : la
    bibliothèque standard n'a pas de LZO et `python-lzo` exige liblzo2 au
    build. Version « safe » : chaque lecture/écriture est bornée et toute
    incohérence lève ValueError au lieu de lire hors du tampon ; la sortie
    doit faire exactement *out_len* octets (taille connue du rectangle).
    Vérifié contre `python-lzo` (liblzo2) et contre un vrai x11vnc, voir
    test_asyncvnc2.TestLzo1x et test_live_x11vnc.
    """
    logger.trace('_lzo1x_decompress() appelée | len(src)={} out_len={}', len(src), out_len)
    _check_alloc_size(out_len, 'Ultra (LZO)')
    out = bytearray()
    ip = 0
    n = len(src)

    def byte() -> int:
        logger.trace('_lzo1x_decompress.byte() appelée')
        nonlocal ip
        if ip >= n:
            _erreur = ValueError('LZO : flux tronqué')
            logger.debug('_lzo1x_decompress.byte() lève | {!r}', _erreur)
            raise _erreur
        v = src[ip]
        ip += 1
        logger.trace('_lzo1x_decompress.byte() retourne | {}', v)
        return v

    def literals(count: int) -> None:
        logger.trace('_lzo1x_decompress.literals() appelée | count={}', count)
        nonlocal ip
        if ip + count > n:
            _erreur = ValueError('LZO : littéraux hors du flux')
            logger.debug('_lzo1x_decompress.literals() lève | {!r}', _erreur)
            raise _erreur
        if len(out) + count > out_len:
            _erreur = ValueError('LZO : sortie plus longue que le rectangle')
            logger.debug('_lzo1x_decompress.literals() lève | {!r}', _erreur)
            raise _erreur
        out.extend(src[ip : ip + count])
        ip += count
        logger.trace('_lzo1x_decompress.literals() terminée')

    def zero_run() -> int:
        # Octets nuls successifs : chacun vaut 255, l'octet non nul suivant s'ajoute.
        logger.trace('_lzo1x_decompress.zero_run() appelée')
        zeros = 0
        while byte() == 0:
            zeros += 1
        _resultat = zeros * 255 + src[ip - 1]
        logger.trace('_lzo1x_decompress.zero_run() retourne | {}', _resultat)
        return _resultat

    def copy_match(dist: int, count: int) -> None:
        logger.trace('_lzo1x_decompress.copy_match() appelée | dist={} count={}', dist, count)
        start = len(out) - dist
        if start < 0:
            _erreur = ValueError('LZO : référence avant le début de la sortie')
            logger.debug('_lzo1x_decompress.copy_match() lève | {!r}', _erreur)
            raise _erreur
        if len(out) + count > out_len:
            _erreur = ValueError('LZO : sortie plus longue que le rectangle')
            logger.debug('_lzo1x_decompress.copy_match() lève | {!r}', _erreur)
            raise _erreur
        if dist >= count:
            out.extend(out[start : start + count])
        else:  # recouvrement : copie octet par octet (répétition)
            for i in range(count):
                out.append(out[start + i])
        logger.trace('_lzo1x_decompress.copy_match() terminée')

    state = 0
    t = byte() if n else 0
    if t > 17:
        t -= 17
        literals(t)
        state = min(4, t)
    else:
        ip = 0
    while True:
        t = byte()
        if t < 16:
            if state == 0:
                if t == 0:
                    t = 15 + zero_run()
                literals(t + 3)
                state = 4
                continue
            if state != 4:
                dist = 1 + (t >> 2) + (byte() << 2)
                copy_match(dist, 2)
            else:
                dist = 1 + 0x0800 + (t >> 2) + (byte() << 2)
                copy_match(dist, 3)
            nxt = t & 3
        elif t >= 64:
            dist = 1 + ((t >> 2) & 7) + (byte() << 3)
            copy_match(dist, (t >> 5) + 1)
            nxt = t & 3
        elif t >= 32:
            count = t & 31
            if count == 0:
                count = 31 + zero_run()
            lo = byte()
            word = lo | (byte() << 8)
            copy_match(1 + (word >> 2), count + 2)
            nxt = word & 3
        else:  # 16..31
            high = (t & 8) << 11
            count = t & 7
            if count == 0:
                count = 7 + zero_run()
            lo = byte()
            word = lo | (byte() << 8)
            dist = high + (word >> 2)
            if dist == 0:  # marqueur de fin (M4 de distance nulle)
                if count != 1:
                    _erreur = ValueError('LZO : marqueur de fin invalide')
                    logger.debug('_lzo1x_decompress() lève | {!r}', _erreur)
                    raise _erreur
                break
            copy_match(dist + 0x4000, count + 2)
            nxt = word & 3
        state = nxt
        if nxt:
            literals(nxt)
    if len(out) != out_len:
        _erreur = ValueError(f'LZO : {len(out)} octets décompressés, {out_len} attendus')
        logger.debug('_lzo1x_decompress() lève | {!r}', _erreur)
        raise _erreur
    _resultat = bytes(out)
    logger.trace('_lzo1x_decompress() retourne | {} octet(s)', len(_resultat))
    return _resultat


class _BytesReader:
    """
    Minimal async-readexactly wrapper over an in-memory buffer, so decompressed
    ZlibHex tile data (already fully available) can be fed through the same
    tile-body decoder used for plain Hextile (which reads from a live StreamReader).
    """

    def __init__(self, data: bytes):
        logger.trace('_BytesReader.__init__() appelée | len(data)={}', len(data))
        self._data = data
        self._pos = 0
        logger.trace('_BytesReader.__init__() terminée')

    async def readexactly(self, n: int) -> bytes:
        logger.trace('_BytesReader.readexactly() appelée | n={}', n)
        chunk = self._data[self._pos : self._pos + n]
        if len(chunk) < n:
            _erreur = IncompleteReadError(chunk, n)
            logger.debug('_BytesReader.readexactly() lève | {!r}', _erreur)
            raise _erreur
        self._pos += n
        logger.trace('_BytesReader.readexactly() retourne | {} octet(s)', len(chunk))
        return chunk


async def _hextile_tile_body(reader, mask: int, bg, fg: bytes, cw: int, ch: int):
    """
    Reads a Hextile tile's background/foreground/subrects (everything except the
    Raw case, which the caller handles separately since it short-circuits
    everything else) and returns (tile_array, new_bg, new_fg).

    Shared between process_hextile (reading live from the network) and
    process_zlibhex's Zlib-compressed tiles (reading from an already-decompressed
    in-memory buffer via _BytesReader) -- both follow identical Hextile rules
    once the subencoding byte and a byte source are in hand.
    """
    logger.trace(
        '_hextile_tile_body() appelée | mask={} bg={} fg={} cw={} ch={}', mask, bg, fg, cw, ch
    )
    if mask & 2:
        bg = await reader.readexactly(4)
    if bg is None:
        _erreur = ValueError(
            'Hextile: first tile of the rectangle did not specify a background colour'
        )
        logger.debug('_hextile_tile_body() lève | {!r}', _erreur)
        raise _erreur
    if mask & 4:
        fg = await reader.readexactly(4)

    tile = np.ndarray((ch, cw, 4), 'B', bg * (cw * ch)).copy()
    if mask & 8:
        n = await read_int(reader, 1)
        coloured = bool(mask & 16)
        for _ in range(n):
            colour = (await reader.readexactly(4)) if coloured else fg
            pos = await read_int(reader, 1)
            size = await read_int(reader, 1)
            sx = (pos >> 4) & 0x0F
            sy = pos & 0x0F
            sw = ((size >> 4) & 0x0F) + 1
            sh = (size & 0x0F) + 1
            tile[sy : sy + sh, sx : sx + sw, :] = np.ndarray((sh, sw, 4), 'B', colour * (sw * sh))
    logger.trace('_hextile_tile_body() retourne | (len(tile)={}, bg={}, fg={})', len(tile), bg, fg)
    return tile, bg, fg


async def _rle_len(reader: StreamReader):
    logger.trace('_rle_len() appelée')
    _pixels = 0
    while True:
        n = await read_int(reader, 1)
        _pixels += n
        if n != 255:
            break
    _resultat = _pixels + 1
    logger.trace('_rle_len() retourne | {}', _resultat)
    return _resultat


async def _update_palette(reader: StreamReader, n: int, palette: list | None = None):
    logger.trace(
        '_update_palette() appelée | n={} len(palette)={}',
        n,
        None if palette is None else len(palette),
    )
    pal_bytes = await reader.readexactly(3 * n)
    pal_list = [pal_bytes[i : i + 3] for i in range(0, 3 * n, 3)]
    palette.clear()
    palette.extend(pal_list)
    logger.trace('_update_palette() terminée')


async def _rle_packedbits(
    reader: StreamReader, cw: int, ch: int, subencoding: int, palette: list
) -> bytes:
    logger.trace(
        '_rle_packedbits() appelée | cw={} ch={} subencoding={} len(palette)={}',
        cw,
        ch,
        subencoding,
        len(palette),
    )
    frame = b''
    if subencoding <= 16:
        # subencoding == 2 .. 16
        await _update_palette(reader, subencoding, palette)
    else:
        # subencoding == 127
        subencoding = len(palette)

    if subencoding == 2:
        bits = 1
    elif subencoding <= 4:
        bits = 2
    else:
        bits = 4
    rowlen = (bits * cw + 7) // 8
    mask = (1 << bits) - 1

    for _ in range(ch):
        row = await reader.readexactly(rowlen)
        offset = 0
        rowit = iter(row)
        for _ in range(cw):
            if offset == 0:
                offset = 8
                packcol = next(rowit)
            offset -= bits
            frame += palette[(packcol >> offset) & mask]
    logger.trace('_rle_packedbits() retourne | {} octet(s)', len(frame))
    return frame


async def _rle_rle(
    reader: StreamReader, cw: int, ch: int, subencoding: int, palette: list
) -> bytes:
    logger.trace(
        '_rle_rle() appelée | cw={} ch={} subencoding={} len(palette)={}',
        cw,
        ch,
        subencoding,
        len(palette),
    )
    frame = b''
    subencoding -= 128
    if subencoding > 1:
        await _update_palette(reader, subencoding, palette)
    elif subencoding == 1:
        subencoding = len(palette)

    tile_pixels = ch * cw
    pixels = 0

    while pixels < tile_pixels:
        if subencoding:
            pal_index = await read_int(reader, 1)
            if pal_index < 128:
                frame += palette[pal_index]
                pixels += 1
                continue
            else:
                pal_index -= 128
                color = palette[pal_index]
        else:
            color = await reader.readexactly(3)
        p = await _rle_len(reader)
        frame += color * p
        pixels += p
    if pixels > tile_pixels:
        _erreur = ValueError('Too many pixels')
        logger.debug('_rle_rle() lève | {!r}', _erreur)
        raise _erreur
    logger.trace('_rle_rle() retourne | {} octet(s)', len(frame))
    return frame


def _zywrle_harr(x0: np.ndarray, x1: np.ndarray) -> tuple:
    """
    PLHarr (Piecewise-Linear Haar) inverse step of ZYWRLE, vectorised.

    Exact port of ``Harr()`` in libvncserver ``common/zywrletemplate.c`` (Hitachi,
    identical to QEMU ``ui/vnc-enc-zywrle.h``): the transform is its own inverse, works
    on signed bytes held in int32 arrays and wraps its results back to int8 like the C
    ``(signed char)`` casts. Returns the new (x0, x1) pair.
    """
    logger.trace('_zywrle_harr() appelée | shape={}', x0.shape)
    differ = ((x0 ^ x1) & 0x80) != 0
    x1d = x1 + x0
    x0d = np.where(((x1d ^ x1) & 0x80) == 0, x0 - x1d, x0)
    x0s = x0 - x1
    x1s = np.where(((x0s ^ x0) & 0x80) == 0, x1 + x0s, x1)
    nouveau0 = ((np.where(differ, x1d, x1s) + 128) & 0xFF) - 128
    nouveau1 = ((np.where(differ, x0d, x0s) + 128) & 0xFF) - 128
    logger.trace('_zywrle_harr() retourne')
    return nouveau0, nouveau1


def _zywrle_synthesize(tile: np.ndarray, level: int) -> np.ndarray:
    """
    Rebuilds the pixels of one ZYWRLE tile from its wavelet coefficients.

    ``tile`` is the (h, w, 3) uint8 result of decoding the nested ZRLE tile (CPIXEL
    bytes 0-2 of a 32bpp little-endian pixel, as negotiated by Video.create()).
    Byte-for-byte port of ``ZYWRLE_SYNTHESIZE`` (libvncserver
    ``common/zywrletemplate.c``, the decoder libvncclient uses; QEMU's
    ``ZYWRLE_ANALYZE`` is its exact counterpart): the coefficients are read in raster
    order over the whole tile, sub-band by sub-band (Hxy, Hy, Hx for each level, then L
    for the last one), the inverse PLHarr wavelet runs over the part of the tile aligned
    on ``2**level`` pixels, then the RCT colour transform turns (V, Y, U) back into
    bytes (2, 1, 0) = (R, G, B). Pixels outside the aligned part travel unchanged, after
    the coefficients. Checked byte for byte against the compiled C code -- see
    ``ZywrleTests`` and ``docs/sessions/session-25-2026-10-24.md``.
    """
    logger.trace('_zywrle_synthesize() appelée | shape={} level={}', tile.shape, level)
    hauteur, largeur = tile.shape[:2]
    masque = ~((1 << level) - 1)
    w, h = largeur & masque, hauteur & masque
    if level <= 0 or w == 0 or h == 0:
        # Même cas que le « return NULL » du C : tuile plus petite que 2**level, inchangée.
        logger.trace('_zywrle_synthesize() retourne | tuile inchangée')
        return tile
    sequence = np.ascontiguousarray(tile).reshape(-1, 3)
    coeffs = np.empty((h, w, 3), np.int32)
    n = 0
    for lv in range(level):
        pas = 2 << lv
        for r in (3, 2, 1, 0) if lv == level - 1 else (3, 2, 1):
            y0 = pas >> 1 if r & 2 else 0
            x0 = pas >> 1 if r & 1 else 0
            nombre = (h // pas) * (w // pas)
            coeffs[y0::pas, x0::pas] = (
                sequence[n : n + nombre].view(np.int8).reshape(h // pas, w // pas, 3)
            )
            n += nombre
    hors_grille = sequence[n:]
    for lv in range(level - 1, -1, -1):
        p, q = 1 << lv, 2 << lv
        coeffs[0::q, 0::p], coeffs[p::q, 0::p] = _zywrle_harr(
            coeffs[0::q, 0::p], coeffs[p::q, 0::p]
        )
        coeffs[0::p, 0::q], coeffs[0::p, p::q] = _zywrle_harr(
            coeffs[0::p, 0::q], coeffs[0::p, p::q]
        )
    u = coeffs[..., 0] << 1
    y = coeffs[..., 1] + 128
    v = coeffs[..., 2] << 1
    g = y - ((u + v) >> 2)
    sortie = np.array(tile, 'B', copy=True)
    sortie[:h, :w, 0] = np.clip(u + g, 0, 255)
    sortie[:h, :w, 1] = np.clip(g, 0, 255)
    sortie[:h, :w, 2] = np.clip(v + g, 0, 255)
    uw, uh = largeur - w, hauteur - h
    k = 0
    if uw:
        sortie[:h, w:] = hors_grille[k : k + h * uw].reshape(h, uw, 3)
        k += h * uw
    if uh:
        sortie[h:, :w] = hors_grille[k : k + uh * w].reshape(uh, w, 3)
        k += uh * w
    if uw and uh:
        sortie[h:, w:] = hors_grille[k:].reshape(uh, uw, 3)
    logger.trace('_zywrle_synthesize() retourne | shape={}', sortie.shape)
    return sortie


async def _tight_read_length(reader: StreamReader) -> int:
    """
    Reads a Tight "compact" length (1-3 bytes) and returns it.
    """
    logger.trace('_tight_read_length() appelée')
    b0 = await read_int(reader, 1)
    length = b0 & 0x7F
    if b0 & 0x80:
        b1 = await read_int(reader, 1)
        length |= (b1 & 0x7F) << 7
        if b1 & 0x80:
            b2 = await read_int(reader, 1)
            length |= b2 << 14
    logger.trace('_tight_read_length() retourne | {}', length)
    return length


def _tight_palette_filter(data: bytes, cw: int, ch: int, palette: list) -> bytes:
    """
    Expands Tight PaletteFilter indices back into TPIXEL (RGB) data.
    """
    logger.trace(
        '_tight_palette_filter() appelée | len(data)={} cw={} ch={} len(palette)={}',
        len(data),
        cw,
        ch,
        len(palette),
    )
    n = len(palette)
    bits = 1 if n == 2 else 8
    rowlen = (bits * cw + 7) // 8
    out = bytearray(cw * ch * 3)
    pos = 0
    for cy in range(ch):
        row = data[pos : pos + rowlen]
        pos += rowlen
        base = cy * cw * 3
        if bits == 1:
            for cx in range(cw):
                byte = row[cx // 8]
                idx = (byte >> (7 - (cx % 8))) & 1
                out[base : base + 3] = palette[idx]
                base += 3
        else:
            for cx in range(cw):
                out[base : base + 3] = palette[row[cx]]
                base += 3
    _resultat = bytes(out)
    logger.trace('_tight_palette_filter() retourne | {} octet(s)', len(_resultat))
    return _resultat


def _tight_gradient_filter(data: bytes, cw: int, ch: int) -> bytes:
    """
    Reverses the Tight GradientFilter prediction to recover raw TPIXEL data.
    """
    logger.trace('_tight_gradient_filter() appelée | len(data)={} cw={} ch={}', len(data), cw, ch)
    out = bytearray(cw * ch * 3)
    prev_row = [(0, 0, 0)] * cw
    for cy in range(ch):
        left = (0, 0, 0)
        cur_row = [(0, 0, 0)] * cw
        base = cy * cw * 3
        for cx in range(cw):
            up = prev_row[cx]
            upleft = prev_row[cx - 1] if cx else (0, 0, 0)
            pixel = [0, 0, 0]
            for c in range(3):
                pred = left[c] + up[c] - upleft[c]
                if pred < 0:
                    pred = 0
                elif pred > 255:
                    pred = 255
                pixel[c] = (data[base + c] + pred) & 0xFF
            pixel = tuple(pixel)
            out[base : base + 3] = bytes(pixel)
            cur_row[cx] = pixel
            left = pixel
            base += 3
        prev_row = cur_row
    _resultat = bytes(out)
    logger.trace('_tight_gradient_filter() retourne | {} octet(s)', len(_resultat))
    return _resultat


def _tight_decode_image(data: bytes, width: int, height: int) -> np.ndarray:
    """
    Decodes a JPEG (Tight) or PNG (TightPng) sub-rectangle. Pillow auto-detects
    the format from the file's magic bytes, so both encodings share this function.

    Requires Pillow (an optional dependency, only needed if the server actually
    sends Jpeg/PngCompression sub-rectangles): pip install Pillow.
    """
    logger.trace(
        '_tight_decode_image() appelée | len(data)={} width={} height={}', len(data), width, height
    )
    try:
        from PIL import Image
    except ImportError as exc:
        _erreur = RuntimeError(
            'Decoding Tight/TightPng image sub-rectangles requires Pillow (pip install Pillow)'
        )
        logger.debug('_tight_decode_image() lève | {!r} (cause : {!r})', _erreur, exc)
        raise _erreur from exc
    import io

    image = Image.open(io.BytesIO(data)).convert('RGB')
    array = np.asarray(image, dtype='B')
    if array.shape != (height, width, 3):
        array = array.reshape((height, width, 3))
    logger.trace('_tight_decode_image() retourne | tableau {}', array.shape)
    return array


#: ClientFence/ServerFence flag bits.
FENCE_FLAG_BLOCK_BEFORE = 0x00000001
FENCE_FLAG_BLOCK_AFTER = 0x00000002
FENCE_FLAG_SYNC_NEXT = 0x00000004
FENCE_FLAG_REQUEST = 0x80000000

#: Bits the client understands and is willing to echo back in a ServerFence reply.
_FENCE_KNOWN_FLAGS = FENCE_FLAG_BLOCK_BEFORE | FENCE_FLAG_BLOCK_AFTER | FENCE_FLAG_SYNC_NEXT

# xvp-message-code values (both directions -- xvp is a "bidirectional"
# message type, code 250, cf. RFC RFB / rfbproto.rst "xvp Client Message"
# and "xvp Server Message"). Only version 1 of the xvp extension is
# currently defined by the spec.
XVP_FAIL = 0  # server -> client: most recent xvp request could not be honoured
XVP_INIT = 1  # server -> client: confirms xvp support, gives highest version supported
XVP_SHUTDOWN = 2  # client -> server: request a clean shutdown
XVP_REBOOT = 3  # client -> server: request a clean reboot
XVP_RESET = 4  # client -> server: request an abrupt reset
_XVP_VERSION = 1  # extension version this client speaks (only version defined so far)

# Extended Clipboard flags (rfbproto.rst "Extended Clipboard Pseudo-Encoding", cf.
# Enc.EXTENDED_CLIPBOARD) -- a single U32 bitfield shared by both directions
# (ClientCutText/ServerCutText). Bits 0-15 are "formats" (what kind of data),
# bits 24-31 are "actions" (what the message means); a message sets exactly one
# action plus zero or more formats, except Caps which may combine several
# formats/actions to declare what the sender is willing to handle. Values
# cross-checked against QEMU's own VNC_CLIPBOARD_* (github.com/qemu/qemu,
# ui/vnc.h, branche master consultée le 2026-09-13) -- identiques.
CLIPBOARD_FORMAT_TEXT = 1 << 0  # UTF-8 plain text -- the only format this fork decodes/encodes
CLIPBOARD_FORMAT_RTF = (
    1 << 1
)  # Microsoft Rich Text Format -- not implemented, see Client.process_extended_clipboard()
CLIPBOARD_FORMAT_HTML = 1 << 2  # Microsoft HTML clipboard fragment -- not implemented
CLIPBOARD_FORMAT_DIB = (
    1 << 3
)  # Microsoft Device Independent Bitmap v5, no file header -- not implemented
CLIPBOARD_FORMAT_FILES = 1 << 4  # reserved by the spec itself, "not defined" -- not implemented
_CLIPBOARD_KNOWN_FORMAT_BITS = range(16)  # bits 0-15 are reserved for formats (5 defined today)
CLIPBOARD_ACTION_CAPS = 1 << 24  # declares which formats/actions the sender is willing to receive
CLIPBOARD_ACTION_REQUEST = 1 << 25  # "send me a Provide for these formats"
CLIPBOARD_ACTION_PEEK = 1 << 26  # "send me a Notify of what's currently available"
CLIPBOARD_ACTION_NOTIFY = 1 << 27  # "these formats are now available" (no payload)
CLIPBOARD_ACTION_PROVIDE = 1 << 28  # carries the actual (zlib-compressed) clipboard data


@dataclass
class Video:
    """
    Video buffer.
    """

    reader: StreamReader = field(repr=False)
    writer: StreamWriter = field(repr=False)
    decompress: object = field(repr=False)
    #    lastrefresh = None;

    #: Desktop name.
    name: str

    #: Width in pixels.
    width: int

    #: Height in pixels.
    height: int

    #: Colour channel order.
    mode: str

    #: Allowed encodings list
    encodings: list | None = None

    #: JPEG quality hint (0-9) advertised by Video.create(), None if not sent. Also selects
    #: the ZYWRLE wavelet level (3 - quality // 3), exactly like QEMU and libvncclient.
    jpeg_quality: int | None = None

    #: Four independent zlib streams used by Tight's BasicCompression.
    tight_streams: list = field(
        default_factory=lambda: [decompressobj() for _ in range(4)], repr=False
    )

    #: Two independent zlib streams used by ZlibHex (one for ZlibRaw tiles, one for Zlib tiles).
    zlibhex_streams: list = field(
        default_factory=lambda: [decompressobj(), decompressobj()], repr=False
    )

    #: 8bpp indexed-colour palette {index: (r, g, b)} (0-255 each), from SetColourMapEntries.
    #: Only meaningful when Video.create() was called with allow_indexed_colour=True and the
    #: server actually proposed an 8bpp PseudoColor format (self.mode == 'indexed8').
    palette: dict = field(default_factory=dict, repr=False)

    #: Current mouse cursor shape (Rich Cursor / X Cursor / Cursor With Alpha), if any.
    cursor: Cursor | None = None

    #: Physical screen layout (ExtendedDesktopSize pseudo-encoding).
    screens: list = field(default_factory=list, repr=False)

    #: Serial number
    serial = 0

    #: 3D numpy array of colour data.
    data: np.ndarray | None = None

    @classmethod
    async def create(
        cls,
        reader: StreamReader,
        writer: StreamWriter,
        encodings: list,
        jpeg_quality: int | None = None,
        compression_level: int | None = None,
        allow_indexed_colour: bool = False,
        shared: bool = True,
    ) -> Video:
        logger.debug(
            'Video.create() appelée | encodings={} jpeg_quality={} compression_level={} allow_indexed_colour={} shared={}',
            encodings,
            jpeg_quality,
            compression_level,
            allow_indexed_colour,
            shared,
        )
        encodings = EncList(encodings)

        writer.write(bytes([1 if shared else 0]))
        width = await read_int(reader, 2)
        height = await read_int(reader, 2)
        mode_data = bytearray(await reader.readexactly(13))
        bits_per_pixel = mode_data[0]
        true_colour = mode_data[3] & 1
        mode_data[2] &= 1  # set big endian flag to 0 or 1
        mode_data[3] &= 1  # set true colour flag to 0 or 1
        mode = video_modes.get(bytes(mode_data))
        await reader.readexactly(3)  # padding
        name = await read_text(reader, 'utf-8')

        if mode is None:
            if allow_indexed_colour and not true_colour and bits_per_pixel == 8:
                # Accept the server's native 8bpp indexed-colour format instead of overriding
                # it with our own truecolour SetPixelFormat. Only Enc.RAW is meaningful here --
                # see process_raw_indexed and the note on the allow_indexed_colour parameter.
                mode = 'indexed8'
            else:
                mode = 'rgba'
                writer.write(b'\x00\x00\x00\x00' + video_definition.get(mode) + b'\x00\x00\x00')

        # jpeg_quality/compression_level are one-shot hints, not real encodings: they never come
        # back as a rectangle, so they're appended as raw values instead of going through EncList
        # (which only accepts Enc members).
        values = [e.value for e in encodings]
        if jpeg_quality is not None:
            if not 0 <= jpeg_quality <= 9:
                _erreur = ValueError('jpeg_quality must be between 0 and 9')
                logger.debug('Video.create() lève | {!r}', _erreur)
                raise _erreur
            values.append(-32 + jpeg_quality)
        if compression_level is not None:
            if not 0 <= compression_level <= 9:
                _erreur = ValueError('compression_level must be between 0 and 9')
                logger.debug('Video.create() lève | {!r}', _erreur)
                raise _erreur
            values.append(-256 + compression_level)

        writer.write(b'\x02\x00' + len(values).to_bytes(2, 'big'))
        writer.write(b''.join(v.to_bytes(4, 'big', signed=True) for v in values))

        decompress = decompressobj()

        _resultat = cls(reader, writer, decompress, name, width, height, mode, encodings)
        _resultat.jpeg_quality = jpeg_quality
        logger.debug('Video.create() retourne | {}x{} mode={}', width, height, mode)
        return _resultat

    def get_rect(
        self, x: int = 0, y: int = 0, width: int | None = None, height: int | None = None
    ) -> tuple:
        """
        Crops the rectangle according to the video buffer.
        """
        logger.trace('Video.get_rect() appelée | x={} y={} width={} height={}', x, y, width, height)
        if x < 0:
            x = 0
        elif x > self.width:
            x = self.width
        if y < 0:
            y = 0
        elif y > self.height:
            y = self.height
        if (width is None) or (width + x > self.width):
            width = self.width - x
        elif width < 0:
            width = 0
        if (height is None) or (height + y > self.height):
            height = self.height - y
        elif height < 0:
            height = 0

        logger.trace(
            'Video.get_rect() retourne | (x={}, y={}, width={}, height={})', x, y, width, height
        )
        return (x, y, width, height)

    def refresh(
        self,
        x: int = 0,
        y: int = 0,
        width: int | None = None,
        height: int | None = None,
        incremental: bool | None = None,
    ):
        """
        Sends a video buffer update request to the server.

        ``incremental`` defaults to "a buffer already exists"; screenshot() forces
        True when it re-requests an area left incomplete (see Client.screenshot()).
        """

        logger.trace(
            'Video.refresh() appelée | x={} y={} width={} height={} incremental={}',
            x,
            y,
            width,
            height,
            incremental,
        )
        if incremental is None:
            incremental = self.data is not None

        (x, y, width, height) = self.get_rect(x, y, width, height)

        self.writer.write(
            b'\x03'
            + incremental.to_bytes(1, 'big')
            + x.to_bytes(2, 'big')
            + y.to_bytes(2, 'big')
            + width.to_bytes(2, 'big')
            + height.to_bytes(2, 'big')
        )
        logger.trace('Video.refresh() terminée')

    def _update_rect(self, x1: int, x2: int, y1: int, y2: int, data: np.ndarray):
        """
        Fills the space of the rectangle with the selected data
        Accepts various input shapes:
            HxWx4 -- raw copy
            1x1x4 -- fills with one color
            HxWx3 -- adds alpha
            1x1x3 -- fills with one color and adds alpha
        """

        #        print(f"_update_rect {x1} +{x2-x1} {y1} +{y2-y1} {data.shape}")
        logger.trace(
            'Video._update_rect() appelée | x1={} x2={} y1={} y2={} len(data)={}',
            x1,
            x2,
            y1,
            y2,
            len(data),
        )
        if self.data is None:
            self.data = np.zeros((self.height, self.width, 4), 'B')
        # indexed8 has no channel-order letters like the truecolour modes ('rgba', 'bgra', ...) --
        # process_raw_indexed always builds its lookup table in RGBA order, so alpha is always
        # channel 3 there.
        a_index = 3 if self.mode == 'indexed8' else self.mode.index('a')
        if data.shape[2] == 4:
            self.data[y1:y2, x1:x2, :] = data
        if data.shape[2] == 3:
            if a_index:
                self.data[y1:y2, x1:x2, 0:3] = data
            else:
                self.data[y1:y2, x1:x2, 1:4] = data
        self.data[y1:y2, x1:x2, a_index] = 255
        self.serial = (self.serial + 1) & 0xFFFFFFF
        logger.trace('Video._update_rect() terminée')

    async def process_raw(self, _reader, x, y, width, height):
        logger.trace(
            'Video.process_raw() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        ff = height * width * 4
        (cx, cy) = (x, y)
        data = b''
        while ff:
            newdata = await _reader.read(ff)
            ff -= len(newdata)
            data += newdata
            rows = len(data) // (width * 4)
            if rows > 0:
                await sleep(0)
                self._update_rect(
                    cx, cx + width, cy, cy + rows, np.ndarray((rows, width, 4), 'B', data)
                )
                cy += rows
                data = data[rows * width * 4 :]
                await sleep(0)
        logger.trace('Video.process_raw() terminée')

    async def process_ultra(self, _reader, x, y, width, height):
        """
        Ultra (9) : U32 taille compressée, puis pixels bruts au format client
        compressés en LZO1X. Chaque rectangle est indépendant (pas de
        contexte partagé, contrairement à zlib). Mode indexé : 1 octet par
        pixel, décodé comme un Raw indexé.
        """
        logger.trace(
            'Video.process_ultra() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        length = await read_int(_reader, 4)
        _check_alloc_size(length, 'Ultra (LZO)')
        bpp = 1 if self.mode == 'indexed8' else 4
        data = _lzo1x_decompress(await _reader.readexactly(length), width * height * bpp)
        if bpp == 1:
            await self.process_raw_indexed(_BytesReader(data), x, y, width, height)
            logger.trace('Video.process_ultra() retourne')
            return
        self._update_rect(x, x + width, y, y + height, np.ndarray((height, width, 4), 'B', data))
        await sleep(0)
        logger.trace('Video.process_ultra() terminée')

    async def process_raw_indexed(self, _reader, x, y, width, height):
        """
        Decodes a Raw rectangle in 8bpp indexed-colour mode: 1 byte per pixel,
        each byte an index into self.palette (populated by SetColourMapEntries).
        Indices with no known palette entry fall back to grayscale (index value
        repeated across R/G/B).

        IMPORTANT -- ordering hazard confirmed by real-world testing: the RFB
        spec does not guarantee SetColourMapEntries arrives before the first
        FramebufferUpdate that uses those colours. If pixel data is decoded
        here before the relevant palette entries are known, those pixels get
        the grayscale fallback rather than their real colour, and this method
        has no way to go back and fix already-decoded pixels once the palette
        arrives later. If precise colours matter immediately, request a fresh
        (non-incremental) FramebufferUpdate after any SetColourMapEntries you
        receive, so the affected area gets redecoded with the palette now known.
        """
        logger.trace(
            'Video.process_raw_indexed() appelée | x={} y={} width={} height={}',
            x,
            y,
            width,
            height,
        )
        indices = np.frombuffer(await _reader.readexactly(width * height), 'B').reshape(
            height, width
        )
        lut = np.empty((256, 4), 'B')
        lut[:, 0] = lut[:, 1] = lut[:, 2] = np.arange(256, dtype='B')
        lut[:, 3] = 255
        for idx, (r, g, b) in self.palette.items():
            if 0 <= idx < 256:
                lut[idx] = (r, g, b, 255)
        self._update_rect(x, x + width, y, y + height, lut[indices])
        await sleep(0)
        logger.trace('Video.process_raw_indexed() terminée')

    async def process_xrle(self, _reader, x, y, width, height, tile_sz, zywrle_level=0):
        """
        Decodes a TRLE (tile_sz=16) or ZRLE/ZYWRLE (tile_sz=64) rectangle.

        ``zywrle_level`` (1-3) is only non-zero for a ZYWRLE (17) rectangle: a Raw tile
        (subencoding 0) then carries a complete nested ZRLE tile holding the wavelet
        coefficients, rebuilt by _zywrle_synthesize() -- see Enc.ZYWRLE.
        """
        logger.trace(
            'Video.process_xrle() appelée | x={} y={} width={} height={} tile_sz={} zywrle_level={}',
            x,
            y,
            width,
            height,
            tile_sz,
            zywrle_level,
        )
        palette = []

        for cx, cy, cw, ch in _tile_gen(tile_sz, tile_sz, x, y, width, height):
            block = await self._xrle_tile(_reader, cw, ch, palette, zywrle_level)
            self._update_rect(cx, cx + cw, cy, cy + ch, block)
            await sleep(0)
        logger.trace('Video.process_xrle() terminée')

    async def _xrle_tile(self, _reader, cw, ch, palette, zywrle_level):
        """
        Reads one TRLE/ZRLE tile and returns its pixels, shape (ch, cw, 3) or (1, 1, 3).

        When ``zywrle_level`` is 1-3 (and its 0x80 "nested" flag is not set) a Raw tile
        is a ZYWRLE tile: subencoding byte 0 followed by a full nested tile (any
        subencoding) whose pixels are wavelet coefficients. This is what QEMU writes
        (``ZRLE_ENCODE_TILE`` calling itself with ``zywrle_level | 0x80`` in
        ``ui/vnc-enc-zrle.c.inc``) and what libvncclient reads (``HandleZRLETile``).
        """
        logger.trace(
            'Video._xrle_tile() appelée | cw={} ch={} zywrle_level={}', cw, ch, zywrle_level
        )
        subencoding = await read_int(_reader, 1)
        await sleep(0)
        if subencoding == 0:
            if 0 < zywrle_level < 0x80:
                coeffs = await self._xrle_tile(_reader, cw, ch, palette, zywrle_level | 0x80)
                coeffs = np.broadcast_to(coeffs, (ch, cw, 3))
                tuile = _zywrle_synthesize(coeffs, zywrle_level)
                logger.trace('Video._xrle_tile() retourne | ZYWRLE niveau {}', zywrle_level)
                return tuile
            block = await _reader.readexactly(ch * cw * 3)
            tuile = np.ndarray((ch, cw, 3), 'B', block)
        elif subencoding == 1:
            block = await _reader.readexactly(3)
            tuile = np.ndarray((1, 1, 3), 'B', block)
        elif (subencoding <= 16) or (subencoding == 127):
            block = await _rle_packedbits(_reader, cw, ch, subencoding, palette)
            tuile = np.ndarray((ch, cw, 3), 'B', block)
        elif subencoding < 128:
            # Valeurs 17-126 : "unused" selon rfbproto.rst / RFC 6143 (aucun format de
            # bit-packing n'est défini au-delà de la taille de palette 16). Ce n'est PAS le
            # format ZYWRLE : la tuile ZYWRLE est un octet 0 suivi d'une tuile imbriquée
            # (branche subencoding == 0 ci-dessus). Les 17-126 vus le 2026-09-09 contre QEMU
            # 8.2.2 venaient d'une désynchronisation du flux (tuile imbriquée lue comme du
            # Raw) -- voir Enc.ZYWRLE et docs/sessions/session-25-2026-10-24.md. Une telle
            # valeur reste donc une erreur de flux : on refuse plutôt que de corrompre l'image.
            _erreur = ValueError(
                f'Palette subencoding {subencoding} (plage 17-126, réservée par la RFC) reçue '
                '-- flux ZRLE désynchronisé ou serveur non conforme ; voir Enc.ZYWRLE'
            )
            logger.debug('Video._xrle_tile() lève | {!r}', _erreur)
            raise _erreur
        else:
            block = await _rle_rle(_reader, cw, ch, subencoding, palette)
            tuile = np.ndarray((ch, cw, 3), 'B', block)
        logger.trace('Video._xrle_tile() retourne | subencoding={}', subencoding)
        return tuile

    async def process_copy(self, _reader, x, y, width, height):
        logger.trace(
            'Video.process_copy() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        srcx = await read_int(_reader, 2)
        srcy = await read_int(_reader, 2)
        #        print(f"Copy Rect {width}x{height} ({srcx},{srcy}) ==> ({x},{y})")
        self._update_rect(
            x, x + width, y, y + height, self.data[srcy : srcy + height, srcx : srcx + width, :]
        )
        logger.trace('Video.process_copy() terminée')

    def _tpixel_vers_mode(self, block: np.ndarray) -> np.ndarray:
        """
        Reorders Tight TPIXEL data (always red, green, blue -- rfbproto.rst § Tight
        Encoding: "the first byte is the red component, the second byte is the green
        component, and the third byte is the blue component") into the byte order of the
        negotiated pixel format, which _update_rect() expects.

        Only 'bgra' and 'abgr' need a swap. 'bgra' is what TigerVNC Xvnc and x11vnc
        propose by default (red_shift=16, little-endian): without this, every Tight
        rectangle came out with red and blue swapped (found 2026-10-24 against a real
        Xvnc, issue #27). CPIXEL (ZRLE/TRLE) is different: it is a slice of the pixel in
        its own byte order, so it needs no reordering.
        """
        logger.trace('Video._tpixel_vers_mode() appelée | mode={} shape={}', self.mode, block.shape)
        if self.mode in ('bgra', 'abgr'):
            block = block[:, :, ::-1]
        logger.trace('Video._tpixel_vers_mode() retourne')
        return block

    async def process_tight(self, _reader, x, y, width, height):
        """
        Decodes a Tight or TightPng-encoded rectangle (BasicCompression, FillCompression,
        JpegCompression or PngCompression).
        """
        logger.trace(
            'Video.process_tight() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        ctl = await read_int(_reader, 1)
        for i in range(4):
            if ctl & (1 << i):
                self.tight_streams[i] = decompressobj()
        await sleep(0)

        if ctl & 0x80:
            kind = ctl & 0xF0
            if kind == 0x80:
                pixel = await _reader.readexactly(3)
                block = pixel * (width * height)
                self._update_rect(
                    x,
                    x + width,
                    y,
                    y + height,
                    self._tpixel_vers_mode(np.ndarray((height, width, 3), 'B', block)),
                )
                logger.trace('Video.process_tight() retourne')
                return
            if kind == 0x90:
                length = await _tight_read_length(_reader)
                _check_alloc_size(length, 'Tight (JPEG/PNG)')
                image_data = await _reader.readexactly(length)
                block = _tight_decode_image(image_data, width, height)
                self._update_rect(x, x + width, y, y + height, self._tpixel_vers_mode(block))
                logger.trace('Video.process_tight() retourne')
                return
            _erreur = ValueError(f'Invalid Tight compression-control byte: {ctl:#x}')
            logger.debug('Video.process_tight() lève | {!r}', _erreur)
            raise _erreur

        stream_id = (ctl >> 4) & 0x03
        filter_id = (await read_int(_reader, 1)) if (ctl & 0x40) else 0
        palette: list = []

        if filter_id == 1:
            n = (await read_int(_reader, 1)) + 1
            pal_bytes = await _reader.readexactly(3 * n)
            palette = [pal_bytes[i : i + 3] for i in range(0, 3 * n, 3)]
            bits = 1 if n == 2 else 8
            data_size = ((bits * width + 7) // 8) * height
        elif filter_id in (0, 2):
            data_size = width * height * 3
        else:
            _erreur = ValueError(f'Unknown Tight filter-id: {filter_id}')
            logger.debug('Video.process_tight() lève | {!r}', _erreur)
            raise _erreur

        if data_size < 12:
            raw = await _reader.readexactly(data_size)
        else:
            length = await _tight_read_length(_reader)
            _check_alloc_size(length, 'Tight (BasicCompression)')
            comp = await _reader.readexactly(length)
            raw = self.tight_streams[stream_id].decompress(comp)

        if filter_id == 1:
            block = _tight_palette_filter(raw, width, height, palette)
        elif filter_id == 2:
            block = _tight_gradient_filter(raw, width, height)
        else:
            block = raw

        self._update_rect(
            x,
            x + width,
            y,
            y + height,
            self._tpixel_vers_mode(np.ndarray((height, width, 3), 'B', block)),
        )
        await sleep(0)
        logger.trace('Video.process_tight() terminée')

    async def process_hextile(self, _reader, x, y, width, height):
        """
        Decodes a Hextile-encoded rectangle.
        """
        logger.trace(
            'Video.process_hextile() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        bg = None
        fg = bytes(4)
        for cx, cy, cw, ch in _tile_gen(16, 16, x, y, width, height):
            mask = await read_int(_reader, 1)
            await sleep(0)

            if mask & 1:
                block = await _reader.readexactly(cw * ch * 4)
                self._update_rect(cx, cx + cw, cy, cy + ch, np.ndarray((ch, cw, 4), 'B', block))
                continue

            tile, bg, fg = await _hextile_tile_body(_reader, mask, bg, fg, cw, ch)
            self._update_rect(cx, cx + cw, cy, cy + ch, tile)
            await sleep(0)
        logger.trace('Video.process_hextile() terminée')

    async def process_rre(self, _reader, x, y, width, height):
        """
        Decodes an RRE-encoded rectangle: a background pixel plus N
        axis-aligned solid-colour subrectangles drawn on top.
        """
        logger.trace(
            'Video.process_rre() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        n = await read_int(_reader, 4)
        bg = await _reader.readexactly(4)
        tile = np.ndarray((height, width, 4), 'B', bg * (width * height)).copy()
        for _ in range(n):
            colour = await _reader.readexactly(4)
            sx = await read_int(_reader, 2)
            sy = await read_int(_reader, 2)
            sw = await read_int(_reader, 2)
            sh = await read_int(_reader, 2)
            tile[sy : sy + sh, sx : sx + sw, :] = np.ndarray((sh, sw, 4), 'B', colour * (sw * sh))
            await sleep(0)
        self._update_rect(x, x + width, y, y + height, tile)
        logger.trace('Video.process_rre() terminée')

    async def process_corre(self, _reader, x, y, width, height):
        """
        Decodes a CoRRE-encoded rectangle: same idea as RRE, but with
        1-byte subrectangle coordinates/dimensions (each subrect confined
        to 0-255) instead of RRE's 2-byte fields -- more compact for small
        tiles. The RFB spec implies the rectangle itself must be <=255x255
        for CoRRE to be legal; enforced explicitly below rather than
        trusting the encoder.
        """
        logger.trace(
            'Video.process_corre() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        if width > 255 or height > 255:
            _erreur = ValueError(
                f'CoRRE: rectangle {width}x{height} exceeds the 255x255 limit '
                f'implied by its 1-byte subrectangle fields'
            )
            logger.debug('Video.process_corre() lève | {!r}', _erreur)
            raise _erreur
        n = await read_int(_reader, 4)
        bg = await _reader.readexactly(4)
        tile = np.ndarray((height, width, 4), 'B', bg * (width * height)).copy()
        for _ in range(n):
            colour = await _reader.readexactly(4)
            sx = await read_int(_reader, 1)
            sy = await read_int(_reader, 1)
            sw = await read_int(_reader, 1)
            sh = await read_int(_reader, 1)
            tile[sy : sy + sh, sx : sx + sw, :] = np.ndarray((sh, sw, 4), 'B', colour * (sw * sh))
            await sleep(0)
        self._update_rect(x, x + width, y, y + height, tile)
        logger.trace('Video.process_corre() terminée')

    async def process_zlibhex(self, _reader, x, y, width, height):
        """
        Decodes a ZlibHex-encoded rectangle (Hextile + zlib, LibVNCServer/x11vnc).

        Extends the Hextile subencoding byte with two more bits: ZlibRaw (0x20,
        cancels all other bits like Raw does in plain Hextile -- the decompressed
        data is w*h raw pixels) and Zlib (0x40, the decompressed data is a plain
        Hextile tile body, parsed per the *same* subencoding byte's lower 5 bits).
        Two independent zlib streams are used: one for ZlibRaw tiles, one for
        Zlib tiles -- both persist for the life of the connection (no reset bits
        in this encoding, unlike Tight).
        """
        logger.trace(
            'Video.process_zlibhex() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        bg = None
        fg = bytes(4)
        for cx, cy, cw, ch in _tile_gen(16, 16, x, y, width, height):
            mask = await read_int(_reader, 1)
            await sleep(0)

            if mask & 0x20:  # ZlibRaw -- cancels all other bits
                length = await read_int(_reader, 2)
                _check_alloc_size(length, 'ZlibHex (ZlibRaw)')
                comp = await _reader.readexactly(length)
                raw = self.zlibhex_streams[0].decompress(comp)
                self._update_rect(cx, cx + cw, cy, cy + ch, np.ndarray((ch, cw, 4), 'B', raw))
                continue

            if mask & 0x40:  # Zlib -- decompressed data is a plain Hextile tile body
                length = await read_int(_reader, 2)
                _check_alloc_size(length, 'ZlibHex (Zlib)')
                comp = await _reader.readexactly(length)
                raw = self.zlibhex_streams[1].decompress(comp)
                tile, bg, fg = await _hextile_tile_body(_BytesReader(raw), mask, bg, fg, cw, ch)
                self._update_rect(cx, cx + cw, cy, cy + ch, tile)
                await sleep(0)
                continue

            if mask & 1:  # plain Raw (uncompressed)
                block = await _reader.readexactly(cw * ch * 4)
                self._update_rect(cx, cx + cw, cy, cy + ch, np.ndarray((ch, cw, 4), 'B', block))
                continue

            tile, bg, fg = await _hextile_tile_body(_reader, mask, bg, fg, cw, ch)
            self._update_rect(cx, cx + cw, cy, cy + ch, tile)
            await sleep(0)
        logger.trace('Video.process_zlibhex() terminée')

    async def process_cursor(self, x, y, width, height):
        """
        Decodes a Rich Cursor pseudo-encoding rectangle into self.cursor.
        """
        logger.debug(
            'Video.process_cursor() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        if width == 0 or height == 0:
            self.cursor = Cursor(x, y, width, height, np.zeros((0, 0, 4), 'B'))
            logger.debug('Video.process_cursor() retourne')
            return
        _check_alloc_size(width * height * 4, 'Curseur (Rich Cursor)')
        pixel_bytes = await self.reader.readexactly(width * height * 4)
        rowlen = (width + 7) // 8
        mask_bytes = await self.reader.readexactly(rowlen * height)
        await sleep(0)

        pixels = np.ndarray((height, width, 4), 'B', pixel_bytes)
        rgb = np.dstack(
            (
                pixels[:, :, self.mode.index('r')],
                pixels[:, :, self.mode.index('g')],
                pixels[:, :, self.mode.index('b')],
            )
        )
        mask_bits = np.unpackbits(np.frombuffer(mask_bytes, 'B').reshape(height, rowlen), axis=1)[
            :, :width
        ]
        alpha = (mask_bits * 255).astype('B')
        self.cursor = Cursor(x, y, width, height, np.dstack((rgb, alpha)))
        logger.debug('Video.process_cursor() terminée')

    async def process_x_cursor(self, x, y, width, height):
        """
        Decodes an X Cursor pseudo-encoding rectangle into self.cursor (older,
        simpler cousin of Rich Cursor: two RGB triplets instead of full
        pixel-format colours, plus a 1-bit-per-pixel bitmap selecting between them).
        """
        logger.debug(
            'Video.process_x_cursor() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        if width == 0 or height == 0:
            self.cursor = Cursor(x, y, width, height, np.zeros((0, 0, 4), 'B'))
            logger.debug('Video.process_x_cursor() retourne')
            return

        _check_alloc_size(width * height * 4, 'Curseur (X Cursor)')
        fore = np.frombuffer(await self.reader.readexactly(3), 'B')
        back = np.frombuffer(await self.reader.readexactly(3), 'B')
        rowlen = (width + 7) // 8
        bitmap_bytes = await self.reader.readexactly(rowlen * height)
        mask_bytes = await self.reader.readexactly(rowlen * height)
        await sleep(0)

        bitmap = np.unpackbits(np.frombuffer(bitmap_bytes, 'B').reshape(height, rowlen), axis=1)[
            :, :width
        ]
        mask = np.unpackbits(np.frombuffer(mask_bytes, 'B').reshape(height, rowlen), axis=1)[
            :, :width
        ]
        rgb = np.where(bitmap[:, :, None].astype(bool), fore, back).astype('B')
        alpha = (mask * 255).astype('B')
        self.cursor = Cursor(x, y, width, height, np.dstack((rgb, alpha)))
        logger.debug('Video.process_x_cursor() terminée')

    async def process_cursor_with_alpha(self, x, y, width, height):
        """
        Decodes a Cursor With Alpha pseudo-encoding rectangle into self.cursor.

        Unlike Rich Cursor / X Cursor, transparency here is a real 8-bit alpha
        channel per pixel (no separate bitmask), always sent as raw 32-bit
        RGBA regardless of the negotiated pixel format. Only the Raw
        sub-encoding (by far the common case in practice) is supported here.
        """
        logger.debug(
            'Video.process_cursor_with_alpha() appelée | x={} y={} width={} height={}',
            x,
            y,
            width,
            height,
        )
        sub_encoding = await read_int(self.reader, 4)
        if width == 0 or height == 0:
            self.cursor = Cursor(x, y, width, height, np.zeros((0, 0, 4), 'B'))
            logger.debug('Video.process_cursor_with_alpha() retourne')
            return
        if sub_encoding != 0:
            _erreur = ValueError(
                f'Cursor With Alpha: unsupported sub-encoding {sub_encoding} (only Raw is handled)'
            )
            logger.debug('Video.process_cursor_with_alpha() lève | {!r}', _erreur)
            raise _erreur
        _check_alloc_size(width * height * 4, 'Curseur (Cursor With Alpha)')
        pixel_bytes = await self.reader.readexactly(width * height * 4)
        await sleep(0)
        self.cursor = Cursor(
            x, y, width, height, np.ndarray((height, width, 4), 'B', pixel_bytes).copy()
        )
        logger.debug('Video.process_cursor_with_alpha() terminée')

    async def process_desktop_size(self, width, height):
        """
        Handles the (simple) DesktopSize pseudo-encoding: resizes the video buffer.
        """
        logger.debug('Video.process_desktop_size() appelée | width={} height={}', width, height)
        self.width = width
        self.height = height
        self.data = None
        await sleep(0)
        logger.debug('Video.process_desktop_size() terminée')

    async def process_extended_desktop_size(self, x, y, width, height):
        """
        Handles the ExtendedDesktopSize pseudo-encoding: resizes the video buffer
        and refreshes the physical screen layout.

        The rectangle's x-position carries the reason code (0 = server-side
        change or reply to a non-incremental request, 1 = reply to this
        client's SetDesktopSize, 2 = another client's request was approved)
        and y-position carries the status code (0 = success) when x is 1.
        """
        logger.debug(
            'Video.process_extended_desktop_size() appelée | x={} y={} width={} height={}',
            x,
            y,
            width,
            height,
        )
        reason = x
        status = y
        count = await read_int(self.reader, 1)
        await self.reader.readexactly(3)  # padding
        screens = []
        for _ in range(count):
            screen_id = await read_int(self.reader, 4)
            sx = await read_int(self.reader, 2)
            sy = await read_int(self.reader, 2)
            sw = await read_int(self.reader, 2)
            sh = await read_int(self.reader, 2)
            flags = await read_int(self.reader, 4)
            screens.append(Screen(sx, sy, sw, sh, id=screen_id, flags=flags))
        if (reason != 1 or status == 0) and (self.width, self.height) != (width, height):
            self.width = width
            self.height = height
            self.data = None
        self.screens = screens
        await sleep(0)
        logger.debug('Video.process_extended_desktop_size() terminée')

    async def read(self):
        logger.trace('Video.read() appelée')
        x = await read_int(self.reader, 2)
        y = await read_int(self.reader, 2)
        width = await read_int(self.reader, 2)
        height = await read_int(self.reader, 2)
        raw_encoding = await read_int(self.reader, 4)
        if (
            raw_encoding >= 0x80000000
        ):  # read_int is unsigned; pseudo-encodings are negative S32 values
            raw_encoding -= 0x100000000
        if raw_encoding == _H264_ENCODING:
            _erreur = NotImplementedError(
                'Received an Open H.264 rectangle (encoding 0x48323634). This encoding is '
                'intentionally not decoded here: it comes from an experimental, unmerged '
                'TigerVNC extension (PR #1194) with no stable, canonical wire-format spec -- '
                'unlike Tight/Hextile/ZlibHex/etc., which are all documented in rfbproto.rst '
                "or LibVNCServer's rfbproto.h. Guessing at the byte layout risked silently "
                'desyncing or corrupting the stream, so this raises instead. It is also never '
                'advertised automatically (it is not an Enc member, so EncList.default() never '
                'includes it) -- seeing this error means a server sent it unprompted. If you '
                'need this encoding, get the exact wire format from the specific server build '
                'in use (it is not guaranteed to be identical across TigerVNC/TurboVNC forks) '
                'before implementing a decoder.'
            )
            logger.debug('Video.read() lève | {!r}', _erreur)
            raise _erreur
        encoding = Enc(raw_encoding)
        length = height * width * 4
        #        print(f"GET VIDEO REC: {x} {y} {width}x{height} / {encoding}")

        if encoding is Enc.RAW:
            if self.mode == 'indexed8':
                await self.process_raw_indexed(self.reader, x, y, width, height)
            else:
                await self.process_raw(self.reader, x, y, width, height)

        elif encoding is Enc.ZLIB:
            length = await read_int(self.reader, 4)
            await self.process_raw(
                StreamZReader(self.reader, self.decompress, length), x, y, width, height
            )

        elif encoding is Enc.ULTRA:
            await self.process_ultra(self.reader, x, y, width, height)

        elif encoding is Enc.TRLE:
            await self.process_xrle(self.reader, x, y, width, height, 16)

        elif (encoding is Enc.ZRLE) or (encoding is Enc.ZYWRLE):
            # Même enveloppe pour les deux (longueur zlib 4 octets puis tuiles 64x64). En
            # ZYWRLE, le niveau d'ondelettes n'est pas transmis : serveur (QEMU) et client
            # (libvncclient) le déduisent tous deux de la qualité JPEG annoncée par le client
            # (3 - qualité // 3). Sans qualité annoncée, QEMU n'envoie que du ZRLE (16).
            zywrle_level = 0
            if encoding is Enc.ZYWRLE and self.jpeg_quality is not None:
                zywrle_level = 3 - self.jpeg_quality // 3
            length = await read_int(self.reader, 4)
            await self.process_xrle(
                StreamZReader(self.reader, self.decompress, length),
                x,
                y,
                width,
                height,
                64,
                zywrle_level,
            )

        elif encoding is Enc.HEXTILE:
            await self.process_hextile(self.reader, x, y, width, height)

        elif encoding is Enc.ZLIBHEX:
            await self.process_zlibhex(self.reader, x, y, width, height)

        elif encoding is Enc.CORRE:
            await self.process_corre(self.reader, x, y, width, height)

        elif encoding is Enc.RRE:
            await self.process_rre(self.reader, x, y, width, height)

        elif encoding is Enc.COPY:
            await self.process_copy(self.reader, x, y, width, height)

        elif (encoding is Enc.TIGHT) or (encoding is Enc.TIGHT_PNG):
            await self.process_tight(self.reader, x, y, width, height)

        elif encoding is Enc.CURSOR:
            await self.process_cursor(x, y, width, height)

        elif encoding is Enc.X_CURSOR:
            await self.process_x_cursor(x, y, width, height)

        elif encoding is Enc.CURSOR_WITH_ALPHA:
            await self.process_cursor_with_alpha(x, y, width, height)

        elif encoding is Enc.DESKTOP_SIZE:
            await self.process_desktop_size(width, height)

        elif encoding is Enc.EXTENDED_DESKTOP_SIZE:
            await self.process_extended_desktop_size(x, y, width, height)

        elif encoding is Enc.LAST_RECT:
            logger.trace('Video.read() retourne | True')
            return True  # signals Client.read() to stop looping over rectangles

        else:
            _erreur = ValueError(encoding)
            logger.debug('Video.read() lève | {!r}', _erreur)
            raise _erreur

        logger.trace('Video.read() retourne | False')
        return False

    def as_rgba(
        self, x: int = 0, y: int = 0, width: int | None = None, height: int | None = None
    ) -> np.ndarray:
        """
        Returns the video buffer or the selected part of it as a 3D RGBA array.
        """

        logger.trace('Video.as_rgba() appelée | x={} y={} width={} height={}', x, y, width, height)
        (x, y, width, height) = self.get_rect(x, y, width, height)

        if self.data is None:
            _resultat = np.zeros((height, width, 4), 'B')
            logger.trace('Video.as_rgba() retourne | tableau {}', _resultat.shape)
            return _resultat
        if self.mode == 'rgba':
            _resultat = self.data[y : y + height, x : x + width, :]
            logger.trace('Video.as_rgba() retourne | tableau {}', _resultat.shape)
            return _resultat
        if self.mode == 'abgr':
            _resultat = self.data[y : y + height, x : x + width, ::-1]
            logger.trace('Video.as_rgba() retourne | tableau {}', _resultat.shape)
            return _resultat
        _resultat = np.dstack(
            (
                self.data[y : y + height, x : x + width, self.mode.index('r')],
                self.data[y : y + height, x : x + width, self.mode.index('g')],
                self.data[y : y + height, x : x + width, self.mode.index('b')],
                self.data[y : y + height, x : x + width, self.mode.index('a')],
            )
        )
        logger.trace('Video.as_rgba() retourne | tableau {}', _resultat.shape)
        return _resultat

    def is_complete(
        self, x: int = 0, y: int = 0, width: int | None = None, height: int | None = None
    ):
        """
        Returns true if the video buffer or the selected part of it is entirely opaque.
        """

        logger.trace(
            'Video.is_complete() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        if self.data is None:
            logger.trace('Video.is_complete() retourne | False')
            return False

        (x, y, width, height) = self.get_rect(x, y, width, height)

        _resultat = self.data[y : y + height, x : x + width, self.mode.index('a')].all()
        logger.trace('Video.is_complete() retourne | {}', bool(_resultat))
        return _resultat

    def detect_screens(self) -> list[Screen]:
        """
        Detect physical screens by inspecting the alpha channel.
        """

        logger.debug('Video.detect_screens() appelée')
        if self.data is None:
            _resultat = []
            logger.debug('Video.detect_screens() retourne | {} élément(s)', len(_resultat))
            return _resultat

        mask = self.data[:, :, self.mode.index('a')]
        mask = np.pad(mask // 255, ((1, 1), (1, 1))).astype(np.int8)
        mask_a = mask[1:, 1:]
        mask_b = mask[1:, :-1]
        mask_c = mask[:-1, 1:]
        mask_d = mask[:-1, :-1]

        screens = []
        while True:
            # Detect corners by ANDing perpendicular pairs of differences.
            corners = product(
                np.argwhere(mask_b - mask_a & mask_c - mask_a == -1),  # top left
                np.argwhere(mask_a - mask_b & mask_d - mask_b == -1),  # top right
                np.argwhere(mask_d - mask_c & mask_a - mask_c == -1),  # bottom left
                np.argwhere(mask_c - mask_d & mask_b - mask_d == -1),
            )  # bottom right

            # Find cases where 3 corners align, forming an  'L' shape.
            rects = set()
            for a, b, c, d in corners:
                ab = a[0] == b[0] and a[1] < b[1]  # top
                cd = c[0] == d[0] and c[1] < d[1]  # bottom
                ac = a[1] == c[1] and a[0] < c[0]  # left
                bd = b[1] == d[1] and b[0] < d[0]  # right
                if ab and ac:
                    rects.add((a[1], a[0], b[1], c[0]))
                if ab and bd:
                    rects.add((a[1], a[0], d[1], d[0]))
                if cd and ac:
                    rects.add((a[1], a[0], d[1], d[0]))
                if cd and bd:
                    rects.add((c[1], b[0], d[1], d[0]))

            # Create screen objects and sort them by their scores.
            candidates = [
                Screen(int(x0), int(y0), int(x1 - x0), int(y1 - y0)) for x0, y0, x1, y1 in rects
            ]
            candidates.sort(key=lambda screen: screen.score, reverse=True)

            # Find a single fully-opaque screen
            for screen in candidates:
                if mask_a[screen.slices].all():
                    mask_a[screen.slices] = 0
                    screens.append(screen)
                    break

            # Finish up if no screens remain
            else:
                logger.debug('Video.detect_screens() retourne | {} octet(s)', len(screens))
                return screens
        logger.debug('Video.detect_screens() terminée')


class UpdateType(Enum):
    """
    Update from server to client.
    """

    #: Video update.
    VIDEO = 0

    #: SetColourMapEntries: server-defined palette for indexed (non-truecolour) pixel formats.
    #: Only sent by a server that ignored our SetPixelFormat truecolour override, or before the
    #: client's first FramebufferUpdateRequest -- see Client.process_set_colour_map_entries.
    SET_COLOUR_MAP_ENTRIES = 1

    #: Bell update.
    BELL = 2

    #: Clipboard update.
    CLIPBOARD = 3

    #: EndOfContinuousUpdates: server confirms continuous updates have stopped.
    END_OF_CONTINUOUS_UPDATES = 150

    #: ServerFence: part of the Fence pseudo-encoding's synchronisation handshake.
    SERVER_FENCE = 248

    #: xvp Server Message: XVP_INIT (support confirmed) or XVP_FAIL (last
    #: shutdown/reboot/reset request refused). See Client.process_xvp().
    XVP = 250


@dataclass
class Client:
    """
    VNC client.
    """

    reader: StreamReader = field(repr=False)
    writer: StreamWriter = field(repr=False)

    #: The shared clipboard.
    clipboard: Clipboard

    #: The virtual keyboard.
    keyboard: Keyboard

    #: The virtual mouse.
    mouse: Mouse

    #: The video buffer.
    video: Video

    #: The server's public key (Mac only)
    host_key: rsa.RSAPublicKey | None

    #: Version RFB effectivement négociée avec le serveur, sous la forme
    #: (major, minor) -- (3, 3), (3, 7) ou (3, 8). Voir Client.create()
    #: pour le repli de version (RFC 6143 §7.1.1 + Appendix A) : ce client
    #: ne demande jamais une version supérieure à celle offerte par le
    #: serveur, et adapte la poignée de main de sécurité en conséquence.
    protocol_version: tuple = (3, 8)

    #: RealVNC-style fingerprint (`%02x-%02x-...`, first 8 bytes of a
    #: SHA-1 digest) of the server's RSA-AES public key, if the connection
    #: used security type 5 (RA2) or 129 (RA2_256) -- see
    #: _rsa_aes_negotiate()'s docstring for exactly what this is a hash of
    #: and why this fork does not itself compare it against anything (no
    #: pinning storage at this layer, unlike host_key's optional reuse for
    #: Apple ARD above -- an application built on this fork is where that
    #: policy belongs, see docs/reference/downstream-consumer.md). None for
    #: every other security type, RA2/RA2_256 included until a successful
    #: handshake has actually produced one.
    rsa_aes_server_key_fingerprint: str | None = None

    #: Whether the server is currently streaming continuous updates.
    continuous_updates_active: bool = False

    #: Whether the server has confirmed xvp support via an XVP_INIT message
    #: (sent by the server after the client requested the XVP pseudo-encoding).
    #: False until that first XVP_INIT arrives -- send_xvp() does not check
    #: this itself, see its docstring.
    xvp_supported: bool = False

    #: Highest xvp-extension-version the server said it supports, from the
    #: most recent XVP_INIT message. 0 until one has been received. Only
    #: version 1 is defined by the spec at this time.
    xvp_version: int = 0

    #: Whether the server has confirmed Extended Clipboard support (cf.
    #: Enc.EXTENDED_CLIPBOARD) by sending a Caps-flagged extended
    #: ServerCutText. False until that first Caps message arrives -- every
    #: send_clipboard_*() method below refuses to send before then, see
    #: their docstrings for why (unlike xvp_supported above, which
    #: send_xvp() deliberately does NOT require).
    clipboard_ext_supported: bool = False

    #: {format bit: max unsolicited size in bytes} from the server's most
    #: recent Caps message (cf. CLIPBOARD_FORMAT_* constants), e.g.
    #: {CLIPBOARD_FORMAT_TEXT: 0}. Empty until clipboard_ext_supported is True.
    clipboard_ext_server_caps: dict = field(default_factory=dict, repr=False)

    #: Palette from the most recent SetColourMapEntries message, if any: {index: (r, g, b)}
    #: with each component 0-65535 (16-bit, per spec) regardless of the actual colour depth in
    #: use. Populated defensively -- see process_set_colour_map_entries for why this should
    #: never actually happen given Video.create() always forces a truecolour pixel format.
    colour_map: dict = field(default_factory=dict, repr=False)

    @classmethod
    async def create(
        cls,
        reader: StreamReader,
        writer: StreamWriter,
        username: str | None = None,
        password: str | None = None,
        host_key: rsa.RSAPublicKey | None = None,
        encodings: list | None = None,
        jpeg_quality: int | None = None,
        compression_level: int | None = None,
        allow_indexed_colour: bool = False,
        shared: bool = True,
        ssl_context: ssl.SSLContext | None = None,
        server_hostname: str | None = None,
    ) -> Client:
        """
        *server_hostname* (added 2026-09-05) is only used for the VeNCrypt
        X509None/X509Vnc sub-types, and only when *ssl_context* is not
        supplied (see _vencrypt_negotiate) -- it is the hostname/IP the
        caller believes it is connecting to, needed so the real certificate
        presented by the server can be checked against it. `connect()`
        passes its own `host` parameter here automatically; `listen()`
        leaves it at `None` since reverse connections have no such target
        hostname to check (see `listen()`'s own docstring).
        """

        logger.debug(
            'Client.create() appelée | identifiant={} mot_de_passe={} cle_hote={} encodings={} jpeg_quality={} compression_level={} allow_indexed_colour={} shared={} tls={} server_hostname={}',
            bool(username),
            bool(password),
            bool(host_key),
            encodings,
            jpeg_quality,
            compression_level,
            allow_indexed_colour,
            shared,
            ssl_context is not None,
            server_hostname,
        )
        intro = await reader.readline()
        if intro[:4] != b'RFB ':
            _erreur = ValueError('not a VNC server')
            logger.debug('Client.create() lève | {!r}', _erreur)
            raise _erreur
        try:
            server_major = int(intro[4:7])
            server_minor = int(intro[8:11])
        except ValueError as exc:
            _erreur = ValueError('not a VNC server')
            logger.debug('Client.create() lève | {!r} (cause : {!r})', _erreur, exc)
            raise _erreur

        # Repli de version de protocole (RFC 6143 §7.1.1 + Appendix A) : ce
        # client ne doit jamais réclamer une version supérieure à celle
        # offerte par le serveur. Seules 3.3, 3.7 et 3.8 sont "publiées" --
        # tout minor 3.x non reconnu doit être traité comme 3.3 ("Any
        # version reported other than 3.7 or 3.8 should be treated as 3.3",
        # Appendix A). Un major > 3 est traité comme 3.8 plutôt que comme un
        # repli 3.3 : en pratique, seuls des serveurs RealVNC Enterprise
        # récents annoncent des majors 4/5 ("RFB 004.001", "RFB 005.000" --
        # confirmé par un rapport de bug tiers qui a dû corriger exactement
        # ce point), et il s'agit là de leur propre numérotation produit,
        # pas d'une évolution du protocole RFB lui-même -- eux-mêmes
        # attendent une réponse "003.008" et se comportent alors en 3.8
        # standard.
        if server_major < 3:
            _erreur = ValueError(f'unsupported RFB protocol version: {intro!r}')
            logger.debug('Client.create() lève | {!r}', _erreur)
            raise _erreur
        elif server_major == 3 and server_minor == 7:
            server_version = (3, 7)
        elif server_major == 3 and server_minor < 7:
            server_version = (3, 3)
        else:
            server_version = (3, 8)

        writer.write('RFB {:03d}.{:03d}\n'.format(*server_version).encode('ascii'))

        if server_version == (3, 3):
            # 3.3 : pas de négociation à deux sens -- le serveur décide
            # seul et envoie directement un U32 (0=échec, 1=None,
            # 2=VNC Authentication) ; le client n'envoie aucun octet de
            # sélection ici (Appendix A.1).
            auth_type = await read_int(reader, 4)
            if auth_type == 0:
                _erreur = ValueError(await read_text(reader, 'utf-8'))
                logger.debug('Client.create() lève | {!r}', _erreur)
                raise _erreur
            if auth_type not in (1, 2):
                _erreur = ValueError(f'unsupported security type: {auth_type}')
                logger.debug('Client.create() lève | {!r}', _erreur)
                raise _erreur
        else:
            auth_types = set(await reader.readexactly(await read_int(reader, 1)))
            if not auth_types:
                _erreur = ValueError(await read_text(reader, 'utf-8'))
                logger.debug('Client.create() lève | {!r}', _erreur)
                raise _erreur
            # VeNCrypt (19) est délibérément en dernier de cette liste de
            # préférence : c'est une fonctionnalité neuve, jamais testée
            # contre un vrai serveur (voir CLAUDE.md), alors que 33/1/2 sont
            # éprouvés. Un serveur qui propose aussi 33/1/2 en plus de 19
            # continue donc à se comporter exactement comme avant ce patch --
            # seul un serveur qui n'offre QUE VeNCrypt (auparavant un échec
            # sec ici, "unsupported auth types") en bénéficie. RSA-AES
            # (129=RA2_256, 5=RA2, ajoutés le 2026-09-15) est classé encore
            # après, pour la même raison (neuf) ; 256 avant 128 entre les
            # deux, comme pour X509Vnc/X509Plain/X509None dans VeNCrypt.
            # MSLogonII (113, ajouté le 2026-09-16) est classé tout
            # dernier avant SASL : au-delà d'être neuf et jamais testé
            # contre un vrai serveur, sa clé Diffie-Hellman de 64 bits est
            # explicitement qualifiée de cassable "immédiatement" par la
            # spec elle-même (rfbproto.rst, section "MSLogonII
            # Authentication") -- elle n'apporte donc pas de
            # confidentialité réelle face à un attaquant actif, seulement
            # un nom d'utilisateur en plus de ce que VNC Authentication (2)
            # offre déjà. SASL (20, ajouté le 2026-09-16, mécanismes
            # PLAIN/ANONYMOUS seulement -- voir _sasl_negotiate()) est
            # classé tout dernier de tous : au moins MSLogonII protège le
            # secret partagé par un vrai échange DH avant de l'utiliser
            # comme clé DES, alors que PLAIN envoie le mot de passe
            # directement sur le fil sans aucune couche de chiffrement
            # propre (contrairement aux sous-types VeNCrypt "...SASL" de
            # la spec, hors périmètre ici -- voir docs/features-backlog.md).
            for auth_type in (33, 1, 2, 19, 129, 5, 113, 20):
                if auth_type in auth_types:
                    writer.write(auth_type.to_bytes(1, 'big'))
                    break
            else:
                _erreur = ValueError(f'unsupported auth types: {auth_types}')
                logger.debug('Client.create() lève | {!r}', _erreur)
                raise _erreur

        # VeNCrypt (TLS anonyme TLSNone/TLSVnc/TLSPlain, ou authentifié par
        # certificat X.509 X509None/X509Vnc/X509Plain depuis 2026-09-05/
        # 2026-09-14) -- voir _vencrypt_negotiate() pour le détail du
        # format. Après ce bloc, `reader`/`writer` pointent vers le flux TLS
        # et non plus vers la socket TCP en clair d'origine -- tout le reste
        # de cette méthode (SecurityResult, ClientInit/ServerInit, etc.)
        # continue de fonctionner sans changement puisqu'il ne manipule que
        # `reader`/`writer`, jamais le transport sous-jacent directement.
        rsa_aes_server_key_fingerprint = None  # RSA-AES seulement (5/129), voir plus bas
        if auth_type == 19:
            reader, writer, vencrypt_subtype = await _vencrypt_negotiate(
                reader, writer, ssl_context, server_hostname
            )
            if vencrypt_subtype in (_VENCRYPT_TLS_VNC, _VENCRYPT_X509_VNC):
                # Les sous-types "Vnc" (anonyme ou X.509) enchaînent sur une
                # authentification VNC Auth standard, désormais sur le flux
                # chiffré -- on réutilise donc tel quel le bloc "VNC
                # authentication" ci-dessous en se faisant simplement passer
                # pour lui. Seule la validation (ou non) du certificat TLS
                # en amont diffère entre les deux ; ce qui suit est
                # identique.
                auth_type = 2
            elif vencrypt_subtype in (_VENCRYPT_TLS_SASL, _VENCRYPT_X509_SASL):
                # SASL (type 20) sur le flux TLS : même bloc auth_type == 20
                # plus bas (issue #32, vérifié contre un vrai QEMU).
                auth_type = 20
            elif vencrypt_subtype in (_VENCRYPT_TLS_PLAIN, _VENCRYPT_X509_PLAIN):
                # Les sous-types "Plain" (ajoutés le 2026-09-14, anonyme ou
                # X.509) envoient un couple identifiant/mot de passe en
                # clair, mais désormais sur le flux chiffré -- format
                # entièrement différent de VNC Auth (aucun défi envoyé par
                # le serveur), donc pas de réutilisation du bloc ci-dessous
                # possible ici : on l'envoie nous-mêmes, directement, et
                # auth_type reste volontairement à 19 (ni le bloc Apple ni
                # le bloc VNC authentication ci-dessous ne doivent se
                # déclencher). Format vérifié contre rfbproto.rst
                # ("Plain subtype") et contre le client de référence
                # TigerVNC (CSecurityPlain.cxx) -- voir le commentaire
                # au-dessus de _VENCRYPT_TLS_NONE. Réutilise les paramètres
                # username/password déjà acceptés ci-dessus pour
                # l'authentification Apple (33) ; encodage UTF-8 (pas de
                # contrainte de taille de clé cryptographique ici, à la
                # différence du DES de VNC Auth juste en dessous).
                if username is None or password is None:
                    _erreur = ValueError(
                        'server requires username and password (VeNCrypt Plain sub-type)'
                    )
                    logger.debug('Client.create() lève | {!r}', _erreur)
                    raise _erreur
                username_bytes = username.encode('utf-8')
                password_bytes = password.encode('utf-8')
                writer.write(
                    len(username_bytes).to_bytes(4, 'big')
                    + len(password_bytes).to_bytes(4, 'big')
                    + username_bytes
                    + password_bytes
                )
            # Les sous-types "None" (anonyme ou X.509) n'ont plus rien à
            # faire ici : ni le bloc Apple ni le bloc VNC authentication
            # ci-dessous ne se déclenchent (auth_type reste 19), et le
            # SecurityResult lu plus
            # bas conclut la négociation -- comportement standard de tout
            # type de sécurité RFB 3.7/3.8, VeNCrypt inclus (le fait que la
            # spec VeNCrypt d'origine ne mentionne pas elle-même ce
            # SecurityResult final s'explique par le fait qu'elle documente
            # uniquement ce qui est spécifique à VeNCrypt, pas la poignée de
            # main RFB générique dans laquelle il s'insère).

        # RSA-AES (5=RA2, AES-128 ; 129=RA2_256, AES-256 -- ajoutés le
        # 2026-09-15) -- voir _rsa_aes_negotiate() pour le détail complet du
        # format et son origine (rfbproto.rst + code source TigerVNC).
        # Contrairement à VeNCrypt ci-dessus, `reader`/`writer` pointent
        # ensuite vers un chiffrement AES-EAX construit dans ce fichier
        # (pas une bibliothèque standard comme `ssl`) -- et le
        # SecurityResult lui-même est déjà chiffré à ce stade (propre à
        # RSA-AES, voir la docstring de _rsa_aes_negotiate()), contrairement
        # à VeNCrypt où seule la poignée de main TLS précède un
        # SecurityResult en clair (ou plutôt : en clair du point de vue de
        # cette fonction, TLS le chiffrant lui-même au niveau du transport).
        if auth_type in (5, 129):
            reader, writer, rsa_aes_server_key_fingerprint = await _rsa_aes_negotiate(
                reader, writer, 128 if auth_type == 5 else 256, username, password
            )

        # Apple authentication
        if auth_type == 33:
            if username is None or password is None:
                _erreur = ValueError('server requires username and password')
                logger.debug('Client.create() lève | {!r}', _erreur)
                raise _erreur
            if host_key is None:
                writer.write(b'\x00\x00\x00\x0a\x01\x00RSA1\x00\x00\x00\x00')
                await reader.readexactly(4)  # packet length
                await reader.readexactly(2)  # packet version
                host_key_length = await read_int(reader, 4)
                host_key = await reader.readexactly(host_key_length)
                host_key = load_der_public_key(host_key)
                await reader.readexactly(1)  # unknown
            aes_key = urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
            encryptor = cipher.encryptor()
            credentials = pack_ard(username) + pack_ard(password)
            writer.write(
                b'\x00\x00\x01\x8a\x01\x00RSA1'
                + b'\x00\x01'
                + encryptor.update(credentials)
                + b'\x00\x01'
                + host_key.encrypt(aes_key, padding=padding.PKCS1v15())
            )
            await reader.readexactly(4)  # unknown

        # VNC authentication
        if auth_type == 2:
            if password is None:
                _erreur = ValueError('server requires password')
                logger.debug('Client.create() lève | {!r}', _erreur)
                raise _erreur
            try:
                raw_password = password.encode('ascii')
            except UnicodeEncodeError as exc:
                logger.debug(
                    'Client.create() mot de passe VNC non ASCII, repli latin-1 | position={}',
                    exc.start,
                )
                # La VNC Auth classique n'a jamais eu d'encodage standard
                # pour les mots de passe non-ASCII. Latin-1 couvre les
                # caractères accentués courants (é, è, à, ç, ù...) en un
                # seul octet chacun -- meilleur compromis possible ici,
                # mais ça ne garantit pas l'interopérabilité avec un
                # serveur qui aurait encodé le mot de passe différemment
                # (limite inhérente au protocole, pas résoluble côté client seul).
                raw_password = password.encode('latin-1', errors='replace')
            des_key = raw_password[:8].ljust(8, b'\x00')
            des_key = bytes(int(bin(n)[:1:-1].ljust(8, '0'), 2) for n in des_key)
            encryptor = Cipher(algorithms.TripleDES(des_key), modes.ECB()).encryptor()
            challenge = await reader.readexactly(16)
            writer.write(encryptor.update(challenge) + encryptor.finalize())

        # MSLogonII (security type 113) -- authentification par nom
        # d'utilisateur + mot de passe, protégée par un échange
        # Diffie-Hellman 64 bits puis un chiffrement DES-CBC des deux
        # champs. Format vérifié contre rfbproto.rst, section "MSLogonII
        # Authentication" (seule source disponible ici -- extension
        # originaire d'UltraVNC, Windows ; aucun serveur de référence
        # installable dans ce sandbox Linux ne la propose, contrairement au
        # reste de ce fichier -- voir docs/features-backlog.md/CLAUDE.md,
        # pas de test contre un vrai serveur pour ce type). La spec
        # prévient elle-même que la clé DH 64 bits "can be cracked by
        # modern computers immediately" : ce type n'apporte donc pas de
        # confidentialité réelle contre un attaquant actif, seulement un
        # nom d'utilisateur en plus de ce que VNC Authentication (2)
        # ci-dessus offre déjà (voir aussi le commentaire sur l'ordre de
        # préférence plus haut).
        if auth_type == 113:
            if username is None or password is None:
                _erreur = ValueError('server requires username and password')
                logger.debug('Client.create() lève | {!r}', _erreur)
                raise _erreur
            generator = await read_int(reader, 8)
            modulus = await read_int(reader, 8)
            server_public = await read_int(reader, 8)
            if modulus < 2:
                _erreur = ValueError(
                    f'paramètre Diffie-Hellman MSLogonII invalide (modulus={modulus})'
                )
                logger.debug('Client.create() lève | {!r}', _erreur)
                raise _erreur
            # Exposant privé client : un entier aléatoire sur 64 bits,
            # ramené dans [1, modulus-2] -- rfbproto.rst ne précise aucune
            # contrainte de génération au-delà de "the client can then
            # generate a shared secret ... using the Diffie-Hellman
            # algorithm", donc une exponentiation modulaire standard
            # (Python `pow(base, exp, mod)`) suffit, sans bibliothèque
            # cryptographique dédiée -- cohérent avec le calcul explicite
            # d'une clé 64 bits que la spec qualifie déjà de non sûre.
            client_private = 1 + int.from_bytes(urandom(8), 'big') % (modulus - 1)
            client_public = pow(generator, client_private, modulus)
            shared_secret = pow(server_public, client_private, modulus).to_bytes(8, 'big')
            # Même bit-reversal DES que VNC Authentication ci-dessus --
            # rfbproto.rst l'indique explicitement ("The DES algorithm
            # used here is the same as the one for VNC authentication,
            # which uses the reverse bit order compared with most
            # implementations"). Contrairement à VNC Auth, la spec précise
            # aussi que "the shared secret is also used as the IV" : elle
            # ne mentionne le bit-reversal qu'à propos de la clé, pas de
            # l'IV -- l'IV est donc utilisé tel quel, non inversé.
            des_key = bytes(int(bin(n)[:1:-1].ljust(8, '0'), 2) for n in shared_secret)
            username_field = _pack_mslogonii_field(username, 256, "nom d'utilisateur")
            password_field = _pack_mslogonii_field(password, 64, 'mot de passe')
            # "The client should encrypt the username and password using
            # DES in CBC mode, respectively" -- lu ici comme deux
            # chiffrements CBC indépendants (une instance par champ,
            # chacune redémarrant avec le même secret partagé comme IV),
            # pas un seul flux continu sur les deux champs concaténés : la
            # spec ne précise pas explicitement ce choix, seule
            # interprétation possible sans un vrai serveur MSLogonII contre
            # lequel vérifier laquelle des deux lectures est la bonne.
            username_encryptor = Cipher(
                algorithms.TripleDES(des_key), modes.CBC(shared_secret)
            ).encryptor()
            username_ciphertext = (
                username_encryptor.update(username_field) + username_encryptor.finalize()
            )
            password_encryptor = Cipher(
                algorithms.TripleDES(des_key), modes.CBC(shared_secret)
            ).encryptor()
            password_ciphertext = (
                password_encryptor.update(password_field) + password_encryptor.finalize()
            )
            writer.write(
                client_public.to_bytes(8, 'big') + username_ciphertext + password_ciphertext
            )

        # SASL (security type 20) -- voir _sasl_negotiate() pour le détail
        # complet (tramage générique, mécanismes PLAIN/ANONYMOUS
        # uniquement, autres mécanismes refusés explicitement).
        if auth_type == 20:
            await _sasl_negotiate(reader, writer, username, password)

        # En 3.3 et 3.7 (mais pas 3.8), le type "None" saute le message
        # SecurityResult et enchaîne directement sur ClientInit/ServerInit
        # (RFC 6143 Appendix A.1 et A.2 -- seule 3.8 envoie un
        # SecurityResult après None).
        if auth_type == 1 and server_version in ((3, 3), (3, 7)):
            auth_result = 0
        else:
            auth_result = await read_int(reader, 4)
        if auth_result == 0:
            _resultat = cls(
                reader=reader,
                writer=writer,
                host_key=host_key,
                protocol_version=server_version,
                rsa_aes_server_key_fingerprint=rsa_aes_server_key_fingerprint,
                clipboard=Clipboard(writer),
                keyboard=Keyboard(writer),
                mouse=Mouse(writer),
                video=await Video.create(
                    reader,
                    writer,
                    encodings,
                    jpeg_quality,
                    compression_level,
                    allow_indexed_colour,
                    shared,
                ),
            )
            logger.debug(
                'Client.create() retourne | client {}x{} prêt',
                _resultat.video.width,
                _resultat.video.height,
            )
            return _resultat
        elif auth_result == 1:
            _erreur = PermissionError('Auth failed')
            logger.debug('Client.create() lève | {!r}', _erreur)
            raise _erreur
        elif auth_result == 2:
            _erreur = PermissionError('Auth failed (too many attempts)')
            logger.debug('Client.create() lève | {!r}', _erreur)
            raise _erreur
        else:
            reason = await reader.readexactly(auth_result)
            _erreur = PermissionError(reason.decode('utf-8'))
            logger.debug('Client.create() lève | {!r}', _erreur)
            raise _erreur

    async def read(self) -> UpdateType:
        """
        Reads an update from the server and returns its type.
        """

        logger.trace('Client.read() appelée')
        update_type = UpdateType(await read_int(self.reader, 1))

        if update_type is UpdateType.CLIPBOARD:
            await self.reader.readexactly(3)  # padding
            raw_length = await read_int(self.reader, 4)
            if (
                raw_length >= 0x80000000
            ):  # read_int is unsigned; Extended Clipboard uses a signed S32 length
                raw_length -= 0x100000000
            if raw_length < 0:
                await self.process_extended_clipboard(-raw_length)
            else:
                self.clipboard.text = (await self.reader.readexactly(raw_length)).decode('latin-1')

        if update_type is UpdateType.SET_COLOUR_MAP_ENTRIES:
            await self.process_set_colour_map_entries()

        if update_type is UpdateType.VIDEO:
            await self.reader.readexactly(1)  # padding
            cnt = await read_int(self.reader, 2)
            #            print(f"UpdateType.VIDEO count={cnt}")
            if cnt == 0xFFFF:
                # Rectangle count unknown: the server signals the end of this
                # update with a LastRect pseudo-rectangle instead.
                while not await self.video.read():
                    pass
            else:
                for _ in range(cnt):
                    await self.video.read()

        if update_type is UpdateType.SERVER_FENCE:
            await self.process_server_fence()

        if update_type is UpdateType.END_OF_CONTINUOUS_UPDATES:
            self.continuous_updates_active = False

        if update_type is UpdateType.XVP:
            await self.process_xvp()

        logger.trace('Client.read() retourne | {}', update_type)
        return update_type

    async def process_set_colour_map_entries(self):
        """
        Reads a SetColourMapEntries message body and stores it in self.colour_map
        (raw 16-bit components, as the spec defines them) and, downsampled to
        8-bit, in self.video.palette (what process_raw_indexed actually renders
        with, when Video.create() was called with allow_indexed_colour=True and
        the server proposed a genuine 8bpp PseudoColor format).

        Outside of that opt-in indexed-colour mode, Video.create() always sends
        a SetPixelFormat forcing 32bpp truecolour, so a compliant server should
        never send this message at all -- it's stored here regardless, purely
        defensively, in case a non-compliant/legacy server (e.g. some embedded
        OOB-management firmware) ignores the client's pixel format anyway.
        """
        logger.debug('Client.process_set_colour_map_entries() appelée')
        await self.reader.readexactly(1)  # padding
        first_colour = await read_int(self.reader, 2)
        n_colours = await read_int(self.reader, 2)
        for i in range(n_colours):
            r = await read_int(self.reader, 2)
            g = await read_int(self.reader, 2)
            b = await read_int(self.reader, 2)
            self.colour_map[first_colour + i] = (r, g, b)
            self.video.palette[first_colour + i] = (r >> 8, g >> 8, b >> 8)
        logger.debug('Client.process_set_colour_map_entries() terminée')

    async def process_server_fence(self):
        """
        Reads a ServerFence message body and, if it's a request, replies with
        a ClientFence carrying the same flags and payload but with the
        Request bit -- and any bits we don't understand -- cleared.
        """
        logger.debug('Client.process_server_fence() appelée')
        await self.reader.readexactly(3)  # padding
        flags = await read_int(self.reader, 4)
        length = await read_int(self.reader, 1)
        payload = await self.reader.readexactly(length) if length else b''

        if flags & FENCE_FLAG_REQUEST:
            await self.send_client_fence(flags & _FENCE_KNOWN_FLAGS, payload)
        logger.debug('Client.process_server_fence() terminée')

    async def process_xvp(self):
        """
        Reads a server xvp message body (type 250, cf. Enc.XVP).

        XVP_INIT confirms the server supports the extension and gives the
        highest xvp-extension-version it supports -- stored in
        self.xvp_supported / self.xvp_version. XVP_FAIL means the most
        recent xvp Client Message (send_xvp_shutdown/_reboot/_reset) was
        refused by the server; it does *not* mean the extension itself is
        unsupported, so it deliberately leaves self.xvp_supported alone.

        Format vérifié contre la spec RFB officielle (rfbproto.rst,
        section "xvp Server Message" + le layout partagé avec "xvp Client
        Message", tous deux type 250 -- message bidirectionnel d'après le
        même document).

        **2026-09-09** : cette méthode ne se déclenche en pratique que si
        le serveur connaît réellement xvp et envoie donc un message de
        type 250 en bonne et due forme. Testé contre un vrai Xvnc
        (TigerVNC 1.13.1) : ce serveur ne supporte PAS xvp et **ferme la
        connexion** ("unknown message type") dès qu'il reçoit un
        message-type 250 -- process_xvp() n'est alors jamais atteint, le
        prochain client.read() échoue avec IncompleteReadError. Voir
        send_xvp() ci-dessous pour le détail complet de ce constat, qui
        concerne surtout l'appelant de send_xvp() plutôt que cette
        méthode-ci (qui ne fait que décoder un message xvp *reçu*, et
        reste correcte pour un serveur qui, lui, supporte réellement
        l'extension).
        """
        logger.debug('Client.process_xvp() appelée')
        await self.reader.readexactly(1)  # padding
        version = await read_int(self.reader, 1)
        code = await read_int(self.reader, 1)
        if code == XVP_INIT:
            self.xvp_supported = True
            self.xvp_version = version
        logger.debug('Client.process_xvp() terminée')

    async def process_extended_clipboard(self, total_length: int):
        """
        Reads the body of an extended-format ServerCutText message (negative
        S32 length, cf. Enc.EXTENDED_CLIPBOARD / CLIPBOARD_ACTION_*).
        Client.read() has already consumed the message-type, padding and the
        length field itself, and hands over here *total_length* = abs(length)
        -- the exact number of bytes remaining for this message, starting
        with the 4-byte flags word.

        Format vérifié contre rfbproto.rst, section "Extended Clipboard
        Pseudo-Encoding", **et** contre deux implémentations serveur réelles
        et indépendantes consultées le 2026-09-13 : le code source de QEMU
        (github.com/qemu/qemu, ui/vnc-clipboard.c + ui/vnc.c:protocol_client_msg,
        branche master) et le binaire Xtigervnc 1.13.1 lui-même (TigerVNC
        étant l'implémentation d'origine de cette extension) -- les deux
        s'accordent avec la spec, aucun écart trouvé.

        Dispatche sur les bits d'action (un seul devrait être présent à la
        fois, sauf Caps qui peut se combiner avec des bits de format) :

        - **Caps** : mémorise les tailles maximales par format déclarées par
          le serveur dans self.clipboard_ext_server_caps et passe
          self.clipboard_ext_supported à True -- c'est ce indicateur que
          chaque send_clipboard_*() ci-dessous exige avant d'émettre quoi que
          ce soit. Contrairement à send_xvp() (qui n'exige PAS xvp_supported,
          voir sa docstring), cette exigence est appliquée ici pour une raison
          concrète et vérifiée : la lecture du code source QEMU 2026-09-13
          (protocol_client_msg) montre qu'un ClientCutText étendu envoyé
          avant que le serveur n'ait négocié cette pseudo-encodage fait
          échouer la connexion entière ("extended clipboard message while
          disabled" -> vnc_client_error()) -- un mode d'échec concret que
          Fence/ContinuousUpdates n'ont pas montré partager dans ce fichier
          à ce jour (leurs propres send_*() ne bloquent pas de la même
          façon, voir leurs docstrings).
        - **Notify** : le pair signale de nouvelles données disponibles dans
          les formats indiqués par *flags* -- journalisé (logger.info) mais
          jamais suivi d'une requête automatique : comme le reste de cette
          bibliothèque (voir Clipboard.write()), c'est toujours l'appelant
          qui décide, jamais ce fichier de sa propre initiative.
        - **Peek** : le pair demande un Notify de nos formats disponibles --
          journalisé, laissé à l'appelant pour la même raison.
        - **Provide** : le pair envoie réellement des données -- un flux zlib
          *autonome par message* (confirmé par lecture de
          vnc_clipboard_provide() dans QEMU : deflateInit/deflate(Z_FINISH)/
          deflateEnd à chaque appel, pas un flux persistant façon Tight/ZRLE)
          contenant un couple (U32 taille, données) par bit de format posé
          dans *flags*, dans l'ordre des bits (0 à 15). Seul le format
          *text* (bit 0) est décodé ici (UTF-8, un octet NUL terminal est
          retiré s'il est présent -- la spec l'exige à l'émission mais tous
          les pairs ne le respectent pas forcément, d'où un retrait
          défensif plutôt qu'une vérification stricte) et écrit dans
          self.clipboard.text -- le même attribut public que l'ancien
          chemin Latin-1, pour qu'un appelant existant qui ne lit que
          self.clipboard.text bénéficie transparemment du texte étendu.
          Les couples rtf/html/dib/files, s'ils sont présents, sont
          correctement consommés (le flux ne se désynchronise jamais) mais
          leur contenu est jeté -- non implémenté, voir features-backlog.md.
        - **Request** : le pair nous demande des données -- journalisé,
          laissé à l'appelant (voir send_clipboard_provide()) : cette
          bibliothèque bas niveau ne lit jamais le presse-papiers du système
          d'elle-même, exactement comme Clipboard.write() existant.

        Lève ValueError sur un message manifestement tronqué ou corrompu
        (moins de 4 octets, tailles de format qui dépassent le flux
        décompressé, ou flux zlib invalide) plutôt que de risquer une
        désynchronisation silencieuse du reste de la connexion RFB.
        """
        logger.debug('Client.process_extended_clipboard() appelée | total_length={}', total_length)
        if total_length < 4:
            _erreur = ValueError(
                f'process_extended_clipboard : message trop court ({total_length} octets, '
                f'4 minimum pour le champ flags)'
            )
            logger.debug('Client.process_extended_clipboard() lève | {!r}', _erreur)
            raise _erreur
        flags = await read_int(self.reader, 4)
        remaining = total_length - 4

        if flags & CLIPBOARD_ACTION_CAPS:
            caps = {}
            for bit in _CLIPBOARD_KNOWN_FORMAT_BITS:
                fmt = 1 << bit
                if flags & fmt:
                    if remaining < 4:
                        _erreur = ValueError(
                            'process_extended_clipboard : Caps tronqué (taille de format manquante)'
                        )
                        logger.debug('Client.process_extended_clipboard() lève | {!r}', _erreur)
                        raise _erreur
                    caps[fmt] = await read_int(self.reader, 4)
                    remaining -= 4
            self.clipboard_ext_server_caps = caps
            self.clipboard_ext_supported = True
            logger.info('process_extended_clipboard | Caps reçu, formats={caps}', caps=caps)
        elif flags & CLIPBOARD_ACTION_NOTIFY:
            logger.info(
                'process_extended_clipboard | Notify reçu, formats disponibles={formats:#06x}',
                formats=flags & 0xFFFF,
            )
        elif flags & CLIPBOARD_ACTION_PEEK:
            logger.info(
                'process_extended_clipboard | Peek reçu (le serveur demande nos formats disponibles)'
            )
        elif flags & CLIPBOARD_ACTION_REQUEST:
            logger.info(
                'process_extended_clipboard | Request reçu, formats demandés={formats:#06x}',
                formats=flags & 0xFFFF,
            )
        elif flags & CLIPBOARD_ACTION_PROVIDE:
            _check_alloc_size(remaining, 'ServerCutText (Extended Clipboard, Provide, compressé)')
            compressed = await self.reader.readexactly(remaining)
            remaining = 0
            decompressor = decompressobj()
            try:
                raw = decompressor.decompress(compressed, _MAX_ALLOC_BYTES)
            except zlib_error as exc:
                _erreur = ValueError(
                    f'process_extended_clipboard : flux zlib invalide dans Provide ({exc})'
                )
                logger.debug(
                    'Client.process_extended_clipboard() lève | {!r} (cause : {!r})', _erreur, exc
                )
                raise _erreur from exc
            if decompressor.unconsumed_tail:
                _erreur = ValueError(
                    'process_extended_clipboard : charge utile décompressée de Provide dépasse le plafond de sécurité'
                )
                logger.debug('Client.process_extended_clipboard() lève | {!r}', _erreur)
                raise _erreur
            offset = 0
            for bit in _CLIPBOARD_KNOWN_FORMAT_BITS:
                fmt = 1 << bit
                if not (flags & fmt):
                    continue
                if offset + 4 > len(raw):
                    _erreur = ValueError(
                        'process_extended_clipboard : Provide tronqué (taille de format manquante)'
                    )
                    logger.debug('Client.process_extended_clipboard() lève | {!r}', _erreur)
                    raise _erreur
                size = int.from_bytes(raw[offset : offset + 4], 'big')
                offset += 4
                if offset + size > len(raw):
                    _erreur = ValueError(
                        'process_extended_clipboard : Provide tronqué (données de format manquantes)'
                    )
                    logger.debug('Client.process_extended_clipboard() lève | {!r}', _erreur)
                    raise _erreur
                data = raw[offset : offset + size]
                offset += size
                if fmt == CLIPBOARD_FORMAT_TEXT:
                    if data.endswith(b'\x00'):
                        data = data[:-1]
                    self.clipboard.text = data.decode('utf-8', errors='replace')
            logger.info(
                'process_extended_clipboard | Provide reçu, formats={formats:#06x}',
                formats=flags & 0xFFFF,
            )

        if remaining:
            await self.reader.readexactly(
                remaining
            )  # ignore tout octet excédentaire, sans désynchroniser le flux
        logger.debug('Client.process_extended_clipboard() terminée')

    async def send_client_fence(self, flags: int, payload: bytes = b''):
        """
        Sends a ClientFence message (type 248). Requires the server to have
        advertised support via the Fence pseudo-encoding.
        """
        logger.debug(
            'Client.send_client_fence() appelée | flags={} len(payload)={}', flags, len(payload)
        )
        if len(payload) > 64:
            _erreur = ValueError('ClientFence payload is limited to 64 bytes')
            logger.debug('Client.send_client_fence() lève | {!r}', _erreur)
            raise _erreur
        self.writer.write(
            bytes([248, 0, 0, 0]) + flags.to_bytes(4, 'big') + bytes([len(payload)]) + payload
        )
        logger.debug('Client.send_client_fence() terminée')

    async def send_enable_continuous_updates(
        self, enable: bool, x: int, y: int, width: int, height: int
    ):
        """
        Sends an EnableContinuousUpdates message (type 150). Only send this
        after the server has confirmed support via the ContinuousUpdates
        pseudo-encoding -- there's no other handshake for it.
        """
        logger.debug(
            'Client.send_enable_continuous_updates() appelée | enable={} x={} y={} width={} height={}',
            enable,
            x,
            y,
            width,
            height,
        )
        self.writer.write(
            bytes([150, 1 if enable else 0])
            + x.to_bytes(2, 'big')
            + y.to_bytes(2, 'big')
            + width.to_bytes(2, 'big')
            + height.to_bytes(2, 'big')
        )
        self.continuous_updates_active = enable
        logger.debug('Client.send_enable_continuous_updates() terminée')

    async def send_set_desktop_size(self, width: int, height: int, screens: list | None = None):
        """
        Demande au serveur de redimensionner le bureau distant (message
        client SetDesktopSize, type 251). Le serveur peut refuser -- la
        réponse arrive en tant que rectangle ExtendedDesktopSize avec
        reason=1 (cf. process_extended_desktop_size), à surveiller côté
        appelant pour savoir si la demande a abouti.

        Si `screens` n'est pas fourni, envoie une disposition à un seul
        écran couvrant tout le nouveau bureau (comportement par défaut
        raisonnable pour un client qui ne gère pas explicitement le
        multi-écran lors du resize). Pour préserver une disposition
        multi-écran existante, passer self.video.screens (éventuellement
        ajustée) en argument.
        """
        logger.debug(
            'Client.send_set_desktop_size() appelée | width={} height={} len(screens)={}',
            width,
            height,
            None if screens is None else len(screens),
        )
        if screens is None:
            screens = [Screen(0, 0, width, height, id=0, flags=0)]

        body = (
            width.to_bytes(2, 'big')
            + height.to_bytes(2, 'big')
            + len(screens).to_bytes(1, 'big')
            + b'\x00'  # padding
        )
        for screen in screens:
            body += (
                screen.id.to_bytes(4, 'big')
                + screen.x.to_bytes(2, 'big')
                + screen.y.to_bytes(2, 'big')
                + screen.width.to_bytes(2, 'big')
                + screen.height.to_bytes(2, 'big')
                + screen.flags.to_bytes(4, 'big')
            )

        logger.info(
            'send_set_desktop_size | width={width} height={height} screen_count={screen_count}',
            width=width,
            height=height,
            screen_count=len(screens),
        )
        self.writer.write(b'\xfb\x00' + body)  # 251, padding, puis le corps
        logger.debug('Client.send_set_desktop_size() terminée')

    async def send_qemu_extended_key_event(self, down: bool, keysym: int, keycode: int):
        """
        Envoie un événement clavier étendu QEMU : keysym ET keycode matériel
        (espace de numérotation Linux evdev) dans le même message, ce qui
        évite l'ambiguïté de traduction keysym<->touche physique que peut
        introduire un layout clavier compliqué (AZERTY inclus).

        Format vérifié le 2026-09-02 contre le code source QEMU officiel
        (github.com/qemu/qemu, fichier ui/vnc.c, commit
        a925240509d1b4b656cc480f1cc79ba4d7c8bc08, branche master) -- cette
        extension n'étant pas documentée dans la RFC RFB, c'est la seule
        source faisant foi. Confirmé côté serveur dans
        protocol_client_msg() : message-type 255 (VNC_MSG_CLIENT_QEMU),
        submessage-type 0 (VNC_MSG_CLIENT_QEMU_EXT_KEY_EVENT), puis
        down-flag en U16 (lu via read_u16(data, 2)), keysym en U32
        (read_u32(data, 4)) et keycode en U32 (read_u32(data, 8)), le tout
        en network byte order -- 12 octets au total ("if (len == 2) return
        12;"). Vérification octet par octet faite dans ce sandbox contre 3
        messages reconstruits à la main d'après cette lecture de source
        (dont des valeurs hautes de bornes U32) : implémentation déjà
        conforme, aucune correction de code nécessaire.

        **2026-09-09 : testé de bout en bout contre un vrai QEMU 8.2.2**
        (`qemu-system-x86_64`, paquet Ubuntu, aucun Proxmox disponible dans
        ce sandbox -- mais c'est le même code serveur `ui/vnc.c` que
        Proxmox utilise pour sa propre console VNC). Vérification par
        preuve visuelle : un secteur de boot x86 minimal écrit pour cette
        session (moins de 50 octets de code, BIOS INT 16h) affiche le caractère
        exact renvoyé par le clavier virtuel du guest -- capture d'écran
        avant/après via `screenshot()` de ce même fichier, donc bien la
        chaîne complète client -> serveur -> périphérique clavier émulé
        -> BIOS guest testée, pas seulement l'envoi. 3 constats réels :

        1. Keysym et keycode cohérents (chiffres, lettres minuscules) :
           le caractère exact apparaît, à chaque fois -- cas nominal
           confirmé de bout en bout.
        2. **`keycode=0` est silencieusement ignoré par ce QEMU** (aucun
           caractère ne remonte), et ne déclenche PAS un repli sur le
           keysym seul -- reconfirmé deux fois avec des keysyms distincts
           (`'3'` puis `'z'`), écran inchangé (0 pixel modifié) dans les
           deux cas. Un appelant doit donc toujours fournir un vrai
           keycode evdev non nul.
        3. **Si le QEMU/Proxmox cible a été démarré avec un layout clavier
           explicite (option `-k <layout>`), `keycode` est intégralement
           ignoré.** Confirmé à la fois en lisant `ext_key_event()` dans
           `ui/vnc.c` (`if (keyboard_layout) { key_event(vs, down, sym); }
           else { do_key_event(vs, down, keycode, sym); }` -- un layout
           explicite bascule sur le chemin keysym-seul, identique au
           vieux message RFB `SetKeyEvent` non étendu) et en relançant le
           même test avec `-k en-us` : un `keycode=0` qui ne produisait
           rien sans `-k` produit alors le caractère attendu à partir du
           seul keysym. **Conséquence pratique : tout l'intérêt de cette
           extension (ne pas dépendre d'un layout côté serveur) disparaît
           silencieusement dès que la cible a un `-k` explicite** -- aucun
           moyen pour ce client de le détecter à l'avance.
        4. Keysym et keycode délibérément incohérents pour une touche
           lettre (ex. keycode de la touche physique A + keysym de 'B') :
           le caractère obtenu n'est ni celui du keycode seul ('a') ni
           celui du keysym seul ('B'), mais 'A' -- hypothèse la plus
           probable (cohérente avec 2 essais indépendants, mais PAS
           confirmée en relisant l'intégralité de `do_key_event()`) : un
           keysym ASCII majuscule A-Z déclenche une touche Shift
           synthétisée côté serveur, appliquée à la touche physique
           désignée par keycode -- comportement observé dans
           `key_event()` pour le chemin non étendu, qui repasse `sym`
           (pas seulement un `sym` déjà mis en minuscule) à
           `do_key_event()`. **Ne pas s'appuyer sur ce cas : toujours
           garder keysym et keycode mutuellement cohérents**, comme le
           ferait un vrai clavier physique -- c'est l'usage pour lequel
           cette extension est conçue, pas un moyen de forcer un
           caractère différent de la touche physique pressée.
        """
        logger.debug('Client.send_qemu_extended_key_event() appelée | down={}', down)
        # Ni keysym ni keycode dans le journal : ce serait un enregistreur de
        # frappes (mot de passe saisi dans la session distante), SOCLE §8.
        logger.info('send_qemu_extended_key_event | down={down}', down=down)
        self.writer.write(
            b'\xff\x00'  # message-type 255, submessage-type 0
            + (1 if down else 0).to_bytes(2, 'big')  # down-flag (U16)
            + keysym.to_bytes(4, 'big')
            + keycode.to_bytes(4, 'big')
        )
        logger.debug('Client.send_qemu_extended_key_event() terminée')

    async def send_xvp(self, code: int, confirm: bool = False):
        """
        Envoie un message client xvp (type 250) demandant au serveur
        d'effectuer un shutdown propre (XVP_SHUTDOWN), un reboot propre
        (XVP_REBOOT) ou un reset brutal (XVP_RESET) du système dont ce
        client affiche le framebuffer. Préférer send_xvp_shutdown() /
        send_xvp_reboot() / send_xvp_reset() ci-dessous plutôt que
        d'appeler cette méthode directement.

        *confirm* (ajouté 2026-09-06) doit être explicitement mis à
        `True` par l'appelant, faute de quoi une `PermissionError` est
        levée avant tout envoi -- garde-fou minimal contre un envoi
        accidentel de cette commande destructive (ex. mauvais bouton
        cliqué dans une UI, appel automatisé mal branché). Ce n'est
        volontairement PAS une confirmation interactive (cette
        bibliothèque bas niveau n'a aucune notion d'UI) : c'est à
        l'appelant final de décider comment obtenir cette confirmation
        (boîte de dialogue, double-clic, argument CLI `--yes`, etc.) et
        de ne passer `confirm=True` qu'une fois cette confirmation
        réellement obtenue. Voir features.md/CLAUDE.md, section
        « Confirmation avant commande xvp destructive ».

        Cette méthode n'exige pas self.xvp_supported -- mais contrairement
        à ce qu'affirmait une version précédente de cette docstring
        (avant test réel), un serveur sans support xvp ne se contente
        **pas forcément** d'ignorer silencieusement le message : **testé
        le 2026-09-09 contre un vrai Xvnc (TigerVNC 1.13.1, aucun support
        xvp)**, ce serveur journalise "unknown message type 250" et
        **ferme immédiatement la connexion** ("unknown message type"),
        exactement comme n'importe quel type de message RFB non reconnu
        qu'il traiterait de la même façon générique -- ce n'est donc pas
        un traitement spécifique à xvp, mais bien le comportement par
        défaut de ce serveur face à un message-type inconnu, quel qu'il
        soit. Un appelant DOIT donc attendre qu'un message XVP_INIT ait
        été reçu (self.xvp_supported == True, via process_xvp()/
        self.read()) avant d'appeler cette méthode, sous peine de
        perdre la connexion RFB entière -- ce n'est plus une simple
        recommandation de prudence mais une précaution nécessaire au vu
        de ce test réel, au moins pour les serveurs qui réagissent comme
        TigerVNC à un message-type inconnu (RFC 6143 ne précise pas de
        comportement obligatoire dans ce cas -- silence, fermeture ou
        autre réaction restent tous conformes à la spec du point de vue
        du serveur).

        Format vérifié contre la spec RFB officielle (rfbproto.rst,
        section "xvp Client Message") -- structure interne testée dans ce
        sandbox contre un flux serveur XVP_INIT fabriqué à la main.
        **2026-09-09 : testé pour de vrai contre TigerVNC/Xvnc 1.13.1**
        (installé via apt dans ce sandbox, `SecurityTypes None`) -- ce
        serveur ne supporte pas xvp (jamais de XVP_INIT reçu, y compris
        après plusieurs FramebufferUpdate) et ferme la connexion dès
        réception d'un send_xvp_shutdown()/_reboot()/_reset() (voir
        détail complet dans docs/sessions/session-10-2026-09-09.md et
        features-backlog.md). Le format binaire lui-même (4 octets,
        message-type 250 + version + code) reste conforme à la spec et
        inchangé par ce constat -- seul le comportement *serveur* face à
        ce message est désormais mieux compris. Aucun serveur supportant
        réellement xvp n'a pu être testé dans ce sandbox (le logiciel
        `xvp` lui-même, distinct d'un serveur VNC/Xvnc classique, n'a pas
        été installé -- voir features-backlog.md pour la discussion de sa
        pertinence).
        """
        logger.debug('Client.send_xvp() appelée | code={} confirm={}', code, confirm)
        if code not in (XVP_SHUTDOWN, XVP_REBOOT, XVP_RESET):
            _erreur = ValueError(f'invalid xvp-message-code: {code}')
            logger.debug('Client.send_xvp() lève | {!r}', _erreur)
            raise _erreur
        code_name = {
            XVP_SHUTDOWN: 'XVP_SHUTDOWN',
            XVP_REBOOT: 'XVP_REBOOT',
            XVP_RESET: 'XVP_RESET',
        }[code]
        if not confirm:
            logger.warning(
                'send_xvp | code={code} ({code_name}) | REFUSÉ -- confirm=True requis',
                code=code,
                code_name=code_name,
            )
            raise PermissionError(
                f'send_xvp({code_name}) is a destructive remote command and requires confirm=True'
            )
        logger.warning(
            'send_xvp | code={code} ({code_name}) | commande destructive envoyée au serveur distant',
            code=code,
            code_name=code_name,
        )
        self.writer.write(bytes([250, 0, _XVP_VERSION, code]))
        logger.debug('Client.send_xvp() terminée')

    async def send_xvp_shutdown(self, confirm: bool = False):
        """Demande un arrêt propre du système distant (xvp). Voir send_xvp() pour *confirm*."""
        logger.debug('Client.send_xvp_shutdown() appelée | confirm={}', confirm)
        await self.send_xvp(XVP_SHUTDOWN, confirm=confirm)
        logger.debug('Client.send_xvp_shutdown() terminée')

    async def send_xvp_reboot(self, confirm: bool = False):
        """Demande un redémarrage propre du système distant (xvp). Voir send_xvp() pour *confirm*."""
        logger.debug('Client.send_xvp_reboot() appelée | confirm={}', confirm)
        await self.send_xvp(XVP_REBOOT, confirm=confirm)
        logger.debug('Client.send_xvp_reboot() terminée')

    async def send_xvp_reset(self, confirm: bool = False):
        """Demande un reset brutal du système distant (xvp). Voir send_xvp() pour *confirm*."""
        logger.debug('Client.send_xvp_reset() appelée | confirm={}', confirm)
        await self.send_xvp(XVP_RESET, confirm=confirm)
        logger.debug('Client.send_xvp_reset() terminée')

    def _require_clipboard_ext(self, method_name: str):
        logger.debug('Client._require_clipboard_ext() appelée | method_name={}', method_name)
        if not self.clipboard_ext_supported:
            _erreur = PermissionError(
                f'{method_name}() requiert que le serveur ait déjà confirmé le support '
                f"d'Extended Clipboard (self.clipboard_ext_supported, cf. Enc.EXTENDED_CLIPBOARD "
                f'et process_extended_clipboard()) -- envoyer ce message avant cette confirmation '
                f'a été observé (code source QEMU 8.2.2 réel, ui/vnc.c:protocol_client_msg) comme '
                f'faisant échouer la connexion entière ("extended clipboard message while '
                f'disabled")'
            )
            logger.debug('Client._require_clipboard_ext() lève | {!r}', _erreur)
            raise _erreur
        logger.debug('Client._require_clipboard_ext() terminée')

    async def send_clipboard_caps(self, max_text_size: int = 0):
        """
        Envoie notre propre Caps (CLIPBOARD_ACTION_CAPS) : déclare les
        formats/actions Extended Clipboard que nous comprenons réellement.
        Optionnel selon la spec -- un serveur qui ne reçoit jamais notre
        Caps suppose par défaut text/rtf/html, notify/request/provide et
        20 Mio de taille max pour le texte (0 pour le reste) -- mais ce
        fork ne décode jamais que le format *text* (voir
        process_extended_clipboard()), donc envoyer une Caps explicite qui
        n'annonce QUE text évite à un serveur de gaspiller de la bande
        passante sur des payloads rtf/html/dib que ce fork jetterait de
        toute façon.

        *max_text_size* (0 par défaut, conformément à la recommandation de
        la spec elle-même) est la plus grande donnée *text* que nous
        acceptons de recevoir sans l'avoir demandée via un Provide -- 0
        force le pair à toujours envoyer un Notify d'abord et attendre un
        send_clipboard_request() explicite, ce que la spec recommande
        précisément pour éviter une ambiguïté entre "tout nouveau jeu de
        formats" et "mise à jour d'un jeu déjà connu, réduite à cause d'une
        limite de taille" (rfbproto.rst). Passer une valeur plus grande
        autorise le pair à nous fournir du texte sans y être invité.

        Exige self.clipboard_ext_supported -- voir _require_clipboard_ext().
        """
        logger.debug('Client.send_clipboard_caps() appelée | max_text_size={}', max_text_size)
        self._require_clipboard_ext('send_clipboard_caps')
        flags = (
            CLIPBOARD_ACTION_CAPS
            | CLIPBOARD_ACTION_PROVIDE
            | CLIPBOARD_ACTION_REQUEST
            | CLIPBOARD_ACTION_NOTIFY
            | CLIPBOARD_FORMAT_TEXT
        )
        body = flags.to_bytes(4, 'big') + max_text_size.to_bytes(4, 'big')
        logger.info('send_clipboard_caps | max_text_size={size}', size=max_text_size)
        self.writer.write(bytes([6, 0, 0, 0]) + (-len(body)).to_bytes(4, 'big', signed=True) + body)
        logger.debug('Client.send_clipboard_caps() terminée')

    async def send_clipboard_notify(self, formats: int = CLIPBOARD_FORMAT_TEXT):
        """
        Envoie un Notify (CLIPBOARD_ACTION_NOTIFY) : signale au pair que de
        nouvelles données sont disponibles de notre côté pour les *formats*
        donnés (aucune charge utile -- c'est au pair de décider s'il
        enchaîne avec un send_clipboard_request()). Exige
        self.clipboard_ext_supported -- voir _require_clipboard_ext().

        **À envoyer avant tout send_clipboard_provide() non sollicité** --
        voir send_clipboard_update() et la docstring de send_clipboard_provide()
        pour la preuve empirique (deux serveurs réels indépendants) que cet
        ordre est nécessaire, pas seulement recommandé par la spec.
        """
        logger.debug('Client.send_clipboard_notify() appelée | formats={}', formats)
        self._require_clipboard_ext('send_clipboard_notify')
        flags = CLIPBOARD_ACTION_NOTIFY | (formats & 0xFFFF)
        logger.info('send_clipboard_notify | formats={formats:#06x}', formats=formats)
        self.writer.write(
            bytes([6, 0, 0, 0]) + (-4).to_bytes(4, 'big', signed=True) + flags.to_bytes(4, 'big')
        )
        logger.debug('Client.send_clipboard_notify() terminée')

    async def send_clipboard_request(self, formats: int = CLIPBOARD_FORMAT_TEXT):
        """
        Envoie un Request (CLIPBOARD_ACTION_REQUEST) : demande au pair de
        nous fournir (Provide) ses données pour les *formats* donnés. La
        réponse, si le pair en envoie une, arrive de façon asynchrone via un
        futur Client.read() qui retournera UpdateType.CLIPBOARD -- pas de
        valeur de retour synchrone ici, comme le reste des messages de
        cette bibliothèque. Exige self.clipboard_ext_supported -- voir
        _require_clipboard_ext().
        """
        logger.debug('Client.send_clipboard_request() appelée | formats={}', formats)
        self._require_clipboard_ext('send_clipboard_request')
        flags = CLIPBOARD_ACTION_REQUEST | (formats & 0xFFFF)
        logger.info('send_clipboard_request | formats={formats:#06x}', formats=formats)
        self.writer.write(
            bytes([6, 0, 0, 0]) + (-4).to_bytes(4, 'big', signed=True) + flags.to_bytes(4, 'big')
        )
        logger.debug('Client.send_clipboard_request() terminée')

    async def send_clipboard_provide(self, text: str):
        """
        Envoie notre *text* au serveur via l'action Provide d'Extended
        Clipboard (CLIPBOARD_ACTION_PROVIDE) -- l'équivalent UTF-8 de
        Clipboard.write() (Latin-1 seul). Exige self.clipboard_ext_supported
        -- voir _require_clipboard_ext() : contrairement à send_xvp(), qui
        n'exige délibérément pas xvp_supported (voir sa docstring), cette
        exigence est appliquée ici sur la foi d'une preuve concrète (code
        source QEMU 8.2.2 réel, voir _require_clipboard_ext()), pas d'une
        simple prudence par défaut.

        **N'appeler cette méthode seule QUE pour répondre à un Request déjà
        reçu** (CLIPBOARD_ACTION_REQUEST, cf. process_extended_clipboard()).
        Pour annoncer un contenu tout nouveau, préférer send_clipboard_update()
        ci-dessous : testé en conditions réelles le 2026-09-13 contre un vrai
        TigerVNC/Xvnc 1.13.1 **et** un vrai QEMU 8.2.2, un Provide envoyé
        seul, sans Notify préalable, est silencieusement ignoré par les
        deux -- TigerVNC le journalise explicitement ("Ignoring unexpected
        clipboard data", car sa propre Caps déclare une taille max de 0
        octet pour le texte non sollicité, cf. send_clipboard_caps()) ;
        QEMU le rejette pour une raison mécanique différente mais liée : sa
        structure interne associant les données à leur émetteur
        (vs->cbinfo->owner == &vs->cbpeer, ui/vnc-clipboard.c) n'existe
        qu'après un Notify de ce même émetteur. Aucun des deux ne coupe la
        connexion dans ce cas (contrairement à un Provide envoyé avant toute
        négociation, voir _require_clipboard_ext()) -- la charge utile est
        juste perdue silencieusement, un mode d'échec plus sournois qu'une
        erreur franche.

        Format vérifié contre rfbproto.rst et contre
        vnc_clipboard_provide() dans ui/vnc-clipboard.c de QEMU (source
        consultée le 2026-09-13) -- seul le format *text* (bit 0) est
        construit ici, conformément à ce que ce fork décode lui-même côté
        réception (voir process_extended_clipboard()). Le payload est un
        flux zlib *autonome par message* (deflateInit/deflate(Z_FINISH)/
        deflateEnd à chaque appel côté QEMU, pas un flux persistant façon
        Tight/ZRLE -- confirmé par lecture directe de ce code source), qui
        contient un unique couple (U32 taille, données) pour le texte,
        terminé par un octet NUL conformément à la spec ("The text must be
        followed by a terminating null even though the length is also
        explicitly given").
        """
        logger.debug('Client.send_clipboard_provide() appelée | len(text)={}', len(text))
        self._require_clipboard_ext('send_clipboard_provide')
        data = text.encode('utf-8') + b'\x00'
        inner = len(data).to_bytes(4, 'big') + data
        compressed = compress(inner)
        flags = CLIPBOARD_ACTION_PROVIDE | CLIPBOARD_FORMAT_TEXT
        body = flags.to_bytes(4, 'big') + compressed
        logger.info('send_clipboard_provide | {n} octets UTF-8 avant compression', n=len(data))
        self.writer.write(bytes([6, 0, 0, 0]) + (-len(body)).to_bytes(4, 'big', signed=True) + body)
        logger.debug('Client.send_clipboard_provide() terminée')

    async def send_clipboard_update(self, text: str):
        """
        Raccourci recommandé pour annoncer un contenu de presse-papiers tout
        nouveau : enchaîne send_clipboard_notify() puis send_clipboard_provide(text).
        C'est l'ordre que deux serveurs réels indépendants (TigerVNC/Xvnc
        1.13.1 et QEMU 8.2.2, testés le 2026-09-13 -- voir
        send_clipboard_provide()) exigent tous les deux pour accepter la
        donnée, chacun pour une raison interne différente -- au point qu'un
        send_clipboard_provide() isolé, bien que parfaitement valide sur le
        fil, se retrouve silencieusement jeté par les deux en pratique.
        N'utiliser send_clipboard_provide() seul que pour répondre à un
        Request déjà reçu (voir sa docstring) ; dans tous les autres cas,
        préférer cette méthode.
        """
        logger.debug('Client.send_clipboard_update() appelée | len(text)={}', len(text))
        await self.send_clipboard_notify()
        await self.send_clipboard_provide(text)
        logger.debug('Client.send_clipboard_update() terminée')

    async def drain(self):
        """
        Waits for data to be written to the server.
        """

        logger.trace('Client.drain() appelée')
        await self.writer.drain()
        logger.trace('Client.drain() terminée')

    async def screenshot(
        self, x: int = 0, y: int = 0, width: int | None = None, height: int | None = None
    ):
        """
        Takes a screenshot and returns a 3D RGBA array.

        Each FramebufferUpdate answers exactly one FramebufferUpdateRequest
        (rfbproto.rst § FramebufferUpdate), so when an update leaves the area
        incomplete a new *incremental* request is sent. TigerVNC Xvnc
        (``VNCSConnectionST::framebufferUpdateRequest``) answers every
        non-incremental request of a client that advertised ExtendedDesktopSize with
        an update holding only that pseudo-rectangle, marks the area as changed and
        sends the pixels on the next incremental request -- as its own viewer does.
        Without the new request screenshot() waited forever, and a non-incremental
        one would loop on desktop-size-only updates (both found 2026-10-24 against a
        real Xvnc, issue #27). The area never received is still "changed" on the
        server side, so an incremental request does bring it.
        """

        logger.trace(
            'Client.screenshot() appelée | x={} y={} width={} height={}', x, y, width, height
        )
        self.video.data = None
        self.video.refresh(x, y, width, height)
        while True:
            update_type = await self.read()
            if update_type is UpdateType.VIDEO:
                if self.video.is_complete(x, y, width, height):
                    _resultat = self.video.as_rgba(x, y, width, height)
                    logger.trace('Client.screenshot() retourne | tableau {}', _resultat.shape)
                    return _resultat
                logger.trace('Client.screenshot() | zone incomplète, nouvelle demande')
                self.video.refresh(x, y, width, height, incremental=True)
        logger.trace('Client.screenshot() terminée')


_WEBSOCKET_GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'  # RFC 6455 §1.3, constante fixe


def _ws_frame(payload: bytes, opcode: int = 0x2, mask: bool = True) -> bytes:
    """
    Construit une trame WebSocket (RFC 6455 §5.2) contenant *payload*.
    *opcode* 0x2 = binaire (celui utilisé pour tout le trafic RFB une fois
    la poignée de main HTTP terminée), 0x8 = close, 0x9 = ping, 0xA = pong.
    RFC 6455 §5.1 impose que toute trame envoyée par un client soit
    masquée (*mask* reste donc à `True` dans tous les usages internes de
    cette fonction) ; la clé de masquage est tirée au hasard à chaque
    trame, comme l'exige la RFC (une clé fixe ou prévisible affaiblirait
    la protection - certes limitée - que le masquage apporte contre le
    cache poisoning de proxies intermédiaires mal écrits, sa seule raison
    d'être réelle d'après la RFC elle-même).
    """
    logger.trace(
        '_ws_frame() appelée | len(payload)={} opcode={} mask={}', len(payload), opcode, mask
    )
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))  # FIN=1, RSV1-3=0, opcode
    length = len(payload)
    mask_bit = 0x80 if mask else 0x00
    if length <= 125:
        header.append(mask_bit | length)
    elif length <= 0xFFFF:
        header.append(mask_bit | 126)
        header += length.to_bytes(2, 'big')
    else:
        header.append(mask_bit | 127)
        header += length.to_bytes(8, 'big')
    if mask:
        key = urandom(4)
        header += key
        masked = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        _resultat = bytes(header) + masked
        logger.trace('_ws_frame() retourne | {} octet(s)', len(_resultat))
        return _resultat
    _resultat = bytes(header) + payload
    logger.trace('_ws_frame() retourne | {} octet(s)', len(_resultat))
    return _resultat


class _WebSocketWriter:
    """
    Enveloppe un `StreamWriter` TCP brut pour que chaque `write()` soit
    automatiquement encadré dans une trame WebSocket binaire avant d'être
    réellement écrit sur le socket -- transparent pour tout le reste
    d'`asyncvnc2.py`, qui continue à voir un objet exposant `write()`/
    `drain()`/`close()`/`wait_closed()` comme n'importe quel `StreamWriter`
    (voir `_ws_wrap_connection()` ci-dessous pour le pendant côté lecture).

    Volontairement minimal : ne cherche pas à imiter la totalité de
    l'API `StreamWriter` (pas de `.transport`, pas de `get_extra_info()`),
    seulement ce dont `Client.create()` et le reste de ce fichier se
    servent réellement. Si un futur patch a besoin de combiner ceci avec
    VeNCrypt (RFB-sur-WebSockets-sur-TLS-VeNCrypt, un empilement exotique
    mais pas interdit par les specs respectives), `_start_tls_client()`
    devra être adapté pour ne plus supposer l'existence de `.transport`.

    *mask* détermine si les trames sortantes sont masquées : `True`
    (défaut) côté client (`_ws_wrap_connection()`, utilisé par
    `connect()`), `False` côté serveur (`_ws_wrap_connection_server()`,
    utilisé par `listen()`) -- RFC 6455 §5.3 : seules les trames
    client-vers-serveur doivent être masquées, jamais l'inverse.
    """

    def __init__(self, raw_writer: StreamWriter, pump_task=None, mask: bool = True):
        logger.debug('_WebSocketWriter.__init__() appelée | mask={}', mask)
        self._raw = raw_writer
        self._pump_task = pump_task
        self._mask = mask
        logger.debug('_WebSocketWriter.__init__() terminée')

    def write(self, data: bytes) -> None:
        logger.trace('_WebSocketWriter.write() appelée | len(data)={}', len(data))
        self._raw.write(_ws_frame(bytes(data), mask=self._mask))
        logger.trace('_WebSocketWriter.write() terminée')

    async def drain(self) -> None:
        logger.trace('_WebSocketWriter.drain() appelée')
        await self._raw.drain()
        logger.trace('_WebSocketWriter.drain() terminée')

    def close(self) -> None:
        logger.debug('_WebSocketWriter.close() appelée')
        try:
            self._raw.write(_ws_frame(b'', opcode=0x8, mask=self._mask))
        except (OSError, RuntimeError, ssl.SSLError) as exc:
            # La connexion peut déjà être à moitié fermée (par ex. si le
            # serveur a fermé le premier) -- on n'empêche pas la fermeture
            # du côté client pour autant, le close WebSocket n'est qu'une
            # politesse protocolaire, pas une étape obligatoire pour que
            # la socket TCP sous-jacente se ferme correctement. Exceptions
            # ciblées (et non plus `Exception` nu) sur la base des erreurs
            # réellement observées à cet endroit lors des tests de ce
            # fichier : `OSError`/`ConnectionError` (celui-ci en est une
            # sous-classe) si le transport TCP sous-jacent est déjà fermé,
            # `RuntimeError` si l'event loop asyncio referme le transport
            # entre-temps, `ssl.SSLError` en TLS (`wss://`) si la session
            # est déjà en cours de fermeture -- journalisé en `debug` pour
            # garder une trace sans faire remonter une erreur pour un
            # événement attendu et sans conséquence.
            logger.debug(
                'WebSocket close(): envoi de la trame de clôture ignoré ({}: {})',
                type(exc).__name__,
                exc,
            )
        self._raw.close()
        if self._pump_task is not None:
            # Découvert par un test réel contre un vrai `websockify` en
            # TLS (`wss://`) : sans cette annulation explicite, la tâche
            # de fond `_ws_pump()` peut se retrouver à lire sur une
            # socket que `self._raw.close()` vient de faire passer en
            # cours de fermeture TLS, et lever une `ssl.SSLError`
            # ("application data after close notify") jamais récupérée
            # par personne -- désormais rattrapée dans `_ws_pump()` lui-
            # même (voir plus bas), mais autant arrêter proprement cette
            # tâche dès que le côté écriture se ferme plutôt que
            # d'attendre qu'elle échoue de son côté.
            self._pump_task.cancel()
        logger.debug('_WebSocketWriter.close() terminée')

    async def wait_closed(self) -> None:
        logger.debug('_WebSocketWriter.wait_closed() appelée')
        try:
            await self._raw.wait_closed()
        except ssl.SSLError as exc:
            if 'APPLICATION_DATA_AFTER_CLOSE_NOTIFY' not in str(exc):
                logger.debug('_WebSocketWriter.wait_closed() relève | {!r}', exc)
                raise
            # Découvert par un test réel contre un vrai `websockify` en
            # TLS (`wss://`, `--run-once`) : quand le pair ferme la
            # connexion TCP juste après avoir envoyé sa dernière trame
            # WebSocket, il arrive qu'OpenSSL considère qu'une trace
            # d'"application data" traîne encore après le close_notify au
            # moment où *nous* tentons notre propre `unwrap()` de
            # fermeture -- pas une corruption de données (la session RFB
            # entière a déjà été lue et vérifiée correcte avant d'arriver
            # ici, cette erreur ne survient que dans le ménage de
            # fermeture), plutôt une course bénigne bien connue entre
            # asyncio et OpenSSL sur la fin de vie d'une connexion TLS
            # (le même symptôme existe indépendamment de WebSockets --
            # voir bpo-39951 -- mais ne se manifestait pas avec le simple
            # `opener` TLS déjà existant testé ailleurs dans ce fichier ;
            # la combinaison avec la tâche de fond `_ws_pump()`, qui
            # continue de lire sur ce même flux jusqu'à son annulation
            # dans `close()` ci-dessus, semble être ce qui la révèle).
            # Ignorée ici uniquement pour ce message d'erreur précis --
            # toute autre `ssl.SSLError` continue de remonter normalement.
            logger.debug('_WebSocketWriter.wait_closed() course TLS bénigne ignorée | {!r}', exc)
        logger.debug('_WebSocketWriter.wait_closed() terminée')


async def _ws_pump(
    raw_reader: StreamReader, raw_writer: StreamWriter, ws_reader: StreamReader
) -> None:
    """
    Tourne en tâche de fond pendant toute la durée de vie d'une connexion
    RFB-sur-WebSockets : lit en continu des trames WebSocket sur
    *raw_reader*, et pousse le contenu utile dans *ws_reader* via
    `feed_data()` pour que le reste d'`asyncvnc2.py` -- qui n'a jamais
    entendu parler de WebSockets -- puisse continuer à faire du
    `await reader.readexactly(n)` normalement (RFC 6455 §5.4 : les
    trames de données peuvent être fragmentées sur plusieurs trames
    physiques par le réseau, indépendamment de tout découpage en messages
    applicatifs RFB -- ce pompage réassemble tout ça en un flux d'octets
    continu, exactement le service que rendrait un vrai `StreamReader` TCP
    si WebSockets n'existait pas).

    Répond aux trames *ping* par un *pong* immédiat (RFC 6455 §5.5.2 :
    "A Pong frame sent in response to a Ping frame must have identical
    'Application data' as found in the message body of the Ping frame
    being replied to"), et à une trame *close* en fermant proprement le
    flux côté lecture (`feed_eof()`) puis en arrêtant la tâche.
    """
    logger.debug('_ws_pump() appelée')
    try:
        while True:
            first2 = await raw_reader.readexactly(2)
            opcode = first2[0] & 0x0F
            masked = bool(first2[1] & 0x80)
            length = first2[1] & 0x7F
            if length == 126:
                length = int.from_bytes(await raw_reader.readexactly(2), 'big')
            elif length == 127:
                length = int.from_bytes(await raw_reader.readexactly(8), 'big')
            mask_key = await raw_reader.readexactly(4) if masked else None
            payload = await raw_reader.readexactly(length) if length else b''
            if mask_key is not None:
                # Un serveur WebSocket conforme à la RFC ne masque jamais
                # ses trames (seul le client y est tenu) -- mais on
                # démasque quand même si le bit est mis, par tolérance
                # envers un serveur non conforme, plutôt que de planter
                # sur un flux par ailleurs parfaitement exploitable (même
                # philosophie que le traitement de "RFB 004.001" pour
                # RealVNC Enterprise ailleurs dans ce fichier).
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

            if opcode in (0x0, 0x2, 0x1):  # continuation / binaire / texte
                ws_reader.feed_data(payload)
            elif opcode == 0x9:  # ping -> pong immédiat, même charge utile
                raw_writer.write(_ws_frame(payload, opcode=0xA))
                await raw_writer.drain()
            elif opcode == 0xA:  # pong : rien à faire
                pass
            elif opcode == 0x8:  # close
                ws_reader.feed_eof()
                logger.debug('_ws_pump() retourne')
                return
            # Les opcodes réservés/inconnus sont ignorés plutôt que de
            # faire échouer toute la connexion -- la RFB elle-même adopte
            # ce principe de tolérance pour ses propres extensions
            # (encodages/pseudo-encodages inconnus simplement ignorés).
    except CancelledError:
        # Une annulation explicite de cette tâche (voir
        # `_WebSocketWriter.close()`) ne doit surtout pas être avalée ici
        # -- cela romprait la sémantique normale d'annulation d'asyncio
        # (l'appelant de `task.cancel()` ne serait jamais notifié).
        logger.debug('_ws_pump() annulée, annulation propagée')
        raise
    except (IncompleteReadError, ConnectionError, OSError) as exc:
        logger.debug('_ws_pump() fin de connexion, EOF signalé | {}: {}', type(exc).__name__, exc)
        # Fin de connexion pendant la lecture d'une trame -- que ce soit
        # une simple coupure TCP (`IncompleteReadError`/`ConnectionError`)
        # ou, découvert par un test réel contre un vrai `websockify` en
        # TLS (`wss://`), une erreur `ssl.SSLError` du type
        # "application data after close notify" quand le pair envoie son
        # message de fermeture TLS avant que cette tâche n'ait fini de
        # lire (`ssl.SSLError` est une sous-classe d'`OSError`, donc
        # couverte ici sans import supplémentaire). Dans tous les cas, le
        # comportement attendu (déjà celui adopté ailleurs dans ce
        # fichier pour le flux RFB lui-même) est de signaler l'EOF au
        # lecteur applicatif plutôt que de laisser une exception sortir
        # sans jamais être récupérée d'une tâche de fond que personne
        # n'attend directement (ce qui produirait le message asyncio
        # "Task exception was never retrieved" sur la sortie standard,
        # sans conséquence fonctionnelle mais trompeur pour l'appelant).
        ws_reader.feed_eof()
    logger.debug('_ws_pump() terminée')


async def _ws_handshake(
    reader: StreamReader, writer: StreamWriter, host: str, port: int, path: str
) -> None:
    """
    Poignée de main HTTP d'upgrade vers WebSocket (RFC 6455 §4.1/§4.2),
    côté client. Envoie `Sec-WebSocket-Protocol: binary`, le sous-protocole
    que `noVNC`/`websockify` (les deux implémentations de référence pour
    RFB-sur-WebSockets) attendent -- mais n'exige pas que le serveur le
    confirme dans sa réponse : certains proxys RFB-sur-WS plus permissifs
    ne le renvoient pas alors qu'ils fonctionnent très bien par ailleurs,
    et la seule chose qui compte réellement pour la suite est que le
    serveur accepte de faire transiter des octets RFB bruts dans des
    trames binaires, ce qu'un statut 101 garantit déjà en pratique pour
    ces deux implémentations.
    """
    logger.debug('_ws_handshake() appelée | host={} port={} path={}', host, port, path)
    key = b64encode(urandom(16)).decode('ascii')
    request = (
        f'GET {path} HTTP/1.1\r\n'
        f'Host: {host}:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: {key}\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'Sec-WebSocket-Protocol: binary\r\n'
        f'\r\n'
    ).encode('ascii')
    writer.write(request)
    await writer.drain()

    status_line = await reader.readline()
    if b'101' not in status_line:
        _erreur = ValueError(f'WebSocket handshake refusée par le serveur : {status_line!r}')
        logger.debug('_ws_handshake() lève | {!r}', _erreur)
        raise _erreur

    headers = {}
    while True:
        line = await reader.readline()
        if line in (b'\r\n', b'\n', b''):
            break
        name, _, value = line.decode('iso-8859-1').partition(':')
        headers[name.strip().lower()] = value.strip()

    expected_accept = b64encode(sha1(key.encode('ascii') + _WEBSOCKET_GUID).digest()).decode(
        'ascii'
    )
    if headers.get('sec-websocket-accept') != expected_accept:
        _erreur = ValueError(
            'WebSocket handshake invalide : Sec-WebSocket-Accept ne correspond pas '
            "à Sec-WebSocket-Key (RFC 6455 §4.2.2) -- le serveur n'est probablement "
            'pas un serveur WebSocket conforme'
        )
        logger.debug('_ws_handshake() lève | {!r}', _erreur)
        raise _erreur
    logger.debug('_ws_handshake() terminée')


async def _ws_wrap_connection(
    reader: StreamReader, writer: StreamWriter, host: str, port: int, path: str
) -> tuple[StreamReader, StreamWriter]:
    """
    Poignée de main WebSocket puis mise en place du tunnel bidirectionnel
    RFB-sur-WebSockets : à partir d'ici, tout le reste de ce fichier
    (`Client.create()` inclus, sans aucune modification) peut continuer à
    parler RFB brut sur le couple `(reader, writer)` retourné exactement
    comme s'il s'agissait d'une connexion TCP ordinaire -- c'est tout
    l'intérêt de ce point d'insertion : contrairement à VeNCrypt (qui
    s'immisce *au milieu* de la poignée de main RFB, côté sécurité),
    WebSockets se négocie entièrement *avant* que le premier octet RFB
    (`ProtocolVersion`) ne soit échangé, donc aucune des fonctions
    `_vencrypt_negotiate()` etc. n'a besoin d'avoir connaissance de ceci.
    """
    logger.debug('_ws_wrap_connection() appelée | host={} port={} path={}', host, port, path)
    await _ws_handshake(reader, writer, host, port, path)

    ws_reader = StreamReader()
    loop = get_running_loop()
    pump_task = loop.create_task(_ws_pump(reader, writer, ws_reader))
    # Le rattacher au StreamReader lui-même (plutôt que de le laisser
    # simplement s'exécuter en arrière-plan sans référence) pour qu'il ne
    # puisse pas être ramassé par le garbage collector en cours de route
    # (piège classique documenté par asyncio lui-même pour
    # `loop.create_task()`) et pour qu'un futur appelant qui voudrait
    # l'annuler explicitement à la fermeture puisse le faire.
    ws_reader._ws_pump_task = pump_task  # type: ignore[attr-defined]

    ws_writer = _WebSocketWriter(writer, pump_task=pump_task)
    logger.debug('_ws_wrap_connection() retourne | (ws_reader, ws_writer)')
    return ws_reader, ws_writer


async def _ws_handshake_server(reader: StreamReader, writer: StreamWriter) -> None:
    """
    Pendant côté serveur de `_ws_handshake()` -- utilisé par
    `listen(websocket=True)` pour accepter une connexion WebSocket
    entrante au lieu d'en initier une (RFC 6455 §4.1/§4.2, côté serveur
    cette fois) : lit la requête HTTP d'upgrade envoyée par le pair
    (typiquement un proxy tiers configuré pour relayer une reconnexion
    inversée -- `websocat` en pratique, PAS `websockify`, voir le
    commentaire dans `listen()` -- ou directement un vrai client
    WebSocket), vérifie qu'il s'agit bien d'une demande d'upgrade WebSocket
    conforme, puis répond `101 Switching Protocols` avec le
    `Sec-WebSocket-Accept` calculé à partir de la `Sec-WebSocket-Key`
    reçue.

    Volontairement tolérant sur deux points où la RFC laisse une marge
    d'interprétation aux implémentations réelles plutôt que d'imposer un
    format strict : la méthode HTTP n'est vérifiée que pour être `GET`
    (la version HTTP exacte du client n'est pas vérifiée, `HTTP/1.0`
    comme `HTTP/1.1` sont acceptés) et l'en-tête `Sec-WebSocket-Protocol`
    n'est renvoyé dans la réponse que si le client l'a lui-même proposé,
    jamais imposé unilatéralement -- même philosophie de tolérance que
    `_ws_handshake()` (client) vis-à-vis de ce même en-tête.
    """
    logger.debug('_ws_handshake_server() appelée')
    request_line = await reader.readline()
    if not request_line.upper().startswith(b'GET '):
        _erreur = ValueError(
            f'requête HTTP invalide pour une poignée de main WebSocket : {request_line!r}'
        )
        logger.debug('_ws_handshake_server() lève | {!r}', _erreur)
        raise _erreur

    headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if line in (b'\r\n', b'\n', b''):
            break
        name, _, value = line.decode('iso-8859-1').partition(':')
        headers[name.strip().lower()] = value.strip()

    if headers.get('upgrade', '').lower() != 'websocket':
        _erreur = ValueError(
            f"en-tête 'Upgrade: websocket' manquant ou incorrect : {headers.get('upgrade')!r}"
        )
        logger.debug('_ws_handshake_server() lève | {!r}', _erreur)
        raise _erreur
    key = headers.get('sec-websocket-key')
    if not key:
        _erreur = ValueError("en-tête 'Sec-WebSocket-Key' manquant dans la requête d'upgrade")
        logger.debug('_ws_handshake_server() lève | {!r}', _erreur)
        raise _erreur

    accept = b64encode(sha1(key.encode('ascii') + _WEBSOCKET_GUID).digest()).decode('ascii')
    response_lines = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        f'Sec-WebSocket-Accept: {accept}',
    ]
    # Le sous-protocole n'est confirmé que si le client (le proxy WS en
    # face, généralement) l'a lui-même demandé -- voir docstring.
    requested_protocols = [
        p.strip() for p in headers.get('sec-websocket-protocol', '').split(',') if p.strip()
    ]
    if 'binary' in requested_protocols:
        response_lines.append('Sec-WebSocket-Protocol: binary')
    response = ('\r\n'.join(response_lines) + '\r\n\r\n').encode('ascii')
    writer.write(response)
    await writer.drain()
    logger.debug('_ws_handshake_server() terminée')


async def _ws_wrap_connection_server(
    reader: StreamReader, writer: StreamWriter
) -> tuple[StreamReader, StreamWriter]:
    """
    Pendant côté serveur de `_ws_wrap_connection()`, pour `listen()`
    (reconnexion inversée) au lieu de `connect()` : accepte la poignée
    de main WebSocket entrante puis met en place le même tunnel
    bidirectionnel que côté client, à la seule différence que les trames
    sortantes ne sont pas masquées (RFC 6455 §5.3, réservé au sens
    client-vers-serveur -- voir `_WebSocketWriter`). `_ws_pump()` lui-même
    n'a besoin d'aucune adaptation : il démasque déjà les trames entrantes
    quand leur bit de masque est positionné, quel que soit le sens
    d'établissement de la connexion.
    """
    logger.debug('_ws_wrap_connection_server() appelée')
    await _ws_handshake_server(reader, writer)

    ws_reader = StreamReader()
    loop = get_running_loop()
    pump_task = loop.create_task(_ws_pump(reader, writer, ws_reader))
    ws_reader._ws_pump_task = pump_task  # type: ignore[attr-defined]

    ws_writer = _WebSocketWriter(writer, pump_task=pump_task, mask=False)
    logger.debug('_ws_wrap_connection_server() retourne | (ws_reader, ws_writer)')
    return ws_reader, ws_writer


@asynccontextmanager
async def connect(
    host: str,
    port: int = 5900,
    username: str | None = None,
    password: str | None = None,
    host_key: rsa.RSAPublicKey | None = None,
    encodings: list | None = None,
    jpeg_quality: int | None = None,
    compression_level: int | None = None,
    allow_indexed_colour: bool = False,
    shared: bool = True,
    opener=None,
    ssl_context: ssl.SSLContext | None = None,
    websocket: bool = False,
    ws_path: str = '/',
):
    """
    Make a VNC client connection. This is an async context manager that returns a connected :class:`Client` instance.

    *ssl_context*/VeNCrypt : si le serveur exige le type de sécurité 19
    (VeNCrypt) et propose le sous-type X509None ou X509Vnc (authentifié par
    certificat, ajouté le 2026-09-05 -- voir `Client.create()`/
    `_vencrypt_negotiate()`), *host* ci-dessus est automatiquement transmis
    comme nom d'hôte à vérifier contre le certificat présenté par le
    serveur -- aucun paramètre supplémentaire à passer pour ça. Voir
    `_vencrypt_negotiate()` pour la CA utilisée par défaut (magasin système)
    et comment fournir une CA privée via *ssl_context*.
    """

    logger.debug(
        'connect() appelée | host={} port={} identifiant={} mot_de_passe={} cle_hote={} encodings={} jpeg_quality={} compression_level={} allow_indexed_colour={} shared={} tls={} websocket={} ws_path={}',
        host,
        port,
        bool(username),
        bool(password),
        bool(host_key),
        encodings,
        jpeg_quality,
        compression_level,
        allow_indexed_colour,
        shared,
        ssl_context is not None,
        websocket,
        ws_path,
    )
    opener = opener or open_connection
    reader, writer = await opener(host, port)
    if websocket:
        # Négociée entièrement avant tout octet RFB -- voir
        # _ws_wrap_connection() pour le détail ; `reader`/`writer` sont
        # remplacés ici par leurs équivalents "démasqués" du tunnel
        # WebSocket, transparents pour Client.create() ci-dessous.
        reader, writer = await _ws_wrap_connection(reader, writer, host, port, ws_path)

    client = await Client.create(
        reader,
        writer,
        username,
        password,
        host_key,
        encodings,
        jpeg_quality,
        compression_level,
        allow_indexed_colour,
        shared,
        ssl_context,
        server_hostname=host,
    )
    try:
        yield client
    finally:
        writer.close()
        await writer.wait_closed()
    logger.debug('connect() terminée')


@asynccontextmanager
async def listen(
    host: str = '0.0.0.0',
    port: int = 5500,
    username: str | None = None,
    password: str | None = None,
    host_key: rsa.RSAPublicKey | None = None,
    encodings: list | None = None,
    jpeg_quality: int | None = None,
    compression_level: int | None = None,
    allow_indexed_colour: bool = False,
    shared: bool = True,
    ssl_context: ssl.SSLContext | None = None,
    websocket: bool = False,
):
    """
    Mode "reconnexion inversée" (reverse connection). Au lieu que ce
    client compose vers le serveur VNC (comme le fait `connect()`), on
    ouvre une socket d'écoute et on attend que ce soit le serveur qui
    vienne se connecter à nous -- cas d'usage classique quand la machine
    à administrer est derrière un NAT/pare-feu qu'elle seule peut
    traverser (ex. Xvnc + `vncconfig -connect`, WinVNC "Add new client",
    UltraVNC `-connect`). Port conventionnel pour l'écoute inversée :
    5500 (par opposition à 5900 pour le mode normal) -- confirmé par la
    documentation RealVNC/TigerVNC/TightVNC/UltraVNC, qui l'utilisent
    tous comme valeur par défaut de leur option `-listen`.

    Une fois la connexion TCP acceptée, le déroulé du protocole RFB lui-
    même est STRICTEMENT IDENTIQUE au mode normal (ProtocolVersion,
    Security, ClientInit/ServerInit, etc.) -- seul le sens
    d'établissement de la connexion TCP change, le rôle RFB de chaque
    extrémité (le serveur RFB envoie toujours le premier message, le
    client RFB répond toujours en premier lieu par ClientInit) restant
    identique. Cette fonction ne fait donc que brancher un listener
    devant `Client.create()`, déjà vérifié par ailleurs : aucun nouveau
    format de message à risque ici.

    Ferme la socket d'écoute dès qu'une connexion est acceptée (mode "un
    seul essai", le plus courant) : si le serveur distant se déconnecte,
    il faut rappeler `listen()` pour une nouvelle tentative. Une
    éventuelle deuxième connexion entrante avant la fermeture de la
    socket d'écoute est immédiatement refermée sans négociation.

    Vérifié par exécution réelle dans ce sandbox : un socket TCP
    localhost bouclé sur lui-même, avec un script jouant le rôle du
    serveur VNC distant (ProtocolVersion, Security de type None,
    SecurityResult, ServerInit fabriqués à la main), confirme que
    `listen()` accepte la connexion entrante et que le `Client` retourné
    est bien utilisable (dimensions, nom de bureau lus correctement).

    *websocket* (2026-09-04, topologie "reverse" complète confirmée le
    2026-09-10) : si `True`, la connexion TCP entrante est d'abord
    traitée comme une poignée de main WebSocket côté serveur (RFC 6455)
    avant que le protocole RFB ne démarre -- utile quand la reconnexion
    inversée doit transiter par un proxy WebSocket plutôt qu'arriver en
    TCP brut. Voir `CLAUDE.md` pour le détail des deux vérifications :
    **2026-09-04**, contre un vrai client WebSocket tiers (bibliothèque
    Python `websockets`) parlant directement à `listen()`, puis
    **2026-09-10**, contre un vrai proxy tiers (`websocat`) relayant
    effectivement une connexion TCP entrante vers une connexion
    WebSocket sortante -- la topologie "reverse" complète, qui restait
    jusque-là non couverte. **`websockify` ne convient PAS pour ce rôle
    de proxy** malgré son nom (voir le commentaire dans le corps de
    cette fonction, plus bas, pour le détail vérifié de pourquoi).

    *ssl_context*/VeNCrypt X509None/X509Vnc (2026-09-05) : contrairement à
    `connect()`, ce mode n'a pas de nom d'hôte "cible" à vérifier -- c'est
    tout le sens de la reconnexion inversée que l'appelant écoute sans
    savoir à l'avance qui va se connecter. `Client.create()` est donc
    appelé ici avec `server_hostname=None`. Vérifié par exécution réelle
    dans ce sandbox (voir CLAUDE.md) : avec `server_hostname=None`, asyncio
    (`loop.start_tls()`/`SSLContext.wrap_bio()`) NE lève PAS d'erreur même
    si *ssl_context* a `check_hostname=True` (le défaut de
    `ssl.create_default_context()`, utilisé si *ssl_context* n'est pas
    fourni) -- il ignore silencieusement la vérification du nom d'hôte,
    faute d'hôte à vérifier, sans désactiver pour autant la vérification de
    la CHAINE de certification contre le magasin de CA de confiance
    (celle-ci continue de s'appliquer normalement). Concrètement : un
    serveur distant qui présente un certificat signé par une CA que
    l'appelant reconnaît est accepté ; un serveur qui présente un
    certificat signé par une CA différente est rejeté avec une vraie
    `ssl.SSLCertVerificationError`, exactement comme pour `connect()` --
    seule la correspondance nom-d'hôte/certificat n'est pas vérifiée ici
    (elle n'aurait de toute façon aucun sens en reconnexion inversée). Pour
    une CA privée, fournir son propre *ssl_context* avec
    `load_verify_locations()`, exactement comme pour `connect()` -- aucun
    besoin de désactiver `check_hostname` soi-même, contrairement à ce
    qu'une lecture rapide de la documentation `ssl` standard (pensée pour
    l'API synchrone `SSLContext.wrap_socket()`, qui elle lève bien
    `ValueError("check_hostname requires server_hostname")` dans cette
    situation -- un chemin de code différent de celui utilisé ici) pourrait
    laisser croire.
    """
    logger.debug(
        'listen() appelée | host={} port={} identifiant={} mot_de_passe={} cle_hote={} encodings={} jpeg_quality={} compression_level={} allow_indexed_colour={} shared={} tls={} websocket={}',
        host,
        port,
        bool(username),
        bool(password),
        bool(host_key),
        encodings,
        jpeg_quality,
        compression_level,
        allow_indexed_colour,
        shared,
        ssl_context is not None,
        websocket,
    )
    incoming: Queue = Queue(maxsize=1)

    async def _accept(reader: StreamReader, writer: StreamWriter):
        logger.debug('listen._accept() appelée')
        try:
            incoming.put_nowait((reader, writer))
        except QueueFull:
            # Une connexion inattendue en plus de la première -- ce mode
            # ne gère qu'une seule reconnexion inversée à la fois.
            logger.warning(
                'listen() connexion supplémentaire refusée (une seule reconnexion inversée à la fois) | pair={}',
                writer.get_extra_info('peername'),
            )
            writer.close()
        logger.debug('listen._accept() terminée')

    server = await start_server(_accept, host, port)
    try:
        reader, writer = await incoming.get()
    finally:
        # On ferme la socket d'écoute (on n'accepte plus de nouvelles
        # connexions) mais SANS attendre server.wait_closed() : sur les
        # versions récentes d'asyncio, wait_closed() attend aussi la
        # fermeture des connexions déjà acceptées -- exactement celle
        # qu'on vient d'extraire de la queue et qu'on s'apprête à garder
        # ouverte pour toute la session RFB. L'attendre ici bloquerait
        # indéfiniment (vérifié dans ce sandbox : deadlock reproductible
        # sous Python 3.12 tant que la connexion RFB reste active).
        server.close()

    if websocket:
        # Rôle serveur WebSocket -- voir _ws_wrap_connection_server()
        # pour le détail. Utile quand la reconnexion inversée doit
        # transiter par un proxy qui relaie une connexion TCP entrante
        # vers une connexion WebSocket sortante, plutôt que la connexion
        # TCP brute que ce mode attend par défaut.
        #
        # ATTENTION, vérifié réellement le 2026-09-10 : `websockify` (le
        # proxy de référence utilisé ailleurs dans ce fichier pour le
        # rôle CLIENT, voir `connect()`) NE PEUT PAS jouer ce rôle-ci.
        # `websockify --help` ne propose que des adresses d'ÉCOUTE en
        # WS/HTTP (`source_port`, `--unix-listen`) et des CIBLES en TCP,
        # socket Unix (`--unix-target`) ou sous-processus
        # (`-- WRAP_COMMAND_LINE`) -- jamais l'inverse (pas de mode
        # "écoute TCP, cible WS"). Un exemple d'invocation
        # (`websockify LISTEN_HOST:LISTEN_PORT --wait`) figurait ici par
        # erreur : `--wait` n'est même pas une option reconnue, et sans
        # elle, une adresse seule échoue avec "Too few arguments" --
        # confirmé par exécution réelle des deux cas dans ce sandbox.
        # Outil qui convient réellement pour ce rôle, vérifié de bout en
        # bout le 2026-09-10 (voir `CLAUDE.md`) : `websocat`
        # (<https://github.com/vi/websocat>, indépendant de ce fork et
        # de `websockify`), par ex.
        # `websocat --binary tcp-listen:BRIDGE_HOST:BRIDGE_PORT ws://LISTEN_HOST:LISTEN_PORT/`.
        reader, writer = await _ws_wrap_connection_server(reader, writer)

    client = await Client.create(
        reader,
        writer,
        username,
        password,
        host_key,
        encodings,
        jpeg_quality,
        compression_level,
        allow_indexed_colour,
        shared,
        ssl_context,
    )
    try:
        yield client
    finally:
        writer.close()
        await writer.wait_closed()
    logger.debug('listen() terminée')
