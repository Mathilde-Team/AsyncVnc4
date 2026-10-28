# SPDX-License-Identifier: GPL-3.0-or-later
"""SASL contre un vrai serveur : le VNC intégré de QEMU (issue #32).

QEMU (ui/vnc-auth-sasl.c) ne propose PLAIN que dans le sous-type VeNCrypt
X509SASL (TLS avec certificat, 263). En SASL seul (type 20) ou en TLSSASL
(TLS anonyme, 264), il exige un mécanisme qui chiffre lui-même (min_ssf=56,
NOPLAINTEXT, NOANONYMOUS) : PLAIN disparaît de la liste. Les tests couvrent
les deux côtés : le chemin qui marche et les refus explicites.

Requiert `qemu-system-x86_64`, `saslpasswd2` (sasl2-bin), le module Cyrus
PLAIN et sasldb (libsasl2-modules). Sans eux, la suite est
sautée, sauf si `ASYNCVNC_LIVE=1`.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest

import asyncvnc2

OUTILS = all(shutil.which(o) for o in ('qemu-system-x86_64', 'saslpasswd2'))
EXIGE = os.environ.get('ASYNCVNC_LIVE') == '1'
UTILISATEUR, MOT_DE_PASSE = 'alice', 'secret12'

# Groupe ffdhe2048 de la RFC 7919 (paramètres publics, figés ici : `openssl
# genpkey -pkeyopt group:ffdhe2048` n'existe pas sur l'OpenSSL des runners).
FFDHE2048_PEM = """\
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
"""


def _port_libre() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _ecrire_pki(dossier: str) -> None:
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    maintenant = datetime.datetime.now(datetime.timezone.utc)
    debut, fin = maintenant - datetime.timedelta(hours=1), maintenant + datetime.timedelta(days=2)

    def nom(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def usage(signature: bool, chiffrement: bool, signe_certs: bool) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=signature,
            content_commitment=False,
            key_encipherment=chiffrement,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=signe_certs,
            crl_sign=signe_certs,
            encipher_only=False,
            decipher_only=False,
        )

    cle_ca = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = (
        x509.CertificateBuilder()
        .subject_name(nom('Test CA'))
        .issuer_name(nom('Test CA'))
        .public_key(cle_ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut)
        .not_valid_after(fin)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(usage(False, False, True), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(cle_ca.public_key()), critical=False
        )
        .sign(cle_ca, hashes.SHA256())
    )
    cle = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    serveur = (
        x509.CertificateBuilder()
        .subject_name(nom('127.0.0.1'))
        .issuer_name(ca.subject)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut)
        .not_valid_after(fin)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(usage(True, True, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(cle_ca.public_key()), critical=False
        )
        .sign(cle_ca, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    with open(os.path.join(dossier, 'ca-cert.pem'), 'wb') as f:
        f.write(ca.public_bytes(pem))
    with open(os.path.join(dossier, 'server-cert.pem'), 'wb') as f:
        f.write(serveur.public_bytes(pem))
    with open(os.path.join(dossier, 'server-key.pem'), 'wb') as f:
        f.write(
            cle.private_bytes(
                pem, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
            )
        )


@unittest.skipUnless(OUTILS or EXIGE, 'QEMU/sasl2-bin absents (ASYNCVNC_LIVE=1 pour exiger)')
class TestQemuSasl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not OUTILS:
            raise AssertionError(
                'ASYNCVNC_LIVE=1 mais qemu-system-x86_64 ou saslpasswd2 est absent'
            )
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.tmp.name
        cls.sasldb = os.path.join(d, 'passwd.db')
        subprocess.run(
            ['saslpasswd2', '-p', '-a', 'qemu', '-f', cls.sasldb, '-c', UTILISATEUR],
            input=MOT_DE_PASSE.encode(),
            check=True,
            capture_output=True,
        )
        # PKI : générée avec `cryptography` (dépendance du projet) plutôt
        # qu'avec openssl : la CA produite par OpenSSL 1.1.1f (runners focal)
        # est refusée par la GnuTLS de QEMU 4.2 (« Unable to import CA
        # certificate list »). keyUsage sur la CA : exigé par Python >= 3.13.
        cls.pki = os.path.join(d, 'pki')
        os.mkdir(cls.pki)
        _ecrire_pki(cls.pki)
        # TLS anonyme : sans dh-params.pem, GnuTLS 3.8 refuse la poignée de
        # main (« Insufficient credentials »).
        cls.anon = os.path.join(d, 'anon')
        os.mkdir(cls.anon)
        with open(f'{cls.anon}/dh-params.pem', 'w', encoding='ascii') as f:
            f.write(FFDHE2048_PEM)
        cls.qemus: list[subprocess.Popen] = []

    @classmethod
    def tearDownClass(cls):
        for q in cls.qemus:
            q.terminate()
            try:
                q.wait(5)
            except subprocess.TimeoutExpired:
                q.kill()
        cls.tmp.cleanup()

    def _qemu(self, mechs: str, tls: str | None) -> int:
        conf = tempfile.mkdtemp(dir=self.tmp.name)
        with open(os.path.join(conf, 'qemu.conf'), 'w', encoding='ascii') as f:
            f.write(f'mech_list: {mechs}\nsasldb_path: {self.sasldb}\n')
        port = _port_libre()
        vnc = f'127.0.0.1:{port - 5900},sasl=on'
        args = []
        if tls == 'x509':
            args = [
                '-object',
                f'tls-creds-x509,id=tls0,dir={self.pki},endpoint=server,verify-peer=off',
            ]
            vnc += ',tls-creds=tls0'
        elif tls == 'anon':
            args = ['-object', f'tls-creds-anon,id=tls0,dir={self.anon},endpoint=server']
            vnc += ',tls-creds=tls0'
        journal = open(os.path.join(conf, 'qemu.log'), 'wb')  # noqa: SIM115
        q = subprocess.Popen(
            ['qemu-system-x86_64', '-display', 'none', '-nodefaults', '-vga', 'std', '-m', '32',
             *args, '-vnc', vnc],
            env={**os.environ, 'SASL_CONF_PATH': conf},
            stdin=subprocess.DEVNULL,
            stdout=journal,
            stderr=subprocess.STDOUT,
        )  # fmt: skip
        journal.close()
        self.qemus.append(q)
        fin = time.monotonic() + 15
        while time.monotonic() < fin and q.poll() is None:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                    return port
            except OSError:
                time.sleep(0.2)
        with open(os.path.join(conf, 'qemu.log'), encoding='utf-8', errors='replace') as f:
            raise TimeoutError(f'QEMU ne répond pas (code {q.poll()}) : {f.read()[-2000:]}')

    def _connect(self, port: int, user: str, pw: str, ca: bool = True):
        ctx = ssl.create_default_context(cafile=f'{self.pki}/ca-cert.pem') if ca else None

        async def scenario():
            async with asyncvnc2.connect(
                '127.0.0.1', port, username=user, password=pw, ssl_context=ctx
            ) as client:
                image = await asyncio.wait_for(client.screenshot(), 20)
                return client.protocol_version, image.shape

        return asyncio.run(asyncio.wait_for(scenario(), 30))

    def test_x509sasl_plain(self):
        port = self._qemu('plain', 'x509')
        version, forme = self._connect(port, UTILISATEUR, MOT_DE_PASSE)
        self.assertEqual(version, (3, 8))
        self.assertEqual(forme[2], 4)
        self.assertGreater(forme[0] * forme[1], 0)

    def test_x509sasl_mauvais_mot_de_passe(self):
        port = self._qemu('plain', 'x509')
        with self.assertRaises(PermissionError):
            self._connect(port, UTILISATEUR, 'mauvais1')

    def test_x509sasl_utilisateur_inconnu(self):
        port = self._qemu('plain', 'x509')
        with self.assertRaises(PermissionError):
            self._connect(port, 'bob', MOT_DE_PASSE)

    def test_x509sasl_certificat_non_reconnu(self):
        port = self._qemu('plain', 'x509')
        with self.assertRaises(ssl.SSLCertVerificationError):
            self._connect(port, UTILISATEUR, MOT_DE_PASSE, ca=False)

    def test_sasl_sans_tls_plain_retire(self):
        port = self._qemu('plain', None)
        # QEMU >= 10 ferme la connexion ; QEMU 4.2 envoie une liste vide.
        with self.assertRaises((ConnectionError, ValueError)) as ctx:
            self._connect(port, UTILISATEUR, MOT_DE_PASSE, ca=False)
        self.assertIn('X509SASL', str(ctx.exception))

    def test_sasl_sans_tls_seulement_digest_md5(self):
        port = self._qemu('digest-md5 plain', None)
        with self.assertRaises(ValueError) as ctx:
            self._connect(port, UTILISATEUR, MOT_DE_PASSE, ca=False)
        self.assertIn('DIGEST-MD5', str(ctx.exception))

    def test_tlssasl_anonyme_plain_retire(self):
        port = self._qemu('plain', 'anon')
        with self.assertRaises((ConnectionError, ValueError)):
            self._connect(port, UTILISATEUR, MOT_DE_PASSE, ca=False)


if __name__ == '__main__':
    unittest.main()
