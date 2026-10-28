# SPDX-License-Identifier: GPL-3.0-or-later
"""Règles loguru vérifiées par AST (SOCLE §8, modèle : Gcm4
``tests/test_loguru_regles.py``).

Périmètre : fichiers Python suivis par git, hors tests (``test_*.py``). Aucun module
n'est importé (analyse AST uniquement, sauf l'audit chargé par chemin).

1. Chaque ``except`` contient un appel de journal. Les manques existants
   sont listés par fichier dans ``EXCEPT_SANS_JOURNAL`` : le compte doit
   être **exact**, donc il ne peut que diminuer (le mettre à jour quand on
   corrige un ``except``, jamais pour en ajouter).
2. Tout module qui définit des fonctions a un logger de module (liste
   ``MODULES_SANS_LOGGER``, qui ne peut que diminuer) ; ``import logging``
   est interdit **hors** ``custom_components/`` (intégration Home
   Assistant : ``_LOGGER`` avec ``logging``, SOCLE §8).
3. Formats cohérents avec le nombre d'arguments, **par style** :
   ``custom_components/`` (logging) attend ``%s`` avec arguments, jamais de
   f-string ; partout ailleurs (loguru) ``{}`` et jamais ``%s``.
4. Aucune variable nommée comme un secret (``pwd``, ``password``,
   ``passwd``, ``passphrase``, ``key``, ``token``, ``secret``...) interpolée
   telle quelle dans un message : ``bool(password)`` ou ``len(pwd)`` sont
   acceptés, ``{password}`` non.
5. ``scripts/audit_debug_sorties.py`` (consigne « debug en entrée et à
   chaque sortie ») : total inférieur ou égal à
   ``scripts/audit_debug_sorties.baseline``.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import re
import string
import subprocess
import sys
import unittest
import warnings
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Tests : fichiers ``test_*.py`` à la racine (disposition à plat du dépôt).
TEST_PREFIX = 'test_'
LOGGER_NAMES = {
    'logger',
    'app_logger',
    '_logger',
    '_LOGGER',
    'LOGGER',
    'log',
    '_log',
    '_loguru_logger',
}
LOG_METHODS = {'trace', 'debug', 'info', 'success', 'warning', 'error', 'exception', 'critical'}
SECRET_NAMES = re.compile(
    r'(pwd|passwd|password|passphrase|key|token|secret|api_?key|private_key|credentials?)',
    re.IGNORECASE,
)

# Fichier -> nombre d'``except`` sans appel de journal (état de l'issue #55).
EXCEPT_SANS_JOURNAL: dict[str, int] = {}

# Modules qui définissent des fonctions sans logger de module.
MODULES_SANS_LOGGER: set[str] = set()


def python_files() -> list[str]:
    """Fichiers du périmètre (suivis par git, hors tests)."""
    out = subprocess.run(
        ['git', 'ls-files', '*.py'], cwd=ROOT, capture_output=True, text=True, check=True
    )
    return [f for f in out.stdout.split() if not Path(f).name.startswith(TEST_PREFIX)]


def parse(path: str) -> ast.Module:
    """AST d'un fichier, sans les SyntaxWarning des docstrings existantes."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', SyntaxWarning)
        return ast.parse((ROOT / path).read_text(encoding='utf-8'))


def is_log_call(node: ast.AST) -> bool:
    """``logger.info(...)``, ``self.logger.debug(...)``, ``app_logger.exception(...)``..."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr not in LOG_METHODS | {'log'}:
        return False
    target = node.func.value
    return (isinstance(target, ast.Name) and target.id in LOGGER_NAMES) or (
        isinstance(target, ast.Attribute) and target.attr in LOGGER_NAMES
    )


def except_sans_journal(tree: ast.Module) -> int:
    """Nombre d'``except`` qui ne contiennent aucun appel de journal."""
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler) and not any(is_log_call(n) for n in ast.walk(node))
    )


def a_un_logger_de_module(tree: ast.Module) -> bool:
    """Logger défini au niveau module (y compris dans un try/if de premier niveau)."""
    statements = list(tree.body)
    for node in tree.body:
        if isinstance(node, (ast.Try, ast.If)):
            statements += (
                node.body + node.orelse + [s for h in getattr(node, 'handlers', []) for s in h.body]
            )
    for node in statements:
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == 'loguru'
            and any((a.asname or a.name) in LOGGER_NAMES for a in node.names)
        ):
            return True
        # Intégration Home Assistant : LOGGER/_LOGGER importé du module const du paquet.
        if (
            isinstance(node, ast.ImportFrom)
            and (node.level > 0 or (node.module or '').startswith('custom_components'))
            and any((a.asname or a.name) in LOGGER_NAMES for a in node.names)
        ):
            return True
        if isinstance(node, ast.Assign) and any(
            getattr(t, 'id', None) in LOGGER_NAMES for t in node.targets
        ):
            return True
    return False


def placeholders(fmt: str) -> int | None:
    """Nombre de champs ``{}`` d'un format, None s'il est invalide."""
    try:
        return sum(1 for _, field, _, _ in string.Formatter().parse(fmt) if field is not None)
    except ValueError:
        return None


def erreurs_de_format(tree: ast.Module, style: str = 'loguru') -> list[str]:
    """Appels de journal dont le format ne correspond pas au style attendu.

    ``loguru`` : placeholders ``{}`` cohérents avec les arguments, jamais
    ``%s`` (loguru ne l'interprète pas).
    ``logging`` (custom_components/, Home Assistant) : ``%s`` paresseux
    avec arguments, jamais de f-string ni de ``{}``.
    """
    fautes = []
    for node in ast.walk(tree):
        if not is_log_call(node) or not node.args:
            continue
        first = node.args[0]
        if node.func.attr == 'log':  # logger.log(niveau, message, ...)
            if len(node.args) < 2:
                continue
            first, extra = node.args[1], len(node.args) - 2
        else:
            extra = len(node.args) - 1
        if isinstance(first, ast.JoinedStr):  # f-string en message
            if style == 'logging':
                fautes.append(f'{node.lineno}: f-string en message (attendu %s paresseux)')
            continue
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue
        if style == 'logging':
            if re.search(r'%[sdrifx]', first.value):
                if not extra:
                    fautes.append(f'{node.lineno}: %s sans argument paresseux')
                elif len(re.findall(r'%[sdrifx]', first.value)) != extra:
                    fautes.append(f'{node.lineno}: %s et arguments en nombre différent')
            elif extra or '{' in first.value:
                fautes.append(f'{node.lineno}: attendu %s paresseux (style logging)')
            continue
        if re.search(r'%[sdrifx]', first.value) and extra:
            fautes.append(f'{node.lineno}: %-format (loguru attend {{}})')
            continue
        if extra or node.keywords:
            count = placeholders(first.value)
            if count is not None and not node.keywords and count != extra:
                fautes.append(f'{node.lineno}: {count} champ(s) {{}} pour {extra} argument(s)')
    return fautes


def _nom(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def secrets_journalises(tree: ast.Module) -> list[str]:
    """Variable de secret passée telle quelle (f-string ou argument) à un appel de journal."""
    fautes = []
    for node in ast.walk(tree):
        if not is_log_call(node):
            continue
        valeurs = [
            v.value for a in node.args for v in ast.walk(a) if isinstance(v, ast.FormattedValue)
        ]
        valeurs += node.args[1:] + [k.value for k in node.keywords]
        for valeur in valeurs:
            nom = _nom(valeur)
            if nom and SECRET_NAMES.fullmatch(nom):
                fautes.append(f'{node.lineno}: {nom}')
    return fautes


def _audit():
    spec = importlib.util.spec_from_file_location(
        'audit_debug_sorties', ROOT / 'scripts' / 'audit_debug_sorties.py'
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules['audit_debug_sorties'] = module
    spec.loader.exec_module(module)
    return module


class TestReglesLoguru(unittest.TestCase):
    """Règles bloquantes du job Qualité."""

    @classmethod
    def setUpClass(cls):
        """Analyse chaque fichier une seule fois."""
        cls.trees = {f: parse(f) for f in python_files()}

    def test_except_sans_journal_ne_peut_que_diminuer(self):
        """Compte exact par fichier : un nouvel except muet fait échouer."""
        actuel = {f: n for f, t in self.trees.items() if (n := except_sans_journal(t))}
        self.assertEqual(
            actuel,
            EXCEPT_SANS_JOURNAL,
            'chaque except doit journaliser (logger.exception / logger.warning) ; '
            'si vous en avez corrigé, baissez EXCEPT_SANS_JOURNAL',
        )

    def test_logger_de_module(self):
        """Tout module qui définit des fonctions a un logger loguru."""
        actuel = {
            f
            for f, t in self.trees.items()
            if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(t))
            and not a_un_logger_de_module(t)
        }
        self.assertEqual(actuel, MODULES_SANS_LOGGER, 'ajouter `from loguru import logger`')

    def test_aucun_import_logging_hors_home_assistant(self):
        """Pas de module logging standard hors custom_components/ (SOCLE §8)."""
        fautes = [
            f'{f}:{n.lineno}'
            for f, t in self.trees.items()
            if not f.startswith('custom_components/')
            for n in ast.walk(t)
            if (
                isinstance(n, ast.Import)
                and any(a.name.split('.')[0] == 'logging' for a in n.names)
            )
            or (
                isinstance(n, ast.ImportFrom)
                and n.level == 0
                and (n.module or '').split('.')[0] == 'logging'
            )
        ]
        self.assertEqual(fautes, [])

    def test_placeholders(self):
        """%s paresseux dans custom_components/, {} ailleurs ; jamais de f-string côté logging."""
        fautes = {}
        for f, t in self.trees.items():
            style = 'logging' if f.startswith('custom_components/') else 'loguru'
            if e := erreurs_de_format(t, style):
                fautes[f] = e
        self.assertEqual(fautes, {})

    def test_aucun_secret_interpole(self):
        """Ni {password} ni logger.debug("...", token) ; bool()/len() acceptés."""
        fautes = {f: e for f, t in self.trees.items() if (e := secrets_journalises(t))}
        self.assertEqual(
            fautes, {}, 'journaliser bool(x), len(x) ou une forme masquée, jamais x tel quel'
        )

    def test_audit_debug_sorties_ne_doit_pas_augmenter(self):
        """Compteur de la consigne « debug en entrée et à chaque sortie »."""
        audit = _audit()
        total = sum(len(v) for v in audit.audit_repository().values())
        reference = audit.read_baseline()
        self.assertLessEqual(
            total,
            reference,
            'nouvelles fonctions sans debug() en entrée/sortie : scripts/audit_debug_sorties.py --details',
        )


class TestDetecteurs(unittest.TestCase):
    """Les détecteurs eux-mêmes."""

    def test_except(self):
        """Un except muet compte, un except journalisé non."""
        tree = ast.parse("try:\n    x()\nexcept A:\n    pass\nexcept B:\n    logger.warning('b')\n")
        self.assertEqual(except_sans_journal(tree), 1)

    def test_format(self):
        """Loguru : champ manquant et %s détectés ; f-string et format correct acceptés."""
        source = 'logger.info("a {} b {}", x)\nlogger.info("a %s", x)\nlogger.info("ok {}", x)\nlogger.info(f"{x}")\n'
        self.assertEqual(
            [e.split(':')[0] for e in erreurs_de_format(ast.parse(source))], ['1', '2']
        )

    def test_format_logging(self):
        """Logging : %s paresseux accepté, f-string et {} refusés."""
        source = '_LOGGER.info("a %s", x)\n_LOGGER.info(f"{x}")\n_LOGGER.info("b {}", x)\n_LOGGER.info("c %s %s", x)\n'
        self.assertEqual(
            [e.split(':')[0] for e in erreurs_de_format(ast.parse(source), 'logging')],
            ['2', '3', '4'],
        )

    def test_secrets(self):
        """Secret interpolé ou passé en argument détecté ; bool() et sous-clé acceptés."""
        tree = ast.parse(
            'logger.debug(f"p={password}")\nlogger.debug(f"p={bool(password)}")\n'
            'logger.debug("t={}", self.token)\nlogger.debug(f"n={key[\'name\']}")\n'
        )
        self.assertEqual([e.split(':')[0] for e in secrets_journalises(tree)], ['1', '3'])

    def test_audit(self):
        """Fonction tracée en entrée et à chaque sortie conforme, l'autre non."""
        audit = _audit()
        source = (
            "def ok(x):\n    logger.debug('in')\n    if x:\n        logger.debug('out')\n        return 1\n"
            "    logger.debug('out')\n    return 2\n"
            'def ko(x):\n    if x:\n        return 1\n    return 2\n'
        )
        self.assertEqual(
            [(n, p) for _, n, p in audit.audit_source(source)], [('ko', ['entrée', 'sortie'])]
        )

    def test_audit_sorties_imbriquees(self):
        """return imbriqué non tracé compté ; fin de bloc with/try/match gérée."""
        audit = _audit()
        source = (
            'def ko(x):\n'
            "    logger.debug('in')\n"
            '    if x:\n'
            '        return 1\n'
            "    with open('f') as fh:\n"
            '        return len(fh.read())\n'
        )
        self.assertEqual([p for _, _, p in audit.audit_source(source)], [['sortie']])

    def test_audit_fonction_vide_et_une_ligne(self):
        """Fonction vide et accesseur d'une ligne exemptés."""
        audit = _audit()
        source = 'def vide():\n    pass\ndef accesseur(x):\n    return x\n'
        self.assertEqual(audit.audit_source(source), [])

    def test_audit_rapport_principal(self):
        """Le total est affiché avec la référence, et --details liste les fonctions."""
        audit = _audit()
        source = 'def ko(x):\n    if x:\n        return 1\n    return 2\n'
        found = audit.audit_source(source)
        self.assertEqual(found, [(1, 'ko', ['entrée', 'sortie'])])

    def test_audit_fins_de_blocs_conformes(self):
        """with, try/finally, match et if/else tracés à la fin : conformes."""
        audit = _audit()
        sources = [
            (
                'def ok(x):\n'
                "    logger.debug('in')\n"
                "    with open('f') as fh:\n"
                "        logger.debug('out')\n"
                '        return len(fh.read())\n'
            ),
            "def ok(x):\n    logger.debug('in')\n    try:\n        x()\n    finally:\n        logger.debug('out')\n",
        ]
        # match/case : syntaxe Python 3.10+ (le dépôt reste testé en 3.9, issue #35).
        if sys.version_info >= (3, 10):
            sources.append(
                'def ok(x):\n'
                "    logger.debug('in')\n"
                '    match x:\n'
                '        case 1:\n'
                "            logger.debug('a')\n"
                '            return 1\n'
                '        case _:\n'
                "            logger.debug('b')\n"
                '            return 2\n'
            )
        sources += [
            (
                'def ok(x):\n'
                "    logger.debug('in')\n"
                '    if x:\n'
                "        logger.debug('a')\n"
                '    else:\n'
                "        logger.debug('b')\n"
            ),
        ]
        for source in sources:
            self.assertEqual(audit.audit_source(source), [], source.splitlines()[0])

    def test_audit_fonction_points_de_suspension(self):
        """Corps réduit à ``...`` : exempté, sans docstring mangée."""
        audit = _audit()
        source = 'def points():\n    ...\n'
        self.assertEqual(audit.audit_source(source), [])

    def test_audit_def_imbrique(self):
        """Une def imbriquée n'est pas un bloc à auditer pour la fonction externe."""
        audit = _audit()
        source = (
            'def exterieure(x):\n'
            "    logger.debug('in')\n"
            '    def interieure(y):\n'
            '        return y\n'
            "    logger.debug('out')\n"
        )
        self.assertEqual(audit.audit_source(source), [])

    def test_audit_branche_vide_et_fin_implicite(self):
        """if sans else et fin implicite non tracée : écart de sortie."""
        audit = _audit()
        sources = [
            "def ko(x):\n    logger.debug('in')\n    if x:\n        logger.debug('a')\n",
            "def ko(x):\n    logger.debug('in')\n    y = x\n",
        ]
        for source in sources:
            self.assertEqual([p for _, _, p in audit.audit_source(source)], [['sortie']])

    def test_audit_raise_sans_trace(self):
        """Raise volontaire non précédé d'un appel de journal : écart de sortie."""
        audit = _audit()
        source = "def ko(x):\n    logger.debug('in')\n    y = x\n    raise ValueError('boom')\n"
        self.assertEqual([p for _, _, p in audit.audit_source(source)], [['sortie']])
        source_conforme = (
            'def ok(x):\n'
            "    logger.debug('in')\n"
            '    y = x\n'
            "    logger.debug('sortie: raise')\n"
            "    raise ValueError('boom')\n"
        )
        self.assertEqual(audit.audit_source(source_conforme), [])

    def test_audit_try_except_en_fin(self):
        """try/except muet en fin de fonction : sortie non tracée."""
        audit = _audit()
        source = "def ko(x):\n    logger.debug('in')\n    try:\n        x()\n    except ValueError:\n        pass\n"
        self.assertEqual([p for _, _, p in audit.audit_source(source)], [['sortie']])

    def test_is_log_call_negatifs(self):
        """Appels quelconques et attributs non journal : non détectés."""
        audit = _audit()
        tree = ast.parse('x = 1\nf(1)\nobj.method(1)\nlogger.niveau_inconnu(1)\n')
        appels = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        self.assertEqual([audit.is_log_call(n) for n in appels], [False, False, False])


class TestAuditCLI(unittest.TestCase):
    """Modes du script d'audit (rapport, --details, --total)."""

    def test_main_total(self):
        """--total affiche le total seul."""
        audit = _audit()
        tampon = io.StringIO()
        with redirect_stdout(tampon):
            code = audit.main(['--total'])
        self.assertEqual(code, 0)
        self.assertEqual(tampon.getvalue().strip(), '0')

    def test_main_rapport(self):
        """Sans option : total et référence affichés."""
        audit = _audit()
        tampon = io.StringIO()
        with redirect_stdout(tampon):
            code = audit.main([])
        self.assertEqual(code, 0)
        self.assertIn('référence : 0', tampon.getvalue())

    def test_main_details(self):
        """--details : une ligne par fonction non conforme (aucune ici)."""
        audit = _audit()
        tampon = io.StringIO()
        with redirect_stdout(tampon):
            code = audit.main(['--details'])
        self.assertEqual(code, 0)
        self.assertEqual(tampon.getvalue().strip(), '')

    def test_audit_repository_et_rapports_avec_ecart(self):
        """Un fichier non conforme apparaît dans --details et le rapport."""
        audit = _audit()
        temporaire = ROOT / 'script_temporaire_non_conforme.py'
        temporaire.write_text(
            'def ko(x):\n    if x:\n        return 1\n    return 2\n', encoding='utf-8'
        )
        self.addCleanup(temporaire.unlink)
        audit.python_files = lambda: [temporaire.name]
        self.assertEqual(list(audit.audit_repository()), [temporaire.name])

        tampon = io.StringIO()
        with redirect_stdout(tampon):
            audit.main(['--details'])
        self.assertIn('ko', tampon.getvalue())

        tampon = io.StringIO()
        with redirect_stdout(tampon):
            audit.main([])
        self.assertIn('1 fonction(s)', tampon.getvalue())


if __name__ == '__main__':
    unittest.main()
