#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit de la consigne « debug en entrée et à chaque sortie » (SOCLE §8).

Le socle Mathilde-Team (Mathilde-Team/.github#10) demande au moins deux
``debug()`` par fonction non triviale : un à l'entrée et un avant chaque
sortie. Ce script compte, par analyse AST (aucun import des modules), les
fonctions qui ne la respectent pas encore :

- **entrée** : la première instruction (après la docstring) n'est pas un
  appel ``<logger>.debug(...)`` ou ``.trace(...)`` ;
- **sortie** : un ``return`` n'est pas immédiatement précédé d'un appel de
  journal, ou la fonction se termine sans ``return`` ni ``raise`` après une
  dernière instruction qui n'est pas un appel de journal (sur chaque chemin
  d'un ``if``/``else``, ``try``/``except``, ``with`` ou ``match`` final).

Les ``raise`` ne sont pas comptés comme des sorties à tracer (l'appelant
journalise l'exception), ni les fonctions vides (``...``, ``pass``), les
lambdas et les méthodes de protocole d'une seule ligne.

Rapport **non bloquant** : seul le total est comparé, par
``tests/test_loguru_regles.py``, à ``scripts/audit_debug_sorties.baseline``,
qui ne doit pas augmenter (le baisser après avoir instrumenté du code).

Usage :

    scripts/audit_debug_sorties.py             # total et top 20 des fichiers
    scripts/audit_debug_sorties.py --details   # une ligne par fonction
    scripts/audit_debug_sorties.py --total     # le total seul
"""

from __future__ import annotations

import argparse
import ast
import os
import subprocess
import sys
import warnings
from collections import Counter
from pathlib import Path

from loguru import logger

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / 'scripts' / 'audit_debug_sorties.baseline'
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
LOG_METHODS = {
    'trace',
    'debug',
    'info',
    'success',
    'warning',
    'error',
    'exception',
    'critical',
    'log',
}


def is_log_call(node: ast.AST, methods: set[str] = LOG_METHODS) -> bool:
    """Vrai pour ``logger.debug(...)``, ``self.logger.info(...)``, etc.

    Args:
        node: Nœud AST.
        methods: Méthodes acceptées.

    Returns:
        bool: Le nœud est une instruction-appel de journal.
    """
    logger.debug('is_log_call() appelée | nœud={}', type(node).__name__)
    call = node.value if isinstance(node, ast.Expr) else node
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in methods
    ):
        logger.debug('is_log_call() retourne | False (pas un appel de journal)')
        return False
    target = call.func.value
    cible_ok = (isinstance(target, ast.Name) and target.id in LOGGER_NAMES) or (
        isinstance(target, ast.Attribute) and target.attr in LOGGER_NAMES
    )
    logger.debug('is_log_call() retourne | {}', cible_ok)
    return cible_ok


def _body_without_docstring(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    logger.debug('_body_without_docstring() appelée | fonction={}', func.name)
    body = list(func.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(getattr(body[0], 'value', None), ast.Constant)
    ) and isinstance(body[0].value.value, str):
        body = body[1:]
    logger.debug('_body_without_docstring() retourne | {} instruction(s)', len(body))
    return body


def _child_blocks(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Blocs d'instructions imbriqués (if/for/while/with/try/match), hors définitions."""
    logger.debug('_child_blocks() appelée | instruction={}', type(stmt).__name__)
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        logger.debug('_child_blocks() retourne | [] (définition)')
        return []
    blocks = [getattr(stmt, f) for f in ('body', 'orelse', 'finalbody') if getattr(stmt, f, None)]
    blocks += [h.body for h in getattr(stmt, 'handlers', [])]
    blocks += [c.body for c in getattr(stmt, 'cases', [])]
    logger.debug('_child_blocks() retourne | {} bloc(s)', len(blocks))
    return blocks


def _returns_without_trace(statements: list[ast.stmt]) -> int:
    """Sorties (``return`` ou ``raise``) non précédées d'un appel de journal.

    Un ``raise`` volontaire est une sortie comme un ``return`` : il doit
    être précédé d'un appel de journal (blocs imbriqués compris).
    """
    logger.debug('_returns_without_trace() appelée | {} instruction(s)', len(statements))
    missing = 0
    previous: ast.stmt | None = None
    for stmt in statements:
        if (
            isinstance(stmt, ast.Return) or (isinstance(stmt, ast.Raise) and stmt.exc is not None)
        ) and not (previous is not None and is_log_call(previous)):
            missing += 1
        for block in _child_blocks(stmt):
            missing += _returns_without_trace(block)
        previous = stmt
    logger.debug('_returns_without_trace() retourne | {} sortie(s) non tracée(s)', missing)
    return missing


def _ends_traced(block: list[ast.stmt]) -> bool:
    """Le bloc se termine par un journal, un ``return`` ou un ``raise`` sur tous ses chemins."""
    logger.debug('_ends_traced() appelée | {} instruction(s)', len(block))
    if not block:
        logger.debug('_ends_traced() retourne | False (bloc vide)')
        return False
    last = block[-1]
    if isinstance(last, (ast.Return, ast.Raise)) or is_log_call(last):
        logger.debug('_ends_traced() retourne | True (sortie ou journal en fin)')
        return True
    if isinstance(last, ast.If):
        traced = _ends_traced(last.body) and _ends_traced(last.orelse)
        logger.debug('_ends_traced() retourne | {} (if/else)', traced)
        return traced
    if isinstance(last, (ast.With, ast.AsyncWith)):
        traced = _ends_traced(last.body)
        logger.debug('_ends_traced() retourne | {} (with)', traced)
        return traced
    if isinstance(last, ast.Try):
        if last.finalbody and _ends_traced(last.finalbody):
            logger.debug('_ends_traced() retourne | True (finally tracé)')
            return True
        main = last.orelse or last.body
        traced = _ends_traced(main) and all(_ends_traced(h.body) for h in last.handlers)
        logger.debug('_ends_traced() retourne | {} (try/except)', traced)
        return traced
    # ast.Match n'existe qu'à partir de Python 3.10 (le dépôt reste compatible 3.9, issue #35).
    match_type = getattr(ast, 'Match', None)
    if match_type is not None and isinstance(last, match_type):
        traced = all(_ends_traced(c.body) for c in last.cases)
        logger.debug('_ends_traced() retourne | {} (match)', traced)
        return traced
    logger.debug('_ends_traced() retourne | False (fin implicite non tracée)')
    return False


def _est_tracede(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """La fonction porte un décorateur qui trace entrée et sorties.

    ``@traced`` (``src/tracing.py``) enveloppe l'appel entier : entrée et
    chaque sortie (retour ou exception) sont journalisées structurellement.
    """
    logger.debug('_est_tracede() appelée | fonction={}', func.name)
    for deco in func.decorator_list:
        if isinstance(deco, ast.Name) and deco.id == 'traced':
            logger.debug('_est_tracede() retourne | True (nom direct)')
            return True
        if isinstance(deco, ast.Attribute) and deco.attr == 'traced':
            logger.debug('_est_tracede() retourne | True (attribut)')
            return True
    logger.debug('_est_tracede() retourne | False')
    return False


def audit_function(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Écarts d'une fonction à la consigne.

    Args:
        func: Définition de fonction.

    Returns:
        list[str]: ``"entrée"``, ``"sortie"`` (ou vide si conforme / exemptée).
    """
    logger.debug('audit_function() appelée | fonction={}', func.name)
    body = _body_without_docstring(func)
    if not body or all(
        isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
        for s in body
    ):
        logger.debug('audit_function() retourne | [] (fonction vide)')
        return []
    if len(body) == 1 and isinstance(body[0], (ast.Return, ast.Raise)):
        logger.debug('audit_function() retourne | [] (une ligne, exemptée)')
        return []  # accesseur ou méthode de protocole d'une ligne
    if _est_tracede(func):
        logger.debug(
            'audit_function() retourne | [] (décorée @traced : entrée et sorties garanties)'
        )
        return []
    problems = []
    if not is_log_call(body[0], {'trace', 'debug'}):
        problems.append('entrée')
    falls_through = not _ends_traced(body)
    if _returns_without_trace(body) or falls_through:
        problems.append('sortie')
    logger.debug('audit_function() retourne | {}', problems)
    return problems


def audit_source(source: str) -> list[tuple[int, str, list[str]]]:
    """(ligne, nom, écarts) de chaque fonction non conforme d'un module.

    Args:
        source: Code Python.

    Returns:
        list[tuple[int, str, list[str]]]: Fonctions à instrumenter.
    """
    logger.debug('audit_source() appelée | {} caractère(s)', len(source))
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', SyntaxWarning)
        tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            problems = audit_function(node)
            if problems:
                found.append((node.lineno, node.name, problems))
    logger.debug('audit_source() retourne | {} fonction(s) non conforme(s)', len(found))
    return found


def python_files() -> list[str]:
    """Fichiers Python suivis par git, hors tests (``test_*.py``).

    Returns:
        list[str]: Chemins relatifs à la racine.
    """
    logger.debug('python_files() appelée')
    out = subprocess.run(
        ['git', 'ls-files', '*.py'], cwd=ROOT, capture_output=True, text=True, check=True
    )
    files = [f for f in out.stdout.split() if not Path(f).name.startswith(TEST_PREFIX)]
    logger.debug('python_files() retourne | {} fichier(s)', len(files))
    return files


def audit_repository() -> dict[str, list[tuple[int, str, list[str]]]]:
    """Audit de tout le dépôt.

    Returns:
        dict[str, list[tuple[int, str, list[str]]]]: Fonctions non conformes par fichier.
    """
    logger.debug('audit_repository() appelée')
    result = {}
    for path in python_files():
        found = audit_source((ROOT / path).read_text(encoding='utf-8'))
        if found:
            result[path] = found
    logger.debug('audit_repository() retourne | {} fichier(s) non conforme(s)', len(result))
    return result


def read_baseline() -> int:
    """Total de référence (``scripts/audit_debug_sorties.baseline``).

    Returns:
        int: Nombre de fonctions non conformes toléré.
    """
    logger.debug('read_baseline() appelée')
    lines = [
        line.split('#', 1)[0].strip() for line in BASELINE.read_text(encoding='utf-8').splitlines()
    ]
    value = int(next(line for line in lines if line))
    logger.debug('read_baseline() retourne | {}', value)
    return value


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée (rapport, code de retour toujours 0).

    Args:
        argv: Arguments (``sys.argv[1:]`` par défaut).

    Returns:
        int: 0.
    """
    logger.trace('main() appelée (avant configuration des puits)')
    logger.remove()
    logger.add(sys.stderr, level='DEBUG' if os.environ.get('SOCLE_DEBUG') else 'WARNING')
    logger.debug('main() appelée')
    parser = argparse.ArgumentParser(
        description='Fonctions sans debug() en entrée ou à chaque sortie'
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--details', action='store_true', help='une ligne par fonction')
    group.add_argument('--total', action='store_true', help='le total seul')
    args = parser.parse_args(argv)

    result = audit_repository()
    total = sum(len(v) for v in result.values())
    if args.total:
        print(total)
    elif args.details:
        for path, found in sorted(result.items()):
            for line, name, problems in found:
                print(f'{path}:{line}: {name} ({", ".join(problems)})')
    else:
        print(
            f'{total} fonction(s) sans debug() en entrée ou à chaque sortie (référence : {read_baseline()})'
        )
        for path, count in Counter({p: len(f) for p, f in result.items()}).most_common(20):
            print(f'{count:6d}  {path}')
    logger.debug('main() retourne | 0 (total={})', total)
    return 0


if __name__ == '__main__':
    sys.exit(main())
