# SPDX-License-Identifier: GPL-3.0-or-later
"""Contrôle indépendant des lignes et branches, seuil unique du projet (#54)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from coverage import Coverage
from loguru import logger


def verifier_couverture(totaux: dict, seuil: float) -> bool:
    """Ne jamais laisser une moyenne masquer un défaut de branches."""
    logger.debug('Vérification de la couverture : entrée seuil={}', seuil)
    conforme = True
    for nom, couverts, total in (
        ('lignes', 'covered_lines', 'num_statements'),
        ('branches', 'covered_branches', 'num_branches'),
    ):
        nombre = totaux[total]
        taux = 100.0 * totaux[couverts] / nombre if nombre else 100.0
        logger.info('Couverture {} : {:.4f} %, seuil {} %', nom, taux, seuil)
        if taux < seuil:
            logger.error('Couverture {} insuffisante', nom)
            conforme = False
    logger.debug('Vérification de la couverture : sortie conforme={}', conforme)
    return conforme


def main() -> int:
    """Lit le rapport JSON et le même fail_under que coverage report."""
    logger.debug('Contrôle de couverture : entrée')
    try:
        chemin = Path(sys.argv[1] if len(sys.argv) > 1 else 'coverage.json')
        totaux = json.loads(chemin.read_text(encoding='utf-8'))['totals']
        seuil = Coverage().get_option('report:fail_under')
        resultat = 0 if verifier_couverture(totaux, seuil) else 1
    except (OSError, ValueError, KeyError, TypeError) as erreur:
        logger.error('Rapport de couverture illisible : {!r}', erreur)
        logger.debug('Contrôle de couverture : sortie 2')
        return 2
    logger.debug('Contrôle de couverture : sortie {}', resultat)
    return resultat


if __name__ == '__main__':
    sys.exit(main())
