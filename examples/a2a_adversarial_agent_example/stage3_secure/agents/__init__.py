"""
Agents Module - Stage 3

Example agent implementations:
- attacker.py: Demonstrates all attacks FAILING
- legitimate_worker.py: Demonstrates proper secure usage
"""

try:
    from .attacker import Stage3Attacker
except ImportError:
    Stage3Attacker = None

try:
    from .legitimate_worker import LegitimateWorker
except ImportError:
    LegitimateWorker = None

__all__ = []

if Stage3Attacker is not None:
    __all__.append('Stage3Attacker')

if LegitimateWorker is not None:
    __all__.append('LegitimateWorker')

__version__ = '3.0.0'