"""
IDDC Framework - Identidad Digital Declarada Congruente
Framework de seguridad Zero-Trust basado en congruencia comportamental de procesos.
Versión 2.0.0 Enterprise
"""

__version__ = "2.0.0"
__author__ = "José Antonio de Jesús Reyes"
__maintainer__ = "ja3230002-hue"
__license__ = "Apache 2.0"
__copyright__ = "Copyright 2025, IDDC Security"
__description__ = "Framework de seguridad Zero-Trust basado en la congruencia comportamental de procesos"

# Core exports
from .core import (
    IDDCFramework,
    SecurityConfig,
    AnalysisResult,
    ProcessMetrics,
    ProcessNotFoundError,
    SeverityLevel,
    AnomalyType,
    DetectorInterface,
    ResponderInterface
)

# Detectors exports
from .detectors import (
    TemporalAnomalyDetector,
    EntropyAnalyzer,
    HiddenObjectDetector
)

# Responders exports
from .responders import (
    ProcessQuarantine,
    AlertSystem,
    AuditLogger
)

# Utility exports (si existen)
try:
    from .utils.metrics import calculate_statistics, generate_report
    __all__.extend(['calculate_statistics', 'generate_report'])
except ImportError:
    pass

# Config exports (si existen)
try:
    from .config import load_config, save_config
    __all__.extend(['load_config', 'save_config'])
except ImportError:
    pass

# API exports (si existen)
try:
    from .api import app
    __all__.extend(['app'])
except ImportError:
    pass

# CLI exports (si existen)
try:
    from .cli import main
    __all__.extend(['main'])
except ImportError:
    pass

# Lista de todas las exportaciones públicas
__all__ = [
    # Core
    'IDDCFramework',
    'SecurityConfig',
    'AnalysisResult',
    'ProcessMetrics',
    'ProcessNotFoundError',
    'SeverityLevel',
    'AnomalyType',
    'DetectorInterface',
    'ResponderInterface',
    
    # Detectors
    'TemporalAnomalyDetector',
    'EntropyAnalyzer',
    'HiddenObjectDetector',
    
    # Responders
    'ProcessQuarantine',
    'AlertSystem',
    'AuditLogger',
    
    # Metadata
    '__version__',
    '__author__',
    '__license__',
    '__description__'
]

# Inicialización de logging
import logging

class IDDCLogFormatter(logging.Formatter):
    """Formateador personalizado para logs de IDDC."""
    
    def format(self, record):
        # Agregar prefijo IDDC a todos los logs
        record.msg = f"IDDC - {record.msg}"
        return super().format(record)

def setup_logging(level=logging.INFO):
    """
    Configura el logging para el framework IDDC.
    
    Args:
        level: Nivel de logging (default: INFO)
    """
    logger = logging.getLogger('iddc')
    logger.setLevel(level)
    
    # Evitar duplicación de handlers
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = IDDCLogFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger

# Setup logging por defecto
logger = setup_logging()

# Mensaje de bienvenida
logger.info(f"IDDC Framework v{__version__} cargado correctamente")
logger.info(f"Copyright {__copyright__}")
logger.info(f"Autor: {__author__}")
logger.info(f"Mantenedor: {__maintainer__}")
