
IDDC Framework - Identidad Digital Declarada Congruente

https://img.shields.io/badge/License-Apache%202.0-blue.svg
https://img.shields.io/badge/Version-2.0.0--enterprise-green.svg
https://img.shields.io/badge/Python-3.8%2B-blue
https://img.shields.io/badge/Maintainer-ja3230002--hue-blue.svg
https://img.shields.io/badge/build-passing-brightgreen
https://img.shields.io/badge/coverage-95%25-brightgreen

Framework de seguridad Zero-Trust basado en la congruencia comportamental de procesos. Implementa el principio fundamental: "La identidad de un proceso es válida únicamente cuando su comportamiento es congruente con su función declarada."

Características principales

· Verificación continua de identidad de procesos mediante monitoreo en tiempo real
· Detección de anomalías temporales y comportamentales usando análisis estadístico avanzado
· Modelo Zero-Trust completo con validación explícita en cada transacción
· Arquitectura modular y extensible para diferentes entornos de ejecución
· Compatibilidad multiplataforma (Linux, Windows, macOS, Kubernetes, Docker)
· Análisis de entropía criptográfica para detección de actividad sospechosa
· Revelación de objetos ocultos mediante técnicas de forensía de memoria
· APIs REST/gRPC para integración con sistemas existentes

Requisitos del sistema

· Sistema Operativo: Linux Kernel 4.4+, Windows 10+, macOS 10.15+
· Python: 3.8 o superior
· RAM: 4GB mínimo (8GB recomendado)
· CPU: 2 cores mínimo (4 cores recomendado)
· Almacenamiento: 10GB mínimo (50GB recomendado)

Instalación rápida

```bash
# Clonar repositorio
git clone https://github.com/ja3230002-hue/iddc-framework.git
cd iddc-framework

# Crear entorno virtual (opcional pero recomendado)
python -m venv venv
source venv/bin/activate  # En Linux/macOS
# venv\Scripts\activate  # En Windows

# Instalar dependencias
pip install -r requirements.txt

# Instalar el paquete en modo desarrollo
pip install -e .

# Ejecutar pruebas
pytest tests/
```

Instalación vía pip

```bash
pip install iddc-framework
```

Uso básico

```python
from iddc import IDDCFramework, SecurityConfig
import asyncio

# Configuración básica
config = SecurityConfig(
    anomaly_threshold=0.85,
    monitoring_interval=5000,  # ms
    enable_entropy_analysis=True,
    enable_temporal_analysis=True
)

# Inicializar framework
framework = IDDCFramework(config=config)

# Monitorear un proceso específico
async def monitor_process():
    pid = 1234  # PID del proceso a monitorear
    result = await framework.monitor_process(pid=pid)
    
    if result.is_congruent:
        print(f"Proceso {pid}: Comportamiento congruente con identidad declarada")
        print(f"Score de confianza: {result.confidence_score:.2%}")
    else:
        print(f"Proceso {pid}: ANOMALÍA DETECTADA")
        print(f"Tipo de anomalía: {result.anomaly_type}")
        print(f"Severidad: {result.severity}")
        print(f"Recomendación: {result.recommended_action}")

# Ejecutar monitoreo
asyncio.run(monitor_process())
```

Ejemplo avanzado: Sistema completo

```python
from iddc import IDDCFramework, SecurityConfig, AlertSystem
from iddc.detectors import TemporalAnomalyDetector, EntropyAnalyzer
from iddc.responders import ProcessQuarantine, AuditLogger
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuración completa
config = SecurityConfig(
    anomaly_threshold=0.85,
    monitoring_interval=3000,
    enable_entropy_analysis=True,
    enable_temporal_analysis=True,
    enable_hidden_object_detection=True,
    crypto_entropy_minimum=7.0,
    response_actions={
        'low': ['alert', 'log'],
        'medium': ['quarantine', 'alert', 'log'],
        'high': ['terminate', 'quarantine', 'alert', 'log']
    }
)

# Inicializar componentes
framework = IDDCFramework(config=config)
alert_system = AlertSystem(
    email_enabled=True,
    webhook_url="https://alerts.tusistema.com/webhook",
    slack_webhook=None  # Opcional
)

# Configurar detectores
temporal_detector = TemporalAnomalyDetector(
    window_size=100,
    sensitivity=0.95
)

entropy_analyzer = EntropyAnalyzer(
    algorithm="shannon",
    minimum_entropy=7.0
)

# Configurar respondedores
quarantine = ProcessQuarantine(isolation_level="full")
audit_logger = AuditLogger(retention_days=365)

# Registrar componentes
framework.register_detector(temporal_detector)
framework.register_detector(entropy_analyzer)
framework.register_responder(quarantine)
framework.register_responder(audit_logger)

# Monitorear múltiples procesos
processes_to_monitor = [1234, 5678, 9012]

async def monitor_system():
    while True:
        for pid in processes_to_monitor:
            try:
                result = await framework.analyze_process(pid)
                
                if not result.is_congruent:
                    # Ejecutar acciones de respuesta según severidad
                    await framework.execute_response_actions(
                        pid=pid,
                        result=result
                    )
                    
                    # Enviar alerta
                    await alert_system.send_alert(
                        severity=result.severity,
                        message=f"Anomalía detectada en proceso {pid}",
                        details=result.to_dict()
                    )
                    
            except ProcessNotFoundError:
                logger.warning(f"Proceso {pid} no encontrado")
            except Exception as e:
                logger.error(f"Error analizando proceso {pid}: {e}")
        
        await asyncio.sleep(config.monitoring_interval / 1000)

# Ejecutar sistema de monitoreo
try:
    asyncio.run(monitor_system())
except KeyboardInterrupt:
    logger.info("Monitoreo detenido por el usuario")
```

Configuración en producción

Crea un archivo config/production.yaml:

```yaml
logging:
  level: INFO
  file: /var/log/iddc/framework.log
  rotation: 10MB
  retention: 30d

monitoring:
  interval: 5000
  alert_threshold: 0.85
  samples: 1000
  enable_real_time: true

security:
  encryption:
    algorithm: AES-256-GCM
    key_rotation: 7d
  audit:
    enabled: true
    retention: 365d
  quarantine:
    enabled: true
    isolation_level: full

detectors:
  temporal:
    enabled: true
    window_size: 500
    sensitivity: 0.95
  entropy:
    enabled: true
    algorithm: shannon
    minimum_entropy: 7.0
  hidden_objects:
    enabled: true
    scan_depth: deep

integrations:
  prometheus:
    enabled: true
    port: 9090
  grafana:
    enabled: true
    dashboard: true
```

Integración con Docker

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Configurar usuario no-root
RUN useradd -m -u 1000 iddc
USER iddc

EXPOSE 8080

CMD ["python", "-m", "iddc", "--config", "config/production.yaml"]
```

docker-compose.yml:

```yaml
version: '3.8'

services:
  iddc:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
    environment:
      - IDDC_ENV=production
      - LOG_LEVEL=INFO
    restart: unless-stopped
    networks:
      - monitoring

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - monitoring

networks:
  monitoring:
    driver: bridge
```

API REST

El framework expone una API REST para integración:

```bash
# Verificar estado del sistema
curl http://localhost:8080/api/v1/health

# Analizar un proceso
curl -X POST http://localhost:8080/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"pid": 1234}'

# Obtener métricas
curl http://localhost:8080/api/v1/metrics

# Listar procesos monitoreados
curl http://localhost:8080/api/v1/processes
```

Documentación

La documentación completa está disponible en:

· Guía de instalación
· API Reference
· Ejemplos de uso
· Configuración avanzada
· Guía de despliegue en producción
· Troubleshooting

Arquitectura

```
IDDC Framework Architecture
├── Core Engine
│   ├── Identity Validator
│   ├── Behavior Analyzer
│   └── Congruence Calculator
├── Detection Modules
│   ├── Temporal Anomaly Detector
│   ├── Cryptographic Entropy Analyzer
│   └── Hidden Object Revealer
├── Response System
│   ├── Process Quarantine
│   ├── Alert Manager
│   └── Audit Logger
└── Integration Layer
    ├── REST API
    ├── gRPC Interface
    └── Plugin System
```

Contribuir

Las contribuciones son bienvenidas. Por favor consulta CONTRIBUTING.md para más detalles sobre el proceso de contribución, estándares de código y guías de desarrollo.

1. Fork el repositorio
2. Crea una rama para tu característica: git checkout -b feature/nueva-funcionalidad
3. Haz commit de tus cambios: git commit -am 'Agrega nueva funcionalidad'
4. Push a la rama: git push origin feature/nueva-funcionalidad
5. Abre un Pull Request

Pruebas

Ejecuta el suite completo de pruebas:

```bash
# Ejecutar todas las pruebas
pytest tests/

# Ejecutar pruebas con cobertura
pytest tests/ --cov=iddc --cov-report=html

# Ejecutar pruebas de integración
pytest tests/integration/

# Ejecutar pruebas de rendimiento
pytest tests/performance/ --benchmark-only
```

Licencia

Este proyecto está licenciado bajo Apache License 2.0 - ver LICENSE para más detalles.

Contacto

· Autor: José Antonio de Jesús Reyes
· Mantenedor: ja3230002-hue
· Reportar problemas: GitHub Issues
· Discusiones: GitHub Discussions

Referencias

· NIST SP 800-207: Zero Trust Architecture
· OWASP SAMM: Security Assurance Maturity Model
· ISO/IEC 27001: Information Security Management
· IDDC Whitepaper: docs/IDDC-Whitepaper.pdf

---

Nota: Este framework está en desarrollo activo. Características y APIs pueden cambiar entre versiones menores. Consulte el CHANGELOG.md para detalles de cambios entre versiones.
