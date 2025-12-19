"""
IDDC Core Framework - Identidad Digital Declarada Congruente
Motor principal del framework de seguridad Zero-Trust.
Arquitecto: José Antonio de Jesús Reyes
Versión: 2.0.0-enterprise
"""

import asyncio
import logging
import psutil
import time
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime
import statistics
from concurrent.futures import ThreadPoolExecutor

# Logger específico para IDDC Core
logger = logging.getLogger("iddc.core")

class SeverityLevel(Enum):
    """Niveles de severidad para anomalías."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AnomalyType(Enum):
    """Tipos de anomalías detectables."""
    COMPUTATIONAL_SPIKE = "computational_spike"
    MEMORY_ANOMALY = "memory_anomaly"
    IO_ANOMALY = "io_anomaly"
    TEMPORAL_FLOOD = "temporal_flood"
    ENTROPY_VIOLATION = "entropy_violation"
    HIDDEN_OBJECT = "hidden_object"
    PROCESS_NOT_FOUND = "process_not_found"
    BEHAVIORAL_DRIFT = "behavioral_drift"

@dataclass
class SecurityConfig:
    """Configuración del framework IDDC."""
    anomaly_threshold: float = 0.85
    monitoring_interval: int = 5000  # ms
    enable_entropy_analysis: bool = True
    enable_temporal_analysis: bool = True
    enable_hidden_object_detection: bool = True
    crypto_entropy_minimum: float = 7.0
    cpu_threshold: float = 90.0
    memory_threshold: float = 85.0
    io_threshold: float = 80.0
    max_threads: int = 10
    response_actions: Dict[str, List[str]] = field(default_factory=lambda: {
        "low": ["alert", "log"],
        "medium": ["quarantine", "alert", "log"],
        "high": ["terminate", "quarantine", "alert", "log", "forensic"],
        "critical": ["immediate_terminate", "system_alert", "forensic", "audit"]
    })

@dataclass
class ProcessMetrics:
    """Métricas de rendimiento de un proceso."""
    pid: int
    cpu_percent: float
    memory_percent: float
    memory_rss: int  # bytes
    memory_vms: int  # bytes
    io_read_count: int
    io_write_count: int
    num_threads: int
    num_handles: int
    create_time: float
    cpu_times_user: float
    cpu_times_system: float
    connections: List[Dict] = field(default_factory=list)
    open_files: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class AnalysisResult:
    """Resultado del análisis de congruencia de un proceso."""
    pid: int
    is_congruent: bool
    confidence_score: float
    anomaly_type: Optional[AnomalyType] = None
    severity: SeverityLevel = SeverityLevel.LOW
    recommended_action: str = "none"
    metrics: Optional[ProcessMetrics] = None
    detector_results: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el resultado a diccionario."""
        result = asdict(self)
        if self.anomaly_type:
            result['anomaly_type'] = self.anomaly_type.value
        result['severity'] = self.severity.value
        if self.metrics:
            result['metrics'] = asdict(self.metrics)
        return result

    def to_json(self) -> str:
        """Convierte el resultado a JSON."""
        import json
        return json.dumps(self.to_dict(), default=str)

class ProcessNotFoundError(Exception):
    """Excepción para procesos no encontrados."""
    pass

class DetectorInterface:
    """Interfaz para detectores de anomalías."""
    
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
    
    async def analyze(self, process: psutil.Process, metrics: ProcessMetrics) -> Dict[str, Any]:
        """
        Analiza un proceso para detectar anomalías.
        
        Args:
            process: Proceso a analizar
            metrics: Métricas del proceso
            
        Returns:
            Dict con resultados del análisis
        """
        raise NotImplementedError

class ResponderInterface:
    """Interfaz para respondedores de incidentes."""
    
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
    
    async def can_handle(self, action: str, result: AnalysisResult) -> bool:
        """
        Verifica si este respondedor puede manejar una acción específica.
        
        Args:
            action: Acción a ejecutar
            result: Resultado del análisis
            
        Returns:
            True si puede manejar la acción
        """
        return self.enabled
    
    async def respond(self, result: AnalysisResult) -> bool:
        """
        Ejecuta una respuesta ante una anomalía detectada.
        
        Args:
            result: Resultado del análisis con anomalía
            
        Returns:
            True si la respuesta fue exitosa
        """
        raise NotImplementedError

class IDDCFramework:
    """
    Motor principal de la Identidad Digital Declarada Congruente.
    Implementa el principio fundamental: La identidad de un proceso es válida 
    únicamente cuando su comportamiento es congruente con su función declarada.
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """
        Inicializa el framework IDDC.
        
        Args:
            config: Configuración del framework (opcional)
        """
        self.config = config or SecurityConfig()
        self.detectors: List[DetectorInterface] = []
        self.responders: List[ResponderInterface] = []
        self.metrics_history: Dict[int, List[ProcessMetrics]] = {}
        self.analysis_history: Dict[int, List[AnalysisResult]] = {}
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_threads)
        self.is_running = False
        self.event_handlers: Dict[str, List[Callable]] = {
            'anomaly_detected': [],
            'process_analyzed': [],
            'response_executed': [],
            'framework_started': [],
            'framework_stopped': []
        }
        
        logger.info("=" * 60)
        logger.info("IDDC FRAMEWORK v2.0.0-enterprise")
        logger.info("Identidad Digital Declarada Congruente")
        logger.info(f"Arquitecto: José Antonio de Jesús Reyes")
        logger.info(f"Mantenedor: ja3230002-hue")
        logger.info("=" * 60)
        logger.info(f"Configuración cargada: {self.config}")

    def register_detector(self, detector: DetectorInterface) -> None:
        """
        Registra un detector de anomalías.
        
        Args:
            detector: Instancia del detector
        """
        self.detectors.append(detector)
        logger.info(f"Detector registrado: {detector.name}")

    def register_responder(self, responder: ResponderInterface) -> None:
        """
        Registra un respondedor de incidentes.
        
        Args:
            responder: Instancia del respondedor
        """
        self.responders.append(responder)
        logger.info(f"Respondedor registrado: {responder.name}")

    def register_event_handler(self, event: str, handler: Callable) -> None:
        """
        Registra un manejador de eventos.
        
        Args:
            event: Nombre del evento
            handler: Función manejadora
        """
        if event in self.event_handlers:
            self.event_handlers[event].append(handler)
            logger.debug(f"Manejador registrado para evento: {event}")
        else:
            logger.warning(f"Evento no reconocido: {event}")

    async def _collect_metrics(self, pid: int) -> ProcessMetrics:
        """
        Recoge métricas detalladas de un proceso.
        
        Args:
            pid: ID del proceso
            
        Returns:
            Métricas del proceso
            
        Raises:
            ProcessNotFoundError: Si el proceso no existe
        """
        try:
            proc = psutil.Process(pid)
            
            # Métricas de CPU
            cpu_percent = proc.cpu_percent(interval=0.1)
            cpu_times = proc.cpu_times()
            
            # Métricas de memoria
            memory_info = proc.memory_info()
            memory_percent = proc.memory_percent()
            
            # Métricas de I/O
            io_counters = proc.io_counters()
            
            # Conexiones de red
            connections = []
            try:
                for conn in proc.connections():
                    conn_dict = {
                        'fd': conn.fd,
                        'family': conn.family.name if conn.family else 'unknown',
                        'type': conn.type.name if conn.type else 'unknown',
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                        'status': conn.status
                    }
                    connections.append(conn_dict)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Archivos abiertos
            open_files = []
            try:
                for file in proc.open_files():
                    open_files.append(file.path)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            metrics = ProcessMetrics(
                pid=pid,
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_rss=memory_info.rss,
                memory_vms=memory_info.vms,
                io_read_count=io_counters.read_count if io_counters else 0,
                io_write_count=io_counters.write_count if io_counters else 0,
                num_threads=proc.num_threads(),
                num_handles=proc.num_handles() if hasattr(proc, 'num_handles') else 0,
                create_time=proc.create_time(),
                cpu_times_user=cpu_times.user,
                cpu_times_system=cpu_times.system,
                connections=connections,
                open_files=open_files
            )
            
            # Almacenar en historial
            if pid not in self.metrics_history:
                self.metrics_history[pid] = []
            self.metrics_history[pid].append(metrics)
            
            # Mantener solo las últimas 1000 métricas
            if len(self.metrics_history[pid]) > 1000:
                self.metrics_history[pid] = self.metrics_history[pid][-1000:]
            
            logger.debug(f"Métricas recogidas para PID {pid}: CPU={cpu_percent}%, Mem={memory_percent}%")
            return metrics
            
        except psutil.NoSuchProcess:
            error_msg = f"Proceso {pid} no encontrado en el espacio de usuario"
            logger.error(error_msg)
            raise ProcessNotFoundError(error_msg)
        except Exception as e:
            logger.error(f"Error recogiendo métricas del proceso {pid}: {e}")
            raise

    async def _run_detectors(self, process: psutil.Process, metrics: ProcessMetrics) -> Dict[str, Any]:
        """
        Ejecuta todos los detectores registrados.
        
        Args:
            process: Proceso a analizar
            metrics: Métricas del proceso
            
        Returns:
            Resultados combinados de todos los detectores
        """
        detector_results = {}
        
        for detector in self.detectors:
            if not detector.enabled:
                continue
                
            try:
                result = await detector.analyze(process, metrics)
                detector_results[detector.name] = result
                logger.debug(f"Detector {detector.name} completado para PID {metrics.pid}")
            except Exception as e:
                logger.error(f"Error en detector {detector.name}: {e}")
                detector_results[detector.name] = {
                    'error': str(e),
                    'anomaly_detected': False
                }
        
        return detector_results

    async def _calculate_congruence(self, metrics: ProcessMetrics, 
                                   detector_results: Dict[str, Any]) -> AnalysisResult:
        """
        Calcula la congruencia basada en métricas y resultados de detectores.
        
        Args:
            metrics: Métricas del proceso
            detector_results: Resultados de los detectores
            
        Returns:
            Resultado del análisis de congruencia
        """
        try:
            # Verificar umbrales básicos
            basic_violations = []
            
            if metrics.cpu_percent > self.config.cpu_threshold:
                basic_violations.append(("cpu_threshold_exceeded", SeverityLevel.MEDIUM))
                logger.warning(f"PID {metrics.pid}: CPU threshold exceeded ({metrics.cpu_percent}% > {self.config.cpu_threshold}%)")
            
            if metrics.memory_percent > self.config.memory_threshold:
                basic_violations.append(("memory_threshold_exceeded", SeverityLevel.MEDIUM))
                logger.warning(f"PID {metrics.pid}: Memory threshold exceeded ({metrics.memory_percent}% > {self.config.memory_threshold}%)")
            
            # Analizar resultados de detectores
            detector_violations = []
            anomaly_detected = False
            max_severity = SeverityLevel.LOW
            
            for detector_name, result in detector_results.items():
                if result.get('anomaly_detected', False):
                    anomaly_detected = True
                    detector_severity = SeverityLevel(result.get('severity', 'low'))
                    
                    if detector_severity.value > max_severity.value:
                        max_severity = detector_severity
                    
                    detector_violations.append((
                        detector_name,
                        result.get('anomaly_type', 'unknown'),
                        detector_severity
                    ))
                    logger.warning(f"Detector {detector_name} encontró anomalía: {result.get('anomaly_type')}")
            
            # Calcular score de confianza
            base_score = 1.0
            
            # Penalizar por violaciones básicas
            for violation, severity in basic_violations:
                if severity == SeverityLevel.MEDIUM:
                    base_score -= 0.1
                elif severity == SeverityLevel.HIGH:
                    base_score -= 0.2
                elif severity == SeverityLevel.CRITICAL:
                    base_score -= 0.4
            
            # Penalizar por anomalías de detectores
            for detector_name, anomaly_type, severity in detector_violations:
                if severity == SeverityLevel.MEDIUM:
                    base_score -= 0.15
                elif severity == SeverityLevel.HIGH:
                    base_score -= 0.3
                elif severity == SeverityLevel.CRITICAL:
                    base_score -= 0.5
            
            # Asegurar que el score esté en [0, 1]
            confidence_score = max(0.0, min(1.0, base_score))
            
            # Determinar si es congruente
            is_congruent = confidence_score >= self.config.anomaly_threshold
            
            # Determinar tipo de anomalía principal
            anomaly_type = None
            if not is_congruent:
                if detector_violations:
                    anomaly_type = AnomalyType(detector_violations[0][1])
                elif basic_violations:
                    if 'cpu' in basic_violations[0][0]:
                        anomaly_type = AnomalyType.COMPUTATIONAL_SPIKE
                    else:
                        anomaly_type = AnomalyType.MEMORY_ANOMALY
                else:
                    anomaly_type = AnomalyType.BEHAVIORAL_DRIFT
            
            # Determinar severidad
            if not is_congruent:
                if max_severity.value > SeverityLevel.LOW.value:
                    severity = max_severity
                elif basic_violations:
                    severity = max([s for _, s in basic_violations], 
                                 key=lambda x: x.value)
                else:
                    severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW
            
            # Recomendar acción basada en severidad
            if is_congruent:
                recommended_action = "monitor"
            else:
                if severity == SeverityLevel.CRITICAL:
                    recommended_action = "immediate_terminate"
                elif severity == SeverityLevel.HIGH:
                    recommended_action = "terminate"
                elif severity == SeverityLevel.MEDIUM:
                    recommended_action = "quarantine"
                else:
                    recommended_action = "alert"
            
            # Generar ID de correlación
            correlation_id = f"iddc_{metrics.pid}_{int(time.time())}_{int(confidence_score*1000)}"
            
            result = AnalysisResult(
                pid=metrics.pid,
                is_congruent=is_congruent,
                confidence_score=confidence_score,
                anomaly_type=anomaly_type,
                severity=severity,
                recommended_action=recommended_action,
                metrics=metrics,
                detector_results=detector_results,
                correlation_id=correlation_id
            )
            
            logger.info(f"Análisis completado para PID {metrics.pid}: "
                       f"Congruente={is_congruent}, "
                       f"Confianza={confidence_score:.2%}, "
                       f"Severidad={severity.value}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error calculando congruencia: {e}")
            # Resultado por defecto en caso de error
            return AnalysisResult(
                pid=metrics.pid,
                is_congruent=False,
                confidence_score=0.0,
                anomaly_type=AnomalyType.BEHAVIORAL_DRIFT,
                severity=SeverityLevel.HIGH,
                recommended_action="investigate",
                metrics=metrics,
                detector_results=detector_results
            )

    async def analyze_process(self, pid: int) -> AnalysisResult:
        """
        Realiza una auditoría quirúrgica de un proceso activo.
        
        Args:
            pid: ID del proceso a analizar
            
        Returns:
            Resultado del análisis de congruencia
            
        Raises:
            ProcessNotFoundError: Si el proceso no existe
        """
        logger.info(f"Iniciando análisis del proceso PID {pid}")
        
        try:
            # Obtener proceso
            process = psutil.Process(pid)
            
            # Recoger métricas
            metrics = await self._collect_metrics(pid)
            
            # Ejecutar detectores
            detector_results = await self._run_detectors(process, metrics)
            
            # Calcular congruencia
            result = await self._calculate_congruence(metrics, detector_results)
            
            # Almacenar en historial
            if pid not in self.analysis_history:
                self.analysis_history[pid] = []
            self.analysis_history[pid].append(result)
            
            # Mantener solo los últimos 100 análisis
            if len(self.analysis_history[pid]) > 100:
                self.analysis_history[pid] = self.analysis_history[pid][-100:]
            
            # Disparar evento
            await self._trigger_event('process_analyzed', result)
            
            if not result.is_congruent:
                logger.warning(f"ANOMALÍA DETECTADA en PID {pid}: "
                             f"{result.anomaly_type.value if result.anomaly_type else 'Unknown'} - "
                             f"Severidad: {result.severity.value}")
                await self._trigger_event('anomaly_detected', result)
            
            return result
            
        except psutil.NoSuchProcess:
            error_msg = f"Proceso {pid} no encontrado"
            logger.error(error_msg)
            result = AnalysisResult(
                pid=pid,
                is_congruent=False,
                confidence_score=0.0,
                anomaly_type=AnomalyType.PROCESS_NOT_FOUND,
                severity=SeverityLevel.CRITICAL,
                recommended_action="alert"
            )
            return result
        except Exception as e:
            logger.error(f"Error analizando proceso {pid}: {e}")
            raise

    async def monitor_process(self, pid: int) -> AnalysisResult:
        """
        Analiza si la identidad de un proceso es congruente con su actividad.
        Método simplificado para uso directo.
        
        Args:
            pid: ID del proceso a monitorear
            
        Returns:
            Resultado del análisis
        """
        return await self.analyze_process(pid)

    async def execute_response_actions(self, pid: int, result: AnalysisResult) -> Dict[str, bool]:
        """
        Coordinación radial de respuesta ante incidentes.
        
        Args:
            pid: ID del proceso
            result: Resultado del análisis
            
        Returns:
            Dict con el estado de cada respuesta ejecutada
        """
        if result.is_congruent:
            logger.debug(f"Proceso {pid} es congruente, no se ejecutan respuestas")
            return {}
        
        logger.warning(f"EJECUTANDO RESPUESTA RADIAL para PID {pid} - "
                      f"Severidad: {result.severity.value} - "
                      f"Tipo: {result.anomaly_type.value if result.anomaly_type else 'Unknown'}")
        
        response_results = {}
        actions = self.config.response_actions.get(result.severity.value, [])
        
        for action in actions:
            for responder in self.responders:
                try:
                    if await responder.can_handle(action, result):
                        success = await responder.respond(result)
                        response_results[f"{responder.name}.{action}"] = success
                        
                        if success:
                            logger.info(f"Respuesta {action} ejecutada exitosamente por {responder.name}")
                        else:
                            logger.error(f"Respuesta {action} falló en {responder.name}")
                except Exception as e:
                    logger.error(f"Error ejecutando respuesta {action} con {responder.name}: {e}")
                    response_results[f"{responder.name}.{action}"] = False
        
        # Disparar evento
        await self._trigger_event('response_executed', {
            'pid': pid,
            'result': result,
            'response_results': response_results
        })
        
        return response_results

    async def monitor_processes(self, pids: List[int], duration: Optional[int] = None) -> None:
        """
        Monitorea múltiples procesos continuamente.
        
        Args:
            pids: Lista de PIDs a monitorear
            duration: Duración en segundos (None para infinito)
        """
        self.is_running = True
        start_time = time.time()
        
        await self._trigger_event('framework_started', {
            'pids': pids,
            'start_time': start_time
        })
        
        logger.info(f"Iniciando monitoreo de {len(pids)} procesos")
        
        try:
            while self.is_running:
                current_time = time.time()
                
                # Verificar duración
                if duration and (current_time - start_time) > duration:
                    logger.info(f"Duración de monitoreo alcanzada: {duration} segundos")
                    break
                
                # Analizar cada proceso
                for pid in pids[:]:  # Copia para poder remover
                    try:
                        result = await self.analyze_process(pid)
                        
                        if not result.is_congruent:
                            await self.execute_response_actions(pid, result)
                            
                    except ProcessNotFoundError:
                        logger.warning(f"Proceso {pid} ya no existe, removiendo de monitoreo")
                        pids.remove(pid)
                    except Exception as e:
                        logger.error(f"Error monitoreando proceso {pid}: {e}")
                
                # Esperar intervalo
                await asyncio.sleep(self.config.monitoring_interval / 1000)
                
        except KeyboardInterrupt:
            logger.info("Monitoreo interrumpido por el usuario")
        except Exception as e:
            logger.error(f"Error en el ciclo de monitoreo: {e}")
        finally:
            self.is_running = False
            await self._trigger_event('framework_stopped', {
                'end_time': time.time(),
                'duration': time.time() - start_time
            })
            logger.info("Monitoreo detenido")

    async def _trigger_event(self, event: str, data: Any) -> None:
        """
        Dispara un evento a todos los manejadores registrados.
        
        Args:
            event: Nombre del evento
            data: Datos del evento
        """
        for handler in self.event_handlers.get(event, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as e:
                logger.error(f"Error en manejador de evento {event}: {e}")

    def get_metrics_history(self, pid: int, limit: int = 100) -> List[ProcessMetrics]:
        """
        Obtiene el historial de métricas de un proceso.
        
        Args:
            pid: ID del proceso
            limit: Número máximo de métricas a retornar
            
        Returns:
            Lista de métricas históricas
        """
        return self.metrics_history.get(pid, [])[-limit:]

    def get_analysis_history(self, pid: int, limit: int = 50) -> List[AnalysisResult]:
        """
        Obtiene el historial de análisis de un proceso.
        
        Args:
            pid: ID del proceso
            limit: Número máximo de análisis a retornar
            
        Returns:
            Lista de análisis históricos
        """
        return self.analysis_history.get(pid, [])[-limit:]

    def stop(self) -> None:
        """Detiene el framework y libera recursos."""
        self.is_running = False
        self.executor.shutdown(wait=True)
        logger.info("Framework IDDC detenido")

    def __del__(self):
        """Destructor para limpieza."""
        try:
            self.stop()
        except:
            pass

# Función de conveniencia para uso rápido
async def monitor_single_process(pid: int, config: Optional[SecurityConfig] = None) -> AnalysisResult:
    """
    Monitorea un solo proceso usando IDDC.
    
    Args:
        pid: ID del proceso
        config: Configuración opcional
        
    Returns:
        Resultado del análisis
    """
    framework = IDDCFramework(config)
    return await framework.monitor_process(pid)
