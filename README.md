# SentryGuard 0.1.0 — Plataforma EDR completa (servidor + agentes + consola)

> **Plataforma EDR modular**: motor de detección (9,026 reglas Sigma + YARA, MITRE ATT&CK, correlación) + servidor .NET 8 (ingestión, auth JWT+TOTP, SignalR, threat intel) + agentes (Go y .NET) + consola React en tiempo real.
>
> Versión: **0.1.0** · Plataformas: **Windows / Linux** · Motores: **.NET 8 / Go / React**

---

## Plataforma (nuevo en v0.1)

```
┌──────────────────────────────────────────────────────────────────────┐
│                        SENTRYGUARD PLATFORM                          │
├──────────────────────────────────────────────────────────────────────┤
│  Consola React ──► Servidor .NET 8 (REST + SignalR)                  │
│  (Dashboard,     │   ├─ Auth: JWT + TOTP + refresh rotation          │
│   detecciones,   │   ├─ Ingestión: /api/events/ingest (rate-limited) │
│   agentes)       │   ├─ Detección: pipeline Sigma+YARA+correlación   │
│                  │   ├─ Integraciones: syslog / webhook / MISP       │
│                  │   └─ BD: SQLite (dev) / PostgreSQL+RLS (prod)     │
│                  └──────────────┬────────────────────────────────────│
│                                 │ HTTPS + mTLS (opcional)            │
│                  ┌──────────────▼────────────────────────────────────│
│                  │  Agentes: Go (binario único, stdlib)              │
│                  │           .NET worker (pipeline F0 reutilizado)   │
│                  └───────────────────────────────────────────────────│
└──────────────────────────────────────────────────────────────────────┘
```

| Componente | Ubicación | Estado |
|---|---|---|
| Servidor .NET 8 | `src/SentryGuard.Server` | F16 ✅ |
| Agente Go | `agents/go` | F17a ✅ |
| Agente .NET worker | `src/SentryGuard.Agent` | F17b ✅ |
| Consola React | `console/sentryguard-console` | F18 ✅ |
| Integraciones | `src/SentryGuard.Server/Integrations` | F19 ✅ |
| CI/CD | `.github/workflows/ci.yml` | F20 ✅ |
| Compliance | `docs/COMPLIANCE.md` | F21 ✅ |

**Guías**: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) · [`docs/API.md`](docs/API.md) · [`CHANGELOG.md`](CHANGELOG.md)

---

# SentryGuard 0.0.1 — EDR Detection Engine (Modular, Windows + Linux) *(histórico)*

---

## ¿Qué es?

SentryGuard es un **módulo de detección** diseñado para ser incorporado en cualquier EDR (Endpoint Detection and Response). Proporciona:

- **Evaluación de reglas Sigma** (3,085 reglas de SigmaHQ)
- **Escaneo YARA** (5,933 reglas de Neo23x0/signature-base)
- **Correlación multi-fuente** (Sigma + YARA = score compuesto)
- **Enriquecimiento MITRE ATT&CK** (404 técnicas, 13 tácticas)
- **Optimización de rendimiento** (93% menos evaluaciones)
- **Telemetría kernel** (driver para Windows)

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTRYGUARD EDR MODULE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  KERNEL       │    │  RUST CORE   │    │  C# RULES    │      │
│  │  DRIVER       │◄──►│  ENGINE      │◄──►│  ENGINE      │      │
│  │  (C/C++)      │    │  (FFI)       │    │  (P/Invoke)  │      │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│         │                   │                   │               │
│         ▼                   ▼                   ▼               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Telemetry   │    │  EventBus    │    │  Sigma       │      │
│  │  Collection  │    │  Scheduler   │    │  Evaluation  │      │
│  │  (WFP)       │    │  Cache       │    │  (3,085)     │      │
│  └──────────────┘    │  ThreadPool  │    ├──────────────┤      │
│                      │  Metrics     │    │  YARA        │      │
│                      └──────────────┘    │  Matching    │      │
│                                          │  (5,933)     │      │
│                                          ├──────────────┤      │
│                                          │  Correlation │      │
│                                          │  Engine      │      │
│                                          ├──────────────┤      │
│                                          │  MITRE       │      │
│                                          │  Enrichment  │      │
│                                          └──────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Componentes

### 1. Kernel Driver (C/C++)
**Ubicación:** `src/driver/`

| Archivo | Función |
|---------|---------|
| `driver.c` | DriverEntry, 12 comandos IOCTL |
| `telemetry.c` | Buffer ring SPSC (128KB) |
| `process.c` | Monitoreo de procesos |
| `thread.c` | Monitoreo de hilos |
| `image.c` | Carga de imágenes DLL |
| `registry.c` | Persistencia en registro |
| `network.c` | Monitoreo de red (WFP) |
| `injection.c` | Detección de inyección |
| `security.c` | Monitoreo de tokens |

**IOCTL Commands:**
```
SG_IOCTL_WAIT_EVENT       - Espera asíncrona de eventos
SG_IOCTL_REGISTER_CLIENT  - Registrar cliente
SG_IOCTL_GET_EVENT        - Obtener siguiente evento
SG_IOCTL_SET_FILTER       - Configurar filtro
```

### 2. Rust Core Engine
**Ubicación:** `src/core/`

| Módulo | Función |
|--------|---------|
| `event_bus.rs` | Publicación/suscripción de eventos |
| `scheduler.rs` | Procesamiento por lotes |
| `cache.rs` | Caché LRU con TTL |
| `thread_pool.rs` | Ejecución asíncrona |
| `metrics.rs` | Contadores de rendimiento |
| `ffi.rs` | Exportaciones C ABI (17 funciones) |

**FFI Functions:**
```c
sentryguard_init()           - Inicializar motor
sentryguard_process_event()  - Procesar evento
sentryguard_evaluate()       - Evaluar reglas
sentryguard_get_metrics()    - Obtener métricas
```

### 3. C# Rule Engine
**Ubicación:** `src/SentryGuard.Rules/`

| Archivo | Función |
|---------|---------|
| `EvaluationEngine.cs` | Compilador Sigma (expression trees) |
| `YaraEngine.cs` | Matcher YARA (patrones) |
| `CorrelationEngine.cs` | scoring multi-fuente |
| `RuleIndex.cs` | Prefiltado por logsource (O(1)) |
| `YaraCache.cs` | Caché hash + features PE |
| `RuleDeduplicator.cs` | Eliminar reglas duplicadas |
| `AlertPrioritizer.cs` | Scoring + throttling |
| `FieldMapper.cs` | Mapeo Sigma→Windows |
| `MitreEnricher.cs` | Contexto MITRE ATT&CK |
| `Alert.cs` | Modelo de alerta |
| `SentryCore.cs` | P/Invoke bridge |

---

## Estadísticas

| Métrica | Valor |
|---------|-------|
| **Reglas Sigma** | 3,085 (SigmaHQ/sigma) |
| **Reglas YARA** | 5,933 (Neo23x0/signature-base) |
| **Correlación** | 7 patrones built-in |
| **TOTAL** | **9,026 reglas** |
| **Técnicas MITRE** | 404 únicas |
| **Tácticas MITRE** | 13 (cobertura completa) |
| **Reglas con MITRE** | 2,996 (97%) |
| **Reducción evaluaciones** | 50% global; 94.7% (PowerShell/4104); 78.4% (Security/4624) |

---

## Instalación

### Prerrequisitos
- .NET 8 SDK
- Rust (opcional, para Rust Core)
- Windows Driver Kit (opcional, para Kernel Driver)

### Build C# Engine
```powershell
cd src/SentryGuard.Rules
dotnet build
```

### Build Rust Core
```powershell
cd src/core
cargo build --release
```

### Build Kernel Driver (requiere WDK)
```powershell
cd src/driver
msbuild /p:Configuration=Release /p:Platform=x64
```

---

## Uso

### C# Engine (Directo)
```csharp
using SentryGuard.Rules.Engine;
using SentryGuard.Rules.Models;

// Inicializar motores
var fieldMapper = new FieldMapper();
var mitreEnricher = new MitreEnricher();
var sigmaEngine = new EvaluationEngine();
var yaraEngine = new YaraEngine();
var correlationEngine = new CorrelationEngine();
var ruleIndex = new RuleIndex();

// Cargar reglas
var sigmaRules = new RuleReader().LoadFromDirectory("Rules/sigma/all");
var yaraCount = yaraEngine.LoadFromDirectory("Rules/yara_json");

// Construir índice (optimización)
ruleIndex.BuildIndex(sigmaRules);

// Crear evento de seguridad
var event = new SecurityEvent
{
    EventType = EventType.ScriptBlock,
    Hostname = "WORKSTATION01",
    EventData = new Dictionary<string, string>
    {
        ["ScriptBlockText"] = "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }",
        ["winlog.channel"] = "Microsoft-Windows-PowerShell/Operational",
        ["winlog.event_id"] = "4104"
    }
};

// Prefiltado (O(1) lookup)
int.TryParse(event.EventData["winlog.event_id"], out int eventId);
var applicableRules = ruleIndex.GetApplicableRules("powershell", eventId);

// Evaluar solo reglas aplicables (~200 en vez de 3,085)
var sigmaResults = sigmaEngine.EvaluateAll(applicableRules, event);

// Escanear YARA
var yaraResults = yaraEngine.Scan(fileBytes);

// Correlacionar
var correlation = correlationEngine.Correlate(sigmaResults, yaraResults);
Console.WriteLine($"Score: {correlation.CompositeScore} | Threat: {correlation.ThreatLevel}");
```

### FFI Bridge (Rust ↔ C#)
```csharp
// SentryCore.cs proporciona P/Invoke
var handle = SentryCore.sentryguard_init();
SentryCore.sentryguard_process_event(handle, eventJson);
var metrics = SentryCore.sentryguard_get_metrics(handle);
SentryCore.sentryguard_shutdown(handle);
```

### Kernel Driver (IOCTL)
```csharp
// Ejemplo de uso desde user-mode
using var driver = new SentryGuardDriver();

// Registrar cliente
var clientInfo = new ClientInfo { FilterMask = 0xFFFF };
driver.RegisterClient(clientInfo);

// Esperar eventos (async)
var events = driver.WaitForEvents(timeoutMs: 1000);

// Procesar eventos
foreach (var evt in events)
{
    Console.WriteLine($"Event: {evt.EventType} | PID: {evt.ProcessId}");
}
```

---

## Optimización de Rendimiento

### RuleIndex (Prefiltado)
```
ANTES: 3,085 reglas evaluadas por evento
DESPUÉS: 162 reglas aplicables para PowerShell/EventID 4104 (94.7% reducción);
         1,531 de media en eventos Sysmon del catálogo (50.4% global)

Cómo funciona:
1. Evento llega con logsource (ej: "powershell")
2. RuleIndex.GetApplicableRules("powershell", 4104)
3. Retorna solo reglas de PowerShell con EventID 4104
4. EvaluationEngine evalúa solo esas reglas
```

### YaraCache (Caché Hash)
```
ANTES: Escanear cada archivo cada vez
DESPUÉS: Archivos duplicados saltan en O(1)

Cómo funciona:
1. Calcular SHA-256 del archivo
2. Buscar en caché → si existe, retornar resultado
3. Si no existe, extraer features PE (imports, secciones, entropía)
4. Prefiltado: si entropía > 7.0 = packed → solo escanea categorías relevantes
5. Guardar en caché para próximas veces
```

### RuleDeduplicator (Eliminación Duplicados)
```
ANTES: 3,085 reglas
DESPUÉS: ~2,800 reglas (9% reducción)

Cómo funciona:
1. Agrupar reglas con mismo detection tree (hash SHA-256)
2. Detectar fuzzy duplicates (>80% similitud en nombre)
3. Mantener versión más completa (severidad, MITRE, etc.)
```

### AlertPrioritizer (Scoring + Throttling)
```
ANTES: Todas las alertas van al SOC
DESPUÉS: Solo Top-50 alertas prioritarias

Cómo funciona:
1. Scoring: severity × confidence × bonuses (MITRE +20%, ransomware +40%)
2. Throttling: 5 min cooldown por regla
3. Supresión: Falsos positivos conocidos se filtran
4. Top-50: Solo las más relevantes
```

---

## MITRE ATT&CK Coverage

### Tácticas Cubiertas (13)
| Táctica | ID | Reglas |
|---------|-----|--------|
| Execution | TA0002 | 642 |
| Persistence | TA0003 | 351 |
| Credential Access | TA0006 | 272 |
| Defense Evasion | TA0005 | 245 |
| Privilege Escalation | TA0004 | 198 |
| Discovery | TA0007 | 187 |
| Lateral Movement | TA0008 | 156 |
| Collection | TA0009 | 134 |
| Impact | TA0040 | 112 |
| Command and Control | TA0011 | 98 |

### Top Técnicas
| Técnica | ID | Reglas |
|---------|-----|--------|
| Scripting Interpreter | T1059 | 214 |
| Binary Proxy Execution | T1218 | 178 |
| Forge Credentials | T1685 | 165 |
| Scheduled Task | T1053 | 142 |
| Process Injection | T1055 | 128 |

---

## Integración con EDR

### Flujo de Datos
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Windows    │     │  Kernel     │     │  User Mode  │
│  Events     │────►│  Driver     │────►│  Collector  │
│  (ETW)      │     │  (WFP)      │     │  (Service)  │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  SOC        │◄────│  Alert      │◄────│  SentryGuard│
│  Dashboard  │     │  Prioritizer│     │  Engine     │
└─────────────┘     └─────────────┘     └─────────────┘
```

### API de Integración
```csharp
// 1. Inicializar motor
var engine = SentryGuardEngine.Initialize(config);

// 2. Registrar callback de eventos
engine.OnEventReceived += (event) => {
    // Tu lógica aquí
};

// 3. Registrar callback de alertas
engine.OnAlertGenerated += (alert) => {
    // Enviar a SIEM/SOC
};

// 4. Iniciar recolección
engine.Start();

// 5. Enviar eventos del kernel
engine.ProcessKernelEvent(kernelEvent);
```

### Configuración
```json
{
  "sentryguard": {
    "sigma_rules_path": "Rules/sigma/all",
    "yara_rules_path": "Rules/yara_json",
    "enable_rule_index": true,
    "enable_yara_cache": true,
    "enable_deduplication": true,
    "alert_throttle_seconds": 300,
    "max_alerts_per_minute": 100,
    "log_level": "INFO"
  }
}
```

---

## Estructura de Directorios

```
SentryGuard/
├── src/
│   ├── driver/                    # Kernel Driver (C/C++)
│   │   ├── inc/                   # Headers
│   │   ├── src/                   # Source files (13 archivos)
│   │   ├── shared/                # IOCTL protocol
│   │   └── test/                  # Tests
│   │
│   ├── core/                      # Rust Core Engine
│   │   ├── src/                   # 10 módulos
│   │   └── Cargo.toml             # Configuración Rust
│   │
│   └── SentryGuard.Rules/         # C# Rule Engine
│       ├── Engine/                # Motores de evaluación
│       ├── Models/                # Modelos de datos
│       ├── Interop/               # FFI Bridge
│       ├── Rules/                 # Reglas (Sigma + YARA)
│       └── Program.cs             # Demo
│
├── docs/
│   └── kernel/                    # Documentación kernel
│
├── scripts_test/                  # Scripts y herramientas
│   ├── 01_sigma_rules/            # Sigma - conversión
│   ├── 02_yara_rules/             # YARA - conversión
│   ├── 03_csharp_engine/          # C# - fixes
│   ├── 04_rust_core/              # Rust - módulos
│   ├── 05_kernel_driver/          # Driver - fases
│   ├── 06_optimization/           # Optimización
│   ├── 07_mitre/                  # MITRE enrichment
│   └── 08_correlation/            # Correlación
│
├── Rules/
│   ├── sigma/all/                 # 3,085 reglas Sigma JSON
│   └── yara_json/                 # 5,933 reglas YARA JSON
│
└── README.md                      # Este archivo
```

---

## Desarrollo

### Build Completo
```powershell
# C# Engine
dotnet build src/SentryGuard.Rules/SentryGuard.Rules.csproj

# Rust Core (requiere Rust)
cd src/core && cargo build --release

# Kernel Driver (requiere WDK)
msbuild src/driver /p:Configuration=Release /p:Platform=x64
```

### Ejecutar Demo
```powershell
dotnet run --project src/SentryGuard.Rules/SentryGuard.Rules.csproj
```

### Ejecutar Tests
```powershell
dotnet test src/SentryGuard.Rules/SentryGuard.Rules.csproj
```

---

## Roadmap

- [x] Sigma rules (3,085)
- [x] YARA rules (5,933)
- [x] MITRE enrichment (404 techniques)
- [x] Correlation engine
- [x] Performance optimization (RuleIndex, YaraCache)
- [x] Kernel driver (telemetry)
- [x] FFI bridge (Rust ↔ C#)
- [ ] Unit tests
- [ ] Integration tests
- [ ] Benchmark suite
- [ ] Docker deployment
- [ ] REST API
- [ ] Grafana dashboards

---

## Licencia

MIT License

---

## Autor

**Nakano-04** | 2026-07-05
