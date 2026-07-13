# CloudSec-Auditor

Auditor de configuración de seguridad en entornos cloud (AWS, Azure, GCP).

> **ADVERTENCIA**: Solo para entornos autorizados. Requiere credenciales legítimas.

## Características

- **Escáner de S3 Buckets** — detección de buckets públicos y logging
- **Escáner de Security Groups** — reglas abiertas (0.0.0.0/0)
- **Escáner de IAM** — usuarios sin MFA, políticas excesivas
- **Escáner de bases de datos** — RDS/Cloud SQL expuestos públicamente
- **Escáner de logging** — CloudTrail/Activity Log habilitado
- **Análisis de riesgos** con scoring por severidad
- **Mapping CIS Benchmark** y OWASP Cloud Top 10
- **Reportes JSON + HTML** con visualizaciones
- **CLI Click** completo

## Aviso Legal

Esta herramienta se proporciona únicamente con fines educativos y para auditorías de seguridad autorizadas. El usuario asume toda la responsabilidad de garantizar que cuenta con la autorización adecuada.

**Al usar este software, aceptas que:**
- Solo lo usarás en cuentas cloud que poseas o para las que tengas autorización explícita
- No realizarás cambios destructivos sin supervisión
- Los autores no asumen responsabilidad por uso indebido

## Requisitos

- Python 3.11+

```bash
git clone https://github.com/Shadow-King-Cyber/CloudSec-Auditor.git
cd CloudSec-Auditor
pip install -r requirements.txt
```

## Inicio Rápido

```bash
# Escaneo completo de seguridad
cloudsec-auditor full-scan --provider aws

# Escaneo de buckets S3
cloudsec-auditor s3-scan

# Escaneo de Security Groups
cloudsec-auditor sg-scan

# Escaneo de IAM
cloudsec-auditor iam-scan

# Escaneo de RDS
cloudsec-auditor rds-scan

# Ver mapping CIS Benchmark
cloudsec-auditor mapping

# Generar reporte
cloudsec-auditor report
```

## Comandos del CLI

```bash
# Escaneo completo
cloudsec-auditor full-scan --provider aws
cloudsec-auditor full-scan --provider azure
cloudsec-auditor full-scan --provider gcp

# Escaneos individuales
cloudsec-auditor s3-scan
cloudsec-auditor sg-scan
cloudsec-auditor iam-scan
cloudsec-auditor rds-scan
cloudsec-auditor logging-scan --provider aws

# Mapping de seguridad
cloudsec-auditor mapping

# Generar reporte
cloudsec-auditor report
```

## Estructura del Proyecto

```
CloudSec-Auditor/
├── cloud_sec_auditor/
│   ├── core/           # AuditLogger, Config
│   ├── scanners/       # S3Scanner, SGScanner, IAMScanner, RDSScanner, LoggingScanner
│   ├── analysis/       # RiskAnalyzer
│   ├── scoring/        # CloudScoring con CIS Benchmark mapping
│   ├── reporting/      # Reportes JSON/HTML
│   └── ui/             # CLI Click
├── tests/              # Suite de tests con pytest
├── requirements.txt    # Dependencias de Python
├── pyproject.toml      # Configuración del proyecto
└── LICENSE             # Licencia MIT
```

## Ejecutar Tests

```bash
pytest -v
```

## Licencia

MIT License — ver [LICENSE](LICENSE)
