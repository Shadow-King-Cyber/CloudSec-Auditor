# CloudSec-Auditor

Auditor de configuración de seguridad en entornos cloud (AWS, Azure, GCP).

> **ADVERTENCIA**: Solo para entornos autorizados. Requiere credenciales legítimas.

## Características

- **Escáner de S3 Buckets** — detección de buckets públicos
- **Escáner de Security Groups** — reglas abiertas (0.0.0.0/0)
- **Escáner de IAM** — usuarios sin MFA, políticas excesivas
- **Escáner de bases de datos** — RDS/Cloud SQL expuestos públicamente
- **Escáner de logging** — CloudTrail/Activity Log habilitado
- **Análisis de riesgos** con scoring por severidad
- **Mapping CIS Benchmark** y OWASP Cloud Top 10
- **CLI Click** completo
- **Reportes JSON + HTML** con Chart.js

## Instalación

```bash
git clone https://github.com/Shadow-King-Cyber/CloudSec-Auditor.git
cd CloudSec-Auditor
pip install -r requirements.txt
```

## Uso

```bash
# Escaneo completo
cloudsec-auditor full-scan --provider aws

# Escaneo de S3
cloudsec-auditor s3-scan

# Escaneo de Security Groups
cloudsec-auditor sg-scan

# Ver mapping CIS
cloudsec-auditor mapping

# Generar reporte
cloudsec-auditor report
```

## Licencia

MIT License — Shadow-King-Cyber
