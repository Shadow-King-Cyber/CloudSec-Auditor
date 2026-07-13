"""Exportación de reportes a HTML con Chart.js."""

from pathlib import Path
from typing import Any


class HtmlExporter:
    """Exporta reportes cloud a HTML con gráficos Chart.js."""

    def __init__(self, output_dir: str | Path = "reports") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, data: dict[str, Any], filename: str = "report.html") -> Path:
        summary = data.get("summary", {})
        severity = summary.get("severity_summary", {})
        provider = data.get("provider", "N/A")

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>CloudSec-Auditor — Reporte</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{ font-family: monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }}
h1 {{ color: #ff4444; }}
canvas {{ max-width: 500px; margin: 20px 0; }}
table {{ border-collapse: collapse; margin: 10px 0; }}
td, th {{ border: 1px solid #00ff41; padding: 8px; }}
</style>
</head>
<body>
<h1>CloudSec-Auditor — Reporte</h1>
<p>Provider: <strong>{provider}</strong></p>
<p>Total findings: <strong>{summary.get('total_findings', 0)}</strong></p>
<h2>Severidad</h2>
<canvas id="severityChart"></canvas>
<h2>CIS Benchmarks</h2>
<table>
<tr><th>ID</th><th>Descripción</th></tr>
{"".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in data.get('cis_mapping', {}).items())}
</table>
<script>
new Chart(document.getElementById('severityChart'), {{
  type: 'doughnut',
  data: {{
    labels: {list(severity.keys())},
    datasets: [{{data: {list(severity.values())}, backgroundColor: ['#ff0000','#ff4444','#ffaa00','#00ff41']}}]
  }}
}});
</script>
</body>
</html>"""

        output = self._output_dir / filename
        output.write_text(html, encoding="utf-8")
        return output
