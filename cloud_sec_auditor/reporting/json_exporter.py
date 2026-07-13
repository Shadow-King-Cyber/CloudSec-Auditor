"""Exportación de reportes a JSON."""

import json
from pathlib import Path
from typing import Any


class JsonExporter:
    """Exporta reportes a formato JSON."""

    def __init__(self, output_dir: str | Path = "reports") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, data: dict[str, Any], filename: str = "report.json") -> Path:
        output = self._output_dir / filename
        output.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return output
