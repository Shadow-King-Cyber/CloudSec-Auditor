"""Scoring de seguridad cloud."""

from dataclasses import dataclass


@dataclass
class CloudScore:
    """Resultado de scoring cloud."""
    total_findings: int
    critico: int
    alto: int
    medio: int
    score: int
    grade: str


class CloudScoring:
    """Calcula el score de seguridad de un entorno cloud."""

    SEVERITY_WEIGHTS = {"Critico": 20, "Alto": 12, "Medio": 5, "Bajo": 2}

    GRADE_THRESHOLDS = [
        (90, "A+"), (80, "A"), (70, "B+"), (60, "B"),
        (50, "C+"), (40, "C"), (30, "D"), (0, "F"),
    ]

    def calculate_score(self, severity_summary: dict[str, int]) -> CloudScore:
        critico = severity_summary.get("Critico", 0)
        alto = severity_summary.get("Alto", 0)
        medio = severity_summary.get("Medio", 0)
        bajo = severity_summary.get("Bajo", 0)
        total = critico + alto + medio + bajo

        deductions = (
            critico * self.SEVERITY_WEIGHTS["Critico"]
            + alto * self.SEVERITY_WEIGHTS["Alto"]
            + medio * self.SEVERITY_WEIGHTS["Medio"]
            + bajo * self.SEVERITY_WEIGHTS["Bajo"]
        )

        score = max(0, 100 - deductions)
        grade = self._get_grade(score)

        return CloudScore(
            total_findings=total,
            critico=critico,
            alto=alto,
            medio=medio,
            score=score,
            grade=grade,
        )

    def _get_grade(self, score: int) -> str:
        for threshold, grade in self.GRADE_THRESHOLDS:
            if score >= threshold:
                return grade
        return "F"

    def get_cis_mapping(self) -> dict[str, str]:
        return {
            "S3.1": "CIS AWS 2.1.1 — S3 Bucket acceso público",
            "SG.1": "CIS AWS 5.2 — Security Groups abiertos",
            "IAM.1": "CIS AWS 1.4 — Root MFA",
            "RDS.1": "CIS AWS 2.3.1 — RDS acceso público",
            "CT.1": "CIS AWS 3.1 — CloudTrail habilitado",
        }
