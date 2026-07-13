"""Tests para el scoring cloud."""

from cloud_sec_auditor.scoring.cloud_scoring import CloudScoring


def test_calculate_score_clean():
    scoring = CloudScoring()
    result = scoring.calculate_score({})
    assert result.score == 100
    assert result.grade == "A+"


def test_calculate_score_with_findings():
    scoring = CloudScoring()
    result = scoring.calculate_score({"Critico": 2, "Alto": 3, "Medio": 5})
    assert result.score < 100
    assert result.total_findings == 10


def test_calculate_score_worst():
    scoring = CloudScoring()
    result = scoring.calculate_score({"Critico": 10, "Alto": 10, "Medio": 10, "Bajo": 10})
    assert result.score == 0
    assert result.grade == "F"


def test_cis_mapping():
    scoring = CloudScoring()
    mapping = scoring.get_cis_mapping()
    assert "S3.1" in mapping
    assert "SG.1" in mapping
    assert len(mapping) == 5
