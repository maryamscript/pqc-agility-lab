import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.scanner.python_ast import CryptoFinding
from app.risk.scoring import RiskInput, calculate_risk, classify_risk


def get_algorithm_weight(finding: CryptoFinding) -> float:
    """
    Determine the algorithm/key-size weighting.

    These values are project-specific and are intended
    for demonstrating risk prioritization.
    """

    if finding.primitive == "RSA":
        if finding.key_size is not None:
            if finding.key_size <= 2048:
                return 2.0

            if finding.key_size <= 3072:
                return 1.5

            return 1.0

        return 2.0

    if finding.primitive == "ECC":
        return 2.0

    return 1.0


def create_cbom(
    findings: list[CryptoFinding],
    data_value: float = 10.0,
    exposure_weight: float = 1.5,
) -> dict[str, Any]:
    """
    Convert scanner findings into a CBOM document.
    """

    components = []

    for finding in findings:
        algorithm_weight = get_algorithm_weight(finding)

        risk_input = RiskInput(
            crypto_strength=10.0
            if finding.quantum_vulnerable
            else 2.0,
            algorithm_weight=algorithm_weight,
            data_value=data_value,
            exposure_weight=exposure_weight,
        )

        risk_score = calculate_risk(risk_input)
        risk_level = classify_risk(risk_score)

        component = {
            "file": finding.file,
            "line": finding.line,
            "column": finding.column,
            "primitive": finding.primitive,
            "library": finding.library,
            "key_size": finding.key_size,
            "curve": finding.curve,
            "quantum_vulnerable": finding.quantum_vulnerable,
            "evidence": finding.evidence,
            "risk": {
                "score": risk_score,
                "level": risk_level,
            },
        }

        components.append(component)

    return {
        "cbom_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": len(findings),
            "quantum_vulnerable": sum(
                finding.quantum_vulnerable for finding in findings
            ),
        },
        "components": components,
    }


def save_cbom(
    cbom: dict[str, Any],
    output_path: str = "../../generated/cbom.json",
) -> None:
    """
    Save the CBOM as formatted JSON.
    """

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as output_file:
        json.dump(cbom, output_file, indent=2)

    print(f"CBOM written to: {path}")

def generate_policy(
    cbom: dict[str, Any],
    output_path: str = "../../generated/config.yaml",
) -> None:
    """
    Generate a crypto-agility policy from the CBOM.

    The policy instructs the future C++ shim to use
    a PQC-hybrid configuration when quantum-vulnerable
    public-key cryptography is discovered.
    """

    quantum_vulnerable = cbom["summary"]["quantum_vulnerable"]

    if quantum_vulnerable > 0:
        crypto_mode = "PQC_HYBRID"
    else:
        crypto_mode = "CLASSICAL"

    policy = {
        "version": 1,
        "crypto_mode": crypto_mode,
        "pqc": {
            "algorithm": "ML-KEM-768",
        },
        "classical": {
            "enabled": True,
            "fallback": True,
        },
        "policy": {
            "RSA": {
                "action": "migrate",
                "replacement": "ML-KEM-768",
            },
            "ECC": {
                "action": "migrate",
                "replacement": "ML-KEM-768",
            },
        },
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        import yaml
    except ImportError:
        raise RuntimeError(
            "PyYAML is required. Run: pip install pyyaml"
        )

    with path.open("w", encoding="utf-8") as output_file:
        yaml.safe_dump(
            policy,
            output_file,
            sort_keys=False,
        )

    print(f"Policy written to: {path}")