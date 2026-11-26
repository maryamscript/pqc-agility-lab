
import json
import yaml

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.scanner.python_ast import CryptoFinding
from app.risk.scoring import (
    RiskInput,
    calculate_risk,
    classify_risk,
)


# --------------------------------------------------------------
# Project output directory
# --------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[3]
GENERATED_DIR = PROJECT_ROOT / "generated"


# --------------------------------------------------------------
# Algorithm weighting
# --------------------------------------------------------------

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


# --------------------------------------------------------------
# CBOM creation
# --------------------------------------------------------------

def create_cbom(
    findings: list[CryptoFinding],
    data_value: float = 10.0,
    exposure_weight: float = 1.5,
) -> dict[str, Any]:
    """
    Convert scanner findings into a Cryptography
    Bill of Materials (CBOM).
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
                finding.quantum_vulnerable
                for finding in findings
            ),
        },
        "components": components,
    }


# --------------------------------------------------------------
# Save CBOM as JSON
# --------------------------------------------------------------

def save_cbom(
    cbom: dict[str, Any],
    output_path: str | Path = GENERATED_DIR / "cbom.json",
) -> None:
    """
    Save the CBOM as a formatted JSON file.
    """

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open("w", encoding="utf-8") as output_file:

        json.dump(
            cbom,
            output_file,
            indent=2,
        )

    print(f"CBOM written to: {path}")


# --------------------------------------------------------------
# Crypto-agility policy creation
# --------------------------------------------------------------

def create_policy(
    cbom: dict[str, Any],
) -> dict[str, Any]:
    """
    Create a crypto-agility policy from CBOM findings.

    This function returns a policy dictionary without
    writing anything to disk.
    """

    vulnerable_count = cbom["summary"]["quantum_vulnerable"]

    if vulnerable_count > 0:
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
            "fallback": False,
        },

        "policy": {
            "RSA": {
                "action": "review_and_migrate",
                "key_establishment": "ML-KEM-768",
                "signature": "ML-DSA",
            },

            "ECC": {
                "action": "review_and_migrate",
                "key_establishment": "ML-KEM-768",
                "signature": "ML-DSA",
            },
        },
    }

    return policy


# --------------------------------------------------------------
# Save crypto-agility policy as YAML
# --------------------------------------------------------------

def generate_policy(
    cbom: dict[str, Any],
    output_path: str | Path = GENERATED_DIR / "config.yaml",
) -> None:
    """
    Generate a crypto-agility policy and save it
    as a YAML configuration file.
    """

    policy = create_policy(cbom)

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open("w", encoding="utf-8") as output_file:

        yaml.safe_dump(
            policy,
            output_file,
            sort_keys=False,
        )

    print(f"Policy written to: {path}")
