import argparse
import json
from pathlib import Path

from app.risk.cbom import (
    create_cbom,
    generate_policy,
    save_cbom,
)
from app.scanner.python_ast import scan_file


def run_scan(input_file: str, output_file: str) -> dict:
    """
    Run the complete scanning pipeline:

        Source → Scanner → Findings → Risk → CBOM
    """

    print(f"Scanning: {input_file}")

    # --------------------------------------------------------------
    # 1. Scan the source file
    # --------------------------------------------------------------

    findings = scan_file(input_file)

    print(f"Findings discovered: {len(findings)}")

    # --------------------------------------------------------------
    # 2. Generate the CBOM
    # --------------------------------------------------------------

    cbom = create_cbom(findings)

    # --------------------------------------------------------------
    # 3. Save the CBOM
    # --------------------------------------------------------------

    save_cbom(cbom, output_file)

    # --------------------------------------------------------------
    # 4. Generate crypto-agility policy
    # --------------------------------------------------------------

    policy_output = "../../generated/config.yaml"

    generate_policy(
        cbom,
        policy_output,
    )

    return cbom


def main():
    parser = argparse.ArgumentParser(
        description="PQC-Agility-Lab crypto scanner"
    )

    parser.add_argument(
        "input",
        help="Python source file to scan",
    )

    parser.add_argument(
        "--output",
        default="../../generated/cbom.json",
        help="Output CBOM JSON file",
    )

    args = parser.parse_args()

    cbom = run_scan(
        input_file=args.input,
        output_file=args.output,
    )

    print()
    print("Scan complete.")
    print(
        f"Total findings: "
        f"{cbom['summary']['total_findings']}"
    )
    print(
        f"Quantum-vulnerable findings: "
        f"{cbom['summary']['quantum_vulnerable']}"
    )


if __name__ == "__main__":
    main()