from dataclasses import dataclass


@dataclass
class RiskInput:
    """
    Inputs used by the PQC-Agility-Lab risk model.
    """

    crypto_strength: float
    algorithm_weight: float
    data_value: float
    exposure_weight: float


def calculate_risk(inputs: RiskInput) -> float:
    """
    Project-specific risk formula:

        Risk = (S_crypto × W_alg) + (V_data × W_exp)
    """

    risk = (
        inputs.crypto_strength * inputs.algorithm_weight
        + inputs.data_value * inputs.exposure_weight
    )

    return round(risk, 2)


def classify_risk(score: float) -> str:
    """
    Convert a numerical score into a simple severity category.
    """

    if score >= 20:
        return "CRITICAL"

    if score >= 15:
        return "HIGH"

    if score >= 8:
        return "MEDIUM"

    return "LOW"