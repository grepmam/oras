# The MIT License (MIT)
#
# Copyright (c) 2025 Marco Martel
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re


FACTOR_GROUP_SIZE = 4
LIKELIHOOD_GROUP_SIZE = 2
IMPACT_GROUP_SIZE = 2


class RiskLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


RISK_MATRIX = {
    RiskLevel.LOW: {
        RiskLevel.LOW: "Note",
        RiskLevel.MEDIUM: "Low",
        RiskLevel.HIGH: "Medium",
        RiskLevel.CRITICAL: "Medium",
    },
    RiskLevel.MEDIUM: {
        RiskLevel.LOW: "Low",
        RiskLevel.MEDIUM: "Medium",
        RiskLevel.HIGH: "High",
        RiskLevel.CRITICAL: "High",
    },
    RiskLevel.HIGH: {
        RiskLevel.LOW: "Medium",
        RiskLevel.MEDIUM: "High",
        RiskLevel.HIGH: "Critical",
        RiskLevel.CRITICAL: "Critical",
    },
}

METRIC_GROUPS = {
    "threat_agent": ["SL", "M", "O", "S"],
    "vulnerability": ["ED", "EE", "A", "ID"],
    "technical_impact": ["LC", "LI", "LAV", "LAC"],
    "business_impact": ["FD", "RD", "NC", "PV"],
}

VECTOR_REGEX = re.compile(
    r"^SL:[0-9]/M:[0-9]/O:[0-9]/S:[0-9]/ED:[0-9]/EE:[0-9]/A:[0-9]/ID:[0-9]/"
    r"LC:[0-9]/LI:[0-9]/LAV:[0-9]/LAC:[0-9]/FD:[0-9]/RD:[0-9]/NC:[0-9]/PV:[0-9]$"
)


class ORASException(Exception):
    """Custom exception for ORAS-related errors."""


class ORAS:

    def __init__(self, vector: str) -> None:
        if not self._vector_is_valid(vector):
            raise ORASException("Vector is not valid.")

        metrics = self._parse_vector(vector)
        score_groups = self._score_by_factor_groups(metrics)

        self._threat_agent_score = score_groups["threat_agent"]
        self._vulnerability_score = score_groups["vulnerability"]
        self._technical_impact_score = score_groups["technical_impact"]
        self._business_impact_score = score_groups["business_impact"]

    def _vector_is_valid(self, vector: str) -> bool:
        """Check if a vector matches the expected format."""
        return bool(VECTOR_REGEX.search(vector))

    def _parse_vector(self, vector: str) -> dict:
        """Parse the vector into a dictionary of metrics."""
        metrics = {}

        raw_metrics = vector.split("/")
        for raw_metric in raw_metrics:
            abbr, value = raw_metric.split(":")
            metrics[abbr] = int(value)

        return metrics

    def _score_by_factor_groups(self, metrics: dict) -> dict:
        """Compute the average score for each metric group."""
        result = {}

        for group_name, factor_keys in METRIC_GROUPS.items():
            total_score = sum(metrics[factor_key] for factor_key in factor_keys)
            result[group_name] = total_score / FACTOR_GROUP_SIZE

        return result

    def calculate_overall_risk_score(self) -> float:
        return self.calculate_likelihood_score() * self.calculate_impact_score()

    def calculate_likelihood_score(self) -> float:
        return (
            self._threat_agent_score + self._vulnerability_score
        ) / LIKELIHOOD_GROUP_SIZE

    def calculate_impact_score(self) -> float:
        return (
            self._technical_impact_score + self._business_impact_score
        ) / IMPACT_GROUP_SIZE

    def calculate_likelihood_level(self) -> str:
        return self._level_by_score(self.calculate_likelihood_score())

    def calculate_impact_level(self) -> str:
        return self._level_by_score(self.calculate_impact_score())

    def calculate_overall_risk_level(self) -> str:
        likelihood_level = self.calculate_likelihood_level()
        impact_level = self.calculate_impact_level()
        return RISK_MATRIX[likelihood_level][impact_level]

    def _level_by_score(self, score: float) -> str:
        """Convert a numeric score into a qualitative risk level."""
        if score <= 3.0:
            return RiskLevel.LOW
        elif score <= 6.0:
            return RiskLevel.MEDIUM
        return RiskLevel.HIGH
