import json
import re
from pathlib import Path
from typing import Any


class SarifReportWriter:
    def __init__(self, output_path: Path):
        self.output_path = Path(output_path)
        self.rules: dict[str, dict[str, Any]] = {}
        self.results: list[dict[str, Any]] = []

    def write(self, findings: list[Any], include_errors: bool = False) -> None:
        self.add_security_findings(findings, include_errors=include_errors)
        self.save()

    def add_security_findings(
        self, findings: list[Any], include_errors: bool = False
    ) -> None:
        for finding in findings:
            if self._get(finding, "is_error", False) and not include_errors:
                continue

            rule_id = self._safe_rule_id(
                self._get(finding, "check_id")
                or self._get(finding, "category")
                or "gitsec-security-check"
            )

            self._add_result(
                rule_id=rule_id,
                name=self._get(finding, "title") or rule_id,
                message=self._get(finding, "evidence")
                or self._get(finding, "title")
                or rule_id,
                severity=self._get(finding, "severity"),
                uri=self._get(finding, "resource") or "unknown",
                description=self._get(finding, "description")
                or self._get(finding, "evidence")
                or "",
                remediation=self._get(finding, "remediation") or "",
                reference_url=self._get(finding, "reference_url") or "",
                properties={
                    "type": "security-check",
                    "category": self._get(finding, "category") or "",
                    "resource": self._get(finding, "resource") or "",
                    "notes": self._get(finding, "notes") or "",
                },
            )

    def add_secret_findings(self, findings: list[Any]) -> None:
        for finding in findings:
            secret_type = (
                self._get(finding, "secret_type")
                or self._get(finding, "type")
                or self._get(finding, "category")
                or "secret"
            )

            file_path = (
                self._get(finding, "file_path")
                or self._get(finding, "filename")
                or self._get(finding, "file")
                or self._get(finding, "resource")
                or "unknown"
            )

            line_number = (
                self._get(finding, "line_number")
                or self._get(finding, "line")
                or self._get(finding, "start_line")
            )

            rule_id = self._safe_rule_id(f"secret-{secret_type}")

            self._add_result(
                rule_id=rule_id,
                name=f"Exposed {secret_type}",
                message=self._get(finding, "evidence")
                or f"Exposed {secret_type} detected",
                severity="Critical",
                uri=file_path,
                line_number=line_number,
                description=self._get(finding, "description")
                or f"A {secret_type} was detected in the repository.",
                remediation=self._get(finding, "remediation")
                or "Rotate this credential immediately. Remove it from repository history and replace it everywhere it was used.",
                reference_url=self._get(finding, "reference_url") or "",
                properties={
                    "type": "secret",
                    "secret_type": secret_type,
                    "repository": self._get(finding, "repository")
                    or self._get(finding, "resource")
                    or "",
                    "resource": self._get(finding, "resource") or "",
                },
            )

    def add_dependency_findings(
        self,
        vulnerabilities: list[Any],
        deprecated_packages: list[dict[str, Any]] | None = None,
        unpinned_dependencies: list[dict[str, Any]] | None = None,
    ) -> None:
        for finding in vulnerabilities:
            package = self._get(finding, "package") or "dependency"
            advisory_id = self._get(finding, "advisory_id") or package
            rule_id = self._safe_rule_id(f"dependency-{advisory_id}")

            self._add_result(
                rule_id=rule_id,
                name=self._get(finding, "title") or f"Vulnerable dependency: {package}",
                message=self._get(finding, "title") or f"Vulnerability found in {package}",
                severity=self._get(finding, "severity"),
                uri=self._get(finding, "file_path") or self._get(finding, "repository") or "unknown",
                description=(
                    f"Package {package}"
                    f" {self._get(finding, 'version') or ''}"
                    f" has a known vulnerability."
                ).strip(),
                remediation="Update the dependency to a secure version.",
                reference_url=self._get(finding, "url") or "",
                properties={
                    "type": "dependency",
                    "repository": self._get(finding, "repository") or "",
                    "package": package,
                    "version": self._get(finding, "version") or "",
                    "ecosystem": self._get(finding, "ecosystem") or "",
                    "advisory_id": advisory_id,
                    "cvss_score": self._get(finding, "cvss_score") or "",
                },
            )

        for package in deprecated_packages or []:
            name = package.get("Package", "dependency")
            rule_id = self._safe_rule_id("dependency-deprecated")

            self._add_result(
                rule_id=rule_id,
                name="Deprecated dependency",
                message=f"Deprecated dependency detected: {name}",
                severity="Low",
                uri=package.get("File") or package.get("Repository") or "unknown",
                description="A deprecated dependency was detected.",
                remediation="Review the dependency and replace it with a maintained alternative where possible.",
                reference_url="",
                properties={
                    "type": "dependency",
                    "dependency_status": "deprecated",
                    "repository": package.get("Repository", ""),
                    "package": name,
                    "version": package.get("Version", ""),
                    "ecosystem": package.get("Ecosystem", ""),
                },
            )

        for package in unpinned_dependencies or []:
            name = package.get("Package", "dependency")
            rule_id = self._safe_rule_id("dependency-unpinned")

            self._add_result(
                rule_id=rule_id,
                name="Unpinned dependency",
                message=f"Unpinned dependency detected: {name}",
                severity="Low",
                uri=package.get("File") or package.get("Repository") or "unknown",
                description="An unpinned dependency was detected.",
                remediation="Pin the dependency version to improve reproducibility and reduce supply-chain risk.",
                reference_url="",
                properties={
                    "type": "dependency",
                    "dependency_status": "unpinned",
                    "repository": package.get("Repository", ""),
                    "package": name,
                    "version": package.get("Version", ""),
                    "ecosystem": package.get("Ecosystem", ""),
                },
            )

    def save(self) -> None:
        self.output_path.write_text(
            json.dumps(self._build_sarif(), indent=2),
            encoding="utf-8",
        )

    def _add_result(
        self,
        rule_id: str,
        name: str,
        message: str,
        severity: str | None,
        uri: str,
        description: str = "",
        remediation: str = "",
        reference_url: str = "",
        line_number: int | str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> None:
        if rule_id not in self.rules:
            rule = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {"text": description or message},
                "help": {"text": remediation or ""},
            }

            if reference_url:
                rule["helpUri"] = reference_url

            self.rules[rule_id] = rule

        physical_location: dict[str, Any] = {
            "artifactLocation": {
                "uri": str(uri or "unknown"),
            }
        }

        normalized_line = self._normalize_line(line_number)
        if normalized_line:
            physical_location["region"] = {
                "startLine": normalized_line,
            }

        result = {
            "ruleId": rule_id,
            "level": self._map_level(severity),
            "message": {
                "text": message,
            },
            "locations": [
                {
                    "physicalLocation": physical_location,
                }
            ],
        }

        if properties:
            result["properties"] = properties

        self.results.append(result)

    def _build_sarif(self) -> dict[str, Any]:
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "gitsec",
                            "informationUri": "https://github.com/aplite-de/gitsec",
                            "rules": list(self.rules.values()),
                        }
                    },
                    "results": self.results,
                }
            ],
        }

    def _map_level(self, severity: str | None) -> str:
        severity_value = (severity or "").lower()

        if severity_value in {"critical", "high"}:
            return "error"
        if severity_value == "medium":
            return "warning"
        if severity_value == "low":
            return "note"

        return "none"

    def _safe_rule_id(self, value: str) -> str:
        safe_value = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(value).strip().lower())
        return safe_value.strip("-") or "gitsec-finding"

    def _normalize_line(self, value: int | str | None) -> int | None:
        if value is None:
            return None

        try:
            line = int(value)
        except (TypeError, ValueError):
            return None

        return line if line > 0 else None

    def _get(self, item: Any, key: str, default: Any = None) -> Any:
        if isinstance(item, dict):
            return item.get(key, default)

        return getattr(item, key, default)