import csv
import os
from pathlib import Path
from typing import List

import typer

from ..models import Finding
from ..output import ExcelReportWriter, HtmlReportWriter, format_security_check_results


def get_token_or_exit(cli_token: str | None) -> str:
    if cli_token:
        return cli_token

    env_token = os.getenv("GITHUB_TOKEN")
    if env_token:
        return env_token

    typer.echo(
        "Error: GitHub token is required. Use --token or set GITHUB_TOKEN.", err=True
    )
    raise typer.Exit(code=1)


def write_results_to_csv(rows: List[Finding], output_path: str) -> None:
    if not rows:
        return

    fieldnames = [
        "check_id",
        "resource",
        "evidence",
        "notes",
        "timestamp",
        "title",
        "severity",
        "category",
        "description",
        "risk",
        "remediation",
        "reference_url",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for finding in rows:
            w.writerow(finding.to_dict())


def print_summary(rows: List[Finding]) -> None:
    if not rows:
        return

    errors = [f for f in rows if f.is_error]
    security_findings = [f for f in rows if not f.is_error]

    if security_findings:
        typer.echo(f"\nFound {len(security_findings)} security issue(s):")
        for finding in security_findings[:5]:
            severity_color = {
                "Critical": typer.colors.RED,
                "High": typer.colors.RED,
                "Medium": typer.colors.YELLOW,
                "Low": typer.colors.WHITE,
            }.get(finding.severity or "", typer.colors.WHITE)

            typer.secho(
                f"  [{finding.severity}] {finding.title}",
                fg=severity_color,
                bold=(finding.severity in ["Critical", "High"]),
            )

        if len(security_findings) > 5:
            typer.echo(f"  ... and {len(security_findings) - 5} more")

    if errors:
        typer.echo(f"\nFound {len(errors)} error(s):")
        for error in errors[:5]:
            error_msg = error.evidence
            if error.notes:
                error_msg += f": {error.notes}"
            typer.secho(f"  ⚠ {error_msg}", fg=typer.colors.YELLOW)

        if len(errors) > 5:
            typer.echo(f"  ... and {len(errors) - 5} more")


def write_outputs(
    findings: List[Finding], base_filename: str, output_folder: Path, formats: List[str]
) -> List[str]:
    output_paths = []
    output_folder.mkdir(parents=True, exist_ok=True)

    if "csv" in formats:
        csv_path = output_folder / f"{base_filename}.csv"
        format_security_check_results(findings, csv_path)
        output_paths.append(str(csv_path))

    if "xls" in formats:
        xls_path = output_folder / f"{base_filename}.xlsx"
        writer = ExcelReportWriter(xls_path)

        parts = base_filename.split("_")
        if len(parts) >= 3 and parts[0] == "security" and parts[1] == "checks":
            repo_name = parts[-1]
            sheet_name = f"sec_checks_{repo_name}"
        else:
            sheet_name = base_filename
        writer.add_security_findings(findings, sheet_name=sheet_name)
        writer.add_summary_sheet(security_findings=findings)
        writer.save()
        output_paths.append(str(xls_path))

    if "html" in formats:
        html_path = output_folder / f"{base_filename}.html"
        writer = HtmlReportWriter(html_path)
        writer.add_security_findings(findings)
        writer.save()
        output_paths.append(str(html_path))
    
    return output_paths
