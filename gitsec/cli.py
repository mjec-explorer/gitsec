import csv
import threading
import time
from pathlib import Path
from typing import List, Optional

import typer

from .core.config_loader import load_config, merge_cli_args
from .core.github_api import GitHubClient
from .core.repo_filter import (
    filter_repositories,
    get_repository_branch,
    should_skip_secrets_scanning,
    should_skip_dependencies_scanning,
    get_enabled_security_modules,
    get_disabled_security_modules,
)
from .models.finding import DependencyFinding
from .modules.dependency_scanning.scanner import DependencyScanner
from .modules.secret_scanning.secrets import (
    scan_local_repository,
    scan_organization_repositories,
    scan_remote_repository,
)
from .output import (
    ExcelReportWriter,
    format_dependency_findings,
    format_secret_findings,
)
from .utils import MODULES, get_token_or_exit, print_summary
from .utils.cli_utils import write_outputs
from .version import __version__

app = typer.Typer(help="GitHub Security Posture Management CLI Tool")


@app.command("security-checks")
def security_checks(
    ctx: typer.Context,
    modules: List[str] = typer.Argument(
        None,
        help="Module names to run (e.g., org-mfa repo-pr-required) or special values: all-org, all-repo",
    ),
    org: Optional[str] = typer.Option(
        None, help="Organization login (required for org-level checks)"
    ),
    repo: Optional[str] = typer.Option(
        None, help="Repository in 'owner/repo' form (required for repo-level checks)"
    ),
    branch: Optional[str] = typer.Option(
        None, help="Branch name to check (only for repo-level checks, defaults to default branch)"
    ),
    base_url: str = typer.Option("https://api.github.com", help="GitHub API base URL"),
    token: Optional[str] = typer.Option(
        None, "--token", envvar="GITHUB_TOKEN", help="GitHub PAT"
    ),
    out_folder: str = typer.Option("out", "--out-folder", help="Output folder"),
    format: str = typer.Option(
        "xls", "--format", help="Output format: csv, xls, or csv,xls for both"
    ),
    max_repos: int = typer.Option(
        100, help="Maximum repositories for org-user-access check (0 for unlimited)"
    ),
):
    """
    Run one or more security checks.

    \b
    Examples:
      gitsec security_checks org-mfa org-sso --org myorg
      gitsec security_checks repo-pr-required --repo owner/repo
      gitsec security_checks all-org --org myorg
      gitsec security_checks all-repo --repo owner/repo

    \b
    Available modules:
      Org-level: org-mfa, org-sso, org-members-can-create-repos,
                 org-default-repo-permission, org-commit-signing, org-pr-required,
                 org-push-protection, org-tag-deletion-protection,
                 org-secrets-scope, org-runners-scope, org-user-access

      Repo-level: repo-commit-signing, repo-pr-required, repo-push-protection,
                  repo-tag-deletion-protection, repo-runners-scope

    \b
    Special values:
      all-org   - Run all organization-level checks
      all-repo  - Run all repository-level checks
    """

    if not modules:
        typer.echo(ctx.get_help())
        raise typer.Exit()

    modules_to_run = []
    for module_name in modules:
        if module_name == "all-org":
            modules_to_run.extend(
                [m for m, config in MODULES.items() if config.scope == "org"]
            )
        elif module_name == "all-repo":
            modules_to_run.extend(
                [m for m, config in MODULES.items() if config.scope == "repo"]
            )
        else:
            modules_to_run.append(module_name)

    modules_to_run = list(dict.fromkeys(modules_to_run))

    invalid_modules = [m for m in modules_to_run if m not in MODULES]
    if invalid_modules:
        typer.echo(f"Error: Unknown modules: {', '.join(invalid_modules)}", err=True)
        typer.echo(
            f"\nAvailable modules: {', '.join(sorted(MODULES.keys()))}", err=True
        )
        raise typer.Exit(code=1)

    if repo and "/" not in repo:
        typer.echo("Error: --repo must be in the form 'owner/repo'", err=True)
        raise typer.Exit(code=1)

    formats = [f.strip() for f in format.split(",")]
    valid_formats = ["csv", "xls", "html"]
    invalid_formats = [f for f in formats if f not in valid_formats]
    if invalid_formats:
        typer.echo(f"Error: Invalid format(s): {', '.join(invalid_formats)}", err=True)
        typer.echo(f"Valid formats: {', '.join(valid_formats)}", err=True)
        raise typer.Exit(code=1)

    token = get_token_or_exit(cli_token=token)
    client = GitHubClient(token=token, base_url=base_url)
    output_dir = Path(out_folder)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []

    typer.echo(f"\nRunning {len(modules_to_run)} security check(s)...\n")

    for module_name in modules_to_run:
        config = MODULES[module_name]

        if config.scope == "org" and not org:
            typer.echo(
                f"Error: Module {module_name} requires --org parameter", err=True
            )
            raise typer.Exit(code=1)
        if config.scope == "repo" and not repo:
            typer.echo(
                f"Error: Module {module_name} requires --repo parameter", err=True
            )
            raise typer.Exit(code=1)

        try:
            if config.scope == "org":
                if config.requires_max_repos:
                    rows = list(
                        config.run_func(client=client, org=org, max_repos=max_repos)
                    )
                else:
                    rows = list(config.run_func(client=client, org=org))
            else:
                rows = list(config.run_func(client=client, repo=repo, branch=branch))

            all_findings.extend(rows)

        except Exception as e:
            typer.echo(f"Error running {module_name}: {e}", err=True)
            raise typer.Exit(code=1)

    security_findings_total = len([f for f in all_findings if not f.is_error])
    error_count = len([f for f in all_findings if f.is_error])
    
    typer.echo(f"Completed {len(modules_to_run)} check(s):")
    typer.echo(f"  Security findings: {security_findings_total}")
    if error_count > 0:
        typer.echo(f"  Errors/warnings: {error_count}")
    
    if all_findings:
        print_summary(all_findings)
        
        base_name = "security_checks"
        if org:
            base_name = f"security_checks_{org}"
        elif repo:
            base_name = f"security_checks_{repo.replace('/', '_')}"

        output_paths = write_outputs(all_findings, base_name, output_dir, formats)
        typer.echo("\nResults written to:")
        for path in output_paths:
            typer.echo(f"  - {path}")
    
    if security_findings_total == 0 and error_count == 0:
        typer.secho("\n✓ No security issues found", fg=typer.colors.GREEN, bold=True)
    elif security_findings_total == 0 and error_count > 0:
        typer.secho("\n✓ No security issues found (some checks had errors)", fg=typer.colors.YELLOW)

@app.command("scan-dependencies")
def scan_dependencies(
    ctx: typer.Context,
    repo: Optional[str] = typer.Option(
        None, "--repo", help="Remote repository in 'owner/repo' form"
    ),
    org: Optional[str] = typer.Option(
        None, "--org", help="Organization login to scan all repositories"
    ),
    local_repo: Optional[str] = typer.Option(
        None, "--local-repo", help="Local repository path"
    ),
    base_url: str = typer.Option("https://api.github.com", help="GitHub API base URL"),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="GITHUB_TOKEN",
        help="GitHub token (required for remote scanning)",
    ),
    out_folder: str = typer.Option("out", "--out-folder", help="Output folder"),
    format: str = typer.Option(
        "xls", "--format", help="Output format: csv, xls, or csv,xls for both"
    ),
):
    """
    Scan repository dependencies for known vulnerabilities using deps.dev.

    Specify exactly one of: --repo, --org, or --local-repo
    """

    provided_options = sum([bool(repo), bool(org), bool(local_repo)])
    if provided_options != 1:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=1)

    results = []

    if local_repo:
        typer.echo(f"Scanning dependencies in local repository: {local_repo}...")
        with DependencyScanner() as scanner:
            result = scanner.scan_repository(local_path=local_repo)
            if result:
                results.append(result)
    else:
        if not token:
            token = get_token_or_exit(cli_token=token)
        client = GitHubClient(token=token, base_url=base_url)

        if repo:
            typer.echo(f"Scanning dependencies in remote repository: {repo}...")
            owner, repo_name = repo.split("/")
            with DependencyScanner(client) as scanner:
                result = scanner.scan_repository(owner=owner, repo=repo_name)
                if result:
                    results.append(result)
        elif org:
            typer.echo(f"Scanning dependencies in organization: {org}...")
            repo_list = client.rest_paginate(
                f"/orgs/{org}/repos", params={"per_page": 100}
            )

            typer.echo(f"Found {len(repo_list)} repositories in {org}")

            with DependencyScanner(client) as scanner:
                for repo_data in repo_list:
                    repo_full = repo_data["full_name"]
                    owner, repo_name = repo_full.split("/")
                    typer.echo(f"Scanning {repo_full}...")
                    result = scanner.scan_repository(owner=owner, repo=repo_name)
                    if result:
                        results.append(result)

    if not results:
        typer.echo("No results to report", err=True)
        raise typer.Exit(code=1)

    formats = [f.strip() for f in format.split(",")]
    valid_formats = ["csv", "xls", "html"]
    invalid_formats = [f for f in formats if f not in valid_formats]
    if invalid_formats:
        typer.echo(f"Error: Invalid format(s): {', '.join(invalid_formats)}", err=True)
        typer.echo(f"Valid formats: {', '.join(valid_formats)}", err=True)
        raise typer.Exit(code=1)

    output_dir = Path(out_folder)
    output_dir.mkdir(parents=True, exist_ok=True)

    vuln_findings = []
    deprecated_list = []
    unpinned_list = []

    for result in results:
        for vuln in result.vulnerabilities:
            vuln_findings.append(
                DependencyFinding(
                    repository=result.repo,
                    package=vuln.dependency.name,
                    version=vuln.dependency.version,
                    ecosystem=vuln.dependency.ecosystem,
                    file_path=vuln.dependency.file_path,
                    severity=vuln.severity,
                    advisory_id=vuln.advisory.id,
                    title=vuln.advisory.title,
                    cvss_score=vuln.advisory.cvss3_score or "N/A",
                    url=vuln.advisory.url,
                )
            )

        for dep in result.deprecations:
            deprecated_list.append(
                {
                    "Repository": result.repo,
                    "Package": dep.dependency.name,
                    "Version": dep.dependency.version,
                    "Ecosystem": dep.dependency.ecosystem,
                    "File": dep.dependency.file_path,
                }
            )

        for unpinned in result.unpinned_dependencies:
            unpinned_list.append(
                {
                    "Repository": result.repo,
                    "Package": unpinned.dependency.name,
                    "Version": unpinned.dependency.raw_version
                    or unpinned.dependency.version,
                    "Ecosystem": unpinned.dependency.ecosystem,
                    "File": unpinned.dependency.file_path,
                }
            )

    typer.echo(f"\n{'='*60}")
    typer.echo(f"Scanned {len(results)} repository(ies)")

    total_deps = sum(r.total_dependencies for r in results)
    total_vulns = len(vuln_findings)
    total_deprecated = len(deprecated_list)
    total_unpinned = len(unpinned_list)

    typer.echo(f"Total dependencies: {total_deps}")
    typer.echo(f"Total vulnerabilities: {total_vulns}")
    typer.echo(f"Total deprecated packages: {total_deprecated}")
    typer.echo(f"Total unpinned dependencies: {total_unpinned}")

    if total_vulns > 0:
        critical = sum(1 for v in vuln_findings if v.severity == "critical")
        high = sum(1 for v in vuln_findings if v.severity == "high")
        medium = sum(1 for v in vuln_findings if v.severity == "medium")
        low = sum(1 for v in vuln_findings if v.severity == "low")

        typer.echo("\nVulnerability breakdown:")
        if critical:
            typer.secho(f"  Critical: {critical}", fg=typer.colors.RED, bold=True)
        if high:
            typer.secho(f"  High: {high}", fg=typer.colors.RED)
        if medium:
            typer.secho(f"  Medium: {medium}", fg=typer.colors.YELLOW)
        if low:
            typer.secho(f"  Low: {low}", fg=typer.colors.WHITE)

    output_paths = []
    base_name = "dependency_scan"
    if org:
        base_name = f"dependency_scan_{org}"
    elif repo:
        base_name = f"dependency_scan_{repo.replace('/', '_')}"

    if "csv" in formats:
        if vuln_findings:
            vuln_path = output_dir / "dependency_vulnerabilities.csv"
            format_dependency_findings(vuln_findings, vuln_path)
            output_paths.append(str(vuln_path))

        if deprecated_list:
            dep_path = output_dir / "deprecated_packages.csv"
            with open(dep_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(deprecated_list[0].keys()))
                writer.writeheader()
                writer.writerows(deprecated_list)
            output_paths.append(str(dep_path))

        if unpinned_list:
            unpinned_path = output_dir / "unpinned_dependencies.csv"
            with open(unpinned_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(unpinned_list[0].keys()))
                writer.writeheader()
                writer.writerows(unpinned_list)
            output_paths.append(str(unpinned_path))

    if "xls" in formats:
        xls_path = output_dir / f"{base_name}.xlsx"
        xls_writer = ExcelReportWriter(xls_path)
        xls_writer.add_dependency_findings(
            vuln_findings, deprecated_list, unpinned_list
        )
        xls_writer.add_summary_sheet(
            dependency_findings=vuln_findings,
            deprecated_packages=deprecated_list,
            unpinned_dependencies=unpinned_list,
        )
        xls_writer.save()
        output_paths.append(str(xls_path))

    typer.echo("\nResults written to:")
    for path in output_paths:
        typer.echo(f"  - {path}")


@app.command("scan-secrets")
def scan_secrets(
    ctx: typer.Context,
    repo: Optional[str] = typer.Option(
        None, "--repo", help="Remote repository in 'owner/repo' form"
    ),
    org: Optional[str] = typer.Option(
        None, "--org", help="Organization login to scan all repositories"
    ),
    local_repo: Optional[str] = typer.Option(
        None, "--local-repo", help="Local repository path"
    ),
    base_url: str = typer.Option("https://api.github.com", help="GitHub API base URL"),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="GITHUB_TOKEN",
        help="GitHub token (required for remote scanning)",
    ),
    out_folder: str = typer.Option("out", "--out-folder", help="Output folder"),
    format: str = typer.Option(
        "xls", "--format", help="Output format: csv, xls, or csv,xls for both"
    ),
):
    """
    Scan repositories for secrets using detect-secrets.

    Specify exactly one of: --repo, --org, or --local-repo
    """

    provided_options = sum([bool(repo), bool(org), bool(local_repo)])
    if provided_options != 1:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=1)

    formats = [f.strip() for f in format.split(",")]
    valid_formats = ["csv", "xls", "html"]
    invalid_formats = [f for f in formats if f not in valid_formats]
    if invalid_formats:
        typer.echo(f"Error: Invalid format(s): {', '.join(invalid_formats)}", err=True)
        typer.echo(f"Valid formats: {', '.join(valid_formats)}", err=True)
        raise typer.Exit(code=1)

    output_dir = Path(out_folder)
    output_dir.mkdir(parents=True, exist_ok=True)

    secret_findings = []

    if local_repo:
        secret_findings = list(scan_local_repository(local_repo))

    else:
        if not token:
            token = get_token_or_exit(cli_token=token)

        client = GitHubClient(token=token, base_url=base_url)

        if repo:
            secret_findings = list(scan_remote_repository(repo, client))
        elif org:
            secret_findings = list(scan_organization_repositories(org, client))

    secrets_found = len(secret_findings)
    typer.echo(f"Summary: {secrets_found} secrets found")

    if secrets_found > 0:
        typer.secho(
            f"{secrets_found} secrets detected!", fg=typer.colors.RED, bold=True
        )
    else:
        typer.secho("No secrets found", fg=typer.colors.GREEN)

    if secret_findings:
        output_paths = []
        base_name = "secret_scan"
        if org:
            base_name = f"secret_scan_{org}"
        elif repo:
            base_name = f"secret_scan_{repo.replace('/', '_')}"
        elif local_repo:
            base_name = f"secret_scan_{Path(local_repo).name}"

        if "csv" in formats:
            csv_path = output_dir / f"{base_name}.csv"
            format_secret_findings(secret_findings, csv_path)
            output_paths.append(str(csv_path))

        if "xls" in formats:
            xls_path = output_dir / f"{base_name}.xlsx"
            writer = ExcelReportWriter(xls_path)
            writer.add_secret_findings(secret_findings)
            writer.add_summary_sheet(secret_findings=secret_findings)
            writer.save()
            output_paths.append(str(xls_path))

        typer.echo("\nResults written to:")
        for path in output_paths:
            typer.echo(f"  - {path}")


@app.command("audit-all")
def audit_all(
    ctx: typer.Context,
    repo: Optional[str] = typer.Option(
        None, "--repo", help="Remote repository in 'owner/repo' form"
    ),
    org: Optional[str] = typer.Option(
        None, "--org", help="Organization login to scan all repositories"
    ),
    local_repo: Optional[str] = typer.Option(
        None, "--local-repo", help="Local repository path"
    ),
    branch: Optional[str] = typer.Option(
        None, help="Branch name to check (only for single repo audits, defaults to default branch)"
    ),
    base_url: str = typer.Option("https://api.github.com", help="GitHub API base URL"),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="GITHUB_TOKEN",
        help="GitHub token (required for remote scanning)",
    ),
    out_folder: str = typer.Option("out", "--out-folder", help="Output folder"),
    max_repos: int = typer.Option(
        100,
        help="Maximum repositories for secret/dependency scanning (0 for unlimited). Repos sorted by recent activity.",
    ),
    config: Optional[str] = typer.Option(
        None, "--config", help="Path to configuration file (.gitsec.yml or .gitsec.json)"
    ),
):
    """
    Run a comprehensive audit including secret scanning, dependency scanning, and security checks.

    This command orchestrates all three security modules and generates a single comprehensive
    Excel report with all findings.

    Specify exactly one of: --repo, --org, or --local-repo

    Note: Security checks are not available for local repositories.
    """
    provided_options = sum([bool(repo), bool(org), bool(local_repo)])
    if provided_options != 1:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=1)

    if repo and "/" not in repo:
        typer.echo("Error: --repo must be in the form 'owner/repo'", err=True)
        raise typer.Exit(code=1)

    try:
        gitsec_config = load_config(config)
    except ValueError as e:
        typer.echo(f"Error loading configuration: {e}", err=True)
        raise typer.Exit(code=1)

    output_dir = Path(out_folder)
    output_dir.mkdir(parents=True, exist_ok=True)

    module_progress = {
        "secrets": "Starting...",
        "dependencies": "Starting...",
        "security": "Starting...",
    }
    progress_lock = threading.Lock()

    def rate_limit_callback(message: str):
        thread_name = threading.current_thread().name
        if "Secret" in thread_name:
            key = "secrets"
        elif "Dependency" in thread_name or "Dep" in thread_name:
            key = "dependencies"
        elif "Security" in thread_name:
            key = "security"
        else:
            key = "secrets"  # default

        with progress_lock:
            module_progress[key] = f"[RATE LIMIT] {message}"

    client = None
    if not local_repo:
        if not token:
            token = get_token_or_exit(cli_token=token)
        client = GitHubClient(
            token=token, base_url=base_url, progress_callback=rate_limit_callback
        )

    if org:
        target_name = org
        target_type = "org"
    elif repo:
        target_name = repo.replace("/", "_")
        target_type = "repo"
    else:
        target_name = Path(local_repo or ".").name
        target_type = "local-repo"

    typer.echo(f"\n{'='*60}")
    typer.echo(f"Starting comprehensive audit for {target_type}: {target_name}")
    if org and max_repos > 0:
        typer.echo(
            f"Repository limit for scanning: {max_repos} (most recently updated)"
        )
        typer.echo("Note: Security checks will run on all org repositories")
    typer.echo(f"{'='*60}\n")

    limited_repos = None
    if org:
        typer.echo("Fetching organization repositories...")
        if client:
            all_repos = client.rest_paginate(
                f"/orgs/{org}/repos", params={"per_page": 100}
            )
        else:
            all_repos = []

        limited_repos = filter_repositories(all_repos, gitsec_config)
        typer.echo(
            f"Selected {len(limited_repos)} repositories (out of {len(all_repos)} total)\n"
        )

    secret_findings = []
    dependency_vulnerabilities = []
    deprecated_packages = []
    unpinned_dependencies = []
    security_findings = []

    module_errors = {}
    module_status = {
        "secrets": "pending",
        "dependencies": "pending",
        "security": "pending",
    }

    def run_secret_scanning():
        try:
            if local_repo:
                with progress_lock:
                    module_progress["secrets"] = f"Scanning {local_repo}..."
                findings = list(scan_local_repository(local_repo))
            elif repo:
                if should_skip_secrets_scanning(repo, gitsec_config):
                    with progress_lock:
                        module_progress["secrets"] = "Skipped (config)"
                    findings = []
                else:
                    with progress_lock:
                        module_progress["secrets"] = f"Scanning {repo}..."
                    findings = list(scan_remote_repository(repo, client))
            elif org:
                findings = []
                total = len(limited_repos)
                for idx, repo_data in enumerate(limited_repos, 1):
                    repo_full = repo_data["full_name"]
                    if should_skip_secrets_scanning(repo_full, gitsec_config):
                        continue
                    with progress_lock:
                        module_progress["secrets"] = (
                            f"Scanning {idx}/{total}: {repo_full}"
                        )
                    try:
                        repo_findings = list(scan_remote_repository(repo_full, client))
                        findings.extend(repo_findings)
                    except Exception:
                        pass

                    # Allow other threads to run
                    time.sleep(0.001)
            else:
                findings = []
            secret_findings.extend(findings)
            module_status["secrets"] = "completed"
        except Exception as e:
            module_status["secrets"] = "error"
            error_msg = f"Secret scanning error: {type(e).__name__}: {e}"
            module_errors["secrets"] = error_msg

    def run_dependency_scanning():
        try:
            results = []
            if local_repo:
                with progress_lock:
                    module_progress["dependencies"] = f"Scanning {local_repo}..."
                with DependencyScanner() as scanner:
                    result = scanner.scan_repository(local_path=local_repo)
                    if result:
                        results.append(result)
            elif repo:
                if should_skip_dependencies_scanning(repo, gitsec_config):
                    with progress_lock:
                        module_progress["dependencies"] = "Skipped (config)"
                else:
                    with progress_lock:
                        module_progress["dependencies"] = f"Scanning {repo}..."
                    owner, repo_name = repo.split("/")
                    with DependencyScanner(client) as scanner:
                        result = scanner.scan_repository(owner=owner, repo=repo_name)
                        if result:
                            results.append(result)
            elif org:
                with progress_lock:
                    module_progress["dependencies"] = "Initializing scanner..."
                with DependencyScanner(client) as scanner:
                    total = len(limited_repos)
                    for idx, repo_data in enumerate(limited_repos, 1):
                        repo_full = repo_data["full_name"]
                        if should_skip_dependencies_scanning(repo_full, gitsec_config):
                            continue
                        owner, repo_name = repo_full.split("/")
                        with progress_lock:
                            module_progress["dependencies"] = (
                                f"Scanning {idx}/{total}: {repo_full}"
                            )
                        try:
                            result = scanner.scan_repository(
                                owner=owner, repo=repo_name
                            )
                            if result:
                                results.append(result)
                        except Exception:
                            pass

            for result in results:
                for vuln in result.vulnerabilities:
                    dependency_vulnerabilities.append(
                        DependencyFinding(
                            repository=result.repo,
                            package=vuln.dependency.name,
                            version=vuln.dependency.version,
                            ecosystem=vuln.dependency.ecosystem,
                            file_path=vuln.dependency.file_path,
                            severity=vuln.severity,
                            advisory_id=vuln.advisory.id,
                            title=vuln.advisory.title,
                            cvss_score=vuln.advisory.cvss3_score or "N/A",
                            url=vuln.advisory.url,
                        )
                    )

                for dep in result.deprecations:
                    deprecated_packages.append(
                        {
                            "Repository": result.repo,
                            "Package": dep.dependency.name,
                            "Version": dep.dependency.version,
                            "Ecosystem": dep.dependency.ecosystem,
                            "File": dep.dependency.file_path,
                        }
                    )

                for unpinned in result.unpinned_dependencies:
                    unpinned_dependencies.append(
                        {
                            "Repository": result.repo,
                            "Package": unpinned.dependency.name,
                            "Version": unpinned.dependency.raw_version
                            or unpinned.dependency.version,
                            "Ecosystem": unpinned.dependency.ecosystem,
                            "File": unpinned.dependency.file_path,
                        }
                    )

            module_status["dependencies"] = "completed"
        except Exception as e:
            module_status["dependencies"] = "error"
            error_msg = f"Dependency scanning error: {type(e).__name__}: {e}"
            module_errors["dependencies"] = error_msg

    def run_security_checks():
        if local_repo:
            module_status["security"] = "skipped"
            with progress_lock:
                module_progress["security"] = "Skipped (local repo)"
            return

        try:
            modules_to_run = []
            if org:
                modules_to_run = [
                    m for m, config in MODULES.items() if config.scope == "org"
                ]
            elif repo:
                modules_to_run = [
                    m for m, config in MODULES.items() if config.scope == "repo"
                ]

            enabled = get_enabled_security_modules(repo, gitsec_config, modules_to_run)
            if enabled:
                modules_to_run = enabled
            disabled = get_disabled_security_modules(repo, gitsec_config)
            modules_to_run = [m for m in modules_to_run if m not in disabled]

            total = len(modules_to_run)
            for idx, module_name in enumerate(modules_to_run, 1):
                config = MODULES[module_name]
                with progress_lock:
                    module_progress["security"] = (
                        f"Running {idx}/{total}: {module_name}"
                    )
                try:
                    if config.scope == "org":
                        if config.requires_max_repos:
                            rows = list(
                                config.run_func(
                                    client=client, org=org, max_repos=max_repos
                                )
                            )
                        else:
                            rows = list(config.run_func(client=client, org=org))
                    else:
                        check_branch = get_repository_branch(repo, gitsec_config, branch)
                        rows = list(config.run_func(client=client, repo=repo, branch=check_branch))
                    security_findings.extend(rows)
                except Exception:
                    pass

            module_status["security"] = "completed"
        except Exception as e:
            module_status["security"] = "error"
            error_msg = f"Security checks error: {type(e).__name__}: {e}"
            module_errors["security"] = error_msg

    typer.echo("\nStarting parallel execution of all modules...")
    typer.echo("-" * 60)

    threads = []
    thread_secrets = threading.Thread(target=run_secret_scanning, name="SecretScanning")
    thread_deps = threading.Thread(
        target=run_dependency_scanning, name="DependencyScanning"
    )
    thread_security = threading.Thread(
        target=run_security_checks, name="SecurityChecks"
    )

    threads.extend([thread_secrets, thread_deps, thread_security])

    for t in threads:
        t.start()

    typer.echo("\nAll modules started. Progress updates every 2 seconds...")
    typer.echo("-" * 60)

    typer.echo("  ⏳ [Secrets] Starting...")
    typer.echo("  ⏳ [Dependencies] Starting...")
    if not local_repo:
        typer.echo("  ⏳ [Security] Starting...")
    else:
        typer.echo("  ⊘ [Security] Skipped (local repo)")

    any_alive = True

    while any_alive:
        time.sleep(2)
        any_alive = any([t.is_alive() for t in threads])

        with progress_lock:
            current_progress = module_progress.copy()
            current_status = module_status.copy()

        lines = []

        if current_status["secrets"] == "completed":
            status_emoji = "✓"
        elif current_status["secrets"] == "error":
            status_emoji = "✗"
        else:
            status_emoji = "⏳"
        secrets_text = current_progress["secrets"][:60]
        lines.append(f"  {status_emoji} [Secrets] {secrets_text}")

        if current_status["dependencies"] == "completed":
            status_emoji = "✓"
        elif current_status["dependencies"] == "error":
            status_emoji = "✗"
        else:
            status_emoji = "⏳"
        deps_text = current_progress["dependencies"][:60]
        lines.append(f"  {status_emoji} [Dependencies] {deps_text}")

        if current_status["security"] == "skipped":
            status_emoji = "⊘"
        elif current_status["security"] == "completed":
            status_emoji = "✓"
        elif current_status["security"] == "error":
            status_emoji = "✗"
        else:
            status_emoji = "⏳"
        security_text = current_progress["security"][:60]
        lines.append(f"  {status_emoji} [Security] {security_text}")

        output = "\033[F" * 3  # Move up 3 lines
        for line in lines:
            output += "\033[2K" + line + "\n"

        typer.echo(output, nl=False)

    for t in threads:
        t.join()

    typer.echo("\n" + "=" * 60)
    typer.echo("MODULE EXECUTION SUMMARY")
    typer.echo("=" * 60)

    typer.echo("\n[1/3] Secret Scanning")
    if module_status["secrets"] == "completed":
        secrets_count = len(secret_findings)
        if secrets_count > 0:
            typer.secho(
                f"✓ Found {secrets_count} secrets", fg=typer.colors.RED, bold=True
            )
        else:
            typer.secho("✓ No secrets found", fg=typer.colors.GREEN)
    elif module_status["secrets"] == "error":
        typer.secho(
            f"✗ Error: {module_errors.get('secrets', 'Unknown error')}",
            fg=typer.colors.RED,
        )

    typer.echo("\n[2/3] Dependency Scanning")
    if module_status["dependencies"] == "completed":
        total_vulns = len(dependency_vulnerabilities)
        total_deprecated = len(deprecated_packages)
        total_unpinned = len(unpinned_dependencies)

        typer.secho("✓ Completed", fg=typer.colors.GREEN)
        typer.echo(f"  Vulnerabilities: {total_vulns}")
        typer.echo(f"  Deprecated packages: {total_deprecated}")
        typer.echo(f"  Unpinned dependencies: {total_unpinned}")
    elif module_status["dependencies"] == "error":
        typer.secho(
            f"✗ Error: {module_errors.get('dependencies', 'Unknown error')}",
            fg=typer.colors.RED,
        )

    typer.echo("\n[3/3] Security Checks")
    if module_status["security"] == "skipped":
        typer.echo("⊘ Skipped (not available for local repositories)")
    elif module_status["security"] == "completed":

        actual_findings = [f for f in security_findings if not f.is_error]
        error_findings = [f for f in security_findings if f.is_error]

        typer.secho(
            f"✓ Completed with {len(actual_findings)} finding(s)",
            fg=typer.colors.GREEN,
        )
        if error_findings:
            typer.echo(f"  {len(error_findings)} check(s) could not be completed")
    elif module_status["security"] == "error":
        typer.secho(
            f"✗ Error: {module_errors.get('security', 'Unknown error')}",
            fg=typer.colors.RED,
        )

    typer.echo("\n" + "=" * 60)
    typer.echo("Generating comprehensive report...")
    typer.echo("=" * 60)

    xls_path = output_dir / f"audit_all_{target_name}.xlsx"
    writer = ExcelReportWriter(xls_path)

    actual_security_findings = [f for f in security_findings if not f.is_error]
    security_check_errors = [f for f in security_findings if f.is_error]

    if actual_security_findings:
        writer.add_security_findings(actual_security_findings)

    if dependency_vulnerabilities or deprecated_packages or unpinned_dependencies:
        writer.add_dependency_findings(
            dependency_vulnerabilities, deprecated_packages, unpinned_dependencies
        )

    if secret_findings:
        writer.add_secret_findings(secret_findings)

    writer.add_summary_sheet(
        security_findings=(
            actual_security_findings if actual_security_findings else None
        ),
        dependency_findings=(
            dependency_vulnerabilities if dependency_vulnerabilities else None
        ),
        secret_findings=secret_findings if secret_findings else None,
        deprecated_packages=deprecated_packages if deprecated_packages else None,
        unpinned_dependencies=unpinned_dependencies if unpinned_dependencies else None,
    )

    writer.save()

    typer.echo("\n" + "=" * 60)
    typer.echo("AUDIT SUMMARY")
    typer.echo("=" * 60)
    typer.echo(f"Target: {target_type} = {target_name}")
    typer.echo("\nResults:")
    typer.echo(f"  Secret findings: {len(secret_findings)}")
    typer.echo(f"  Dependency vulnerabilities: {len(dependency_vulnerabilities)}")
    typer.echo(f"  Deprecated packages: {len(deprecated_packages)}")
    typer.echo(f"  Unpinned dependencies: {len(unpinned_dependencies)}")
    typer.echo(f"  Security check findings: {len(actual_security_findings)}")

    critical_deps = [
        v for v in dependency_vulnerabilities if v.severity.lower() == "critical"
    ]
    critical_security = [
        f
        for f in actual_security_findings
        if f.severity and f.severity.lower() == "critical"
    ]

    total_critical = len(secret_findings) + len(critical_deps) + len(critical_security)
    total_high = len(
        [v for v in dependency_vulnerabilities if v.severity.lower() == "high"]
    ) + len(
        [
            f
            for f in actual_security_findings
            if f.severity and f.severity.lower() == "high"
        ]
    )

    typer.echo(f"\nCritical findings: {total_critical}")
    typer.echo(f"High findings: {total_high}")
    typer.echo(
        f"Total findings: {len(secret_findings) + len(dependency_vulnerabilities) + len(actual_security_findings)}"
    )

    if security_check_errors:
        typer.echo("\n" + "=" * 60)
        typer.echo("CHECKS THAT COULD NOT BE COMPLETED")
        typer.echo("=" * 60)
        typer.echo(
            f"\n{len(security_check_errors)} security check(s) could not be completed."
        )
        typer.echo("This typically indicates insufficient token permissions.\n")

        errors_by_check: dict[str, list] = {}
        for error in security_check_errors:
            check_id = error.check_id
            if check_id not in errors_by_check:
                errors_by_check[check_id] = []
            errors_by_check[check_id].append(error)

        for check_id, errors in errors_by_check.items():
            typer.echo(
                f"\n[{check_id}] {errors[0].title if errors[0].title else check_id}"
            )
            typer.echo(f"  Failed on {len(errors)} resource(s)")
            typer.echo(f"  Reason: {errors[0].evidence}")
            if errors[0].notes:
                notes = errors[0].notes
                if (
                    "403" in notes
                    or "permission" in notes.lower()
                    or "forbidden" in notes.lower()
                ):
                    typer.echo(
                        "  Action: Grant additional token permissions (e.g., 'repo', 'admin:org', 'read:org')"
                    )
                elif "404" in notes:
                    typer.echo("  Action: Verify resource exists and token has access")
                else:
                    typer.echo(
                        f"  Details: {notes[:100]}..."
                        if len(notes) > 100
                        else f"  Details: {notes}"
                    )

        typer.echo("\n" + "=" * 60)

    typer.echo(f"\n✓ Comprehensive report written to: {xls_path}")
    typer.echo("=" * 60 + "\n")


@app.command("validate-config")
def validate_config(
    config: str = typer.Option(
        None, "--config", help="Path to configuration file to validate"
    ),
):
    """
    Validate a gitsec configuration file.
    
    Checks if the configuration file is valid YAML/JSON and matches the expected schema.
    """
    if not config:
        typer.echo("Error: --config parameter is required", err=True)
        raise typer.Exit(code=1)
    
    try:
        gitsec_config = load_config(config)
        if not gitsec_config:
            typer.echo(f"Error: Configuration file not found: {config}", err=True)
            raise typer.Exit(code=1)
        
        typer.secho("✓ Configuration file is valid", fg=typer.colors.GREEN, bold=True)
        typer.echo(f"\nConfiguration summary:")
        
        if gitsec_config.target:
            if gitsec_config.target.org:
                typer.echo(f"  Target: Organization '{gitsec_config.target.org}'")
            elif gitsec_config.target.repo:
                typer.echo(f"  Target: Repository '{gitsec_config.target.repo}'")
            elif gitsec_config.target.local_repo:
                typer.echo(f"  Target: Local repository '{gitsec_config.target.local_repo}'")
        
        if gitsec_config.repositories:
            if gitsec_config.repositories.include:
                typer.echo(f"  Include patterns: {len(gitsec_config.repositories.include)}")
            if gitsec_config.repositories.exclude:
                typer.echo(f"  Exclude patterns: {len(gitsec_config.repositories.exclude)}")
            if gitsec_config.repositories.max_count:
                typer.echo(f"  Max repositories: {gitsec_config.repositories.max_count}")
        
        if gitsec_config.security_checks:
            if gitsec_config.security_checks.enabled_modules:
                typer.echo(f"  Enabled modules: {len(gitsec_config.security_checks.enabled_modules)}")
            if gitsec_config.security_checks.disabled_modules:
                typer.echo(f"  Disabled modules: {len(gitsec_config.security_checks.disabled_modules)}")
        
        if gitsec_config.repository_overrides:
            typer.echo(f"  Repository overrides: {len(gitsec_config.repository_overrides)}")
        
    except ValueError as e:
        typer.secho(f"✗ Configuration file is invalid", fg=typer.colors.RED, bold=True)
        typer.echo(f"\nError: {e}", err=True)
        raise typer.Exit(code=1)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None,
        "--version",
        callback=lambda v: print_version() if v else None,
        is_eager=True,
        help="Show the tool version and exit.",
    ),
):
    """GitHub Security Posture Management CLI Tool."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


def print_version():
    typer.echo(f"GitHub Security Tool version: {__version__}")
    raise typer.Exit()


if __name__ == "__main__":
    app()
