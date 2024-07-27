from py_watchdog import py_watchdog
from py_watchdog.py_watchdog import VulnerablePackage
import typer
from rich.console import Console
import os
from pathlib import Path
import re
import time

app = typer.Typer(name="py_watchdog")
CONSOLE = Console(soft_wrap=True)
VERSION = "0.0.1"
_URL_PATTERN = r"^(https:\/\/|http:\/\/|www\.|git@)(github|gitlab)\.com(\/[\w.-]+){2,}$"


@app.command()
def main(
    path: str = typer.Argument(
        help="Path to the file or directory to check vulnerabilities"
    ),
    dont_fail: bool = typer.Option(
        False,
        "--dont-fail",
        "-d",
        help="Don't fail if vulnerable packages are found",
    ),
) -> None:
    is_dir = Path(path).is_dir()
    _invocation_path = os.getcwd()
    is_url = bool(re.match(_URL_PATTERN, path))

    CONSOLE.rule(f":dog: PyWatchdog v{VERSION}")
    CONSOLE.print(f"Checking {path} for vulnerable packages...")

    start_time = time.time()
    vuln_pkgs: list[VulnerablePackage] = py_watchdog.main(path, is_dir, is_url)
    execution_time = time.time() - start_time

    if vuln_pkgs:
        CONSOLE.print(
            f"Found {len(vuln_pkgs)} vulnerable package{'s' if len(vuln_pkgs) > 1 else ''} in {execution_time:.4f}s"
        )

        for pkg in vuln_pkgs:
            CONSOLE.rule(style="red")
            CONSOLE.print(
                f"[bold red]Package:[/bold red] {pkg.pkg_name} [bold red]Version:[/bold red] {pkg.vuln_version}\n"
                + f"[bold green]Fixed version:[/bold green] {pkg.fixed_version}\n"
                + f"[red]Vuln ID:[/red] {pkg.vuln_id} [red]Aliases[/red]: {pkg.vuln_aliases}\n"
                + f"Location: {pkg.path}"
            )

        if not dont_fail:
            raise typer.Exit(code=1)

    CONSOLE.print(f"No vulnerable packages found in {execution_time:.4f}s")


if __name__ == "__main__":
    app()
