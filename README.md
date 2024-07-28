# 🐶 immunipy

<p align="center">
    <em>A Python SCA tool that acts as a watchdog, keeping an eye out for security vulnerabilities and reporting them promptly, written in Rust.</em>
</p>

<p align="center">
    <a href="https://sonarcloud.io/summary/new_code?id=rohaquinlop_immunipy" target="_blank">
        <img src="https://sonarcloud.io/api/project_badges/measure?project=rohaquinlop_immunipy&metric=alert_status" alt="Quality Gate">
    </a>
    <a href="https://pypi.org/project/immunipy" target="_blank">
        <img src="https://img.shields.io/pypi/v/immunipy?color=%2334D058&label=pypi%20package" alt="Package version">
    </a>
</p>

**immunipy** analyses the Python dependencies of your project and checks for security vulnerabilities.

## Features

- **Security Vulnerabilities**: immunipy checks for security vulnerabilities on real time in your Python dependencies.
- **Fast and Lightweight**: immunipy is written in Rust, which makes it fast and lightweight.
- **CI/CD Integration**: You can use immunipy in your CI/CD pipeline.
- **Easy to Use**: immunipy is easy to use.

## Requirements

- Python >= 3.7

- It's necessary to have your Python dependencies in a `requirements.txt` file or a `poetry.lock` file.

## Installation

You can install immunipy using pip:

```bash
pip install immunipy
```

## Usage


To check for security vulnerabilities in your Python dependencies, run:

**requirements.txt**

```bash
immunipy /path/to/requirements.txt
```

**poetry.lock**

```bash
immunipy /path/to/poetry.lock
```

**Project directory**

```bash
immunipy /path/to/your/project/directory
```

**Git project URL**

```bash
immunipy https://your-git-project
```


**Example:**

```bash
$ immunipy ./tests
```

Output:
```bash
────────────────── 🐶 immunipy v0.0.1 ───────────────────
Checking . for vulnerable packages...
 [00:00:01] ########################################       2/2       Done!
Found 2 vulnerable packages in 1.4394s
─────────────────────────────────────────────────────────
Package: jinja2 Version: 2.4.1
Fixed version: 3.1.4
Vuln ID: GHSA-h75v-3vvj-5mfj Aliases: ['CVE-2024-34064']
Location: ./tests/poetry.lock
─────────────────────────────────────────────────────────
Package: jinja2 Version: 2.4.1
Fixed version: 3.1.4
Vuln ID: GHSA-h75v-3vvj-5mfj Aliases: ['CVE-2024-34064']
Location: ./tests/requirements.txt
```

### Options

- `--dont-fail` or `-d`: Don't return a non-zero exit code if vulnerabilities are found.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
