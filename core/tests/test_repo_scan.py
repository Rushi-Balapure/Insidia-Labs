from __future__ import annotations

import json
from pathlib import Path

from insidia import repo_scan


def _write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_any_layout_is_scanned(tmp_path: Path) -> None:
    _write(tmp_path, "app/settings.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    _write(tmp_path, "app/views.py", "import os\n\ndef run(cmd):\n    os.system(cmd)\n")
    _write(tmp_path, "web/src/page.ts", "el.innerHTML = input;\n")
    _write(tmp_path, "requirements/base.txt", "")
    _write(tmp_path, "requirements-dev.txt", "Flask==2.0.1\nrequests>=2\n")
    _write(tmp_path, "web/package.json", json.dumps({"dependencies": {"lodash": "4.17.15"}}))
    _write(tmp_path, "node_modules/x/index.js", "eval(x)\n")

    secrets = repo_scan.secrets(tmp_path)
    assert [hit.location for hit in secrets.hits] == ["app/settings.py:1"]

    sinks = repo_scan.sinks(tmp_path)
    assert {(hit.rule, hit.location) for hit in sinks.hits} == {
        ("os-system", "app/views.py:4"),
        ("inner-html", "web/src/page.ts:1"),
    }

    deps = repo_scan.dependencies(tmp_path)
    assert {hit.rule for hit in deps.hits} == {"CVE-2023-30861", "CVE-2021-23337"}


def test_safe_code_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "main.py",
        "import ast\nmodel.eval()\nast.literal_eval(s)\n# eval(x)\n"
        "yaml.load(f, Loader=yaml.SafeLoader)\npattern.exec(s)\n",
    )
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"lodash": "^4.17.15"}}))
    _write(tmp_path, "requirements.txt", "pyyaml==6.0.1\n")

    assert repo_scan.secrets(tmp_path).hits == ()
    assert repo_scan.sinks(tmp_path).hits == ()
    deps = repo_scan.dependencies(tmp_path)
    assert deps.hits == ()
    assert "osv-scanner" in deps.untested


def test_an_empty_repository_is_not_a_pass(tmp_path: Path) -> None:
    assert repo_scan.secrets(tmp_path).untested
    assert repo_scan.sinks(tmp_path).untested
    assert repo_scan.dependencies(tmp_path).untested


def test_branch_pins_and_triple_equals_are_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "requirements.txt",
        "Django==3.2.0\nurllib3==2.0.0\nWerkzeug==2.2.3rc1\nJinja2===2.10\n",
    )
    deps = repo_scan.dependencies(tmp_path)
    found = {(hit.line, hit.rule, hit.location) for hit in deps.hits}
    assert ("Django==3.2.0", "CVE-2024-27351", "requirements.txt:1") in found
    assert ("Django==3.2.0", "CVE-2022-28346", "requirements.txt:1") in found
    assert ("urllib3==2.0.0", "CVE-2023-45803", "requirements.txt:2") in found
    assert ("Werkzeug==2.2.3rc1", "CVE-2023-25577", "requirements.txt:3") in found
    assert ("Jinja2==2.10", "CVE-2020-28493", "requirements.txt:4") in found
    assert deps.untested == ""


def test_django_1_x_pins_are_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "django==1.2\n")
    _write(
        tmp_path,
        "setup.py",
        "from setuptools import setup\n"
        "setup(install_requires=[\n"
        '    "django==1.11",\n'
        "])\n",
    )
    deps = repo_scan.dependencies(tmp_path)
    found = {(hit.line, hit.rule, hit.location) for hit in deps.hits}
    assert ("django==1.2", "CVE-2022-28346", "requirements.txt:1") in found
    assert ("django==1.11", "CVE-2022-28346", "setup.py:3") in found


def test_patched_branch_versions_are_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "requirements.txt",
        "django==3.2.25\nurllib3==2.0.7\nurllib3==1.26.18\nwerkzeug==2.2.3\njinja2==3.1.4\n",
    )
    deps = repo_scan.dependencies(tmp_path)
    assert deps.hits == ()
    assert "osv-scanner" in deps.untested


def test_prereleases_sort_before_the_final_release(tmp_path: Path) -> None:
    order = ["2.2.3.dev1", "2.2.3a1", "2.2.3b1", "2.2.3rc1", "2.2.3", "2.2.3.post1"]
    parsed = [repo_scan._parse_version(text) for text in order]
    assert all(item is not None for item in parsed)
    assert parsed == sorted(parsed)
    assert repo_scan._parse_version("1.0") == repo_scan._parse_version("1.0.0")
    assert repo_scan._parse_version("Node_Fetch") is None

    assert repo_scan._normalize_name("Node_Fetch") == "node-fetch"
    assert repo_scan._normalize_name("PyYAML") == "pyyaml"
    _write(
        tmp_path,
        "requirements.txt",
        "werkzeug==2.2.3.dev1\n"
        "werkzeug==2.2.3a1\n"
        "werkzeug==2.2.3b1\n"
        "werkzeug==2.2.3rc1\n"
        "werkzeug==2.2.3\n",
    )
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"Node_Fetch": "2.6.6"}}))
    deps = repo_scan.dependencies(tmp_path)
    flagged = {hit.line for hit in deps.hits}
    assert flagged == {
        "werkzeug==2.2.3.dev1",
        "werkzeug==2.2.3a1",
        "werkzeug==2.2.3b1",
        "werkzeug==2.2.3rc1",
        "Node_Fetch==2.6.6",
    }
    assert {hit.rule for hit in deps.hits if hit.line.startswith("werkzeug")} == {"CVE-2023-25577"}
    assert {hit.rule for hit in deps.hits if "Fetch" in hit.line} == {"CVE-2022-0235"}


def test_lockfiles_and_other_manifests_are_parsed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Pipfile.lock",
        json.dumps(
            {
                "default": {"werkzeug": {"version": "==0.15.0"}},
                "develop": {"flask": {"version": "==2.0.1"}},
            },
            indent=2,
        ),
    )
    _write(
        tmp_path,
        "Pipfile",
        '[packages]\npillow = "==8.0.0"\n\n[dev-packages]\npytest = "*"\n',
    )
    _write(
        tmp_path,
        "poetry.lock",
        '[[package]]\nname = "jinja2"\nversion = "3.1.4"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "1.26.0"\n',
    )
    _write(
        tmp_path,
        "uv.lock",
        'version = 1\n\n'
        '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\nsource = { virtual = "." }\n\n'
        '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
    )
    _write(
        tmp_path,
        "setup.cfg",
        "[options]\ninstall_requires =\n    django==3.2.0\n",
    )
    _write(
        tmp_path,
        "setup.py",
        "from setuptools import setup\n"
        "setup(install_requires=[\n"
        '    "requests==2.25.0",\n'
        "])\n"
        "assert counter == 1\n",
    )
    _write(
        tmp_path,
        "pyproject.toml",
        "[project]\n"
        'dependencies = ["Jinja2===2.10", "safe-thing>=1"]\n\n'
        "[tool.poetry.dependencies]\n"
        'python = "^3.12"\n'
        'pyyaml = "5.3.1"\n',
    )
    deps = repo_scan.dependencies(tmp_path)
    by_file: dict[str, set[str]] = {}
    for hit in deps.hits:
        path, _, lineno = hit.location.rpartition(":")
        source = (tmp_path / path).read_text(encoding="utf-8").splitlines()[int(lineno) - 1]
        assert hit.line.split("==", 1)[0].lower() in source.lower()
        by_file.setdefault(path, set()).add(hit.rule)
    assert by_file["Pipfile.lock"] >= {"CVE-2023-25577", "CVE-2023-30861"}
    assert by_file["Pipfile"] == {"CVE-2022-22817"}
    assert by_file["poetry.lock"] == {"CVE-2023-45803"}
    assert by_file["uv.lock"] == {"CVE-2023-45803"}
    assert by_file["setup.cfg"] >= {"CVE-2024-27351", "CVE-2022-28346"}
    assert by_file["setup.py"] == {"CVE-2023-32681"}
    assert by_file["pyproject.toml"] >= {"CVE-2020-28493", "CVE-2020-14343"}


def test_repo_checks_report_the_units_they_counted(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "x = 1\n")
    _write(tmp_path, "notes.txt", "hello\n")
    secrets = repo_scan.secrets(tmp_path)
    assert secrets.hits == ()
    assert secrets.counted == 2
    assert secrets.unit == "file"
    sinks = repo_scan.sinks(tmp_path)
    assert sinks.hits == ()
    assert sinks.counted == 1
    assert sinks.unit == "file"

    _write(tmp_path, "requirements.txt", "pyyaml==5.3.1\n")
    deps = repo_scan.dependencies(tmp_path)
    assert deps.hits
    assert deps.counted == 1
    assert deps.unit == "dependency"

    bare = tmp_path / "empty"
    bare.mkdir()
    missed = repo_scan.dependencies(bare)
    assert missed.counted == 0
    assert missed.unit == ""
    _write(bare, "requirements.txt", "# comment only\n")
    manifests = repo_scan.dependencies(bare)
    assert manifests.hits == ()
    assert manifests.counted == 1
    assert manifests.unit == "manifest"
