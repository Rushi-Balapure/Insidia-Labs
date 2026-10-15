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
