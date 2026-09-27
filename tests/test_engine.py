from pathlib import Path

from repodoctor.baseline import create as create_baseline
from repodoctor.baseline import load as load_baseline
from repodoctor.config import Config
from repodoctor.engine import scan
from repodoctor.reporters import to_sarif


def write(root: Path, name: str, content: str) -> None:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def test_detects_secret_but_redacts_excerpt(tmp_path: Path) -> None:
    write(tmp_path, ".gitignore", ".env\n")
    write(tmp_path, "README.md", "# demo")
    write(tmp_path, "LICENSE", "MIT")
    write(tmp_path, "tests/test_demo.py", "pass")
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    write(tmp_path, "app.py", f'token = "{token}"\n')
    result = scan(tmp_path, config=Config())
    secret = next(item for item in result.findings if item.rule_id == "SEC-001")
    assert "REDACTED" in (secret.code_excerpt or "")
    assert "A1b2C3d4" not in (secret.code_excerpt or "")


def test_suppression_and_sarif(tmp_path: Path) -> None:
    write(tmp_path, ".gitignore", ".env\n")
    write(tmp_path, "README.md", "# demo")
    write(tmp_path, "LICENSE", "MIT")
    write(tmp_path, "src/app.py", "eval(user_input)\n")
    config = Config.model_validate({"ignore": [{"rule": "SEC-003", "path": "src/**"}]})
    result = scan(tmp_path, config=config)
    assert all(item.rule_id != "SEC-003" for item in result.findings)
    assert to_sarif(result)["version"] == "2.1.0"


def test_does_not_treat_documentation_strings_as_executable_code(tmp_path: Path) -> None:
    write(tmp_path, ".gitignore", ".env\n")
    write(tmp_path, "README.md", "# demo")
    write(tmp_path, "LICENSE", "MIT")
    write(tmp_path, "app.py", 'description = "Do not use eval(user_input)"\n')
    result = scan(tmp_path, config=Config())
    assert all(item.rule_id != "SEC-003" for item in result.findings)


def test_baseline_hides_existing_fingerprints(tmp_path: Path) -> None:
    write(tmp_path, "README.md", "# demo")
    first = scan(tmp_path, config=Config())
    create_baseline(tmp_path, first)
    second = scan(tmp_path, config=Config(), baseline=load_baseline(tmp_path))
    assert first.findings
    assert second.findings == []


def test_detects_insecure_docker_and_cors_configuration(tmp_path: Path) -> None:
    write(tmp_path, ".gitignore", ".env\n")
    write(tmp_path, "README.md", "# demo")
    write(tmp_path, "LICENSE", "MIT")
    write(
        tmp_path,
        "compose.yml",
        "services:\n  app:\n    privileged: true\n    network_mode: host\n"
        "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    )
    write(
        tmp_path,
        "main.py",
        'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n',
    )
    findings = {item.rule_id for item in scan(tmp_path, config=Config()).findings}
    assert {"SEC-005", "DOCKER-002", "DOCKER-003", "DOCKER-004"} <= findings
