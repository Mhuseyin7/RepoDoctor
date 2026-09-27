from pathlib import Path

from fastapi.testclient import TestClient

from repodoctor.api import create_app
from repodoctor.config import Config
from repodoctor.engine import scan
from repodoctor.fixes import planned_fixes
from repodoctor.reporters import write_report


def test_safe_fix_is_previewable_and_opt_in(tmp_path: Path) -> None:
    changes = planned_fixes(tmp_path, Config())
    assert len(changes) == 1
    assert not (tmp_path / ".gitignore").exists()
    changes[0].apply()
    assert ".env" in (tmp_path / ".gitignore").read_text(encoding="utf-8")


def test_writes_sarif_report(tmp_path: Path) -> None:
    result = scan(tmp_path, config=Config())
    destination = tmp_path / "reports" / "scan.sarif"
    write_report(result, "sarif", destination)
    assert '"version": "2.1.0"' in destination.read_text(encoding="utf-8")


def test_dashboard_api_persists_local_scan(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REPODOCTOR_ALLOWED_ROOTS", str(tmp_path))
    database = tmp_path / "dashboard.db"
    app = create_app(f"sqlite:///{database.as_posix()}")
    with TestClient(app) as client:
        response = client.post("/api/scans", json={"path": str(tmp_path)})
        assert response.status_code == 201, response.text
        scan_id = response.json()["id"]
        assert client.get(f"/api/scans/{scan_id}").status_code == 200
        repositories = client.get("/api/repositories")
        assert repositories.status_code == 200
        assert repositories.json()[0]["path"] == str(tmp_path)
