# RepoDoctor

> Local-first repository health, security ve developer-experience auditor.

RepoDoctor, bir repository'nin health durumunu local ortamda analiz eden açık kaynak bir developer tool'dur. Security riskleri, CI/CD hygiene, Docker configuration, documentation, dependency ve code-quality sinyallerini deterministic rules ile inceler; source code'u çalıştırmaz ve varsayılan olarak hiçbir yere upload etmez.

**Bu açık kaynak software, [muhammedkoca.com.tr](https://muhammedkoca.com.tr) tarafından geliştirilmiştir.**

## Neden RepoDoctor?

Bir projede linter, test runner ve dependency scanner bulunabilir; ancak repository seviyesindeki temel sorunları tek bir yerden görmek çoğu zaman zordur. RepoDoctor bu boşluğu doldurur:

- Committed secret, tracked `.env`, unsafe shell execution ve dynamic evaluation gibi security sinyallerini inceler.
- Dockerfile, Docker Compose ve GitHub Actions configuration'larını gözden geçirir.
- README, LICENSE, test, `.gitignore` ve lockfile gibi project hygiene kontrollerini yapar.
- Terminal, JSON, Markdown ve GitHub Code Scanning uyumlu SARIF output üretir.
- Finding fingerprint'leri ve baseline mode ile legacy project'lerde sadece yeni sorunlara odaklanır.

RepoDoctor, language-specific linter veya vulnerability database yerine geçmez. Yanlış güven hissi üretmemek için yalnızca deterministic ve anlamlı bulgular sunmayı hedefler.

## Quick start

Gereksinim: Python **3.13+**.

```bash
pipx install git+https://github.com/Mhuseyin7/RepoDoctor.git
repodoctor scan .
```

## Self-hosted dashboard

CLI bağımsız çalışır; dashboard tamamen optional'dır. Dashboard API, scan history ve finding'leri seçtiğiniz database'e saklar. Source code yalnızca `REPODOCTOR_ALLOWED_ROOTS` içindeki local path'lerde analiz edilir.

```bash
# API: SQLite ile local development
python -m pip install -e ".[server]"
$env:REPODOCTOR_ALLOWED_ROOTS = "C:\repositories"
repodoctor serve --host 127.0.0.1 --port 8000

# Web dashboard
cd apps/web
npm install
$env:NEXT_PUBLIC_API_URL = "http://localhost:8000"
npm run dev
```

Production-like local stack için `.env.example` dosyasını `.env` olarak kopyalayın, güçlü bir `POSTGRES_PASSWORD` ayarlayın ve `docker compose up --build` çalıştırın. API `http://localhost:8000`, dashboard `http://localhost:3000` üzerinde açılır. PostgreSQL için `REPODOCTOR_DATABASE_URL` kullanılır; Alembic migration'ları `migrations/` dizinindedir.

## Release ve distribution

`v*` tag push'ları wheel ve source distribution üretir, GitHub Release oluşturur. GitHub Release publish edildiğinde PyPI trusted publishing workflow'u devreye girer; PyPI proje ayarlarında GitHub publisher olarak `Mhuseyin7/RepoDoctor` tanımlanmalıdır. Bu tasarım API token saklamaz. Publish sonrası kullanıcılar `pipx install repodoctor` ile CLI'ı kurabilir.

Local development için:

```bash
git clone https://github.com/Mhuseyin7/RepoDoctor.git
cd RepoDoctor
python -m pip install -e ".[dev]"
repodoctor scan .
```

## CLI kullanım örnekleri

```bash
# Standart terminal report
repodoctor scan .

# Machine-readable output
repodoctor scan . --format json
repodoctor scan . --format sarif
repodoctor scan . --format markdown

# Sadece high severity bulguları göster
repodoctor scan . --severity high

# CI için chosen severity seviyesinde fail et
repodoctor scan . --fail-on high

# Config oluştur, ortamı kontrol et ve bir rule'u açıkla
repodoctor init
repodoctor doctor
repodoctor explain SEC-001

# Mevcut bulgular için baseline oluştur
repodoctor baseline create
```

Exit code'lar deterministictir:

| Kod | Anlamı |
| --- | --- |
| `0` | Scan başarıyla tamamlandı. |
| `1` | `fail_on` eşiğini karşılayan finding var. |
| `2` | Configuration veya input problemi var. |
| `3` | Beklenmeyen RepoDoctor internal error oluştu. |

## Configuration

`repodoctor init`, strict validation kullanan `.repodoctor.yml` dosyasını oluşturur.

```yaml
version: 1

exclude:
  - vendor/**
  - fixtures/**

severity:
  fail_on: high

rules:
  SEC-003:
    enabled: false

ignore:
  - rule: CODE-002
    path: tests/**
    reason: Test fixture davranışı
```

`exclude`, file traversal sırasında uygulanır. `ignore` ise belirli bir rule'u yalnızca seçilen path için suppress eder; bu yaklaşım suppression kararlarının review edilebilir kalmasına yardımcı olur.

## Baseline mode

Legacy repository'lerde çok sayıda mevcut finding olabilir. Aşağıdaki komut, mevcut fingerprint'leri `.repodoctor-baseline.json` içine kaydeder:

```bash
repodoctor baseline create
```

Sonraki scan'lerde baseline'daki finding'ler gizlenir; tüm sonuçları yeniden görmek için `--no-baseline` kullanabilirsiniz.

## Built-in analiz alanları

| Alan | Örnek kontroller |
| --- | --- |
| Security | Credential-like values, tracked environment files, `eval`/`exec`, unsafe shell invocation |
| Docker | Root user ve privileged container configuration |
| CI/CD | GitHub Actions `write-all` permissions ve mutable action refs |
| Git hygiene | `.gitignore` ve environment-file exclusion |
| Documentation | README ve LICENSE varlığı |
| Testing | Conventional test file veya test directory detection |
| Dependencies | Manifest/lockfile uyumu |
| Code quality | Çok büyük source file ve boş exception handler |

Secret-like value içeren finding'lerde code excerpt redact edilir. RepoDoctor repository code'unu execute etmez; symlink, binary file ve maximum file-size kontrolleri ile scan scope'unu güvenli şekilde sınırlar.

## Output ve SARIF

JSON output CI system veya internal tooling için uygundur. SARIF 2.1.0 output, GitHub Code Scanning ile kullanılabilir:

```bash
repodoctor scan . --format sarif
repodoctor scan . --format sarif --output repodoctor.sarif
```

Her finding; rule ID, severity, confidence, file location, remediation ve stable fingerprint taşır. Bu sayede CI result'ları ve baseline karşılaştırmaları machine-readable kalır.

## GitHub Action

Repository içinde composite GitHub Action bulunur. Mevcut branch üzerinden şu şekilde kullanılabilir:

```yaml
- uses: Mhuseyin7/RepoDoctor@main
  with:
    fail-on: high
    format: sarif
```

Action, source'u yalnızca GitHub runner üzerinde install eder ve scan eder; third-party service'e source upload etmez. SARIF result'ını Code Scanning'e upload etmek için workflow'a GitHub'ın `upload-sarif` step'ini ekleyebilirsiniz.

## Architecture

```text
Repository discovery
        ↓
Safe file classification
        ↓
Built-in rule registry
        ↓
Findings + stable fingerprints
        ↓
Configuration / suppression / baseline
        ↓
Terminal, JSON, Markdown veya SARIF reporter
```

Codebase, analyzer ve rule'ların bağımsız test edilebileceği modüllere ayrılmıştır:

- `discovery`: repository root sınırları, `.gitignore`, symlink, binary ve size controls
- `rules`: deterministic built-in rule registry
- `engine`: rule filtering, scoring, suppression ve baseline behavior
- `reporters`: terminal, JSON, Markdown ve SARIF serialization
- `cli`: Typer tabanlı command interface
- `api`: FastAPI + SQLAlchemy ile opt-in scan persistence ve self-hosted endpoint'ler
- `apps/web`: Next.js, TypeScript strict mode, Tailwind ve TanStack Query dashboard

## Privacy ve güvenlik yaklaşımı

- Local-first: source code varsayılan olarak cihazınızdan çıkmaz.
- No mandatory account, telemetry veya AI API call yoktur.
- Repository code execute edilmez.
- Secret-like excerpt'ler report içinde redact edilir.
- Parser veya filesystem hataları CLI boundary'de açık bir error code ile bildirilir.

## Development

```bash
python -m pip install -e ".[dev]"
ruff format .
ruff check .
pytest
mypy src
```

Yeni rule'lar deterministic olmalı; actionable remediation içermeli; secret leak üretmemeli; detection ve false-positive senaryoları için test ile gelmelidir.

## Contributing ve security

Katkı süreci için [CONTRIBUTING.md](CONTRIBUTING.md), security report procedure için [SECURITY.md](SECURITY.md) dosyasına bakın. Bu project MIT License ile lisanslanmıştır.

---

Developed by [muhammedkoca.com.tr](https://muhammedkoca.com.tr) · Open source software for healthier repositories.
