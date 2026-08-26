# GitHub Actions Security Auditor

![CI](https://github.com/KaanTuran28/GitHub-Actions-Security-Auditor/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A static security auditor for GitHub Actions workflow files. Flags the CI/CD supply-chain and script-injection patterns documented by GitHub's own security guidance and tools like `zizmor`/StepSecurity — the same class of issue behind real incidents like the 2025 `tj-actions/changed-files` compromise.

### Overview

- **`pull_request_target` + PR-head checkout** — the classic setup that runs base-repo secrets against attacker-controlled code from a fork's PR.
- **Self-hosted runner on `pull_request`** — a fork's PR can execute arbitrary code directly on your own infrastructure.
- **Unpinned third-party actions** — `uses: owner/action@v1` (a mutable tag) instead of a full commit SHA; a compromised or re-tagged release silently changes what the step runs. First-party `actions/*`/`github/*` actions are excluded from this specific check to keep the signal-to-noise ratio high.
- **Untrusted input interpolated into `run:`** — an issue/PR/comment title or body substituted directly into a shell script is a documented script-injection vector (GitHub's own security lab has written about this extensively).
- **Secrets echoed to logs** — a `run:` step that explicitly prints a `secrets.*` value.
- **`permissions: write-all`** — at the workflow or job level.

### Installation

Requires Python 3.9+ and `PyYAML`.

```bash
git clone <this-repo>
cd GitHub-Actions-Security-Auditor
pip install -e .
```

This installs a `github-actions-security-auditor` command. You can also run the script directly with `python github_actions_security_auditor.py` after `pip install -r requirements.txt`.

### Usage

```bash
github-actions-security-auditor --path .github/workflows/ci.yml --output report.md
github-actions-security-auditor --path .github/workflows/ --format json --output report.json
```

| Flag | Default | Description |
|---|---|---|
| `--path` | *(required)* | A single workflow file, or a directory (e.g. `.github/workflows`) to scan recursively |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

### CI Integration

Run this against your own workflows before merging a change to `.github/workflows/`:

```bash
github-actions-security-auditor --path .github/workflows/ --fail-on high
```

```yaml
# GitHub Actions step
- name: Audit GitHub Actions workflows
  run: github-actions-security-auditor --path .github/workflows/ --fail-on high
```

This project's own [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) passes its own audit with zero findings.

### Example Output

[`sample_workflows/insecure_example.yml`](./sample_workflows/insecure_example.yml) demonstrates every check above; [`sample_workflows/hardened_example.yml`](./sample_workflows/hardened_example.yml) is its fixed counterpart (`env:`-indirection instead of direct interpolation, GitHub-hosted runner, SHA-pinned third-party action, scoped `permissions: contents: read`) and produces **zero findings**. See [`sample_report.md`](./sample_report.md) — real output from scanning `insecure_example.yml`: 4 HIGH, 2 MEDIUM.

### A PyYAML gotcha worth knowing

PyYAML follows YAML 1.1, which parses a bare `on:` key as the **boolean `True`**, not the string `"on"` — so `yaml.safe_load("on: push\n...")` produces a dict with key `True`, not `"on"`. Since every GitHub Actions workflow starts with `on:`, this project's `get_triggers()` explicitly checks both `workflow.get("on")` and `workflow.get(True)` — verified directly in the test suite (`test_get_triggers_handles_pyyaml_bare_on_gotcha`) so a future refactor can't silently reintroduce it.

### Limitations

Static and heuristic — it doesn't resolve reusable/composite workflows (`uses: ./.github/workflows/other.yml` or a called workflow's own permissions), doesn't evaluate `if:` conditions, and its "untrusted input" pattern list, while covering the most common documented vectors, isn't exhaustive. Treat it as a fast first pass, not a replacement for a full audit tool like `zizmor`.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Project Structure

```
GitHub-Actions-Security-Auditor/
├── github_actions_security_auditor.py
├── pyproject.toml
├── sample_workflows/
│   ├── insecure_example.yml
│   └── hardened_example.yml
├── sample_report.md
├── tests/
│   └── test_github_actions_security_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

GitHub Actions workflow dosyaları için statik bir güvenlik denetleyicisi. GitHub'ın kendi güvenlik rehberliği ve `zizmor`/StepSecurity gibi araçlar tarafından belgelenen CI/CD tedarik zinciri (supply-chain) ve script-injection kalıplarını tespit eder — 2025'teki `tj-actions/changed-files` ihlali gibi gerçek olayların arkasındaki sorun sınıfının aynısı.

### Genel Bakış

- **`pull_request_target` + PR-head checkout** — base repo sırlarının (secrets), fork'tan gelen bir PR'daki saldırgan kontrolündeki koda karşı çalıştırıldığı klasik kurulum.
- **`pull_request` üzerinde self-hosted runner** — bir fork'un PR'ı, doğrudan kendi altyapınızda keyfi kod çalıştırabilir.
- **Sabitlenmemiş (pinlenmemiş) üçüncü taraf action'lar** — tam bir commit SHA'sı yerine `uses: owner/action@v1` (değiştirilebilir bir tag); ele geçirilmiş veya yeniden etiketlenmiş bir sürüm, adımın ne çalıştırdığını sessizce değiştirir. Birinci taraf `actions/*`/`github/*` action'ları, sinyal-gürültü oranını yüksek tutmak için bu özel kontrolün dışında tutulur.
- **`run:` içine interpolasyonla eklenen güvenilmeyen girdi** — bir issue/PR/yorum başlığının veya gövdesinin doğrudan bir shell script'ine yerleştirilmesi belgelenmiş bir script-injection vektörüdür (GitHub'ın kendi güvenlik laboratuvarı bu konuda kapsamlı yazılar yazmıştır).
- **Loglara yankılanan sırlar** — bir `secrets.*` değerini açıkça yazdıran bir `run:` adımı.
- **`permissions: write-all`** — workflow veya job seviyesinde.

### Kurulum

Python 3.9+ ve `PyYAML` gerektirir.

```bash
git clone <this-repo>
cd GitHub-Actions-Security-Auditor
pip install -e .
```

Bu, bir `github-actions-security-auditor` komutu kurar. `pip install -r requirements.txt` sonrasında doğrudan `python github_actions_security_auditor.py` ile de scripti çalıştırabilirsiniz.

### Kullanım

```bash
github-actions-security-auditor --path .github/workflows/ci.yml --output report.md
github-actions-security-auditor --path .github/workflows/ --format json --output report.json
```

| Bayrak (Flag) | Varsayılan | Açıklama |
|---|---|---|
| `--path` | *(zorunlu)* | Tek bir workflow dosyası, veya recursive olarak taranacak bir dizin (örn. `.github/workflows`) |
| `--output` | `sample_report.md` | Raporun yazılacağı dosya yolu |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium`, veya `high` — bu ciddiyet seviyesinde veya üzerinde bir bulgu varsa çıkış kodu `1` olur |

### CI Entegrasyonu

`.github/workflows/` içindeki bir değişikliği merge etmeden önce, bunu kendi workflow'larınıza karşı çalıştırın:

```bash
github-actions-security-auditor --path .github/workflows/ --fail-on high
```

```yaml
# GitHub Actions step
- name: Audit GitHub Actions workflows
  run: github-actions-security-auditor --path .github/workflows/ --fail-on high
```

Bu projenin kendi [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) dosyası, kendi denetiminden sıfır bulguyla geçer.

### Örnek Çıktı

[`sample_workflows/insecure_example.yml`](./sample_workflows/insecure_example.yml) yukarıdaki her kontrolü örnekler; [`sample_workflows/hardened_example.yml`](./sample_workflows/hardened_example.yml) ise düzeltilmiş karşılığıdır (doğrudan interpolasyon yerine `env:` dolaylı yönlendirmesi, GitHub-hosted runner, SHA ile sabitlenmiş üçüncü taraf action, kapsamı daraltılmış `permissions: contents: read`) ve **sıfır bulgu** üretir. `insecure_example.yml` taramasından gerçek çıktı için [`sample_report.md`](./sample_report.md) dosyasına bakın: 4 HIGH, 2 MEDIUM.

### Bilinmesi Gereken Bir PyYAML Tuzağı

PyYAML, YAML 1.1'i takip eder; bu da çıplak (bare) bir `on:` anahtarını `"on"` string'i olarak değil, **boolean `True`** olarak ayrıştırır — yani `yaml.safe_load("on: push\n...")`, anahtarı `"on"` değil `True` olan bir dict üretir. Her GitHub Actions workflow'u `on:` ile başladığından, bu projenin `get_triggers()` fonksiyonu hem `workflow.get("on")` hem de `workflow.get(True)`'yu açıkça kontrol eder — bu davranış doğrudan test suite'inde (`test_get_triggers_handles_pyyaml_bare_on_gotcha`) doğrulanır, böylece ileride yapılacak bir refactor bu sorunu sessizce yeniden ortaya çıkaramaz.

### Sınırlamalar

Statik ve sezgiseldir (heuristic) — yeniden kullanılabilir/composite workflow'ları (`uses: ./.github/workflows/other.yml` veya çağrılan bir workflow'un kendi izinleri) çözümlemez, `if:` koşullarını değerlendirmez ve "güvenilmeyen girdi" kalıp listesi, en yaygın belgelenmiş vektörleri kapsamakla birlikte kapsamlı değildir. Bunu, `zizmor` gibi tam kapsamlı bir denetim aracının yerine değil, hızlı bir ilk geçiş olarak değerlendirin.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Proje Yapısı

```
GitHub-Actions-Security-Auditor/
├── github_actions_security_auditor.py
├── pyproject.toml
├── sample_workflows/
│   ├── insecure_example.yml
│   └── hardened_example.yml
├── sample_report.md
├── tests/
│   └── test_github_actions_security_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
