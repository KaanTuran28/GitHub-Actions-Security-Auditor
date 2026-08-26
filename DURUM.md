# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: GitHub Actions workflow dosyalarını statik denetleyen CLI aracı — `pull_request_target` + PR-head checkout (fork PR'ının base-repo secret'larıyla kendi kodunu çalıştırması), `pull_request` tetikleyicisiyle self-hosted runner, pinlenmemiş third-party action, güvenilmeyen context (issue/PR title/body) `run:` içine doğrudan enjekte edilmesi (script injection — gerçek, dokümante edilmiş bir GitHub Actions zafiyet sınıfı), secret'ın log'a echo edilmesi, `permissions: write-all`. `tj-actions/changed-files` gibi gerçek tedarik zinciri olaylarıyla aynı sınıf.
- **Gerçek bir tasarım hatası test sırasında yakalandı ve düzeltildi**: self-hosted-runner ve job-level permissions kontrolleri yanlışlıkla `iter_steps()` (adım bazlı) döngüsünün içine yerleştirilmişti — bu da (a) adımı olmayan bir job için kontrolün hiç çalışmamasına, (b) birden fazla adımı olan bir job için kontrolün adım sayısı kadar TEKRARLANMASINA yol açıyordu (insecure_example.yml'de beklenen 4 HIGH yerine gerçekte 7 HIGH çıktı — self-hosted bulgusu 4 kez tekrarlanmıştı). Ayrı bir `iter_jobs()` fonksiyonu eklenerek job-bazlı kontroller doğru şekilde job başına bir kez çalışacak hale getirildi.
- **Dikkat edilen bir PyYAML tuzağı**: PyYAML (YAML 1.1) çıplak `on:` anahtarını string `"on"` değil, boolean `True` olarak parse ediyor — her GitHub Actions workflow'u `on:` ile başladığı için bu, bu türden bir aracı yazan herkesin karşılaşacağı gerçek bir tuzak. `get_triggers()` hem `"on"` hem `True` anahtarını kontrol ediyor, ayrı bir testle (`test_get_triggers_handles_pyyaml_bare_on_gotcha`) doğrulandı.
- Dosya: `github_actions_security_auditor.py`, 2 örnek workflow (`insecure_example.yml` — 6 kontrolün hepsini gösteriyor, `hardened_example.yml` — 0 bulgu), `tests/test_github_actions_security_auditor.py` (29 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Eğlenceli bir doğrulama: Bu projenin kendi `.github/workflows/ci.yml`'i, kendi aracıyla denetlendiğinde 0 bulgu veriyor (README'de belirtildi).
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}`.
- Durum: ✅ 29/29 test gerçekten çalıştırılıp geçti, `ruff check .` temiz. CLI her iki örneğe karşı gerçekten çalıştırıldı: `insecure_example.yml` → 4 HIGH + 2 MEDIUM, `hardened_example.yml` → 0 bulgu. `sample_report.md` gerçek çalıştırmadan üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `GitHub-Actions-Security-Auditor` adıyla repo aç, git init + push.
