# Manifest-Management: Stabilitäts- und Zuverlässigkeitskonzept

## Datenfluss und Lebenszyklus
1. Upload erzeugt Chunk-Metadaten und signiertes Manifest.
2. Manifest wird atomar geschrieben (`*.tmp` + `replace`) und vorherige Version als `.bak` gesichert.
3. Löschungen verschieben Manifeste zuerst in `.trash` statt sofortigem `unlink`.
4. Bei `load()` werden fehlende Dateien automatisch aus `.bak` oder `.trash` wiederhergestellt.
5. Konsistenzprüfung (`run_manifest_consistency_check`) validiert periodisch Signatur/JSON und repariert aus Backup/Trash.

## Eingebaute Transaktionsmechanik
- **Atomare Writes**: temporäre Datei, `flush + fsync`, danach `Path.replace`.
- **Rolling Backup**: vor jedem Überschreiben wird vorherige Datei nach `*.bak` verschoben.
- **Soft Delete / Undo**: Löschung über Recycle-Bin (`manifests/.trash/`) mit Retention (`MANIFEST_TRASH_RETENTION`).
- **Locking**: exklusiver Lock über `.manifest.lock` (`O_EXCL`), um konkurrierende Writer zu serialisieren.

## Race Conditions und Gegenmaßnahmen
- **Parallel Write vs. Delete**: globaler Manifest-Lock verhindert inkonsistente Zwischenstände.
- **Read während Rewrite**: `replace` minimiert Fenster für teilschreibende Reads.
- **Versehentliche Früh-Löschung**: Delete verschiebt in Trash; `load()` kann selbst-heilen.
- **Korruptes JSON nach Crash**: Konsistenzprüfung erkennt Fehler und restauriert aus Backup.

## Logging / Observability
- Zentrales Audit-Log: `manifests/manifest_audit.log` (JSON-Lines).
- Events: `write`, `delete`, `backup`, `restore_from_backup`, `restore_from_trash`, `consistency_run`, `write_error`, `signature_invalid`.
- Erweiterbar für ELK/Prometheus-Scraper (Datei- oder Sidecar-Collector).

## Berechtigungs-/Zugriffsschutz
- Schreibzugriffe werden im `ManifestStore` zentralisiert.
- Empfohlen im Deployment:
  - OS-ACLs auf `manifests/` nur für dcloud-Service-User.
  - Optionaler AppArmor/SELinux-Profileinsatz.
  - Lock-Datei-Monitoring zur Erkennung hängen gebliebener Prozesse.

## Empfohlene Libraries/Technologien
- **Atomare File-Operationen**: Python `atomicwrites` (optional als Ersatz/Ergänzung), `os.replace`.
- **Strukturierte Logs**: `structlog` oder `python-json-logger`.
- **Monitoring**: Prometheus (Export von Konsistenzmetriken), ELK/OpenSearch für Audit-Logs.
- **Fehlertracking**: Sentry SDK für Ausnahme-Telemetrie.

## Kritische Beispielroutinen
- `ManifestStore.save()` → atomisches Schreiben + Backup + Audit.
- `ManifestStore.delete()` → Move-to-Trash statt Hard-Delete.
- `ManifestStore.load()` → automatische Wiederherstellung bei fehlender Datei.
- `ManifestStore.run_manifest_consistency_check()` → Reparatur- und Prüfzyklus.
