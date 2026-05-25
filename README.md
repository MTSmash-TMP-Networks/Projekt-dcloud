# dcloud – dezentraler Desktop-Speicher mit Peer-Replikation

dcloud ist ein Python-basierter Storage-Client mit Web-Dashboard im Desktop-Stil. Jeder Knoten kann Dateien lokal speichern, automatisch im LAN oder über PHP-Relays andere Peers finden und Dateien zur Ausfallsicherheit auf aktive Peers replizieren. Das Dashboard enthält Datei-Explorer, integrierte Datei-Vorschau, Transfer-Center, Peer-Netzwerk, Chat, SMB-Freigabe, Audit-Logs, Einstellungen und temporäre externe Download-Links.

> Aktueller Status: Das Projekt ist ein funktionsfähiger MVP/Prototyp. Die Web-UI besitzt jetzt eine lokale Benutzerverwaltung mit Login, Admin-Rollen und erster Setup-Seite. Für produktive Nutzung bleiben Firewall, VPN, Reverse Proxy oder ein separates internes Netz sinnvoll, weil Peer-/Relay-Endpunkte weiterhin erreichbar sein müssen.

## Kurzüberblick

- Web-Dashboard im Win11-Desktop-Stil unter `http://127.0.0.1:8787`
- Lokale Benutzerverwaltung mit Ersteinrichtung, Login, Admin-/Benutzer-Rollen und Passwort-Hashing
- Datei-Upload mit lokaler Sofort-Speicherung
- Integrierte Vorschau für Bilder, PDFs, Audio, Video, CSV und Excel-Tabellen ohne direkten Browser-Download
- Dynamische RAID-1-Mirror-Replikation auf aktive Peers für Ausfallsicherheit
- „Auf Peers auslagern“, um lokale Chunks nach erfolgreicher Peer-Kopie zu entfernen
- P2P-Downloads mit Chunk-Wiederherstellung von der aktuell schnellsten erreichbaren Quelle
- Große Batch-/Pack-Transfers statt einzelner Chunk-Anfragen
- Adaptive Komprimierung mit `zlib`, optional `zstd`, Mindest-Ersparnis und Skip-Regeln für bereits komprimierte Dateien
- Automatische LAN-Discovery per UDP auf Port `6881`
- Peer-Gossip, Bootstrap-Peers und deaktivierbare Peers
- PHP-Relay-Unterstützung mit Standard- und Backup-Relay
- PHP-Forwarder für direkte Peer-API-Aufrufe, Mailbox-Fallback für NAT-Fälle
- Temporäre externe Download-Links mit maximal 60 Minuten Laufzeit
- Reverse-Mailbox-Download über Relay, wenn der Node von außen nicht direkt erreichbar ist
- Peer-Chat mit ungelesen-Badge, Emojis, Bildversand und Datei-Teilen
- Interner Dashboard-Browser mit Server-Proxy, `peername.dcloud`-Auflösung, normalem Webzugriff, JavaScript-Unterstützung, aktualisierender Adressleiste, Ladeindikator, proxy-tauglicher Suchfunktion, lokalem `storage/web`-Hosting und Download-Ablage in `storage/Downloads`
- Lokaler Web-Ordner `storage/web` als Datei-Explorer-Spezialordner `web`, inkl. Upload, Unterordnern, Texteditor und optionaler PHP-Ausführung über `php-cgi`/`php`
- Standardordner `storage/Downloads` als Datei-Explorer-Spezialordner **Downloads**; Downloads aus dem Dashboard-Browser werden dort serverseitig gespeichert
- Optionaler eingebetteter SMB-Server
- OpenWrt-, Linux-, macOS-, Windows- und Windows-Docker-Installationspfade
- Auto-Update-Skripte für systemd, launchd und OpenWrt-Cron
- Docker-Compose-Variante für Windows mit PowerShell-Helfer

## Architektur

```text
Browser / Dashboard
        │
        ▼
Flask Web-UI + Peer-API (:8787)
        │
        ├── ManifestStore
        │     └── signierte Datei-Manifeste mit Chunk-Locations
        │
        ├── ChunkStore
        │     └── content-addressed Chunks unter storage/chunks/
        │
        ├── Background Replication Worker
        │     └── repliziert fehlende Sicherheitskopien asynchron
        │
        ├── UDP Discovery (:6881)
        │     └── LAN-Suche, Bootstrap, Gossip, NAT-Parent-Routing
        │
        ├── HTTP/PHP Relay
        │     └── Peer-Discovery, Forwarder, Mailbox, externe Relay-Streams
        │
        └── Optional SMB
              └── SMB-Zugriff auf den lokalen Speicherpfad
```

Die Dateiübertragung nutzt nach Möglichkeit direkte Peer-Verbindungen. Wenn das nicht klappt, wird ein PHP-Forwarder versucht. Als letzte Stufe dient die Relay-Mailbox, bei der der nicht direkt erreichbare Peer aktiv beim Relay nach Aufgaben fragt und Antworten zurückschiebt.

## Hauptfunktionen im Dashboard

### Desktop und Fenster

Das Dashboard ist als Desktop-Oberfläche aufgebaut. Wichtige Bereiche sind über Icons erreichbar:

- **Dateien** – Explorer für Upload, Download, Ordner, Löschen, Verschieben, Freigaben, Auslagern, externe Links und umschaltbare Ansichten
- **Transfer-Center** – erscheint nur während aktiver Uploads oder Downloads und verschwindet danach vollständig
- **Netzwerk** – aktive Peers, deaktivierte Peers, Relay-Status, Peer-Suche und manuelles Hinzufügen
- **Peer-Chat** – Nachrichten, Emojis, Bilder und Datei-Karten
- **Benutzer** – lokale Benutzer anlegen, deaktivieren, löschen, Rollen ändern und Passwörter zurücksetzen
- **SMB** – SMB-Status und SMB-Einstellungen
- **System** – Speicher, Node-Status, Version, Hintergrundjobs
- **Audit-Logs** – Logausgabe getrennt vom Systemstatus
- **Einstellungen** – Storage, Komprimierung, Relay, SMB, Netzwerk



### Interner Browser und dcloud-Webhosting

Das Dashboard enthält ein Desktop-Icon **Browser**. Standardmäßig läuft der Browser jetzt wieder **direkt im Dashboard**, aber nicht mehr als einfache iframe-Einbettung fremder Seiten. Stattdessen nutzt dcloud einen serverseitigen Browser-Proxy: Der dcloud-Server ruft externe Webseiten ab, schreibt Links, Formulare, Stylesheets und häufige dynamische Requests auf `/browser/view?...` um und zeigt die Seite im Dashboard an. Dadurch funktioniert der Browser auch dann, wenn dcloud auf einem Server läuft und du extern über das Web-Dashboard zugreifst. Normale `http://`- und `https://`-Adressen sowie dcloud-interne Hostnamen wie `peername.dcloud` werden über diesen Server-Proxy geöffnet. Für den eigenen Node wird beim Start automatisch ein neuer Ordner angelegt:

```text
storage/web
```

Die Startseite liegt dort als `index.html`. Der Ordner erscheint zusätzlich direkt im dcloud **Datei-Explorer** als Spezialordner **web**. Dort kannst du HTML-, PHP-, CSS-, JavaScript- und Asset-Dateien direkt hochladen, Unterordner anlegen, löschen und bearbeitbare Textdateien mit dem integrierten **Web-Texteditor** öffnen und speichern. Änderungen landen unmittelbar in `storage/web` und sind danach direkt im Dashboard-Browser sichtbar.

Statische Dateien wie HTML, CSS, JavaScript, Bilder und Downloads werden über `/dcloud-site/...` ausgeliefert. PHP-Dateien mit der Endung `.php` werden ausgeführt, wenn auf dem System `php-cgi` oder alternativ `php` installiert ist. Ohne PHP-Binary bleibt die statische Auslieferung aktiv und PHP-Dateien liefern einen Hinweistext. `requirements.txt` enthält dazu einen Hinweis als System-Abhängigkeit; `php`/`php-cgi` ist kein Python-Paket und muss über das Betriebssystem installiert werden.

Im Dashboard-Browser ist die eigene Seite unter dem angezeigten Hostnamen erreichbar, zum Beispiel:

```text
http://peername.dcloud/
```

Aktive Peers werden ebenfalls über ihre dcloud-Namen aufgelöst. Bei direkten LAN-Peers lädt der Browser deren `/dcloud-site`-Route direkt; bei Relay-Peers wird zuerst der schnelle Relay-Forwarder und danach die Relay-Mailbox verwendet. Wenn der schnelle Relay-Forwarder eine generische Server-Fehlerseite liefert, fällt dcloud jetzt automatisch auf die Mailbox-Variante zurück. Dafür muss auf dem Relay-Server die aktuelle `relay/dcloud_relay.php` aus diesem Paket liegen, weil ältere Relay-Dateien `/dcloud-site` blockieren. Das Betriebssystem-DNS wird dadurch nicht verändert: Die `.dcloud`-Namen sind bewusst im dcloud-Browser der App aufgelöst.

Die Webspace-Route `/dcloud-site` wird ohne Weiterleitung und mit automatischer Initialisierung von `storage/web/index.html` ausgeliefert. Interne Fehler werden als Klartext mit Ursache zurückgegeben, damit im Browser nicht nur eine generische Flask-Seite wie „Internal Server Error“ erscheint.

### Browser-Downloads

Der Dashboard-Browser speichert echte Datei-Downloads serverseitig in `storage/Downloads`. Der Ordner wird beim Start automatisch erstellt und erscheint von Anfang an im dcloud Datei-Explorer als **Downloads**. Dateien aus diesem Ordner können über den Datei-Explorer geöffnet, heruntergeladen oder gelöscht werden. Interne Proxy-/Browser-Artefakte wie temporäre `f.txt`-/`f-1.txt`-Antworten werden nicht mehr als sichtbare Downloads angezeigt.

Der Browser läuft vollständig im Web-Dashboard. Der frühere native Qt-Button wurde entfernt, damit die Funktion auch auf Servern mit externem Dashboard-Zugriff nutzbar bleibt. Beim Öffnen weiterführender Links, Formularen oder scriptgesteuerter Navigation aktualisiert sich die Adressleiste auf die Ziel-URL, und unten rechts zeigt ein Ladeindikator laufende Seitenwechsel an. Der Server-Proxy übersetzt Links, Formulare, `fetch`, `XMLHttpRequest`, dynamische URL-Attribute und einfache JavaScript-Import-/Worker-Pfade auf `/browser/view`. Hinweis: Ein serverseitig übersetzter Webmodus kann viele moderne Webseiten anzeigen, ist aber kein vollständiger Ersatz für Chrome/Firefox. Seiten mit starkem Bot-Schutz, komplexen Service-Workern oder hart codierten Origin-Prüfungen können weiterhin eingeschränkt sein. Google/reCAPTCHA ist ein solcher Fall: Die CAPTCHA-Sitekeys sind nur für Google-Domains gültig und funktionieren nicht unter `localhost`, deiner Dashboard-Domain oder einer proxied `.dcloud`-Ansicht. dcloud erkennt diese Sperre und bietet stattdessen eine proxy-taugliche Suchansicht an; CAPTCHA-/Bot-Schutz wird nicht umgangen.

### Login und Benutzerverwaltung

Beim ersten Start ohne vorhandene Benutzerdatei leitet dcloud automatisch auf `/setup` um. Dort wird der erste Administrator erstellt. Danach sind Dashboard, Dateiaktionen, Einstellungen, Chat-UI, Logs und lokale Verwaltungs-APIs loginpflichtig.

Gespeichert wird lokal unter:

```text
storage/users.json
```

Die Passwörter werden nicht im Klartext gespeichert, sondern als Werkzeug/Flask-kompatible Passwort-Hashes. Administratoren können im Dashboard über das Icon **Benutzer**:

- neue Benutzer erstellen
- Rollen zwischen `admin` und `user` wechseln
- Benutzer aktivieren/deaktivieren
- Passwörter zurücksetzen
- Benutzer löschen

Schutzgrenzen:

- Die Web-UI und lokale Verwaltungsaktionen sind durch Login geschützt.
- `/external/<token>` bleibt öffentlich, weil diese Links absichtlich extern teilbar sind und zeitlich ablaufen.
- `/healthz` bleibt offen für Statuschecks.
- `/api/p2p/...` bleibt offen für Peers/Relay-Transporte; diese Endpunkte dürfen nicht an eine Browser-Session gebunden werden, sonst würden Peer-Replikation, Chat und externe Relay-Streams nicht funktionieren.

Wenn das Admin-Passwort verloren geht, kann bei gestopptem Dienst die Datei `storage/users.json` gesichert und entfernt werden. Beim nächsten Start erscheint wieder die Ersteinrichtung.


### Datei-Explorer, Ansichten und Peer-Freigaben

Der Datei-Explorer trennt lokale Dateien und eingehende Peer-Freigaben klar voneinander:

- **Meine Dateien** ist der lokale Standardordner für eigene Uploads.
- **Freigaben von Peers** ist ein Systemordner für Dateien, die andere Knoten mit diesem Node geteilt haben. Eingehende Manifeste werden dort angezeigt, auch wenn sie auf dem Quellknoten in einem anderen Ordner lagen.
- Eigene Dateien bleiben in ihrer gewählten Ordnerstruktur und zeigen nur per Status, ob sie an Peers freigegeben wurden.
- Der Systemordner **Freigaben von Peers** kann nicht gelöscht werden; verschwindet eine Freigabe, wird sie durch Revocation/Privatsetzen des Eigentümers entfernt.

Die Ansicht kann wie im Windows-Explorer umgeschaltet werden:

- **Kacheln** für eine große Desktop-artige Darstellung
- **Liste** für kompakte Dateizeilen
- **Details** für eine tabellarischere Übersicht mit Größe/Status

Die gewählte Ansicht wird im Browser lokal gespeichert.

### Integrierte Datei-Vorschau

Unterstützte Dateien können direkt im Dashboard geöffnet werden, ohne dass sofort ein klassischer Browser-Download ausgelöst wird. Doppelklick auf eine unterstützte Datei oder Rechtsklick → **Vorschau öffnen** öffnet das neue Vorschaufenster.

Unterstützt sind aktuell:

- Bilder: PNG, JPG/JPEG, GIF, WebP, BMP, SVG
- PDFs
- Audio: MP3, WAV, OGG, M4A, FLAC
- Video: MP4, WebM, MOV, M4V, soweit der Browser den Codec abspielen kann
- Tabellen: CSV, XLSX, XLSM als browserfreundliche Tabellenansicht
- Text-/Log-/JSON-/XML-/YAML-Dateien als Inline-Vorschau

Bei ausgelagerten Dateien stellt dcloud fehlende Chunks zuerst über lokale/Peer-Quellen wieder her und zeigt die Datei danach inline an. Für alte Excel-Formate wie `.xls` oder OpenDocument-Tabellen kann das Vorschaufenster eine Hinweisseite anzeigen, wenn der Browser-/Server-Fallback sie nicht direkt lesen kann. Der normale Button **Herunterladen** bleibt immer verfügbar.

### Datei-Upload

Beim Upload wird die Datei zuerst lokal gespeichert und sofort im Dashboard sichtbar. Die Replikation auf Peers läuft danach im Hintergrund. Dadurch blockieren große Dateien nicht mehr den Browser-Upload.

Die Replikation arbeitet jetzt als dynamischer RAID-1-Mirror: Es werden ganze Chunk-Kopien gespiegelt, keine Parity- oder Stripe-Blöcke. Ohne Peers bleibt eine lokale Kopie. Sobald Peers aktiv sind, wird mindestens eine zweite Kopie angestrebt. Kommen mehr Speicher-Peers hinzu, erhöht sich der Mirror-Faktor automatisch bis zum aktuellen Schutzlimit von vier Kopien pro Chunk.

Ablauf:

1. Browser sendet Datei an den lokalen dcloud-Node.
2. dcloud zerlegt die Datei in Chunks.
3. Chunks werden adaptiv komprimiert und content-addressed gespeichert.
4. Manifest wird lokal geschrieben und signiert.
5. Datei erscheint sofort im Dashboard.
6. Hintergrund-Worker repliziert Chunks auf aktive Peers.
7. Das Manifest wird mit erfolgreichen Peer-Locations aktualisiert.

### Download und Wiederherstellung

Downloads prüfen zuerst, ob alle benötigten Chunks lokal vorhanden sind. Fehlende Chunks werden von Peers geladen. Vor dem Abruf werden die aktiven Quellen per schneller Health-/Antwortzeit-Prüfung sortiert. dcloud versucht dadurch zuerst den Peer, der aktuell am schnellsten antwortet, statt starr der Manifest-Reihenfolge zu folgen.

Dabei werden große Pack-/Batch-Requests verwendet, damit nicht jeder Chunk einzeln angefragt wird. Falls ein großer Block über Relay nicht funktioniert, wird der Block automatisch kleiner wiederholt.

### Auf Peers auslagern

Mit „Auf Peers auslagern“ kann eine Datei nach erfolgreicher Peer-Replikation lokal entlastet werden. Lokale Chunk-Dateien werden nur gelöscht, wenn kein aktives Manifest sie lokal noch benötigt. Deduplizierte Chunks bleiben geschützt.

Für ausgelagerte Dateien bleibt das System RAID-1-artig: Wenn Peers verschwinden, zählt dcloud nur aktuell erreichbare Kopien als gesund. Der Hintergrund-Worker versucht fehlende Spiegel auf neue aktive Peers nachzubauen. Falls die lokale Kopie bereits entfernt wurde, kann der Worker einen fehlenden Chunk von der schnellsten noch erreichbaren Quelle holen und anschließend auf neue Ziele spiegeln. Sind alle Quellen offline, bleibt das Manifest erhalten und die Reparatur wird beim nächsten Peer-Signal erneut versucht.

### Peer-Chat

Der Chat ist peerbasiert:

- rote Badge nur bei ungelesenen Nachrichten größer `0`
- ungelesene Nachrichten werden beim Öffnen des Chats als gelesen markiert
- Emoji-Auswahl im Eingabebereich
- Bildversand mit Vorschau in der Chat-Bubble
- Datei-Teilen über grafische Dateiauswahl statt ID-Eingabe
- geteilte Dateien werden als Datei-Karte mit Download-Aktion angezeigt

### Temporäre externe Download-Links

Per Rechtsklick auf eine eigene Datei kann ein externer Link erstellt werden. Die Gültigkeit ist serverseitig auf maximal **60 Minuten** begrenzt.

Es gibt zwei Link-Arten:

1. **Direkt-Link**: `/external/<token>` auf dem dcloud-Node. Funktioniert nur, wenn der Node von außen erreichbar ist.
2. **Relay-Link**: `dcloud_relay.php?action=external_download&token=...`. Das Relay nimmt den Browser-Download an und fordert den Node über die Mailbox auf, den Stream aktiv zum Relay zu senden.

Der Relay-Link speichert nicht dauerhaft die Datei auf dem Relay. Er puffert nur kurzlebige Stream-Pakete für den laufenden Download. Für sehr große öffentliche Downloads sind Portfreigabe, VPN, Reverse Proxy oder später ein echter Reverse-Tunnel effizienter.

### SMB

Der optionale SMB-Server kann im Dashboard aktiviert werden. Beim Aktivieren, Deaktivieren oder Ändern von Port/Benutzer/Passwort wird der SMB-Dienst innerhalb des laufenden dcloud-Prozesses neu gestartet. Auf Ports unter `1024`, insbesondere `445`, sind unter Linux/macOS meist Root-Rechte nötig. Auf Systemen mit bereits laufendem Samba/Windows-Dateifreigabe kann der Port belegt sein.

## Speicher- und Datenmodell

```text
storage/
├── chunks/
│   └── ab/
│       └── abcdef....chunk
├── manifests/
│   └── <manifest_id>.json
├── downloads/
├── tmp/
├── identity/
│   └── node_ed25519.key
├── disabled_peers.json
└── external_links.json
```

- Chunks werden über SHA-256 der gespeicherten Bytes adressiert.
- Manifeste sind Ed25519-signiert.
- Node-ID ist `SHA-256(public_key_bytes)`.
- Private Keys bleiben lokal unter `storage/identity/`.
- Alte `zlib`- und unkomprimierte Chunks bleiben lesbar.
- `zstd`-Chunks benötigen auf lesenden Peers das optionale Python-Paket `zstandard`.

## Netzwerk und Ports

| Zweck | Standard | Protokoll | Hinweis |
| --- | ---: | --- | --- |
| Dashboard und Peer-API | `8787` | TCP/HTTP | Standardhost `0.0.0.0`, lokal über `127.0.0.1` erreichbar |
| LAN-Discovery | `6881` | UDP | nutzt bei belegtem Port Range `6881-6891` |
| SMB | `445` | TCP | optional, benötigt oft Root/Admin-Rechte |
| PHP-Relay | extern | HTTP/HTTPS | `dcloud_relay.php` auf Webspace oder Server |

Für LAN-Betrieb müssen TCP `8787` und UDP `6881-6891` im lokalen Netz erlaubt sein. Für reine Relay-Nutzung reicht ausgehender HTTP/HTTPS-Zugriff vom dcloud-Node zum Relay.

## Standard-Relays

Die Konfiguration enthält standardmäßig:

```yaml
relay_urls:
  - "https://support.tmp-networks.de/dcstorage/dcloud_relay.php"
  - "http://dcloud.byethost12.com/dcloud_relay.php"
```

Wenn PHP-Vermittlung bewusst deaktiviert werden soll, muss `relay_urls: []` gesetzt werden. Bestehende Installationen mit alter Konfiguration bekommen das Backup-Relay automatisch ergänzt, solange die Relay-Funktion nicht ausdrücklich deaktiviert wurde.

## Komprimierung

Neue Uploads nutzen `storage.compression`:

```yaml
storage:
  compression:
    mode: auto              # auto, fast, balanced, max, off
    algorithm: zlib         # auto, zlib, zstd, none
    level: 1
    min_savings_percent: 3.0
    min_savings_bytes: 65536
    skip_incompressible: true
```

Empfehlung:

- `mode: auto`
- `algorithm: zlib` für maximale Kompatibilität
- optional `algorithm: zstd`, wenn alle Peers `zstandard` installiert haben
- `skip_incompressible: true` für bessere Performance bei ZIP, JPG, PNG, MP4, PDF, 7z, RAR usw.

Optionales zstd installieren:

```bash
. .venv/bin/activate
pip install zstandard
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python -m pip install zstandard
```

## Voraussetzungen

### Allgemein

- Python 3.11 oder neuer empfohlen
- Git
- optional für Windows: Docker Desktop
- ausgehende HTTP/HTTPS-Verbindung für Relays und Updates
- genügend Speicherplatz im gewählten `storage.path`

### Python-Pakete

Pflichtpakete aus `requirements.txt`:

- `Flask`
- `PyYAML`
- `cryptography`

Optionale Python-/System-Erweiterungen:

- `impacket`
- `zstandard` für zstd-Komprimierung

## Manuelle Installation

Diese Variante funktioniert auf Linux, macOS und Windows, wenn Python und Git vorhanden sind.

### Linux/macOS

```bash
git clone https://github.com/MTSmash-TMP-Networks/Projekt-dcloud.git dcloud
cd dcloud
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m dcloud_client.main --config config.yml
```

Dashboard öffnen:

```text
http://127.0.0.1:8787
```

Beim ersten Öffnen erscheint automatisch die Ersteinrichtung für den ersten Admin-Benutzer.

### Windows PowerShell

```powershell
git clone https://github.com/MTSmash-TMP-Networks/Projekt-dcloud.git dcloud
cd dcloud
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m dcloud_client.main --config config.yml
```

Falls PowerShell das Aktivieren blockiert:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Alternativ ohne Aktivieren:

```powershell
.\.venv\Scripts\python -m dcloud_client.main --config config.yml
```

## Installation per `.sh`-Skript

Das Hauptskript ist:

```text
scripts/install_dcloud_service.sh
```

Es unterstützt:

- `--target linux` für systemd
- `--target openwrt` für OpenWrt `/etc/init.d` + Cron-Autoupdate
- `--target windows` für ein PowerShell-Bootstrap-Skript mit geplanter Aufgabe
- `--target auto` zur automatischen Erkennung

Optionen:

```text
--role server              aktuell nur server
--storage-gb N             freigegebener Speicher in GB, Minimum 5
--enable-smb               SMB in config.yml aktivieren
--disable-smb              SMB deaktivieren
--smb-user USER            SMB-Benutzername
--smb-pass PASS            SMB-Passwort
--install-dir PATH         Installationsverzeichnis
--service-name NAME        Service-/Task-/Init-Name
--target auto|linux|openwrt|windows
```

### Linux mit systemd

Als Root oder per `sudo` ausführen:

```bash
curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service.sh | sudo sh -s -- \
  --target linux \
  --role server \
  --storage-gb 200 \
  --install-dir /opt/dcloud \
  --service-name dcloud
```

Mit SMB:

```bash
curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service.sh | sudo sh -s -- \
  --target linux \
  --role server \
  --storage-gb 200 \
  --enable-smb \
  --smb-user dcloud \
  --smb-pass 'starkes-passwort'
```

Service verwalten:

```bash
sudo systemctl status dcloud
sudo systemctl restart dcloud
sudo systemctl stop dcloud
sudo systemctl start dcloud
sudo journalctl -u dcloud -f
```

Auto-Update verwalten:

```bash
sudo systemctl status dcloud-autoupdate.timer
sudo systemctl list-timers | grep dcloud
sudo systemctl restart dcloud-autoupdate.timer
```

Das Linux-Autoupdate prüft regelmäßig das Git-Remote, stoppt den Dienst, zieht per `git pull --ff-only`, installiert `requirements.txt` neu und startet den Dienst wieder.

### OpenWrt

Empfohlen ist ein Installationspfad mit ausreichend Speicher, zum Beispiel USB/SSD unter `/opt/dcloud`.

```sh
opkg update
opkg install ca-bundle curl git-http python3 python3-pip python3-flask python3-cryptography python3-cffi python3-pycparser python3-yaml
```

Installation:

```sh
curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service.sh | sh -s -- \
  --target openwrt \
  --role server \
  --storage-gb 50 \
  --install-dir /opt/dcloud \
  --service-name dcloud
```

Mit SMB:

```sh
curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service.sh | sh -s -- \
  --target openwrt \
  --role server \
  --storage-gb 50 \
  --enable-smb \
  --smb-user dcloud \
  --smb-pass 'starkes-passwort'
```

Service verwalten:

```sh
/etc/init.d/dcloud status
/etc/init.d/dcloud restart
/etc/init.d/dcloud stop
/etc/init.d/dcloud start
logread | tail -n 120
```

Autoupdate:

```sh
/usr/bin/dcloud_autoupdate.sh
cat /opt/dcloud/logs/autoupdate.log
cat /etc/crontabs/root | grep dcloud
```

Das OpenWrt-Autoupdate nutzt eine Lock-Datei unter `/tmp`, startet den Dienst nach jedem Updateversuch per Cleanup-Trap wieder und vermeidet ein blindes komplettes `pip install -r requirements.txt`. Das schützt kleine Router vor langen Builds und verhindert, dass der Dienst nach einem Updatefehler dauerhaft aus bleibt.

Firewall-Regeln werden vom Skript für LAN-Zugriff angelegt:

- TCP Web/API-Port aus `config.yml`, standardmäßig `8787`
- UDP `6881-6891`

### macOS mit launchd

Für macOS gibt es ein eigenes Skript:

```text
scripts/install_dcloud_service_mac.sh
```

Voraussetzungen:

```bash
xcode-select --install
# optional, falls Python fehlt:
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python git
```

Installation:

```bash
curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service_mac.sh | bash -s -- \
  --role server \
  --storage-gb 200 \
  --install-dir "$HOME/dcloud" \
  --service-name de.tmp-networks.dcloud
```

Mit SMB:

```bash
curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service_mac.sh | bash -s -- \
  --role server \
  --storage-gb 200 \
  --enable-smb \
  --smb-user dcloud \
  --smb-pass 'starkes-passwort'
```

launchd verwalten:

```bash
launchctl list | grep dcloud
launchctl unload "$HOME/Library/LaunchAgents/de.tmp-networks.dcloud.plist"
launchctl load "$HOME/Library/LaunchAgents/de.tmp-networks.dcloud.plist"
tail -f "$HOME/dcloud/logs/dcloud.out.log"
tail -f "$HOME/dcloud/logs/dcloud.err.log"
```

macOS-Autoupdate:

```bash
launchctl list | grep autoupdate
tail -f "$HOME/dcloud/logs/dcloud.autoupdate.out.log"
tail -f "$HOME/dcloud/logs/dcloud.autoupdate.err.log"
```

Hinweis: Der SMB-Port `445` ist auf macOS häufig bereits vom System belegt oder benötigt erhöhte Rechte. Nutze bei Bedarf einen anderen Port in den SMB-Einstellungen.

### Windows per Bootstrap

Das `.sh`-Skript kann unter Git Bash/MSYS/Cygwin einen Windows-Bootstrap erzeugen. Danach wird ein PowerShell-Skript als Administrator ausgeführt.

In Git Bash:

```bash
sh scripts/install_dcloud_service.sh \
  --target windows \
  --role server \
  --storage-gb 200 \
  --install-dir "C:/dcloud" \
  --service-name dcloud
```

Danach PowerShell als Administrator öffnen:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\dcloud\install_windows_service.ps1"
```

Geplante Aufgabe verwalten:

```powershell
Get-ScheduledTask -TaskName dcloud
Start-ScheduledTask -TaskName dcloud
Stop-ScheduledTask -TaskName dcloud
Unregister-ScheduledTask -TaskName dcloud
```

Manueller Windows-Start ohne geplante Aufgabe:

```powershell
cd C:\dcloud
.\.venv\Scripts\python -m dcloud_client.main --config config.yml
```


## Windows-Installation mit Docker Desktop

Für Windows ist Docker die empfohlene Variante, wenn die native Python-/Scheduled-Task-Installation Probleme macht. dcloud läuft dann in einem Linux-Container; Konfiguration, Identität, Chunks und Manifeste bleiben dauerhaft im lokalen Ordner `docker-data/` erhalten.

### Voraussetzungen

1. Docker Desktop für Windows installieren.
2. Docker Desktop starten und warten, bis die Engine bereit ist.
3. Projektordner öffnen, zum Beispiel in PowerShell.

### Schnellstart

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1
```

Danach öffnen:

```text
http://127.0.0.1:8787
```

Beim ersten Öffnen erscheint automatisch die Ersteinrichtung für den ersten Admin-Benutzer.

Das Skript erzeugt automatisch:

```text
docker/.env.windows
docker-data/
```

`docker-data/` enthält die persistente dcloud-Konfiguration und den Speicher. Diesen Ordner nicht löschen, wenn Node-ID, Dateien und Manifeste erhalten bleiben sollen.

### Start mit eigenen Parametern

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 `
  -NodeName "Mein Windows dcloud" `
  -DashboardPort 8787 `
  -DiscoveryUdpPort 6881 `
  -StorageLimitGiB 200
```

### Container verwalten

Status anzeigen:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -Status
```

Logs anzeigen:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -Logs
```

Neustarten:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -Restart
```

Stoppen:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -Stop
```

Container entfernen, Daten aber behalten:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -Clean
```

### Docker Compose direkt verwenden

Alternativ ohne PowerShell-Helfer:

```powershell
docker compose --env-file .\docker\.env.windows -f docker-compose.windows.yml up -d --build
```

Logs:

```powershell
docker compose --env-file .\docker\.env.windows -f docker-compose.windows.yml logs -f --tail 200
```

Stoppen:

```powershell
docker compose --env-file .\docker\.env.windows -f docker-compose.windows.yml down
```

### SMB mit Docker auf Windows

SMB ist in der Docker-Variante standardmäßig deaktiviert. Grund: Windows verwendet Port `445` oft selbst für die Windows-Dateifreigabe. Wenn der Container ebenfalls Port `445` binden soll, kann der Start fehlschlagen.

Aktivieren lässt es sich trotzdem mit:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -EnableSmb
```

Wenn der Container danach nicht startet, ohne SMB starten:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -Stop
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1
```

Für Windows ist meist besser: Dashboard und normale Downloads nutzen oder SMB nativ außerhalb von Docker betreiben.

### Wichtige Docker-Hinweise

- Web/API-Port im Container ist intern immer `8787`; der Host-Port wird über `-DashboardPort` gemappt.
- UDP-Discovery wird als UDP-Port `6881` gemappt. Docker Desktop kann Broadcast im LAN je nach Netzwerkmodus einschränken. PHP-Relay/Bootstrap funktioniert trotzdem.
- Externe temporäre Links funktionieren über das Relay weiterhin, solange der Container ausgehend HTTP/HTTPS erreicht.
- Bei Updates einfach erneut starten:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1
```

Dabei wird das Image neu gebaut und der vorhandene `docker-data/`-Ordner weiterverwendet.

## PHP-Relay installieren

Das PHP-Relay besteht aus einer Datei:

```text
relay/dcloud_relay.php
```

Installation auf einem Webserver:

1. `dcloud_relay.php` auf den Webspace kopieren.
2. Schreibrechte für das Relay-Datenverzeichnis erlauben. Das Skript legt standardmäßig `dcloud-relay-data/` neben sich an.
3. PHP mit `curl`-Extension ist empfohlen. Ohne cURL nutzt das Skript einen HTTP-Stream-Fallback, der weniger robust ist.
4. Wichtig für `peername.dcloud` über Relay: Vorhandene Relay-Installationen müssen mit dieser Datei aktualisiert werden, weil die Relay-Allowlist jetzt zusätzlich `/dcloud-site` erlaubt.
5. Die URL im Dashboard oder in `config.yml` unter `network.relay_urls` eintragen.

Beispiel:

```yaml
network:
  relay_urls:
    - "https://example.org/dcloud_relay.php"
```

Wichtige Hinweise:

- Das Relay sollte über HTTPS laufen.
- Das Relay ist kein dauerhafter Dateispeicher. Peer-Webseiten werden nur durchgereicht; HTML/PHP-Dateien bleiben auf dem jeweiligen dcloud-Node.
- Für externe temporäre Links werden nur kurzlebige Token und Stream-Pakete gehalten.
- Für große Datenmengen ist ein eigener VPS oder die Python-Relay-Variante stabiler als Shared Hosting.

## Python-Relay-Alternative

Für Server/VPS gibt es zusätzlich:

```text
relay/dcloud_relay_server.py
```

Startbeispiel:

```bash
python relay/dcloud_relay_server.py
```

Diese Variante ist für viele Transfers stabiler als PHP auf Shared Hosting. Je nach Deployment sollte sie hinter einem Reverse Proxy mit HTTPS betrieben werden.

## Beispiel-`config.yml`

```yaml
node:
  name: dcloud-node
  identity_path: ./storage/identity
  client_type: server

storage:
  path: ./storage
  limit_bytes: 53687091200
  min_free_bytes: 1073741824
  chunk_size_bytes: 4194304
  compression:
    mode: auto
    algorithm: zlib
    level: 1
    min_savings_percent: 3.0
    min_savings_bytes: 65536
    skip_incompressible: true

web:
  host: 0.0.0.0
  port: 8787

network:
  udp_host: 0.0.0.0
  udp_port: 6881
  udp_port_range:
    start: 6881
    end: 6891
  bootstrap_nodes: []
  tree_parent_nodes: []
  relay_children: false
  discovery_interval_seconds: 10
  auto_discovery_enabled: true
  auto_discovery_ports: [6881]
  auto_discovery_hosts: [255.255.255.255]
  startup_discovery_seconds: 12
  startup_discovery_interval_seconds: 2
  peer_timeout_seconds: 35
  peer_cleanup_interval_seconds: 5
  relay_url: "https://support.tmp-networks.de/dcstorage/dcloud_relay.php"
  relay_urls:
    - "https://support.tmp-networks.de/dcstorage/dcloud_relay.php"
    - "http://dcloud.byethost12.com/dcloud_relay.php"
  relay_secret: ""
  relay_poll_interval_seconds: 1
  relay_request_timeout_seconds: 180
  relay_chunk_size_bytes: 524288

security:
  protocol_magic: DCLOUD1

smb:
  enabled: false
  host: 0.0.0.0
  port: 445
  share_name: DCLOUD
  username: ""
  password: ""
```

## Typische Bedienung

### Datei hochladen

1. Dashboard öffnen.
2. Fenster **Dateien** öffnen.
3. Datei auswählen und hochladen.
4. Während des aktiven Uploads erscheint das **Transfer-Center** automatisch und verschwindet danach wieder.

### Datei ansehen

1. Fenster **Dateien** öffnen.
2. Unterstützte Datei per Doppelklick öffnen oder per Rechtsklick **Vorschau öffnen** wählen.
3. Im Vorschaufenster können Bilder, PDFs, MP3/Audio, MP4/Video und Tabellen direkt betrachtet werden.
4. Bei Bedarf über **Herunterladen** weiterhin den klassischen Download starten.

### Datei auf Peer auslagern

1. Rechtsklick auf Datei.
2. **Auf Peers auslagern** wählen.
3. Warten, bis mindestens eine Peer-Kopie erfolgreich geschrieben wurde.
4. Lokale Chunks werden nur gelöscht, wenn dadurch keine andere lokale Datei beschädigt wird.

### Datei per Chat teilen

1. **Peer-Chat** öffnen.
2. Peer auswählen.
3. Auf Büroklammer klicken.
4. Datei grafisch aus der Dateiliste auswählen.
5. Nachricht senden.

### Externen Link erstellen

1. Rechtsklick auf eigene Datei.
2. **Externen Link erstellen** wählen.
3. Gültigkeit in Minuten eingeben, maximal `60`.
4. Link kopieren und weitergeben.

### Peer deaktivieren

1. **Netzwerk** öffnen.
2. Peer in aktiver Liste deaktivieren.
3. Der Peer bleibt in `disabled_peers.json` gesperrt und wird durch Discovery/Relay nicht automatisch wieder aktiv.
4. Bei Bedarf im Bereich **Deaktivierte Peers** wieder zulassen.

## Wartung und Fehlerdiagnose

### Logs

Dashboard:

- Fenster **Audit-Logs** öffnen

Linux/systemd:

```bash
sudo journalctl -u dcloud -f
```

OpenWrt:

```sh
logread | tail -n 120
cat /opt/dcloud/logs/autoupdate.log
```

macOS:

```bash
tail -f "$HOME/dcloud/logs/dcloud.out.log"
tail -f "$HOME/dcloud/logs/dcloud.err.log"
```

Windows:

```powershell
Get-ScheduledTask -TaskName dcloud
Get-ScheduledTaskInfo -TaskName dcloud
```

### Healthcheck

```bash
curl http://127.0.0.1:8787/healthz
```

### Ports prüfen

Linux:

```bash
ss -ltnup | grep -E '8787|6881|445'
```

OpenWrt:

```sh
netstat -ltnup | grep -E '8787|6881|445'
```

Windows PowerShell:

```powershell
netstat -ano | findstr "8787 6881 445"
```

## Häufige Probleme

### Dashboard ist lokal erreichbar, aber andere Peers sehen den Node nicht

- Prüfe Firewall für TCP `8787` und UDP `6881-6891`.
- Prüfe, ob `web.host` auf `0.0.0.0` steht.
- Prüfe, ob Peers eventuell deaktiviert wurden.
- Bei Docker/VM/Router muss UDP-Broadcast ggf. explizit erlaubt werden.

### Relay-Link wird erstellt, Download bricht aber ab

- Stelle sicher, dass die neue `relay/dcloud_relay.php` auf dem Relay-Server liegt.
- Prüfe, ob der dcloud-Node ausgehend zum Relay verbinden kann.
- Shared-Hosting kann lange Downloads abbrechen; dann besser eigenes Relay oder Reverse Proxy nutzen.

### SMB-Haken verschwindet oder SMB startet nicht

- Aktuelle Version nutzen; SMB wird beim Speichern der Einstellungen neu gestartet.
- Prüfe, ob Port `445` belegt ist.
- Auf Linux/macOS benötigt Port `445` meist Root-Rechte.
- Testweise einen höheren Port verwenden, zum Beispiel `1445`.

### Upload großer Dateien ist langsam

- Upload selbst sollte nach lokaler Speicherung fertig sein; die Peer-Replikation läuft im Hintergrund.
- Das Transfer-Center erscheint nur während aktiver Uploads/Downloads; Peer-Replikation läuft nach lokaler Speicherung im Hintergrund weiter.
- Bei Relay-Peers sind kleinere Pakete absichtlich sicherer, aber langsamer.
- Für große Datenmengen sind direkte Peers, VPN oder Portfreigabe schneller als Shared-PHP-Relay.

### zstd-Chunks können auf einem Peer nicht gelesen werden

- Auf allen Peers `zstandard` installieren oder `algorithm: zlib` nutzen.
- Bereits vorhandene zstd-Chunks benötigen zum Lesen weiterhin zstd-Unterstützung.

## Sicherheitshinweise

- Dashboard und lokale Verwaltungsaktionen sind loginpflichtig.
- `web.host: 0.0.0.0` macht Dashboard und Peer-API im LAN erreichbar.
- Stelle den Dienst trotzdem nicht ungeschützt ins Internet, weil P2P-/Relay-Endpunkte weiterhin erreichbar sein müssen.
- Nutze Firewall, VPN oder Reverse Proxy, wenn du dcloud außerhalb deines LANs bereitstellst.
- Private Node-Keys niemals teilen.
- Relay-URLs sollten nach Möglichkeit HTTPS verwenden.
- Temporäre externe Links sind tokenbasiert, aber jeder mit Link kann bis zum Ablauf herunterladen.

## Entwicklungsstatus und Grenzen

Bewusst noch nicht vollständig enthalten:

- kein vollständiges DHT
- kein Erasure Coding
- keine echte Ende-zu-Ende-Dateiverschlüsselung
- Benutzerverwaltung ist lokal vorhanden; noch keine mandantenfähigen Datei-Rechte pro Benutzer
- kein WebRTC/QUIC-Hole-Punching
- kein permanenter Reverse-Tunnel für externe Links

Die Codebasis ist modular aufgebaut, damit spätere Transport-, Index- und Verschlüsselungsprovider ergänzt werden können.

## Modulübersicht

| Pfad | Aufgabe |
| --- | --- |
| `dcloud_client/main.py` | Startpunkt, Logging, Konfiguration, Dienste initialisieren |
| `dcloud_client/config.py` | YAML-Konfiguration laden, normalisieren und speichern |
| `dcloud_client/identity.py` | Ed25519-Identität und Node-ID |
| `dcloud_client/crypto.py` | Hashing, Signaturen, Base64-Helfer |
| `dcloud_client/storage.py` | Chunk-Speicher, adaptive Komprimierung, atomare Writes |
| `dcloud_client/manifests.py` | Signierte Manifeste, Placement, Restore, Löschung |
| `dcloud_client/network/udp_discovery.py` | UDP-Discovery, Gossip, NAT-Parent-Weiterleitung |
| `dcloud_client/network/http_relay.py` | PHP-Relay-Client, Forwarder, Mailbox, externe Streams |
| `dcloud_client/network/p2p_storage.py` | Peer-Transfers, Batch-/Pack-Upload und Download |
| `dcloud_client/network/smb_server.py` | optionaler eingebetteter SMB-Server |
| `dcloud_client/network/peers.py` | Peer-Liste, Deduplizierung, Deaktivierung |
| `dcloud_client/web/app.py` | Flask-Routen für Dashboard, Dateien, Webhosting, Web-Dateien, Server-Browser-Proxy, Chat, Benutzerverwaltung, P2P-API |
| `dcloud_client/web/auth.py` | Lokale Benutzerverwaltung mit Passwort-Hashing und JSON-Store |
| `dcloud_client/web/templates/dashboard.html` | Desktop-Dashboard, JavaScript und UI |
| `dcloud_client/web/templates/login.html` | Login-Seite für das Dashboard |
| `dcloud_client/web/templates/setup.html` | Ersteinrichtung für den ersten Admin-Benutzer |
| `relay/dcloud_relay.php` | PHP-Relay für Shared Hosting/Webserver |
| `relay/dcloud_relay_server.py` | Python-Relay-Alternative für Server/VPS |
| `scripts/install_dcloud_service.sh` | Linux/OpenWrt/Windows-Bootstrap |
| `scripts/install_dcloud_service_mac.sh` | macOS-launchd-Installer |
| `scripts/install_dcloud_docker_windows.ps1` | Windows-Docker-Installer/Starter |
| `scripts/docker-entrypoint.sh` | Docker-Entrypoint für persistente Config unter `/data` |
| `Dockerfile` | Docker-Image für dcloud |
| `docker-compose.windows.yml` | Docker-Compose für Windows ohne SMB |
| `docker-compose.smb.yml` | Optionales SMB-Compose-Overlay |

## Lizenz

Siehe `LICENSE`.
