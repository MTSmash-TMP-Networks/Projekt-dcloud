# dcloud Client MVP – dezentraler Datenspeicher

Dieses Repository enthält eine erste Python-MVP-Codebasis für einen später dezentralen Storage-Client. Der Client läuft lokal, erzeugt beim ersten Start eine eigene Node-Identität, stellt konfigurierbaren Speicher bereit, komprimiert Uploads, zerlegt sie in content-addressed Chunks und erzeugt signierte Manifeste. In den Einstellungen kann der Knoten als **Server** markiert werden und der freigegebene Speicher wird mit mindestens 5 GB begrenzt. Eine zentrale API ist **nicht** fest verdrahtet: Jeder Client lauscht selbst als kleiner UDP-Discovery-Server und sucht im LAN automatisch nach sichtbaren dcloud-Clients auf UDP-Port **6881**. Zusätzlich ist ein öffentliches PHP-HTTP-Relay fest hinterlegt, damit Peers außerhalb des gleichen Heimnetzwerks kommunizieren können. Der Client versucht dabei zuerst direkte Peer-Verbindungen, danach einen kurzlebigen PHP-HTTP-Forwarder ohne Chunk-Ablage und erst zuletzt die Webserver-Mailbox als Fallback; weitere selbst gehostete Relays können in den Einstellungen ergänzt werden und werden per Discovery/Gossip im Netzwerk verteilt.

## Architekturübersicht

```text
Lokale/LAN Web UI + Peer-API (Flask, 0.0.0.0:8787)
        │
        ├── ManifestStore ── signierte Datei-Manifeste
        │        │
        │        └── ChunkStore ── content-addressed storage unter storage/chunks/
        │
        ├── IdentityManager ── Ed25519-Schlüssel, Node-ID = SHA-256(Public Key)
        │
        └── PeerProvider / Transport
                 └── UdpDiscoveryTransport für Discovery, Peer-Gossip und Control-Nachrichten
```

Der MVP speichert Uploads jetzt zuerst lokal und macht sie sofort sichtbar. Die Ausfallsicherheits-Kopie auf aktiven Speicher-Peers läuft anschließend als Hintergrund-Replikation weiter, damit große Dateien den Browser-Upload nicht mehr blockieren. Jeder Chunk wird lokal zlib-komprimiert und content-adressiert gespeichert; der Hintergrund-Worker schreibt fehlende Sicherheitskopien danach gebündelt an Peers und aktualisiert das Manifest, sobald die Redundanz hergestellt wurde. Dadurch wächst der nutzbare Verbundspeicher mit jedem aktiven Peer, der Speicher freigibt, ohne dass der Upload auf langsame Internet-/Relay-Routen warten muss. UDP-Discovery akzeptiert nur Pakete mit dem konfigurierten `protocol_magic`. Jeder Client ist gleichzeitig Discovery-Client und Discovery-Server: Beim Start sendet der Client sofort Discovery-Hellos an die konfigurierten Auto-Discovery-Ziele, standardmäßig per LAN-Broadcast auf Port **6881**. Sobald ein automatisch gefundener, Bootstrap- oder manuell eingetragener Peer antwortet, tauschen beide ihre Peer-Listen aus und geben neue Peers weiter, damit alle Knoten ohne zentralen Server voneinander erfahren. Die aktive Peer-Liste enthält nur Knoten, die innerhalb des konfigurierten Timeouts direkt geantwortet haben; gossippte Einträge werden erst nach eigener Antwort aktiv und Offline-Peers verschwinden automatisch. Hinter einem NAT kann eine Baumstruktur betrieben werden: Nur ein Node im lokalen Netzwerk benötigt eine Portfreigabe und setzt `relay_children: true`; die übrigen lokalen Nodes tragen ihn als `tree_parent_nodes` ein und werden über diesen Parent für Discovery-/Control-Nachrichten erreichbar.

## Modulbeschreibung

| Modul | Aufgabe |
| --- | --- |
| `dcloud_client/main.py` | CLI-Einstieg, Logging, Konfiguration, Initialisierung von Identity, Storage, Manifesten, Peers, UDP-Discovery und Web-UI. |
| `dcloud_client/config.py` | Lädt `config.yml`, erstellt sie bei Bedarf aus `data/default_config.yml`, normalisiert Pfade, validiert Kernwerte und speichert Desktop-Einstellungen wie Client-Typ und freigegebenen Speicher. |
| `dcloud_client/identity.py` | Erstellt/lädt lokale Ed25519-Private-Keys, leitet Public Key und Node-ID ab. |
| `dcloud_client/crypto.py` | SHA-256, Ed25519-Signaturen, Base64-Helfer und Signaturprüfung. |
| `dcloud_client/storage.py` | Content-addressed chunk storage, zlib-Kompression pro Chunk, atomare Writes über `tmp`, Speicherlimit- und Mindestfreispeicherprüfung. |
| `dcloud_client/manifests.py` | Manifest-Erzeugung, kanonische Signaturdaten, Round-Robin-Peer-Platzierung, Speicherung, Prüfung, Löschung und Wiederherstellung aus Chunks. |
| `dcloud_client/network/peers.py` | `PeerProvider`-, `IndexProvider`-Interfaces und thread-sichere In-Memory-Peer-Liste mit Deduplizierung und Offline-Timeout. |
| `dcloud_client/network/transport.py` | Transport-Protokollinterface für spätere UDP/QUIC/libp2p/WebRTC-Backends. |
| `dcloud_client/network/udp_discovery.py` | UDP-Discovery mit automatischer LAN-Suche auf Port 6881, Bootstrap-Hello, manuell startbarem Peer-Einstieg, aktivem Peer-Listen-Gossip, Offline-Bereinigung, NAT-Tree-Relay und Magic-Header-Filter. |
| `dcloud_client/network/http_relay.py` | Optionaler HTTP/PHP-Relay-Transport für entfernte Peers hinter NAT: Registrierung, Peer-Discovery, direkter PHP-HTTP-Forwarder und Mailbox-Fallback für die bestehende P2P-API. |
| `dcloud_client/network/smb_server.py` | Optionaler eingebetteter SMB-Server für direkten Dateizugriff auf den lokalen `storage/`-Pfad. |
| `dcloud_client/network/p2p_storage.py` | HTTP-basierter Peer-Transfer für komprimierte Chunks, Manifest-Freigaben, signierte Freigabe-Revocations und signierte Datei-Löschungen inklusive Chunk-Bereinigung. Discovery bleibt UDP; Daten laufen direkt über die Flask Peer-API oder optional über das PHP-Relay. |
| `relay/dcloud_relay.php` | Einzelne PHP-Datei für einen Webserver, der entfernten Peers als HTTP-Forwarder und Mailbox-Fallback dient. |
| `relay/dcloud_relay_server.py` | Optionale Python-Relay-Alternative fuer VPS/Plesk-Python-Apps; schneller und stabiler als PHP bei vielen Chunk-Transfers. |
| `dcloud_client/web/app.py` | Flask-App mit Dashboard, Upload, Download und Healthcheck. |
| `dcloud_client/web/templates/` | HTML-Templates für Dashboard und Dateiliste. |

## Plattformen

- Python 3.11+
- Primär Linux und Windows
- Perspektivisch OpenWrt: Die Runtime hält Abhängigkeiten klein (`Flask`, `PyYAML`, `cryptography`). Für sehr kleine Router kann später eine abgespeckte HTTP-UI oder ein reines CLI-Profil ergänzt werden.

## Installation und Start

```bash
python3.11 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m dcloud_client.main --config config.yml
```

Der Modulstart sollte normalerweise aus dem Repository-Root erfolgen. Falls du bereits in `dcloud_client/` gewechselt bist, funktionieren zusätzlich beide Varianten:

```bash
python -m dcloud_client.main --config ../config.yml
python main.py --config ../config.yml
```

Beim ersten Start wird `config.yml` erzeugt, falls sie noch nicht existiert. Danach ist die lokale Weboberfläche standardmäßig hier erreichbar. Der Client sucht sofort im LAN nach anderen dcloud-Clients auf UDP-Port **6881**. Im Dashboard kann zusätzlich ein Peer als `host:port` eingetragen werden; der Austausch startet sofort und weitere bekannte Peers werden automatisch verteilt. Für Nodes hinter NAT kann derselbe Eintrag als NAT-Parent markiert werden:

```text
http://127.0.0.1:8787
```

> Sicherheit: Standard ist jetzt `0.0.0.0`, damit die Peer-API im LAN erreichbar ist. Nutze Firewall-Regeln oder setze `web.host: 127.0.0.1`, wenn dieser Knoten keine Chunks von anderen Peers annehmen soll.

## Beispiel-`config.yml`

```yaml
node:
  name: dcloud-node
  identity_path: ./storage/identity
  client_type: server
storage:
  path: ./storage
  limit_bytes: 53687091200 # freigegebener Speicher, Minimum 5 GiB
  min_free_bytes: 1073741824
  chunk_size_bytes: 4194304
web:
  host: 0.0.0.0 # Peer-API im LAN erreichbar; lokal weiter über 127.0.0.1 nutzbar
  port: 8787
network:
  udp_host: 0.0.0.0
  udp_port: 6881
  udp_port_range:
    start: 6881
    end: 6891
  bootstrap_nodes:
    - 192.0.2.10:6881 # optionaler Einstiegspunkt, kein zentraler Server
  tree_parent_nodes:
    - 192.0.2.20:6881 # optional: LAN-Parent mit Portfreigabe für NAT-Baum
  relay_children: false # true auf dem Parent-Node mit Portfreigabe
  discovery_interval_seconds: 10
  auto_discovery_enabled: true
  auto_discovery_ports:
    - 6881 # Standard-Port für sichtbare dcloud-Clients
  auto_discovery_hosts:
    - 255.255.255.255 # LAN-Broadcast; optional weitere Broadcast-Ziele ergänzen
  startup_discovery_seconds: 12
  startup_discovery_interval_seconds: 2
  peer_timeout_seconds: 35 # Offline-Peers nach ca. 3 verpassten Discovery-Runden entfernen
  peer_cleanup_interval_seconds: 5
  relay_url: "https://support.tmp-networks.de/dcstorage/dcloud_relay.php" # primäres öffentliches Standard-Relay
  relay_urls:
    - "https://support.tmp-networks.de/dcstorage/dcloud_relay.php" # primäres Standard-Relay
    - "http://dcloud.byethost12.com/dcloud_relay.php" # festes Backup-Relay
  relay_secret: "" # deprecated: Tages-Token werden automatisch vom PHP-Relay erzeugt
  relay_poll_interval_seconds: 1
  relay_request_timeout_seconds: 180
security:
  protocol_magic: DCLOUD1
```



## Automatische LAN-Discovery

Standardmäßig sucht jeder Client ohne manuelle Konfiguration nach anderen dcloud-Clients im lokalen Netzwerk:

- Der Client lauscht auf dem konfigurierten UDP-Port, bevorzugt **6881**. Wenn der Port lokal belegt ist, wird ein Port aus `udp_port_range` gewählt.
- Beim Start werden für `startup_discovery_seconds` schnelle Discovery-Hellos gesendet, standardmäßig alle 2 Sekunden.
- Danach läuft die Suche regelmäßig über `discovery_interval_seconds`.
- Gefundene Peers antworten mit `hello_ack`; anschließend tauschen die Knoten ihre Peer-Listen aus und verbinden das Netz per Gossip weiter.
- Gossippte Peers sind zunächst nur Kandidaten. Sie erscheinen erst in der Online-Liste, wenn sie selbst direkt antworten.
- Offline-Peers werden nach `peer_timeout_seconds` automatisch entfernt; gleiche Host/Port-Endpunkte werden dedupliziert, damit die Liste nicht vollläuft.
- Der Button **„Netzwerksuche aktualisieren“** in den Einstellungen löst jetzt einen echten sofortigen Discovery-Lauf aus und aktualisiert nicht nur die Anzeige.

Für normale LANs reicht der Broadcast `255.255.255.255`. Falls ein Netzwerk gerichtete Broadcast-Adressen benötigt, können weitere Ziele unter `network.auto_discovery_hosts` ergänzt werden. Die Firewall muss eingehende/ausgehende UDP-Pakete auf Port 6881 erlauben.

## PHP-Relay / Proxy für Peers außerhalb des LANs

Für Peers in unterschiedlichen Heimnetzwerken wird ein PHP-Webserver als Vermittlungs- und Relay-Pfad genutzt. Das ist kein echter UDP-TURN-Server wie bei WebRTC. Ab Relay-Version **1.3.0** gibt es zwei Pfade: Zuerst versucht der Client einen direkten PHP-HTTP-Forwarder, bei dem der Webserver die P2P-API-Anfrage unmittelbar an die beim Relay registrierte öffentliche Peer-IP und den Web-Port weiterleitet. Dabei werden keine einzelnen Chunk-Dateien auf dem Relay abgelegt. Wenn der Ziel-Peer aus Sicht des Webservers nicht erreichbar ist, etwa wegen CGNAT, Firewall oder fehlender Portfreigabe, fällt der Client automatisch auf die bisherige HTTP-Mailbox zurück: Jeder Client holt dann eingehende P2P-API-Anfragen aus seiner Queue und schreibt Antworten zurück. Dadurch bleiben Manifest-Freigaben, Revocations, Datei-Löschungen und Chunk-Transfers auch ohne direkt erreichbaren eingehenden Port möglich.

Das öffentliche Standard-Relay `https://support.tmp-networks.de/dcstorage/dcloud_relay.php` und das Backup-Relay `http://dcloud.byethost12.com/dcloud_relay.php` sind fest im Client aktiv, solange PHP-Vermittlung nicht bewusst deaktiviert wurde. In den Einstellungen können zusätzliche Relay-URLs eingetragen werden. Diese zusätzlichen Relays werden in `network.relay_urls` gespeichert, bei der nächsten Discovery an andere Peers verteilt und von diesen automatisch ebenfalls genutzt. Dadurch bleibt das Netzwerk erreichbar, selbst wenn einzelne Relay-Server später ausfallen oder einzelne Nutzer eigene Relays hosten.

Einrichtung für ein eigenes Zusatz-Relay:

1. Datei `relay/dcloud_relay.php` auf einen PHP-fähigen Webspace hochladen, zum Beispiel nach `https://deine-domain.de/dcloud_relay.php`.
2. In dcloud unter **Einstellungen → PHP-Relay / Proxy für Internet-Peers** die URL bei **Weitere Relay-URLs hinzufügen** eintragen.
3. **Netzwerksuche aktualisieren** anklicken oder kurz warten, bis das Relay-Polling die entfernten Peers einsammelt und neue Relay-URLs weitergibt.

Das Relay-Passwort muss nicht mehr manuell gepflegt werden. Die PHP-Datei erzeugt beim ersten Start lokal einen zufälligen Seed, leitet daraus täglich einen neuen Relay-Zugriffsschlüssel ab und gibt den aktuellen Tages-Schlüssel über die `health`-Aktion an Clients aus. Clients erneuern ihn automatisch, geben den Tokenstatus in Relay-Metadaten mit und akzeptieren dadurch die tägliche Rotation ohne Nutzereingriff.

Ab Relay-Version **1.3.0** enthält `dcloud_relay.php` zusätzlich den `direct_proxy_request`-Modus. Dieser Modus funktioniert ähnlich wie ein kleiner HTTP-Forwarder: Er erlaubt ausschließlich `GET`/`POST` auf `/api/p2p/...`, leitet nur ausgewählte Header weiter und verbindet nur zu öffentlich routbaren Peer-IPs, damit der Webserver nicht als offener Proxy oder SSRF-Werkzeug missbraucht wird. Ältere Relay-Härtungen bleiben enthalten: leere Bodies, ungültiges JSON und fehlerhafte `register`-Requests mit fehlenden `peer`-Metadaten liefern saubere JSON-Fehlermeldungen, Long-Polling bleibt aktiv und Speicher-Metadaten werden nicht durch minimale Heartbeats überschrieben.

Wichtig für große Dateien: Auch der PHP-Forwarder arbeitet über HTTP/JSON/Base64 vom Client zum Relay und vom Relay zum Ziel-Peer, speichert die Chunk-Nutzdaten aber nicht mehr als einzelne Mailbox-Dateien. Peer-Replikation läuft nach dem lokalen Upload im Hintergrund und nutzt gebündelte binäre Upload-Packs über `/api/p2p/chunks/batch/pack/upload`, statt den Upload-Request mit jedem Remote-Chunk zu blockieren. Bei sehr restriktiven Webspaces müssen trotzdem `post_max_size`, `memory_limit`, PHP-cURL oder aktivierte HTTP-Stream-Wrapper und Request-Timeouts ausreichend groß sein. Der Relay-Worker registriert sich nicht mehr bei jedem Poll-Zyklus neu, sondern hält per Long-Polling die Mailbox warm. Der empfangende Client verarbeitet Mailbox-Relay-Requests parallel in kleinen Worker-Threads. Wenn ein Webspace beim Zurückschreiben einer Antwort hängt, blockiert das nicht mehr die komplette Mailbox und der lokale Upload bleibt nicht mitten in der Datei stehen. Für das LAN bleibt der direkte HTTP-Transfer schneller; die Reihenfolge ist: direkter Peer-HTTP-Transfer → PHP-Forwarder ohne Chunk-Ablage → Mailbox-Relay als NAT-Fallback. Beim Wiederherstellen einer geteilten Datei lädt der Empfänger fehlende Chunks zusätzlich gebündelt über `/api/p2p/chunks/batch/download`, statt für jeden Chunk einen eigenen HTTP-/PHP-Forwarder-Request auszulösen; der alte Einzelabruf bleibt nur als Kompatibilitäts-Fallback für ältere Peers aktiv.

### Optionale Python-Relay-Alternative

Wenn dein Webserver Python als dauerhafte App oder kleinen Hintergrundprozess ausführen kann, ist `relay/dcloud_relay_server.py` oft besser als PHP. Die Python-Variante verwendet das gleiche JSON-Protokoll und das gleiche automatische Tages-Token-System, arbeitet aber mit einem `ThreadingHTTPServer` und blockiert bei vielen gleichzeitigen Chunk-Requests deutlich weniger.

Beispiel lokal/VPS:

```bash
cd relay
python3 dcloud_relay_server.py --host 0.0.0.0 --port 8788
```

Danach kannst du per nginx/Apache/Plesk eine HTTPS-URL auf diesen Port weiterleiten und diese URL in den dcloud-Einstellungen als weiteres Relay eintragen. Die festen PHP-Relays bleiben weiterhin aktiv; die Python-Relay-URL wird wie alle Zusatz-Relays im Netzwerk verteilt.



## Optional integrierter SMB-Server

Der Client kann optional einen eigenen SMB-Server starten, damit der lokale Speicherpfad zusätzlich als Netzlaufwerk erreichbar ist (z. B. `\\<node-ip>\DCLOUD`).

```yaml
smb:
  enabled: true
  host: 0.0.0.0
  port: 445
  share_name: DCLOUD
  username: ""
  password: ""
```

Hinweis: Für den SMB-Server wird `impacket` benötigt (ist in `requirements.txt` enthalten). Auf Linux ist Port 445 ggf. nur mit erhöhten Rechten bindbar.

## Client-Typ und Speicherfreigabe

Im Einstellungsfenster kann jeder Knoten als **Server** betrieben werden:

- **Server:** Der Knoten wird als dauerhaftes Speicherziel für das Peer-to-Peer-Netz angekündigt. Andere Peers dürfen diesen Client für P2P-Ablage einplanen.

Der freigegebene Speicher wird in GB konfiguriert und kann über die UI nicht unter **5 GB** gesetzt werden. Die Einstellung wird in `config.yml` gespeichert und zur Laufzeit direkt auf das aktive Speicherlimit angewendet.

## P2P-Freigaben

Über Rechtsklick auf eine Datei kann eine Freigabe gezielt für einen Peer oder für alle aktiven Peers erstellt werden. Die UI zeigt dafür nicht nur IP-Adressen, sondern automatisch generierte Anzeigenamen wie „Blauer Falke 1A2B“, falls ein Knoten keinen eigenen Namen konfiguriert hat. Beim Freigeben wird das signierte Manifest direkt an den ausgewählten Peer übertragen. Wird die Freigabe deaktiviert, erzeugt der Besitzer eine signierte Revocation für das alte geteilte Manifest; aktive Ziel-Peers entfernen es sofort aus ihrer sichtbaren Dateiliste, offline gewesene Ziel-Peers werden beim nächsten Erreichen erneut bereinigt. Die Chunks selbst bleiben bei einer reinen Freigabe-Deaktivierung verteilt auf den im Manifest genannten Speicher-Knoten; der empfangende Peer lädt fehlende Chunks beim Download von diesen Knoten nach. Löscht der Besitzer die Datei vollständig, erzeugt er zusätzlich eine signierte Datei-Löschung. Aktive Speicher-/Freigabe-Peers entfernen dann sowohl sichtbare Manifeste als auch unreferenzierte Chunk-Kopien. Ist ein Peer offline, bleibt die Löschung als Tombstone vorgemerkt und wird beim nächsten Wiederauftauchen zugestellt; alte Manifeste derselben Datei werden danach nicht mehr importiert.

## NAT-Baum / Parent-Node im lokalen Netzwerk

Wenn mehrere Nodes hinter demselben NAT laufen, muss nicht jeder Node eine eigene Portfreigabe bekommen:

1. Ein Node im lokalen Netzwerk bekommt die Portfreigabe und setzt `network.relay_children: true`.
2. Die anderen lokalen Nodes tragen diesen Node als `network.tree_parent_nodes` ein oder markieren ihn im Dashboard als „NAT-Parent“.
3. Der Parent nimmt diese Children in seine Peer-Liste auf und veröffentlicht sie im Gossip mit `route_via_node_id`.
4. Andere Peers senden Discovery-/Control-Nachrichten an diese Children über den Parent; der Parent leitet sie an die lokale Adresse des Child weiter.

Damit entsteht eine Baumstruktur ohne zentralen Server: Außen sichtbare Nodes können lokale Unterbäume repräsentieren, während die einzelnen Child-Nodes nur ausgehende UDP-Pakete zum Parent benötigen.

## Upload-/Download-Ablauf im MVP

1. Benutzer öffnet `http://127.0.0.1:8787`.
2. Benutzer wählt eine Datei im Desktop-Explorer aus.
3. Der Client speichert die Datei temporär unter `storage/tmp/`.
4. `ChunkStore` liest die Datei in Blöcken der konfigurierten `chunk_size_bytes`; wenn die aktiven Speicherziele nur per PHP-Relay/Forwarder erreichbar sind, wird automatisch die kleinere `network.relay_chunk_size_bytes` verwendet.
5. Jeder Chunk wird komprimiert, danach wird SHA-256 über die tatsächlich gespeicherten Bytes berechnet.
6. Der Upload-Plan rotiert die Chunks über den lokalen Knoten und alle aktiven Speicher-Peers. Sobald mindestens ein Speicher-Peer vorhanden ist, wird jeder Chunk nach Möglichkeit mit zwei Speicherorten im Manifest abgelegt. Remote-Ziele erhalten den komprimierten Chunk über `/api/p2p/chunks/<hash>`.
7. Kann ein Remote-Peer den Chunk nicht annehmen, wird der nächste Zielknoten versucht. Falls die gewünschte Redundanz nicht erreicht wird, wird lokal eine Sicherheitskopie gespeichert und im Manifest als Fallback markiert.
8. `ManifestStore` erstellt ein signiertes Manifest mit Datei-Metadaten, Chunk-Liste, konkreten Chunk-Locations, Placement-Status und Access-Liste.
9. Beim Download prüft der Client das Manifest, lädt fehlende Chunks von den im Manifest genannten aktiven Peers nach und stellt die Datei unter `storage/downloads/` wieder her.
10. Beim Löschen einer eigenen Datei sendet der Besitzer eine signierte Delete-Nachricht an alle Peers, die laut Manifest Chunks oder Freigaben halten könnten. Diese Peers löschen das Manifest und alle nicht mehr referenzierten Chunks. Offline-Peers werden später nachsynchronisiert.

Die Upload-UI zeigt dabei zwei Ebenen: zuerst den Browser-Transfer zur lokalen Web-App und anschließend die lokale Serververarbeitung. Sobald das lokale Manifest geschrieben ist, ist der Upload für den Nutzer abgeschlossen; der gleiche Statusdialog zeigt danach weiter die asynchrone Hintergrund-Replikation an, ohne den Upload-Request oder das Dashboard zu blockieren.

## Storage-Layout

```text
storage/
├── chunks/
│   └── ab/
│       └── abcdef....chunk
├── manifests/
│   └── <manifest_id>.json
├── tmp/
├── downloads/
└── identity/
    └── node_ed25519.key
```

## Sicherheitsdesign im MVP

- Private Keys bleiben ausschließlich lokal.
- Node-ID ist `SHA-256(public_key_bytes)`.
- Manifest-Signaturen nutzen Ed25519.
- Chunks werden über SHA-256 adressiert und beim Lesen geprüft.
- UDP-Discovery ignoriert Pakete ohne korrektes `protocol_magic` und verteilt nur Discovery-Metadaten wie Node-ID, Name, UDP-Port, Web-API-Port, Speicherfreigabe und bekannte Peers.
- Die Web-/Peer-API bindet standardmäßig an `0.0.0.0`, damit LAN-Peers Chunks übertragen können; Firewall-Regeln bleiben für Produktivbetrieb wichtig.
- Das PHP-Relay speichert nur kurzlebige Peer-Metadaten, Request-Mailboxen, Antworten und einen lokalen Seed für automatisch rotierende Tages-Token. HTTPS bleibt für öffentliche Deployments wichtig.
- Manifeststruktur enthält bereits ein `encryption`-Feld für spätere clientseitige Verschlüsselung.

## Spätere Erweiterungen

### P2P-Replikation weiter ausbauen

- Auf dem bestehenden Peer-Gossip aufbauen und `IndexProvider.announce_manifest()` sowie `find_chunk()` mit einem DHT- oder Multi-Node-Index implementieren.
- Den aktuell festen Mindest-Replikationsfaktor später konfigurierbar machen oder durch Erasure-Coding pro Manifest ergänzen.
- Background-Jobs für Chunk-Repair, Rebalancing und Garbage Collection ergänzen.
- Peer-Scores für Verfügbarkeit, Latenz, Storage-Beiträge und Fehlverhalten einführen.

### Relay-Nodes und NAT-Traversal

- Relay als optionalen Peer-Typ modellieren, nicht als zentrale Wahrheit.
- UDP hole punching und STUN-artige Adressbeobachtung ergänzen.
- Für nicht direkt erreichbare Nodes Relay-Reservations mit Ablaufzeit nutzen.

### QUIC, libp2p oder WebRTC

- Neue Klassen gegen das `Transport`-Protocol implementieren.
- Chunk-Transfer von Discovery entkoppelt halten: UDP bleibt Control Plane, QUIC/HTTP/WebRTC wird Data Plane.
- Nachrichten später mit Node-Key signieren und Nonces gegen Replay-Angriffe verwenden.

### Dezentrale Indexierung

- `IndexProvider` austauschbar halten:
  - `LocalIndexProvider` für Offline-/Einzelknotenbetrieb.
  - `BootstrapIndexProvider` als temporärer Tracker.
  - `DHTIndexProvider` für vollständig dezentrale Suche.
  - `MultiNodeIndexProvider` für redundante, signierte Announcements.
- Announcements als signierte Records mit TTL speichern.
- Manifest-IDs und Chunk-Hashes als Content Keys verwenden.

### Clientseitige Verschlüsselung

- Datei vor dem Chunking verschlüsseln, damit Chunks nie Klartext verlassen.
- Pro Datei Data Encryption Key erzeugen.
- Schlüssel nur lokal oder für berechtigte Empfänger asymmetrisch verpackt speichern.
- Manifest `encryption` um Algorithmus, Nonce/IV, Key-Wrapping-Metadaten und Policy erweitern.

## Entwicklungsstatus

Bewusst nicht enthalten:

- kein vollständiges DHT
- kein Blockchain-/Token-System
- noch kein DHT/Repair/Rebalancing für langfristige Replikation
- keine NAT-Traversal-Implementierung
- keine öffentliche Authentifizierung für die Web-UI

Der MVP ist als saubere, modulare Grundlage gedacht, damit zentrale Komponenten später entfernt und durch dezentrale Provider ersetzt werden können.

## Service-Installer per `curl` (Linux/OpenWrt/Windows-Bootstrap)

Es gibt ein Install-Script unter `scripts/install_dcloud_service.sh`, das den Client als Service einrichtet und dabei Rolle (Server), freigegebenen Speicher und SMB-Konfiguration setzt.

Beispiel:

```bash
curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service.sh | sh -s -- \
  --target linux \
  --role server \
  --storage-gb 200 \
  --enable-smb \
  --smb-user dcloud \
  --smb-pass 'starkes-passwort'
```

Hinweise:

- `--target linux` richtet einen `systemd`-Service ein.
- `--target openwrt` richtet einen `/etc/init.d`-Service ein.
- OpenWrt-Autoupdate nutzt eine Lock-Datei unter `/tmp`, startet den Dienst per Cleanup-Trap nach jedem Updateversuch wieder und vermeidet ein komplettes `pip install -r requirements.txt`, damit kleine Router nicht beim Dependency-Build hängen bleiben. Logs landen in `INSTALL_DIR/logs/autoupdate.log`.
- `--target windows` erzeugt ein PowerShell-Bootstrap-Skript für eine geplante Aufgabe beim Systemstart (als Dienst-Ersatz).
- Mindestwert für `--storage-gb` ist `5`.
