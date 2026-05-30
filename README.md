# dcloud Direct-Peer Build

Diese Variante entfernt das PHP-Relay vollständig aus dem Projekt. Dateiübertragung, Freigaben, externe Links und Gateway-Zugriff laufen ausschließlich über direkte Peer-Routen.

## Netzwerkmodell

- LAN: automatische UDP-Discovery plus direkter HTTP-Transfer auf dem dcloud-Port.
- Internet: manuell eingetragene NAT-/DDNS-Endpunkte oder HTTPS-Reverse-Proxy.
- Gateway/Mesh: ein erreichbarer Peer meldet seine internen Peers, gespeicherten Gateway-Routen und lokalen Subnetze. Diese Informationen werden weiter an alle bekannten Peers gegossipt; der Gateway kann Chunks/Freigaben auch über mehrere App-Gateway-Hops weiterleiten.
- Kein PHP-Fallback: wenn kein direkter Weg erreichbar ist, erscheint eine klare Fehlermeldung.

## Dashboard

Im Dashboard werden Peers unter **Direkte NAT-/DDNS-Endpunkte** eingetragen, zum Beispiel:

```text
https://peer.example.de
http://mein-ddns.net:8787
http://203.0.113.10:8787
```

Beim Eintragen wird `/healthz` geprüft und danach ein signierter Peer-Austausch über `/api/p2p/peers/connect` gestartet. Dadurch speichert die Gegenseite automatisch die Rückroute zu diesem Knoten und beide Seiten tauschen nicht nur sich selbst, sondern ihre komplette bekannte Peer-/Gateway-Routenliste aus. Einseitiges Eintragen reicht also als Einstieg: die weiteren Peers hinter beiden Standorten werden anschließend im Mesh verteilt und als „direkt“ oder „über Gateway erreichbar“ angezeigt.


### Standort-/VPN-Subnetz-Gateway

Wenn zwei Peers aus unterschiedlichen Netzen direkt verbunden sind, verteilt dcloud jetzt die sichtbaren Peers aktiv in beide Richtungen. Beispiel:

```text
Standort A: 192.168.1.0/24, Gateway-Peer 192.168.1.3
Standort B: 192.168.3.0/24, Gateway-Peer 192.168.3.4
```

Wenn `192.168.1.3` und `192.168.3.4` erfolgreich verbunden sind, tauschen sie signiert ihre Peer-Listen, gespeicherten Gateway-Routen und lokalen Subnetz-Hinweise aus. Die Informationen werden danach weiter an alle aktiven Peers verteilt. Peers wie `192.168.3.5` lernen dadurch alle bekannten Peers aus `192.168.1.0/24` als „über Gateway erreichbar“ und umgekehrt. Dateiübertragung, Freigaben und Chunk-Zugriffe laufen dann über den passenden Gateway-Pfad weiter; bei Bedarf auch über mehrere dcloud-App-Gateway-Hops.

Wichtig: Das ist eine Anwendungsebene innerhalb von dcloud. Das Tool setzt keine Betriebssystem-Routen, NAT-Regeln oder Firewall-Regeln. Andere Programme auf dem Rechner sehen dadurch nicht automatisch das entfernte Subnetz. Für dcloud-Peers reicht diese App-Gateway-Route aber aus.

## Ports

| Zweck | Port | Hinweis |
| --- | --- | --- |
| Dashboard/P2P-API/Transfer | TCP 8787 | Für direkte Internet-Peers per Portfreigabe oder Reverse Proxy erreichbar machen |
| LAN-Discovery | UDP 6881 | Nur für lokale automatische Suche nötig |
| HTTPS-Reverse-Proxy | TCP 443 | Empfohlen für öffentliche Endpunkte |
| SMB | TCP 445 | Nur lokal verwenden, nicht öffentlich freigeben |


## Adaptive Speicherverteilung

Die Direct-Peer-Variante verteilt Dateien nicht mehr stumpf als komplette RAID-1-Kopie auf jeden Peer. Stattdessen gilt:

- Pro Datei muss mindestens ein erreichbarer Knoten die komplette Datei als Seed besitzen.
- Wenn der lokale Speicher voll ist, wird zuerst ein vollständiger Remote-Seed auf einem erreichbaren Speicher-Peer erstellt.
- Weitere Peers erhalten rotierende Chunk-Streifen. Mit mehr Peers steigt die Zahl der Kopien pro Chunk stufenweise.
- Fällt ein Peer während der Verteilung aus, werden offene Chunks auf andere aktive Peers umgelegt, statt den ganzen Ablauf abzubrechen.
- Die UI zeigt deshalb Kopien pro Chunk und das adaptive Verteilungsprofil an, nicht mehr eine starre RAID-1-Spiegelung pro Peer.

### Hintergrund-Verteilung nach Upload

Der Upload wartet nicht mehr auf den kompletten Redundanzaufbau. Sobald die Datei lokal gespeichert ist oder bei vollem lokalem Speicher ein vollständiger Remote-Seed existiert, wird der Upload als abgeschlossen gemeldet. Die adaptive Verteilung auf weitere Peers läuft danach als entkoppelter Hintergrund-Job weiter. Dadurch ist die Datei schneller sichtbar und ein langsamer oder ausfallender Zusatz-Peer blockiert nicht mehr den eigentlichen Upload.

Richtwerte:

| Aktive Speicher-Peers | Profil | Ziel |
| --- | --- | --- |
| 0 | Einzelner Seed | lokale Datei bleibt komplett |
| 1 | Seed + Spiegel-Peer | zwei Kopien pro Chunk |
| 2-3 | Seed + rotierende Chunk-Streifen | zwei Kopien pro Chunk, logisch verteilt |
| 4-6 | Seed + doppelte Chunk-Streifen | drei Kopien pro Chunk |
| 7+ | Seed + mehrfache Chunk-Streifen | bis zu vier Kopien pro Chunk |

## Freigaben

Freigaben werden direkt an bekannte Peers zugestellt. Zusätzlich ziehen Peers eingehende Freigaben aktiv von erreichbaren Peers nach, damit Freigaben auch erscheinen, wenn ein Ziel-Peer beim Erstellen kurz offline war.

## Externe Links

Externe Links zeigen direkt auf den aktuellen Peer/Gateway. Damit sie von außen funktionieren, muss dieser Peer öffentlich erreichbar sein, z. B. über DDNS/Portfreigabe oder Reverse Proxy.

## Entfernt

- `relay/` mit PHP- und Python-Relay-Dateien
- `dcloud_client/network/http_relay.py`
- automatische Relay-Discovery
- PHP-Forwarder/Mailbox-Transfers
- Relay-basierte externe Downloadlinks

## Installation

Die normale Python-/Docker-Installation bleibt gleich. Wichtig ist nur, dass die Peers im Dashboard über direkte Endpunkte verbunden werden.
