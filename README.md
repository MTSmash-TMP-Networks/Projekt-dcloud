# dcloud Direct-Peer Build

Diese Variante entfernt das PHP-Relay vollständig aus dem Projekt. Dateiübertragung, Freigaben, externe Links und Gateway-Zugriff laufen ausschließlich über direkte Peer-Routen.

## Netzwerkmodell

- LAN: automatische UDP-Discovery plus direkter HTTP-Transfer auf dem dcloud-Port.
- Internet: manuell eingetragene NAT-/DDNS-Endpunkte oder HTTPS-Reverse-Proxy.
- Gateway: ein öffentlich erreichbarer Peer meldet seine internen Peers und kann für diese Chunks/Freigaben weiterleiten.
- Kein PHP-Fallback: wenn kein direkter Weg erreichbar ist, erscheint eine klare Fehlermeldung.

## Dashboard

Im Dashboard werden Peers unter **Direkte NAT-/DDNS-Endpunkte** eingetragen, zum Beispiel:

```text
https://peer.example.de
http://mein-ddns.net:8787
http://203.0.113.10:8787
```

Beim Eintragen wird `/healthz` geprüft und danach ein signierter Peer-Austausch über `/api/p2p/peers/connect` gestartet. Dadurch speichert die Gegenseite automatisch die Rückroute zu diesem Knoten, sofern sie über LAN/VPN/NAT erreichbar ist. Einseitiges Eintragen reicht also für beide Seiten, wenn beide Richtungen direkt routbar sind. Danach können Freigaben, Uploads, Downloads und Gateway-Zugriffe direkt über diesen Endpunkt laufen.

## Ports

| Zweck | Port | Hinweis |
| --- | --- | --- |
| Dashboard/P2P-API/Transfer | TCP 8787 | Für direkte Internet-Peers per Portfreigabe oder Reverse Proxy erreichbar machen |
| LAN-Discovery | UDP 6881 | Nur für lokale automatische Suche nötig |
| HTTPS-Reverse-Proxy | TCP 443 | Empfohlen für öffentliche Endpunkte |
| SMB | TCP 445 | Nur lokal verwenden, nicht öffentlich freigeben |

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
