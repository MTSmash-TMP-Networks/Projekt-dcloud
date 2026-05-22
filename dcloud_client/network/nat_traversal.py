"""Best-effort NAT traversal helpers (UPnP IGD + NAT-PMP)."""
from __future__ import annotations

import logging
import re
import socket
import struct
import time
from urllib import request
from xml.etree import ElementTree

LOG = logging.getLogger(__name__)


def _default_gateway_linux() -> str | None:
    try:
        with open('/proc/net/route', 'r', encoding='utf-8') as handle:
            next(handle, None)
            for line in handle:
                fields = line.strip().split()
                if len(fields) < 3:
                    continue
                if fields[1] != '00000000':
                    continue
                gateway_hex = fields[2]
                raw = bytes.fromhex(gateway_hex)
                return '.'.join(str(b) for b in raw)
    except Exception:
        return None
    return None


def _soap_add_mapping(control_url: str, service: str, local_ip: str, port: int, lease_seconds: int = 3600) -> bool:
    body = f"""<?xml version=\"1.0\"?>
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
<s:Body><u:AddPortMapping xmlns:u=\"{service}\"><NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>{port}</NewInternalPort><NewInternalClient>{local_ip}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>dcloud</NewPortMappingDescription><NewLeaseDuration>{lease_seconds}</NewLeaseDuration></u:AddPortMapping></s:Body>
</s:Envelope>""".encode('utf-8')
    req = request.Request(control_url, data=body, method='POST')
    req.add_header('Content-Type', 'text/xml; charset="utf-8"')
    req.add_header('SOAPAction', f'"{service}#AddPortMapping"')
    try:
        with request.urlopen(req, timeout=3.5) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def try_upnp_port_mapping(port: int) -> bool:
    msg = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST:239.255.255.250:1900',
        'MAN:"ssdp:discover"',
        'MX:2',
        'ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1', '', ''
    ]).encode('ascii')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(2.0)
    sock.sendto(msg, ('239.255.255.250', 1900))
    location = ''
    end = time.time() + 2.2
    while time.time() < end:
        try:
            data, _ = sock.recvfrom(4096)
        except OSError:
            break
        text = data.decode('utf-8', errors='ignore')
        match = re.search(r'(?im)^location:\s*(.+)$', text)
        if match:
            location = match.group(1).strip()
            break
    sock.close()
    if not location:
        return False
    try:
        with request.urlopen(location, timeout=3.5) as resp:
            xml = resp.read()
        root = ElementTree.fromstring(xml)
    except Exception:
        return False
    ns = {'d': 'urn:schemas-upnp-org:device-1-0'}
    control_url = None
    service_type = None
    for service in root.findall('.//d:service', ns):
        st = (service.findtext('d:serviceType', default='', namespaces=ns) or '').strip()
        if 'WANIPConnection' in st or 'WANPPPConnection' in st:
            control = (service.findtext('d:controlURL', default='', namespaces=ns) or '').strip()
            if control:
                service_type = st
                base = location.rsplit('/', 1)[0]
                control_url = control if control.startswith('http') else f"{base}/{control.lstrip('/')}"
                break
    if not control_url or not service_type:
        return False
    local_ip = socket.gethostbyname(socket.gethostname()) or '127.0.0.1'
    return _soap_add_mapping(control_url, service_type, local_ip, port)


def try_nat_pmp_port_mapping(port: int, lifetime_seconds: int = 3600) -> bool:
    gw = _default_gateway_linux()
    if not gw:
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        packet = struct.pack('!BBHHI', 0, 1, port, port, lifetime_seconds)
        sock.sendto(packet, (gw, 5351))
        data, _ = sock.recvfrom(32)
        if len(data) < 16:
            return False
        version, op, result = data[0], data[1], struct.unpack('!H', data[2:4])[0]
        return version == 0 and op == 129 and result == 0
    except OSError:
        return False
    finally:
        sock.close()
