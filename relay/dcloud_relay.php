<?php
declare(strict_types=1);

/*
 * dcloud PHP HTTP relay/proxy
 *
 * Upload this single file to a PHP-capable webspace and enter its public URL in
 * dcloud under Einstellungen -> PHP-Relay. It provides a small HTTP mailbox for
 * clients that cannot reach each other directly because they are behind NAT or
 * in different networks.
 *
 * Relay access uses an automatic daily token. The PHP script creates a local
 * random seed on first run, derives a day-token from it, exposes the current
 * token through the health action and accepts the current/previous day token.
 * No manual shared password is required in the client UI.
 * For large files/chunks, raise PHP values such as post_max_size,
 * upload_max_filesize and memory_limit on the webserver.
 */

const DCLOUD_RELAY_VERSION = '1.2.9';
const DCLOUD_RELAY_TOKEN_ROTATION_SECONDS = 86400;
const DCLOUD_PEER_TTL_SECONDS = 45;
const DCLOUD_MESSAGE_TTL_SECONDS = 900;
const DCLOUD_MAX_REQUESTS_PER_POLL = 16;
const DCLOUD_MAX_ENCODED_BODY_BYTES = 268435456; // 256 MiB base64 payload
const DCLOUD_CLEANUP_INTERVAL_SECONDS = 30;

$GLOBALS['DCLOUD_CURRENT_INPUT'] = [];

// Some shared hosting stacks or older uploaded revisions may accidentally emit
// warnings/diagnostics before the relay response. Keep responses parseable for
// the Python client by buffering all output and flushing exactly one JSON object.
if (ob_get_level() === 0) {
    ob_start();
}

function dcloud_storage_dir(): string {
    static $cachedDir = null;
    if (is_string($cachedDir) && $cachedDir !== '') {
        return $cachedDir;
    }

    $dir = __DIR__ . DIRECTORY_SEPARATOR . 'dcloud-relay-data';
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        dcloud_fail('Relay-Datenverzeichnis konnte nicht erstellt werden', 500);
    }
    $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
    if (!file_exists($htaccess)) {
        @file_put_contents($htaccess, "Deny from all\n");
    }
    foreach (['queues', 'responses'] as $sub) {
        $path = $dir . DIRECTORY_SEPARATOR . $sub;
        if (!is_dir($path) && !@mkdir($path, 0700, true) && !is_dir($path)) {
            dcloud_fail('Relay-Unterverzeichnis konnte nicht erstellt werden', 500);
        }
    }
    $cachedDir = $dir;
    return $dir;
}

function dcloud_seed_file(): string {
    return dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'relay-token-seed.txt';
}

function dcloud_relay_seed(): string {
    static $cachedSeed = null;
    if (is_string($cachedSeed) && $cachedSeed !== '') {
        return $cachedSeed;
    }

    $file = dcloud_seed_file();
    if (!file_exists($file)) {
        $seed = bin2hex(random_bytes(32));
        if (file_put_contents($file, $seed, LOCK_EX) === false) {
            dcloud_fail('Relay-Token-Seed konnte nicht erstellt werden', 500);
        }
        @chmod($file, 0600);
        $cachedSeed = $seed;
        return $seed;
    }
    $seed = trim((string)file_get_contents($file));
    if ($seed === '' || !preg_match('/^[A-Fa-f0-9]{64,}$/', $seed)) {
        $seed = bin2hex(random_bytes(32));
        if (file_put_contents($file, $seed, LOCK_EX) === false) {
            dcloud_fail('Relay-Token-Seed konnte nicht erneuert werden', 500);
        }
        @chmod($file, 0600);
    }
    $cachedSeed = $seed;
    return $seed;
}

function dcloud_token_day(int $offset = 0): string {
    return gmdate('Y-m-d', time() + ($offset * DCLOUD_RELAY_TOKEN_ROTATION_SECONDS));
}

function dcloud_token_for_day(string $day): string {
    return hash_hmac('sha256', 'dcloud-relay-v1|' . $day, dcloud_relay_seed());
}

function dcloud_current_relay_token(): array {
    $day = dcloud_token_day(0);
    $midnight = strtotime($day . ' 00:00:00 UTC');
    $expiresAt = ($midnight === false ? time() : $midnight) + DCLOUD_RELAY_TOKEN_ROTATION_SECONDS;
    return [
        'relay_token' => dcloud_token_for_day($day),
        'relay_token_day' => $day,
        'relay_token_expires_at' => $expiresAt,
        'relay_token_rotation_seconds' => DCLOUD_RELAY_TOKEN_ROTATION_SECONDS,
        'relay_token_mode' => 'automatic-daily',
    ];
}

function dcloud_relay_token_is_valid(string $provided): bool {
    $provided = trim($provided);
    if ($provided === '') {
        return false;
    }
    foreach ([0, -1] as $offset) {
        if (hash_equals(dcloud_token_for_day(dcloud_token_day($offset)), $provided)) {
            return true;
        }
    }
    return false;
}

function dcloud_render_landing_page(): void {
    $status = dcloud_current_relay_token();
    $peersPath = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'peers.json';
    $peers = dcloud_read_json_file($peersPath, []);
    $now = time();
    $activePeers = 0;
    foreach ($peers as $peer) {
        if (!is_array($peer)) {
            continue;
        }
        $age = $now - (int)($peer['relay_seen_at'] ?? 0);
        if ($age <= DCLOUD_PEER_TTL_SECONDS) {
            $activePeers++;
        }
    }

    $expiresIn = max(0, (int)$status['relay_token_expires_at'] - $now);
    $html = '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>dcloud Relay Status</title><style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem}main{max-width:720px;margin:0 auto;background:#111827;border:1px solid #1f2937;border-radius:14px;padding:1.5rem}h1{margin-top:0}dl{display:grid;grid-template-columns:max-content 1fr;gap:.5rem 1rem}dt{color:#94a3b8}dd{margin:0}.ok{color:#22c55e;font-weight:600}.hint{margin-top:1rem;color:#cbd5e1}</style></head><body><main>'
        . '<h1>dcloud Relay aktiv</h1>'
        . '<p class="ok">Der Endpoint ist erreichbar. Browser-Aufrufe zeigen diese Statusseite statt JSON.</p>'
        . '<dl>'
        . '<dt>Version</dt><dd>' . htmlspecialchars(DCLOUD_RELAY_VERSION, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</dd>'
        . '<dt>Aktive Peers</dt><dd>' . (string)$activePeers . '</dd>'
        . '<dt>Token-Rotation</dt><dd>' . (string)DCLOUD_RELAY_TOKEN_ROTATION_SECONDS . ' Sekunden</dd>'
        . '<dt>Token gueltig bis</dt><dd>' . gmdate('Y-m-d H:i:s', (int)$status['relay_token_expires_at']) . ' UTC</dd>'
        . '<dt>Restlaufzeit</dt><dd>' . (string)$expiresIn . ' Sekunden</dd>'
        . '</dl>'
        . '<p class="hint">Peer-Clients nutzen weiter POST+JSON (action=health/register/send/poll/...</p>'
        . '</main></body></html>';

    while (ob_get_level() > 0) {
        @ob_end_clean();
    }
    if (!headers_sent()) {
        http_response_code(200);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Accel-Buffering: no');
    }
    echo $html;
    flush();
    exit;
}

function dcloud_json_response(array $payload, int $status = 200): void {
    // Guarantee a single JSON document per HTTP request. This also removes any
    // earlier notices or debug output that would otherwise cause Python/JS to
    // fail with "Extra data after JSON". Content-Length helps nginx/FastCGI
    // discard any accidental trailing bytes from stale buffers or old opcache
    // workers instead of appending them to the JSON response.
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }
    $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($encoded === false) {
        $encoded = '{"ok":false,"message":"JSON encoding failed"}';
    }
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Accel-Buffering: no');
        header('Content-Length: ' . strlen($encoded));
    }
    echo $encoded;
    flush();
    exit;
}

function dcloud_fail(string $message, int $status = 200, array $details = []): void {
    // Hosted panels such as Plesk/nginx often log every 4xx as a server error.
    // Relay protocol validation errors are returned as JSON with ok=false and
    // HTTP 200 so the Python client can show the real message and the webserver
    // logs do not look like the PHP endpoint is missing or broken. Hard limits
    // and server-side failures may still pass 413/500 explicitly.
    $safeStatus = ($status >= 500 || $status === 413) ? $status : 200;
    $input = $GLOBALS['DCLOUD_CURRENT_INPUT'] ?? [];
    $action = is_array($input) ? (string)($input['action'] ?? '') : '';
    if ($action === '') {
        $action = (string)($_POST['action'] ?? ($_GET['action'] ?? ''));
    }
    $logPayload = array_merge([
        'status' => $status,
        'returned_status' => $safeStatus,
        'message' => $message,
        'action' => $action,
    ], $details);
    dcloud_log_event('error', $logPayload);
    dcloud_json_response(['ok' => false, 'message' => $message, 'status' => $status, 'details' => $details], $safeStatus);
}

function dcloud_log_event(string $type, array $payload): void {
    // Best-effort diagnostics for hosted PHP environments. Logging must never
    // break relay traffic; failures are intentionally ignored.
    try {
        $dir = dcloud_storage_dir();
        $line = json_encode([
            'time' => gmdate('c'),
            'type' => $type,
            'remote_addr' => (string)($_SERVER['REMOTE_ADDR'] ?? ''),
            'payload' => $payload,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
        @file_put_contents($dir . DIRECTORY_SEPARATOR . 'relay-events.log', $line, FILE_APPEND | LOCK_EX);
    } catch (Throwable $exception) {
        // no-op
    }
}

function dcloud_request_method(): string {
    return strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'POST'));
}

function dcloud_read_input(): array {
    $method = dcloud_request_method();

    // Browser checks, uptime monitors and simple curl tests should never create
    // PHP fatal errors. The client still uses POST+JSON for relay actions, but
    // GET/HEAD without a JSON body now return the public health payload.
    if ($method === 'GET' || $method === 'HEAD') {
        $action = (string)($_GET['action'] ?? '');
        if ($action === '' || $action === 'status' || $action === 'landing') {
            dcloud_render_landing_page();
        }
        if ($action !== 'health') {
            dcloud_fail('GET unterstuetzt nur status/landing oder action=health', 405);
        }
        return [
            'protocol' => 'dcloud-relay-v1',
            'action' => 'health',
        ];
    }

    if ($method === 'OPTIONS') {
        dcloud_json_response(['ok' => true, 'version' => DCLOUD_RELAY_VERSION, 'time' => time()]);
    }

    if ($method !== 'POST') {
        dcloud_fail('Nur POST JSON wird unterstuetzt', 405);
    }

    $raw = file_get_contents('php://input');
    $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($raw === false) {
        dcloud_fail('Request konnte nicht gelesen werden', 400);
    }
    if ($raw === '') {
        if ($contentLength > 0) {
            dcloud_fail('Request-Body ist leer; moeglicherweise wurde er durch PHP-Limits wie post_max_size verworfen', 413);
        }
        dcloud_fail('Leerer Request', 400);
    }

    try {
        $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException $exception) {
        dcloud_fail('Request muss gueltiges JSON sein: ' . $exception->getMessage(), 400);
    }
    if (!is_array($decoded)) {
        dcloud_fail('Request muss ein JSON-Objekt sein', 400);
    }

    $data = $decoded;
    $GLOBALS['DCLOUD_CURRENT_INPUT'] = is_array($data) ? $data : [];
    if (($data['protocol'] ?? '') !== 'dcloud-relay-v1') {
        // Be tolerant for diagnostics/older clients if an action is present, but
        // keep recording the mismatch. Without an action this is not a relay request.
        if (!isset($data['action'])) {
            dcloud_fail('Falsches Relay-Protokoll', 400);
        }
        dcloud_log_event('warning', ['message' => 'Falsches oder fehlendes Protokoll wurde toleriert', 'action' => (string)($data['action'] ?? '')]);
    }

    // The health action is intentionally public: it is how clients fetch the
    // automatic daily relay token. Normalize aliases here as well so POST
    // health/ping/status cannot be rejected before reaching the dispatcher.
    $actionForAuth = dcloud_normalize_action((string)($data['action'] ?? ''));
    $data['action'] = $actionForAuth;
    $GLOBALS['DCLOUD_CURRENT_INPUT'] = $data;
    if ($actionForAuth !== 'health') {
        $provided = (string)($data['relay_token'] ?? ($data['secret'] ?? ''));
        if (!dcloud_relay_token_is_valid($provided)) {
            dcloud_fail('Relay-Tages-Token fehlt oder ist abgelaufen', 403);
        }
    }
    return $data;
}

function dcloud_valid_id($value): bool {
    if (!is_string($value) && !is_numeric($value)) {
        return false;
    }
    $text = trim((string)$value);
    return $text !== '' && preg_match('/^[A-Za-z0-9_.:-]{1,160}$/', $text) === 1;
}

function dcloud_safe_id(string $value, string $label = 'id'): string {
    $value = trim($value);
    if (!dcloud_valid_id($value)) {
        dcloud_fail('Ungueltige ' . $label, 200, [
            'field' => $label,
            'value_length' => strlen($value),
            'value_preview' => substr($value, 0, 24),
        ]);
    }
    return $value;
}

function dcloud_first_string_value(array $input, array $keys): string {
    foreach ($keys as $key) {
        if (array_key_exists($key, $input) && (is_string($input[$key]) || is_numeric($input[$key]))) {
            $value = trim((string)$input[$key]);
            if ($value !== '') {
                return $value;
            }
        }
    }
    return '';
}

function dcloud_safe_filename(string $value): string {
    return preg_replace('/[^A-Za-z0-9_.:-]/', '_', $value);
}

function dcloud_queue_dir(string $nodeId): string {
    $dir = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'queues' . DIRECTORY_SEPARATOR . dcloud_safe_filename($nodeId);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        dcloud_fail('Relay-Queue konnte nicht erstellt werden', 500);
    }
    return $dir;
}

function dcloud_response_file(string $requestId): string {
    return dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'responses' . DIRECTORY_SEPARATOR . dcloud_safe_filename($requestId) . '.json';
}

function dcloud_read_json_file(string $path, array $fallback): array {
    if (!file_exists($path)) {
        return $fallback;
    }
    $raw = file_get_contents($path);
    if ($raw === false || $raw === '') {
        return $fallback;
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $fallback;
}

function dcloud_write_json_file(string $path, array $data): void {
    $tmp = $path . '.' . bin2hex(random_bytes(6)) . '.tmp';
    if (file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX) === false) {
        dcloud_fail('Relay kann nicht schreiben', 500);
    }
    if (!@rename($tmp, $path)) {
        @unlink($tmp);
        dcloud_fail('Relay kann Datei nicht austauschen', 500);
    }
}

function dcloud_with_peer_lock(callable $callback) {
    $lockPath = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'peers.lock';
    $handle = fopen($lockPath, 'c+');
    if (!$handle) {
        dcloud_fail('Relay-Lock konnte nicht geoeffnet werden', 500);
    }
    flock($handle, LOCK_EX);
    try {
        return $callback();
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function dcloud_envelope_is_valid(array $payload): bool {
    if (!dcloud_valid_id($payload['request_id'] ?? '')) {
        return false;
    }
    if (!dcloud_valid_id($payload['from_node_id'] ?? '') || !dcloud_valid_id($payload['to_node_id'] ?? '')) {
        return false;
    }
    $method = strtoupper((string)($payload['method'] ?? ''));
    $path = (string)($payload['path'] ?? '');
    return in_array($method, ['GET', 'POST'], true) && strncmp($path, '/api/p2p/', 9) === 0;
}

function dcloud_response_payload_is_valid(array $payload): bool {
    return dcloud_valid_id($payload['request_id'] ?? '');
}

function dcloud_cleanup(): void {
    $now = time();
    $queueBase = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'queues';
    foreach (glob($queueBase . DIRECTORY_SEPARATOR . '*' . DIRECTORY_SEPARATOR . '*.json') ?: [] as $file) {
        $expired = filemtime($file) !== false && $now - filemtime($file) > DCLOUD_MESSAGE_TTL_SECONDS;
        $payload = dcloud_read_json_file($file, []);
        if ($expired || !$payload || !dcloud_envelope_is_valid($payload)) {
            @unlink($file);
        }
    }

    $responseBase = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'responses';
    $responseFiles = glob($responseBase . DIRECTORY_SEPARATOR . '*.json') ?: [];
    // Old relay versions could write responses/.json for an empty request_id.
    // glob('*.json') does not always include dotfiles, so remove it explicitly.
    $legacyEmptyResponse = $responseBase . DIRECTORY_SEPARATOR . '.json';
    if (file_exists($legacyEmptyResponse)) {
        $responseFiles[] = $legacyEmptyResponse;
    }
    foreach ($responseFiles as $file) {
        $expired = filemtime($file) !== false && $now - filemtime($file) > DCLOUD_MESSAGE_TTL_SECONDS;
        $payload = dcloud_read_json_file($file, []);
        if ($expired || !$payload || !dcloud_response_payload_is_valid($payload)) {
            @unlink($file);
        }
    }
}

function dcloud_cleanup_if_due(): void {
    $marker = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'cleanup.last';
    $now = time();
    $last = 0;
    if (file_exists($marker)) {
        $raw = @file_get_contents($marker);
        if (is_string($raw) && $raw !== '') {
            $last = (int)trim($raw);
        }
    }
    if ($last > 0 && ($now - $last) < DCLOUD_CLEANUP_INTERVAL_SECONDS) {
        return;
    }

    dcloud_cleanup();
    @file_put_contents($marker, (string)$now, LOCK_EX);
}

function dcloud_sanitize_relay_urls($value): array {
    if ($value === null) {
        return [];
    }
    $items = is_array($value) ? $value : preg_split('/[\s,;]+/', (string)$value);
    $urls = [];
    foreach ($items ?: [] as $raw) {
        $url = rtrim(trim((string)$raw), '/');
        if ($url === '' || !preg_match('/^https?:\/\//i', $url)) {
            continue;
        }
        if (!in_array($url, $urls, true)) {
            $urls[] = $url;
        }
        if (count($urls) >= 20) {
            break;
        }
    }
    return $urls;
}

function dcloud_sanitize_relay_tokens($value): array {
    if (!is_array($value)) {
        return [];
    }
    $tokens = [];
    foreach ($value as $item) {
        if (!is_array($item)) {
            continue;
        }
        $url = rtrim(trim((string)($item['relay_url'] ?? ($item['url'] ?? ''))), '/');
        $token = trim((string)($item['relay_token'] ?? ($item['token'] ?? '')));
        if ($url === '' || $token === '' || !preg_match('/^https?:\/\//i', $url)) {
            continue;
        }
        $tokens[] = [
            'relay_url' => $url,
            'relay_token_day' => substr((string)($item['relay_token_day'] ?? ($item['day'] ?? '')), 0, 16),
            'relay_token_expires_at' => max(0, (int)($item['relay_token_expires_at'] ?? ($item['expires_at'] ?? 0))),
            'relay_token' => substr($token, 0, 128),
        ];
        if (count($tokens) >= 20) {
            break;
        }
    }
    return $tokens;
}

function dcloud_sanitize_peer($peer, string $nodeId): array {
    if (!is_array($peer)) {
        dcloud_fail('Peer-Metadaten fehlen', 400);
    }
    $clientType = $peer['client_type'] ?? null;
    if (!in_array($clientType, ['server', 'pc'], true)) {
        $clientType = null;
    }
    $relayUrls = dcloud_sanitize_relay_urls($peer['relay_urls'] ?? ($peer['relay_url'] ?? null));
    return [
        'node_id' => $nodeId,
        'public_key' => (string)($peer['public_key'] ?? ''),
        'name' => substr((string)($peer['name'] ?? 'dcloud-node'), 0, 80),
        'udp_port' => max(0, min(65535, (int)($peer['udp_port'] ?? 0))),
        'web_port' => max(0, min(65535, (int)($peer['web_port'] ?? 0))),
        'protocol_magic' => (string)($peer['protocol_magic'] ?? 'DCLOUD1'),
        'client_type' => $clientType,
        'shared_storage_bytes' => max(0, (int)($peer['shared_storage_bytes'] ?? 0)),
        'free_storage_bytes' => max(0, (int)($peer['free_storage_bytes'] ?? 0)),
        'accepts_peer_storage' => !empty($peer['accepts_peer_storage']),
        'relay_url' => $relayUrls[0] ?? '',
        'relay_urls' => $relayUrls,
        'relay_tokens' => dcloud_sanitize_relay_tokens($peer['relay_tokens'] ?? []),
        'relay_seen_at' => time(),
        'via_relay' => true,
    ];
}

function dcloud_active_peers_except(string $ownNodeId): array {
    $path = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'peers.json';
    $peers = dcloud_read_json_file($path, []);
    $now = time();
    $active = [];
    foreach ($peers as $nodeId => $peer) {
        if (!is_array($peer)) {
            continue;
        }
        $age = $now - (int)($peer['relay_seen_at'] ?? 0);
        if ($age <= DCLOUD_PEER_TTL_SECONDS && $nodeId !== $ownNodeId) {
            $peer['relay_age_seconds'] = $age;
            $active[] = $peer;
        }
    }
    return $active;
}

function dcloud_register(array $input): void {
    $nodeId = dcloud_safe_id((string)($input['node_id'] ?? ''), 'node_id');
    $peer = $input['peer'] ?? null;

    // New clients send all metadata in the peer object. This fallback keeps the
    // relay tolerant to slightly older clients that accidentally sent metadata
    // at the top level, while still rejecting empty/null register requests.
    if (!is_array($peer)) {
        foreach (['public_key', 'name', 'udp_port', 'web_port', 'client_type', 'shared_storage_bytes', 'free_storage_bytes', 'accepts_peer_storage', 'relay_url', 'relay_urls'] as $key) {
            if (array_key_exists($key, $input)) {
                $peer = $input;
                break;
            }
        }
    }
    if (!is_array($peer)) {
        // Do not reject a node completely when an older or partially configured
        // client registers without the nested peer object. A minimal heartbeat is
        // enough for relay diagnostics and later poll cycles; richer metadata will
        // replace it automatically on the next valid register.
        dcloud_log_event('warning', ['message' => 'Register ohne peer-Metadaten wurde minimal akzeptiert', 'node_id' => $nodeId]);
        $peer = [
            'node_id' => $nodeId,
            'name' => 'dcloud-node',
            'protocol_magic' => 'DCLOUD1',
            'relay_urls' => [],
        ];
    }

    $peers = dcloud_with_peer_lock(function () use ($nodeId, $peer) {
        $path = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'peers.json';
        $peers = dcloud_read_json_file($path, []);
        $now = time();
        foreach ($peers as $existingNodeId => $existingPeer) {
            if (!is_array($existingPeer) || $now - (int)($existingPeer['relay_seen_at'] ?? 0) > DCLOUD_PEER_TTL_SECONDS) {
                unset($peers[$existingNodeId]);
            }
        }

        $existing = isset($peers[$nodeId]) && is_array($peers[$nodeId]) ? $peers[$nodeId] : [];
        $sanitized = dcloud_sanitize_peer($peer, $nodeId);
        // Some probes/older clients may only send a minimal register. Do not let
        // such a heartbeat wipe useful storage metadata, otherwise other nodes
        // stop treating this peer as a valid storage target.
        foreach (['public_key', 'client_type', 'shared_storage_bytes', 'free_storage_bytes', 'accepts_peer_storage', 'relay_url', 'relay_urls', 'relay_tokens', 'web_port', 'udp_port'] as $key) {
            $newValue = $sanitized[$key] ?? null;
            $emptyNewValue = $newValue === null || $newValue === '' || $newValue === [] || $newValue === 0 || $newValue === false;
            if ($emptyNewValue && array_key_exists($key, $existing)) {
                $sanitized[$key] = $existing[$key];
            }
        }
        $sanitized['relay_seen_at'] = $now;
        $peers[$nodeId] = $sanitized;
        dcloud_write_json_file($path, $peers);
        return dcloud_active_peers_except($nodeId);
    });
    $relayUrls = [];
    foreach ($peers as $peerInfo) {
        foreach (dcloud_sanitize_relay_urls($peerInfo['relay_urls'] ?? ($peerInfo['relay_url'] ?? null)) as $relayUrl) {
            if (!in_array($relayUrl, $relayUrls, true)) {
                $relayUrls[] = $relayUrl;
            }
        }
    }
    dcloud_json_response(array_merge(['ok' => true, 'version' => DCLOUD_RELAY_VERSION, 'peers' => $peers, 'relay_urls' => $relayUrls], dcloud_current_relay_token()));
}

function dcloud_enqueue_request(array $input): void {
    $fromNodeId = dcloud_safe_id(dcloud_first_string_value($input, ['node_id', 'from_node_id', 'sender_node_id']), 'node_id');
    $toNodeIdRaw = dcloud_first_string_value($input, ['to_node_id', 'target_node_id', 'target_node', 'peer_node_id', 'recipient_node_id']);
    $requestIdRaw = dcloud_first_string_value($input, ['request_id', 'id', 'relay_request_id']);
    if ($toNodeIdRaw === '' || $requestIdRaw === '') {
        dcloud_fail('Relay-Anfrage ist unvollstaendig', 200, [
            'missing_to_node_id' => $toNodeIdRaw === '',
            'missing_request_id' => $requestIdRaw === '',
            'keys' => array_keys($input),
        ]);
    }
    $toNodeId = dcloud_safe_id($toNodeIdRaw, 'to_node_id');
    $requestId = dcloud_safe_id($requestIdRaw, 'request_id');
    $method = strtoupper((string)($input['method'] ?? 'GET'));
    $path = (string)($input['path'] ?? ($input['api_path'] ?? ''));
    if (!in_array($method, ['GET', 'POST'], true) || strncmp($path, '/api/p2p/', 9) !== 0) {
        dcloud_fail('Nur GET/POST auf /api/p2p/ sind erlaubt', 403, ['method' => $method, 'path' => $path]);
    }
    $bodyBase64 = (string)($input['body_base64'] ?? ($input['body'] ?? ''));
    if (strlen($bodyBase64) > DCLOUD_MAX_ENCODED_BODY_BYTES) {
        dcloud_fail('Relay-Nutzdaten sind zu gross', 413);
    }
    $headers = $input['headers'] ?? [];
    if (!is_array($headers)) {
        $headers = [];
    }
    $envelope = [
        'request_id' => $requestId,
        'from_node_id' => $fromNodeId,
        'to_node_id' => $toNodeId,
        'method' => $method,
        'path' => $path,
        'headers' => $headers,
        'body_base64' => $bodyBase64,
        'created_at' => time(),
    ];
    $file = dcloud_queue_dir($toNodeId) . DIRECTORY_SEPARATOR . time() . '-' . dcloud_safe_filename($requestId) . '.json';
    dcloud_write_json_file($file, $envelope);
    dcloud_json_response(['ok' => true, 'request_id' => $requestId, 'to_node_id' => $toNodeId]);
}

function dcloud_poll_requests(array $input): void {
    $nodeId = dcloud_safe_id((string)($input['node_id'] ?? ''), 'node_id');
    $max = max(1, min(DCLOUD_MAX_REQUESTS_PER_POLL, (int)($input['max_requests'] ?? DCLOUD_MAX_REQUESTS_PER_POLL)));
    $waitUntil = microtime(true) + max(0.0, min(5.0, (float)($input['wait_seconds'] ?? 0)));
    do {
        $files = glob(dcloud_queue_dir($nodeId) . DIRECTORY_SEPARATOR . '*.json') ?: [];
        // Queue files are prefixed with unix timestamps, so lexicographic
        // ordering already matches creation order without costly filemtime().
        sort($files, SORT_STRING);
        $requests = [];
        foreach (array_slice($files, 0, $max) as $file) {
            $payload = dcloud_read_json_file($file, []);
            @unlink($file);
            if ($payload && dcloud_envelope_is_valid($payload)) {
                $requests[] = $payload;
            } else {
                dcloud_log_event('warning', ['message' => 'Ungueltiger Queue-Eintrag wurde verworfen', 'file' => basename($file)]);
            }
        }
        if ($requests || microtime(true) >= $waitUntil) {
            dcloud_json_response(['ok' => true, 'requests' => $requests]);
        }
        usleep(200000);
    } while (true);
}

function dcloud_post_response(array $input): void {
    $requestId = dcloud_safe_id(dcloud_first_string_value($input, ['request_id', 'id', 'relay_request_id']), 'request_id');
    $bodyBase64 = (string)($input['body_base64'] ?? '');
    if (strlen($bodyBase64) > DCLOUD_MAX_ENCODED_BODY_BYTES) {
        dcloud_fail('Relay-Antwort ist zu gross', 413);
    }
    $headers = $input['headers'] ?? [];
    if (!is_array($headers)) {
        $headers = [];
    }
    $response = [
        'request_id' => $requestId,
        'status_code' => (int)($input['status_code'] ?? 502),
        'headers' => $headers,
        'body_base64' => $bodyBase64,
        'created_at' => time(),
    ];
    dcloud_write_json_file(dcloud_response_file($requestId), $response);
    dcloud_json_response(['ok' => true, 'request_id' => $requestId]);
}

function dcloud_poll_response(array $input): void {
    $requestId = dcloud_safe_id(dcloud_first_string_value($input, ['request_id', 'id', 'relay_request_id']), 'request_id');
    $waitUntil = microtime(true) + max(0.0, min(5.0, (float)($input['wait_seconds'] ?? 0)));
    $file = dcloud_response_file($requestId);
    do {
        if (file_exists($file)) {
            $response = dcloud_read_json_file($file, []);
            @unlink($file);
            if (!$response || !dcloud_response_payload_is_valid($response) || (string)($response['request_id'] ?? '') !== $requestId) {
                dcloud_log_event('warning', ['message' => 'Ungueltige Relay-Antwort wurde verworfen', 'request_id' => $requestId]);
                dcloud_json_response(['ok' => true, 'ready' => false]);
            }
            dcloud_json_response(['ok' => true, 'ready' => true, 'response' => $response]);
        }
        if (microtime(true) >= $waitUntil) {
            dcloud_json_response(['ok' => true, 'ready' => false]);
        }
        usleep(200000);
    } while (true);
}

function dcloud_normalize_action(string $action): string {
    $action = strtolower(trim($action));
    if ($action === '') {
        return 'health';
    }
    $aliases = [
        'ping' => 'health',
        'status' => 'health',
        'announce' => 'register',
        'heartbeat' => 'register',
        'register_peer' => 'register',
        'peer_register' => 'register',
        'enqueue' => 'enqueue_request',
        'send_request' => 'enqueue_request',
        'proxy_request' => 'enqueue_request',
        'relay_request' => 'enqueue_request',
        'fetch_requests' => 'poll_requests',
        'get_requests' => 'poll_requests',
        'poll' => 'poll_requests',
        'queue_poll' => 'poll_requests',
        'send_response' => 'post_response',
        'relay_response' => 'post_response',
        'set_response' => 'post_response',
        'fetch_response' => 'poll_response',
        'get_response' => 'poll_response',
        'poll_result' => 'poll_response',
    ];
    return $aliases[$action] ?? $action;
}

try {
    $input = dcloud_read_input();
    $action = dcloud_normalize_action((string)($input['action'] ?? ''));
    // Polling actions are latency-sensitive and can run very frequently.
    // Avoid a full relay filesystem sweep on every long-poll cycle.
    if (!in_array($action, ['poll_requests', 'poll_response'], true)) {
        dcloud_cleanup_if_due();
    }
    $input['action'] = $action;

    switch ($action) {
        case 'health':
            dcloud_json_response(array_merge(['ok' => true, 'version' => DCLOUD_RELAY_VERSION, 'time' => time()], dcloud_current_relay_token()));
            return;
        case 'register':
            dcloud_register($input);
            return;
        case 'enqueue_request':
            dcloud_enqueue_request($input);
            return;
        case 'poll_requests':
            dcloud_poll_requests($input);
            return;
        case 'post_response':
            dcloud_post_response($input);
            return;
        case 'poll_response':
            dcloud_poll_response($input);
            return;
        default:
            // Unknown actions are client/protocol errors, not a missing PHP file.
            // Return 400 instead of 404 so hosting logs and the UI do not look
            // like the relay endpoint itself is unreachable.
            dcloud_fail('Unbekannte Relay-Aktion: ' . $action, 400);
    }
} catch (Throwable $exception) {
    // Last-resort safety net: malformed external requests must produce JSON,
    // not a PHP fatal page in the webserver log.
    dcloud_json_response([
        'ok' => false,
        'message' => 'Relay-Fehler: ' . $exception->getMessage(),
    ], 500);
}
