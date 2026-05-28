<?php
declare(strict_types=1);

/*
 * dcloud PHP HTTP relay/proxy
 *
 * - POST + JSON: Relay API (health/register/enqueue_request/poll_requests/post_response/poll_response/direct_proxy_request/direct_proxy_request_raw/create_external_download_link)
 * - GET/HEAD: Landing page, health JSON, or temporary external downloads (?action=external_download)
 *
 * Landing page intentionally reveals only minimal information.
 */

const DCLOUD_RELAY_VERSION = '1.6.1-chat-alias';
const DCLOUD_RELAY_TOKEN_ROTATION_SECONDS = 86400;
const DCLOUD_PEER_TTL_SECONDS = 45;
const DCLOUD_MESSAGE_TTL_SECONDS = 900;
const DCLOUD_MAX_REQUESTS_PER_POLL = 64;
const DCLOUD_MAX_ENCODED_BODY_BYTES = 268435456; // 256 MiB base64 payload
const DCLOUD_DIRECT_PROXY_MAX_ENCODED_BODY_BYTES = 67108864; // 64 MiB base64 payload per non-persistent forward
const DCLOUD_DIRECT_PROXY_CONNECT_TIMEOUT_SECONDS = 4;
const DCLOUD_DIRECT_PROXY_TIMEOUT_SECONDS = 90;
const DCLOUD_CLEANUP_INTERVAL_SECONDS = 30;
const DCLOUD_EXTERNAL_LINK_MAX_TTL_SECONDS = 3600;
const DCLOUD_EXTERNAL_LINK_TOKEN_BYTES = 24;
const DCLOUD_EXTERNAL_MAILBOX_TIMEOUT_SECONDS = 300;
const DCLOUD_EXTERNAL_MAILBOX_MAX_FILE_BYTES = 190000000; // legacy JSON/base64 mailbox safety limit
const DCLOUD_EXTERNAL_STREAM_CHUNK_TTL_SECONDS = 3900;

$GLOBALS['DCLOUD_CURRENT_INPUT'] = [];

/**
 * Start buffering early to prevent any accidental output from breaking JSON/HTML.
 */
if (ob_get_level() === 0) {
    ob_start();
}

/**
 * Hard-stop any further output and close the connection cleanly.
 */
function dcloud_finalize_and_exit(): void {
    // Try to force-close the request so nothing else can append output.
    if (function_exists('fastcgi_finish_request')) {
        @fastcgi_finish_request();
    }
    exit;
}

function dcloud_clear_all_output_buffers(): void {
    // Clear as many levels as possible (some hosts stack multiple buffers).
    for ($i = 0; $i < 50 && ob_get_level() > 0; $i++) {
        @ob_end_clean();
    }
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

function dcloud_external_links_file(): string {
    return dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'external-download-links.json';
}

function dcloud_read_external_links(): array {
    $path = dcloud_external_links_file();
    $data = dcloud_read_json_file($path, []);
    return is_array($data) ? $data : [];
}

function dcloud_write_external_links(array $links): void {
    $path = dcloud_external_links_file();
    $tmp = $path . '.tmp';
    $encoded = json_encode($links, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    if ($encoded === false) {
        dcloud_fail('Relay-Link-Daten konnten nicht serialisiert werden', 500);
    }
    if (@file_put_contents($tmp, $encoded, LOCK_EX) === false) {
        dcloud_fail('Relay-Link-Daten konnten nicht gespeichert werden', 500);
    }
    @chmod($tmp, 0600);
    if (!@rename($tmp, $path)) {
        @unlink($tmp);
        dcloud_fail('Relay-Link-Daten konnten nicht ersetzt werden', 500);
    }
    @chmod($path, 0600);
}

function dcloud_cleanup_external_links(bool $persist = true): int {
    $links = dcloud_read_external_links();
    $now = time();
    $removed = 0;
    foreach ($links as $token => $item) {
        if (!is_array($item) || (int)($item['expires_at'] ?? 0) <= $now) {
            unset($links[$token]);
            $removed++;
        }
    }
    if ($removed > 0 && $persist) {
        dcloud_write_external_links($links);
    }
    return $removed;
}

function dcloud_current_script_url(array $params = []): string {
    $https = !empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off';
    $scheme = $https ? 'https' : 'http';
    $host = (string)($_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost'));
    $host = preg_replace('/[^A-Za-z0-9.\-_:\[\]]/', '', $host) ?: 'localhost';
    $script = (string)($_SERVER['SCRIPT_NAME'] ?? '');
    if ($script === '') {
        $script = (string)($_SERVER['PHP_SELF'] ?? '/dcloud_relay.php');
    }
    $base = $scheme . '://' . $host . $script;
    if ($params) {
        $base .= '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }
    return $base;
}

function dcloud_safe_public_token($value): string {
    $token = trim((string)$value);
    if ($token === '' || !preg_match('/^[A-Za-z0-9_-]{12,160}$/', $token)) {
        dcloud_fail('Ungueltiger Download-Token', 404);
    }
    return $token;
}


function dcloud_path_is_allowed_for_peer_web(string $method, string $path): bool {
    $method = strtoupper($method);
    if (!in_array($method, ['GET', 'POST'], true)) return false;
    // dcloud peer websites are served by the client under /dcloud-site.
    // Keep the relay allow-list narrow so it cannot be used as a general proxy.
    return $path === '/dcloud-site' || strncmp($path, '/dcloud-site/', 13) === 0 || strncmp($path, '/dcloud-site?', 13) === 0;
}

function dcloud_path_is_allowed_for_mailbox(string $method, string $path): bool {
    $method = strtoupper($method);
    if (!in_array($method, ['GET', 'POST'], true)) return false;
    if (strncmp($path, '/api/p2p/', 9) === 0) return true;
    if (dcloud_path_is_allowed_for_peer_web($method, $path)) return true;
    if ($method === 'GET' && preg_match('#^/api/external-relay/stream/[A-Za-z0-9_-]{12,200}/[A-Za-z0-9_.:-]{12,160}$#', $path) === 1) return true;
    if ($method === 'GET' && preg_match('#^/external/[A-Za-z0-9_-]{12,200}$#', $path) === 1) return true;
    return false;
}


function dcloud_remove_tree(string $dir): void {
    if (!is_dir($dir)) return;
    $items = scandir($dir);
    if ($items !== false) {
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                dcloud_remove_tree($path);
            } else {
                @unlink($path);
            }
        }
    }
    @rmdir($dir);
}

function dcloud_external_stream_base_dir(): string {
    $dir = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'external-streams';
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        dcloud_fail('Relay-Stream-Verzeichnis konnte nicht erstellt werden', 500);
    }
    return $dir;
}

function dcloud_external_stream_dir(string $streamId): string {
    $safe = dcloud_safe_filename($streamId);
    $dir = dcloud_external_stream_base_dir() . DIRECTORY_SEPARATOR . $safe;
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        dcloud_fail('Relay-Stream konnte nicht erstellt werden', 500);
    }
    return $dir;
}

function dcloud_external_stream_chunk_file(string $streamId, int $sequence): string {
    return dcloud_external_stream_dir($streamId) . DIRECTORY_SEPARATOR . sprintf('chunk-%08d.bin', $sequence);
}

function dcloud_external_stream_cleanup(): void {
    $base = dcloud_external_stream_base_dir();
    $now = time();
    foreach (glob($base . DIRECTORY_SEPARATOR . '*') ?: [] as $dir) {
        if (!is_dir($dir)) continue;
        $mtime = (int)@filemtime($dir);
        if ($mtime <= 0 || $now - $mtime > DCLOUD_EXTERNAL_STREAM_CHUNK_TTL_SECONDS) {
            dcloud_remove_tree($dir);
        }
    }
}

function dcloud_external_stream_write_atomic(string $path, string $data): void {
    $tmp = $path . '.' . bin2hex(random_bytes(6)) . '.tmp';
    if (file_put_contents($tmp, $data, LOCK_EX) === false) {
        dcloud_fail('Relay-Stream konnte nicht geschrieben werden', 500);
    }
    if (!@rename($tmp, $path)) {
        @unlink($tmp);
        dcloud_fail('Relay-Stream-Datei konnte nicht ausgetauscht werden', 500);
    }
}

function dcloud_external_stream_event(array $input): void {
    $streamId = dcloud_safe_id(dcloud_first_string_value($input, ['stream_id', 'external_stream_id']), 'stream_id');
    $action = dcloud_normalize_action((string)($input['action'] ?? ''));
    $dir = dcloud_external_stream_dir($streamId);
    @touch($dir);

    if ($action === 'external_stream_start') {
        $meta = [
            'stream_id' => $streamId,
            'file_name' => dcloud_safe_external_file_name($input['file_name'] ?? 'download.bin'),
            'file_size' => max(0, (int)($input['file_size'] ?? 0)),
            'content_type' => (string)($input['content_type'] ?? 'application/octet-stream'),
            'created_at' => time(),
        ];
        dcloud_write_json_file($dir . DIRECTORY_SEPARATOR . 'meta.json', $meta);
        dcloud_json_response(['ok' => true, 'stream_id' => $streamId, 'event' => 'start']);
    }

    if ($action === 'external_stream_chunk') {
        $sequence = max(0, (int)($input['sequence'] ?? -1));
        $bodyBase64 = (string)($input['body_base64'] ?? '');
        $decoded = base64_decode($bodyBase64, true);
        if ($decoded === false) {
            dcloud_fail('Relay-Stream-Chunk ist ungueltig base64-kodiert', 400);
        }
        dcloud_external_stream_write_atomic(dcloud_external_stream_chunk_file($streamId, $sequence), $decoded);
        dcloud_json_response(['ok' => true, 'stream_id' => $streamId, 'event' => 'chunk', 'sequence' => $sequence, 'bytes' => strlen($decoded)]);
    }

    if ($action === 'external_stream_finish') {
        $done = [
            'stream_id' => $streamId,
            'chunks' => max(0, (int)($input['chunks'] ?? 0)),
            'bytes' => max(0, (int)($input['bytes'] ?? 0)),
            'finished_at' => time(),
        ];
        dcloud_write_json_file($dir . DIRECTORY_SEPARATOR . 'done.json', $done);
        dcloud_json_response(['ok' => true, 'stream_id' => $streamId, 'event' => 'finish']);
    }

    if ($action === 'external_stream_error') {
        $error = [
            'stream_id' => $streamId,
            'message' => substr((string)($input['message'] ?? 'Unbekannter externer Download-Fehler'), 0, 500),
            'failed_at' => time(),
        ];
        dcloud_write_json_file($dir . DIRECTORY_SEPARATOR . 'error.json', $error);
        dcloud_json_response(['ok' => true, 'stream_id' => $streamId, 'event' => 'error']);
    }

    dcloud_fail('Ungueltiges Relay-Stream-Ereignis', 400, ['action' => $action]);
}

function dcloud_send_external_stream_headers(array $meta, string $fallbackFileName, int $fallbackFileSize): void {
    if (headers_sent()) return;
    $fileName = dcloud_safe_external_file_name($meta['file_name'] ?? $fallbackFileName);
    $fileSize = max(0, (int)($meta['file_size'] ?? $fallbackFileSize));
    http_response_code(200);
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . addcslashes($fileName, "\\\"") . '"');
    header('Cache-Control: no-store');
    header('X-Accel-Buffering: no');
    header('X-Content-Type-Options: nosniff');
    header('X-DCloud-Relay-Mode: reverse_mailbox_stream');
    if ($fileSize > 0) {
        header('Content-Length: ' . $fileSize);
    }
    header('Connection: close');
}

function dcloud_external_download_via_stream_mailbox(string $targetNodeId, string $localToken, string $fileName, int $fileSize): void {
    @set_time_limit(max(30, DCLOUD_EXTERNAL_MAILBOX_TIMEOUT_SECONDS + 60));
    dcloud_external_stream_cleanup();
    $streamId = bin2hex(random_bytes(16));
    $requestId = bin2hex(random_bytes(16));
    $fromNodeId = 'external-' . substr($requestId, 0, 16);
    $envelope = [
        'request_id' => $requestId,
        'from_node_id' => $fromNodeId,
        'to_node_id' => $targetNodeId,
        'method' => 'GET',
        'path' => '/api/external-relay/stream/' . rawurlencode($localToken) . '/' . rawurlencode($streamId),
        'headers' => [
            'Accept' => 'application/octet-stream',
            'X-DCloud-External-Relay' => '1',
            'X-DCloud-External-Stream-ID' => $streamId,
        ],
        'body_base64' => '',
        'created_at' => time(),
        'external_download' => true,
    ];
    $file = dcloud_queue_dir($targetNodeId) . DIRECTORY_SEPARATOR . time() . '-' . dcloud_safe_filename($requestId) . '.json';
    dcloud_write_json_file($file, $envelope);

    $dir = dcloud_external_stream_dir($streamId);
    $metaFile = $dir . DIRECTORY_SEPARATOR . 'meta.json';
    $doneFile = $dir . DIRECTORY_SEPARATOR . 'done.json';
    $errorFile = $dir . DIRECTORY_SEPARATOR . 'error.json';
    $deadline = microtime(true) + DCLOUD_EXTERNAL_MAILBOX_TIMEOUT_SECONDS;
    $sequence = 0;
    $headersSent = false;

    while (microtime(true) < $deadline) {
        if (file_exists($errorFile)) {
            $error = dcloud_read_json_file($errorFile, []);
            if (!$headersSent) {
                dcloud_clear_all_output_buffers();
                http_response_code(502);
                header('Content-Type: text/plain; charset=utf-8');
                header('Cache-Control: no-store');
                echo (string)($error['message'] ?? 'Der dcloud-Node konnte den externen Download nicht bereitstellen.');
                dcloud_remove_tree($dir);
                dcloud_finalize_and_exit();
            }
            dcloud_remove_tree($dir);
            dcloud_finalize_and_exit();
        }

        if (!$headersSent) {
            if (file_exists($metaFile)) {
                $meta = dcloud_read_json_file($metaFile, []);
                dcloud_clear_all_output_buffers();
                dcloud_send_external_stream_headers($meta, $fileName, $fileSize);
                $headersSent = true;
                @flush();
            } else {
                usleep(200000);
                continue;
            }
        }

        $chunkFile = dcloud_external_stream_chunk_file($streamId, $sequence);
        if (file_exists($chunkFile)) {
            $chunk = file_get_contents($chunkFile);
            @unlink($chunkFile);
            if ($chunk !== false && $chunk !== '') {
                echo $chunk;
                @flush();
            }
            $sequence++;
            $deadline = microtime(true) + DCLOUD_EXTERNAL_MAILBOX_TIMEOUT_SECONDS;
            continue;
        }

        if (file_exists($doneFile)) {
            dcloud_remove_tree($dir);
            dcloud_finalize_and_exit();
        }
        usleep(200000);
    }

    if (!$headersSent) {
        dcloud_clear_all_output_buffers();
        http_response_code(504);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        echo 'Der dcloud-Node hat den externen Relay-Download nicht rechtzeitig gestartet. Bitte pruefen, ob dcloud laeuft und mit dem PHP-Relay verbunden ist.';
    }
    dcloud_remove_tree($dir);
    dcloud_finalize_and_exit();
}

function dcloud_response_headers_to_browser(array $headers): array {
    $out = [];
    foreach ($headers as $name => $value) {
        if (is_int($name)) {
            if (!is_string($value) || strpos($value, ':') === false) continue;
            [$name, $value] = explode(':', $value, 2);
        }
        $name = trim((string)$name);
        if ($name === '') continue;
        $lower = strtolower($name);
        if ($lower === 'content-type' || $lower === 'content-disposition' || $lower === 'content-length' || strncmp($lower, 'x-dcloud-', 9) === 0) {
            $out[$name] = trim((string)$value);
        }
    }
    return $out;
}

function dcloud_send_mailbox_response_to_browser(array $response): void {
    $statusCode = (int)($response['status_code'] ?? 502);
    $headers = is_array($response['headers'] ?? null) ? dcloud_response_headers_to_browser($response['headers']) : [];
    $bodyBase64 = (string)($response['body_base64'] ?? '');
    $body = '';
    if ($bodyBase64 !== '') {
        $decoded = base64_decode($bodyBase64, true);
        if ($decoded === false) {
            dcloud_clear_all_output_buffers();
            http_response_code(502);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-store');
            echo 'Die Relay-Mailbox-Antwort enthaelt ungueltige Nutzdaten.';
            dcloud_finalize_and_exit();
        }
        $body = $decoded;
    }

    dcloud_clear_all_output_buffers();
    if (!headers_sent()) {
        http_response_code($statusCode > 0 ? $statusCode : 502);
        header('Cache-Control: no-store');
        header('X-Accel-Buffering: no');
        header('X-Content-Type-Options: nosniff');
        header('X-DCloud-Relay-Mode: mailbox_external');
        $contentType = $headers['Content-Type'] ?? ($headers['content-type'] ?? 'application/octet-stream');
        header('Content-Type: ' . str_replace(["\r", "\n"], ' ', (string)$contentType));
        $contentDisposition = $headers['Content-Disposition'] ?? ($headers['content-disposition'] ?? '');
        if ($contentDisposition !== '') {
            header('Content-Disposition: ' . str_replace(["\r", "\n"], ' ', (string)$contentDisposition));
        }
        $contentLength = $headers['Content-Length'] ?? ($headers['content-length'] ?? '');
        if ($contentLength !== '' && preg_match('/^\d+$/', (string)$contentLength)) {
            header('Content-Length: ' . (string)$contentLength);
        } else {
            header('Content-Length: ' . strlen($body));
        }
    }
    echo $body;
    dcloud_finalize_and_exit();
}

function dcloud_external_download_via_mailbox(string $targetNodeId, string $localToken): void {
    @set_time_limit(max(30, DCLOUD_EXTERNAL_MAILBOX_TIMEOUT_SECONDS + 30));
    $requestId = bin2hex(random_bytes(16));
    $fromNodeId = 'external-' . substr($requestId, 0, 16);
    $envelope = [
        'request_id' => $requestId,
        'from_node_id' => $fromNodeId,
        'to_node_id' => $targetNodeId,
        'method' => 'GET',
        'path' => '/external/' . rawurlencode($localToken),
        'headers' => [
            'Accept' => 'application/octet-stream',
            'X-DCloud-External-Relay' => '1',
            'X-DCloud-Relay-Mailbox' => '1',
        ],
        'body_base64' => '',
        'created_at' => time(),
        'external_download' => true,
    ];
    $file = dcloud_queue_dir($targetNodeId) . DIRECTORY_SEPARATOR . time() . '-' . dcloud_safe_filename($requestId) . '.json';
    dcloud_write_json_file($file, $envelope);

    $deadline = microtime(true) + DCLOUD_EXTERNAL_MAILBOX_TIMEOUT_SECONDS;
    $responseFile = dcloud_response_file($requestId);
    do {
        if (file_exists($responseFile)) {
            $response = dcloud_read_json_file($responseFile, []);
            @unlink($responseFile);
            if (!$response || !dcloud_response_payload_is_valid($response) || (string)($response['request_id'] ?? '') !== $requestId) {
                dcloud_clear_all_output_buffers();
                http_response_code(502);
                header('Content-Type: text/plain; charset=utf-8');
                header('Cache-Control: no-store');
                echo 'Die Relay-Mailbox hat eine ungueltige Download-Antwort erhalten.';
                dcloud_finalize_and_exit();
            }
            dcloud_send_mailbox_response_to_browser($response);
        }
        usleep(200000);
    } while (microtime(true) < $deadline);

    dcloud_clear_all_output_buffers();
    http_response_code(504);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo 'Der dcloud-Node hat den externen Relay-Download nicht rechtzeitig beantwortet. Bitte pruefen, ob dcloud laeuft und mit dem PHP-Relay verbunden ist.';
    dcloud_finalize_and_exit();
}

function dcloud_safe_external_file_name($value): string {
    $name = trim((string)$value);
    $name = preg_replace('/[\r\n\x00-\x1F]+/', ' ', $name) ?: '';
    $name = trim($name);
    if ($name === '') return 'download.bin';
    return substr($name, 0, 180);
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


function dcloud_legacy_relay_secret(): string {
    static $cached = null;
    if ($cached !== null) return $cached;

    $envSecret = trim((string)(getenv('DCLOUD_RELAY_SECRET') ?: ''));
    if ($envSecret !== '') {
        $cached = $envSecret;
        return $cached;
    }

    $file = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'relay-secret.txt';
    if (!file_exists($file)) {
        $cached = '';
        return $cached;
    }

    $secret = trim((string)@file_get_contents($file));
    $cached = $secret;
    return $cached;
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

    $legacySecret = dcloud_legacy_relay_secret();
    return $legacySecret !== '' && hash_equals($legacySecret, $provided);
}

function dcloud_relay_signature_is_valid(array $data): bool {
    if (!function_exists('sodium_crypto_sign_verify_detached')) {
        return false;
    }
    $action = dcloud_normalize_action((string)($data['action'] ?? ''));
    $nodeId = trim((string)($data['node_id'] ?? ''));
    $publicKeyB64 = trim((string)($data['public_key'] ?? ''));
    $timestampText = trim((string)($data['relay_signature_timestamp'] ?? ''));
    $nonce = trim((string)($data['relay_signature_nonce'] ?? ''));
    $signatureB64 = trim((string)($data['relay_signature'] ?? ''));
    if ($action === '' || $nodeId === '' || $publicKeyB64 === '' || $timestampText === '' || $nonce === '' || $signatureB64 === '') {
        return false;
    }
    if (!preg_match('/^[A-Za-z0-9_.:-]{8,160}$/', $nodeId) || !preg_match('/^[A-Za-z0-9_.:-]{8,128}$/', $nonce)) {
        return false;
    }
    $timestamp = (int)$timestampText;
    if ($timestamp <= 0 || abs(time() - $timestamp) > 300) {
        return false;
    }
    $publicKey = base64_decode($publicKeyB64, true);
    $signature = base64_decode($signatureB64, true);
    if ($publicKey === false || $signature === false || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
        return false;
    }
    if (!hash_equals(hash('sha256', $publicKey), $nodeId)) {
        return false;
    }
    $canonical = $action . "\n" . $nodeId . "\n" . $timestampText . "\n" . $nonce;
    return sodium_crypto_sign_verify_detached($signature, $canonical, $publicKey);
}

function dcloud_relay_request_is_authenticated(array $data): bool {
    $provided = (string)($data['relay_token'] ?? ($data['secret'] ?? ''));
    if (dcloud_relay_token_is_valid($provided)) {
        return true;
    }
    return dcloud_relay_signature_is_valid($data);
}

function dcloud_request_method(): string {
    return strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'POST'));
}

function dcloud_accept_header(): string {
    return strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? ''));
}


function dcloud_public_client_ip(): string {
    $candidates = [];
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $key) {
        $value = trim((string)($_SERVER[$key] ?? ''));
        if ($value !== '') $candidates[] = $value;
    }
    $forwarded = (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
    foreach (explode(',', $forwarded) as $part) {
        $value = trim($part);
        if ($value !== '') $candidates[] = $value;
    }
    $fallback = '';
    foreach ($candidates as $candidate) {
        if (filter_var($candidate, FILTER_VALIDATE_IP) === false) continue;
        if ($fallback === '') $fallback = $candidate;
        if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
            return $candidate;
        }
    }
    return $fallback;
}

function dcloud_is_browser_request(): bool {
    $accept = dcloud_accept_header();
    // Typical browsers send text/html. API clients often send */* or application/json.
    if (strpos($accept, 'text/html') !== false) {
        return true;
    }
    // Fallback heuristic: User-Agent present and not a typical script client.
    $ua = strtolower((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    if ($ua !== '' && (strpos($ua, 'mozilla') !== false || strpos($ua, 'chrome') !== false || strpos($ua, 'safari') !== false || strpos($ua, 'firefox') !== false)) {
        return true;
    }
    return false;
}

/**
 * Minimal modern landing page (no tokens, no times, no exact peer counts).
 */
function dcloud_render_landing_page(): void {
    // Compute only a coarse activity bucket.
    $peersPath = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'peers.json';
    $peers = dcloud_read_json_file($peersPath, []);
    $now = time();

    $activePeers = 0;
    foreach ($peers as $peer) {
        if (!is_array($peer)) continue;
        $age = $now - (int)($peer['relay_seen_at'] ?? 0);
        if ($age <= DCLOUD_PEER_TTL_SECONDS) $activePeers++;
    }

    $activity = 'Keine';
    if ($activePeers >= 1 && $activePeers <= 2) $activity = 'Niedrig';
    elseif ($activePeers >= 3 && $activePeers <= 7) $activity = 'Normal';
    elseif ($activePeers >= 8) $activity = 'Hoch';

    dcloud_clear_all_output_buffers();

    if (!headers_sent()) {
        http_response_code(200);
        header('Content-Type: text/html; charset=utf-8');

        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
        header('Vary: Accept, Accept-Encoding');

        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header('X-Frame-Options: DENY');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'");

        // Try to stop reverse proxies from buffering/merging outputs.
        header('X-Accel-Buffering: no');
        header('Connection: close');
    }

    $version = htmlspecialchars(DCLOUD_RELAY_VERSION, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $activitySafe = htmlspecialchars($activity, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    $html = <<<HTML
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>dcloud Relay</title>
  <style>
    :root{
      --bg1:#070a12; --bg2:#0b1430;
      --card:rgba(255,255,255,.06);
      --stroke:rgba(255,255,255,.12);
      --text:#eaf0ff; --muted:#a8b3d4;
      --ok:#22c55e;
      --shadow: 0 18px 60px rgba(0,0,0,.45);
    }
    *{box-sizing:border-box}
    body{
      margin:0; min-height:100vh;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      color:var(--text);
      background:
        radial-gradient(1100px 520px at 15% 10%, rgba(99,102,241,.22), transparent 60%),
        radial-gradient(900px 520px at 85% 20%, rgba(34,197,94,.16), transparent 55%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
      padding: 44px 16px;
    }
    .wrap{max-width: 920px; margin: 0 auto;}
    .panel{
      border: 1px solid var(--stroke);
      background: linear-gradient(180deg, rgba(255,255,255,.09), rgba(255,255,255,.04));
      border-radius: 18px;
      box-shadow: var(--shadow);
      overflow:hidden;
    }
    .header{
      padding: 18px 18px 14px 18px;
      display:flex; align-items:center; justify-content:space-between; gap:12px;
      border-bottom: 1px solid rgba(255,255,255,.08);
      flex-wrap:wrap;
    }
    h1{font-size: 18px; margin:0; letter-spacing:.2px}
    .sub{color:var(--muted); font-size: 13px; margin-top:4px}
    .badge{
      display:inline-flex; align-items:center; gap:10px;
      padding: 8px 12px; border-radius: 999px;
      background: rgba(34,197,94,.14);
      border: 1px solid rgba(34,197,94,.25);
      color: #c9f7d6;
      font-weight: 750;
      white-space:nowrap;
    }
    .dot{
      width:10px; height:10px; border-radius:50%;
      background: var(--ok);
      box-shadow: 0 0 0 6px rgba(34,197,94,.12);
    }
    .grid{
      padding: 16px 18px 18px 18px;
      display:grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    .card{
      border:1px solid rgba(255,255,255,.10);
      background: rgba(0,0,0,.18);
      border-radius: 14px;
      padding: 14px 14px;
    }
    .k{color:var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing:.14em}
    .v{margin-top:7px; font-size: 16px; font-weight: 800}
    .footer{
      padding: 0 18px 18px 18px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }
    code{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      padding: 2px 6px;
      border-radius: 8px;
      background: rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.10);
      color: #eef4ff;
    }
    @media (max-width: 760px){
      .grid{grid-template-columns: 1fr;}
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="panel">
      <div class="header">
        <div>
          <h1>dcloud Relay</h1>
          <div class="sub">Öffentliche Statusseite (reduzierte Informationen)</div>
        </div>
        <div class="badge"><span class="dot"></span> Online</div>
      </div>

      <div class="grid">
        <div class="card">
          <div class="k">Dienst</div>
          <div class="v">Relay Endpoint</div>
        </div>
        <div class="card">
          <div class="k">Aktivität</div>
          <div class="v">{$activitySafe}</div>
        </div>
        <div class="card">
          <div class="k">API</div>
          <div class="v"><code>POST</code> JSON</div>
        </div>
        <div class="card">
          <div class="k">Version</div>
          <div class="v">v{$version}</div>
        </div>
      </div>

      <div class="footer">
        Für dcloud-Clients/Monitoring: <code>?action=health</code> (JSON).<br>
        Diese Seite blendet absichtlich Tokens, Zeiten und exakte Peer-Daten aus.
      </div>
    </div>
  </div>
</body>
</html>
HTML;

    echo $html;
    dcloud_finalize_and_exit();
}

function dcloud_json_response(array $payload, int $status = 200): void {
    dcloud_clear_all_output_buffers();

    $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($encoded === false) {
        $encoded = '{"ok":false,"message":"JSON encoding failed"}';
    }

    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Accel-Buffering: no');
        header('X-Content-Type-Options: nosniff');
        header('Connection: close');
        header('Content-Length: ' . strlen($encoded));
    }

    echo $encoded;
    dcloud_finalize_and_exit();
}

function dcloud_fail(string $message, int $status = 200, array $details = []): void {
    $safeStatus = ($status >= 500 || $status === 413) ? $status : 200;
    $input = $GLOBALS['DCLOUD_CURRENT_INPUT'] ?? [];
    $action = is_array($input) ? (string)($input['action'] ?? '') : '';
    if ($action === '') {
        $action = (string)($_POST['action'] ?? ($_GET['action'] ?? ''));
    }
    dcloud_log_event('error', array_merge([
        'status' => $status,
        'returned_status' => $safeStatus,
        'message' => $message,
        'action' => $action,
    ], $details));

    dcloud_json_response(['ok' => false, 'message' => $message, 'status' => $status, 'details' => $details], $safeStatus);
}

function dcloud_log_event(string $type, array $payload): void {
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
        // ignore
    }
}

function dcloud_read_input(): array {
    $method = dcloud_request_method();

    // GET/HEAD is for humans (landing) unless explicitly requesting JSON health.
    if ($method === 'GET' || $method === 'HEAD') {
        $action = strtolower(trim((string)($_GET['action'] ?? '')));
        if ($action === 'health' || $action === 'ping') {
            return ['protocol' => 'dcloud-relay-v1', 'action' => 'health'];
        }
        if ($action === 'external_download' || $action === 'download') {
            dcloud_external_download_via_relay((string)($_GET['token'] ?? ''));
        }
        dcloud_render_landing_page();
    }

    if ($method === 'OPTIONS') {
        dcloud_json_response(['ok' => true, 'version' => DCLOUD_RELAY_VERSION, 'time' => time()]);
    }

    if ($method !== 'POST') {
        // If a browser hits it with something odd (rare), show landing instead of JSON spam.
        if (dcloud_is_browser_request()) {
            dcloud_render_landing_page();
        }
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
    $GLOBALS['DCLOUD_CURRENT_INPUT'] = $data;

    if (($data['protocol'] ?? '') !== 'dcloud-relay-v1') {
        if (!isset($data['action'])) {
            dcloud_fail('Falsches Relay-Protokoll', 400);
        }
        dcloud_log_event('warning', [
            'message' => 'Falsches oder fehlendes Protokoll wurde toleriert',
            'action' => (string)($data['action'] ?? ''),
        ]);
    }

    $actionForAuth = dcloud_normalize_action((string)($data['action'] ?? ''));
    $data['action'] = $actionForAuth;
    $GLOBALS['DCLOUD_CURRENT_INPUT'] = $data;

    if ($actionForAuth !== 'health') {
        if (!dcloud_relay_request_is_authenticated($data)) {
            dcloud_fail('Relay-Token fehlt oder ist abgelaufen', 403);
        }
    }

    return $data;
}

function dcloud_valid_id($value): bool {
    if (!is_string($value) && !is_numeric($value)) return false;
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
            if ($value !== '') return $value;
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
    if (!file_exists($path)) return $fallback;
    $raw = file_get_contents($path);
    if ($raw === false || $raw === '') return $fallback;
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
    if (!$handle) dcloud_fail('Relay-Lock konnte nicht geoeffnet werden', 500);
    flock($handle, LOCK_EX);
    try {
        return $callback();
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function dcloud_envelope_is_valid(array $payload): bool {
    if (!dcloud_valid_id($payload['request_id'] ?? '')) return false;
    if (!dcloud_valid_id($payload['from_node_id'] ?? '') || !dcloud_valid_id($payload['to_node_id'] ?? '')) return false;
    $method = strtoupper((string)($payload['method'] ?? ''));
    $path = (string)($payload['path'] ?? '');
    return dcloud_path_is_allowed_for_mailbox($method, $path);
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
    $legacyEmptyResponse = $responseBase . DIRECTORY_SEPARATOR . '.json';
    if (file_exists($legacyEmptyResponse)) $responseFiles[] = $legacyEmptyResponse;

    foreach ($responseFiles as $file) {
        $expired = filemtime($file) !== false && $now - filemtime($file) > DCLOUD_MESSAGE_TTL_SECONDS;
        $payload = dcloud_read_json_file($file, []);
        if ($expired || !$payload || !dcloud_response_payload_is_valid($payload)) {
            @unlink($file);
        }
    }

    dcloud_cleanup_external_links(true);
    dcloud_external_stream_cleanup();
}

function dcloud_cleanup_if_due(): void {
    $marker = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'cleanup.last';
    $now = time();
    $last = 0;
    if (file_exists($marker)) {
        $raw = @file_get_contents($marker);
        if (is_string($raw) && $raw !== '') $last = (int)trim($raw);
    }
    if ($last > 0 && ($now - $last) < DCLOUD_CLEANUP_INTERVAL_SECONDS) return;

    dcloud_cleanup();
    @file_put_contents($marker, (string)$now, LOCK_EX);
}

function dcloud_sanitize_relay_urls($value): array {
    if ($value === null) return [];
    $items = is_array($value) ? $value : preg_split('/[\s,;]+/', (string)$value);
    $urls = [];
    foreach ($items ?: [] as $raw) {
        $url = rtrim(trim((string)$raw), '/');
        if ($url === '' || !preg_match('/^https?:\/\//i', $url)) continue;
        if (!in_array($url, $urls, true)) $urls[] = $url;
        if (count($urls) >= 20) break;
    }
    return $urls;
}

function dcloud_sanitize_relay_tokens($value): array {
    if (!is_array($value)) return [];
    $tokens = [];
    foreach ($value as $item) {
        if (!is_array($item)) continue;
        $url = rtrim(trim((string)($item['relay_url'] ?? ($item['url'] ?? ''))), '/');
        $token = trim((string)($item['relay_token'] ?? ($item['token'] ?? '')));
        if ($url === '' || $token === '' || !preg_match('/^https?:\/\//i', $url)) continue;
        $tokens[] = [
            'relay_url' => $url,
            'relay_token_day' => substr((string)($item['relay_token_day'] ?? ($item['day'] ?? '')), 0, 16),
            'relay_token_expires_at' => max(0, (int)($item['relay_token_expires_at'] ?? ($item['expires_at'] ?? 0))),
            'relay_token' => substr($token, 0, 128),
        ];
        if (count($tokens) >= 20) break;
    }
    return $tokens;
}


function dcloud_sanitize_string_list($value, int $maxItems = 32, int $maxLength = 128): array {
    if ($value === null) return [];
    $items = is_array($value) ? $value : preg_split('/[\s,;]+/', (string)$value);
    $out = [];
    foreach ($items ?: [] as $raw) {
        $item = substr(trim(preg_replace('/[\r\n\t]+/', ' ', (string)$raw)), 0, $maxLength);
        if ($item === '') continue;
        if (!in_array($item, $out, true)) $out[] = $item;
        if (count($out) >= $maxItems) break;
    }
    return $out;
}

function dcloud_sanitize_inventory($value): array {
    if (!is_array($value)) return ['manifests' => [], 'updated_at' => time()];
    $rawManifests = $value['manifests'] ?? $value;
    if (!is_array($rawManifests)) return ['manifests' => [], 'updated_at' => time()];
    $manifests = [];
    foreach ($rawManifests as $key => $item) {
        if (is_array($item) && array_key_exists('manifest_id', $item)) {
            $manifestId = substr(trim((string)$item['manifest_id']), 0, 160);
            $chunksRaw = $item['chunk_hashes'] ?? ($item['chunks'] ?? []);
        } else {
            $manifestId = substr(trim((string)$key), 0, 160);
            $chunksRaw = $item;
        }
        if ($manifestId === '' || in_array($manifestId, ['updated_at', 'version'], true)) continue;
        $chunks = dcloud_sanitize_string_list($chunksRaw, 512, 96);
        if (!$chunks) continue;
        $manifests[] = [
            'manifest_id' => $manifestId,
            'chunk_hashes' => $chunks,
            'chunk_count' => count($chunks),
        ];
        if (count($manifests) >= 200) break;
    }
    return ['manifests' => $manifests, 'updated_at' => time(), 'version' => 1];
}

function dcloud_sanitize_peer($peer, string $nodeId): array {
    if (!is_array($peer)) dcloud_fail('Peer-Metadaten fehlen', 400);

    $clientType = $peer['client_type'] ?? null;
    if (!in_array($clientType, ['server'], true)) $clientType = null;

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
        'chat_enabled' => array_key_exists('chat_enabled', $peer) ? !empty($peer['chat_enabled']) : true,
        'chat_alias' => substr(trim(preg_replace('/[\r\n\t]+/', ' ', (string)($peer['chat_alias'] ?? ''))), 0, 48),
        'relay_url' => $relayUrls[0] ?? '',
        'relay_urls' => $relayUrls,
        'relay_tokens' => dcloud_sanitize_relay_tokens($peer['relay_tokens'] ?? []),
        'lan_addresses' => dcloud_sanitize_string_list($peer['lan_addresses'] ?? ($peer['local_addresses'] ?? []), 8, 80),
        'inventory' => dcloud_sanitize_inventory($peer['inventory'] ?? ($peer['chunk_inventory'] ?? [])),
        'public_ip' => substr((string)($peer['public_ip'] ?? ''), 0, 80),
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
        if (!is_array($peer)) continue;
        $age = $now - (int)($peer['relay_seen_at'] ?? 0);
        if ($age <= DCLOUD_PEER_TTL_SECONDS && $nodeId !== $ownNodeId) {
            $peer['relay_age_seconds'] = $age;
            $active[] = $peer;
        }
    }
    return $active;
}


function dcloud_find_active_peer(string $nodeId): array {
    $path = dcloud_storage_dir() . DIRECTORY_SEPARATOR . 'peers.json';
    $peers = dcloud_read_json_file($path, []);
    if (!isset($peers[$nodeId]) || !is_array($peers[$nodeId])) {
        dcloud_fail('Ziel-Peer ist nicht beim Relay registriert', 404, ['target_node_id' => $nodeId]);
    }
    $peer = $peers[$nodeId];
    $age = time() - (int)($peer['relay_seen_at'] ?? 0);
    if ($age > DCLOUD_PEER_TTL_SECONDS) {
        dcloud_fail('Ziel-Peer ist nicht mehr aktiv', 404, ['target_node_id' => $nodeId, 'age_seconds' => $age]);
    }
    return $peer;
}

function dcloud_is_public_ip(string $ip): bool {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

function dcloud_forward_target_url(array $peer, string $path): string {
    $host = trim((string)($peer['public_ip'] ?? ''));
    $port = (int)($peer['web_port'] ?? 0);
    if ($host === '' || $port <= 0 || $port > 65535) {
        dcloud_fail('Ziel-Peer hat keine oeffentliche Web-Adresse registriert', 404);
    }
    if (!dcloud_is_public_ip($host)) {
        dcloud_fail('Ziel-Peer-Adresse ist nicht oeffentlich routbar; PHP-Forwarder wird aus Sicherheitsgruenden nicht verwendet', 404, ['public_ip' => $host]);
    }
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $host = '[' . $host . ']';
    }
    return 'http://' . $host . ':' . $port . $path;
}

function dcloud_allowed_forward_headers(array $headers): array {
    $allowed = [];
    foreach ($headers as $key => $value) {
        $name = trim((string)$key);
        $lower = strtolower($name);
        if ($name === '') continue;
        if ($lower === 'content-type' || $lower === 'accept' || strncmp($lower, 'x-dcloud-', 9) === 0) {
            $cleanValue = str_replace(["\r", "\n"], ' ', (string)$value);
            $allowed[$name] = $cleanValue;
        }
    }
    return $allowed;
}

function dcloud_headers_for_json(array $headers): array {
    $out = [];
    foreach ($headers as $line) {
        if (!is_string($line) || strpos($line, ':') === false) continue;
        [$name, $value] = explode(':', $line, 2);
        $name = trim($name);
        if ($name === '') continue;
        $lower = strtolower($name);
        if ($lower === 'content-type' || $lower === 'content-disposition' || $lower === 'content-length' || strncmp($lower, 'x-dcloud-', 9) === 0) {
            $out[$name] = trim($value);
        }
    }
    return $out;
}


function dcloud_status_from_header_lines(array $headers): int {
    $status = 0;
    foreach ($headers as $line) {
        if (is_string($line) && preg_match('/^HTTP\/\S+\s+(\d{3})\b/', $line, $matches)) {
            $status = (int)$matches[1];
        }
    }
    return $status > 0 ? $status : 502;
}

function dcloud_perform_direct_proxy_http(string $url, string $method, array $headers, string $body, int $timeout): array {
    $headerLines = [];
    foreach ($headers as $key => $value) {
        $headerLines[] = $key . ': ' . $value;
    }

    if (function_exists('curl_init')) {
        $responseHeaders = [];
        $ch = curl_init($url);
        if ($ch === false) {
            dcloud_fail('PHP-Forwarder konnte cURL nicht initialisieren', 500);
        }
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, DCLOUD_DIRECT_PROXY_CONNECT_TIMEOUT_SECONDS);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        if (defined('CURLPROTO_HTTP')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
            curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP);
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headerLines);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($curl, string $line) use (&$responseHeaders): int {
            $trimmed = trim($line);
            if ($trimmed !== '') $responseHeaders[] = $trimmed;
            return strlen($line);
        });
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $responseBody = curl_exec($ch);
        $curlErrno = curl_errno($ch);
        $curlError = curl_error($ch);
        $statusCode = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($responseBody === false || $curlErrno !== 0) {
            dcloud_fail('PHP-Forwarder konnte Ziel-Peer nicht direkt erreichen', 502, [
                'curl_errno' => $curlErrno,
                'curl_error' => substr($curlError, 0, 160),
            ]);
        }
        return [
            'status_code' => $statusCode > 0 ? $statusCode : dcloud_status_from_header_lines($responseHeaders),
            'headers' => $responseHeaders,
            'body' => (string)$responseBody,
            'engine' => 'curl',
        ];
    }

    $contextOptions = [
        'http' => [
            'method' => $method,
            'header' => implode("\r\n", $headerLines),
            'timeout' => $timeout,
            'ignore_errors' => true,
            'follow_location' => 0,
        ],
    ];
    if ($method === 'POST') {
        $contextOptions['http']['content'] = $body;
    }
    $context = stream_context_create($contextOptions);
    $responseBody = @file_get_contents($url, false, $context);
    $responseHeaders = isset($http_response_header) && is_array($http_response_header) ? $http_response_header : [];
    if ($responseBody === false) {
        $lastError = error_get_last();
        dcloud_fail('PHP-Forwarder konnte Ziel-Peer nicht direkt erreichen', 502, [
            'stream_error' => substr((string)($lastError['message'] ?? 'unknown'), 0, 160),
        ]);
    }
    return [
        'status_code' => dcloud_status_from_header_lines($responseHeaders),
        'headers' => $responseHeaders,
        'body' => (string)$responseBody,
        'engine' => 'stream',
    ];
}

function dcloud_decode_direct_proxy_input(array $input): array {
    $targetNodeIdRaw = dcloud_first_string_value($input, ['target_node_id', 'to_node_id', 'target_node', 'peer_node_id', 'recipient_node_id']);
    if ($targetNodeIdRaw === '') {
        dcloud_fail('PHP-Forwarder-Anfrage ist unvollstaendig: target_node_id fehlt', 400);
    }
    $targetNodeId = dcloud_safe_id($targetNodeIdRaw, 'target_node_id');
    $method = strtoupper((string)($input['method'] ?? 'GET'));
    $path = (string)($input['path'] ?? ($input['api_path'] ?? ''));
    $allowedPeerApi = strncmp($path, '/api/p2p/', 9) === 0;
    $allowedPeerWeb = dcloud_path_is_allowed_for_peer_web($method, $path);
    if (!in_array($method, ['GET', 'POST'], true) || (!$allowedPeerApi && !$allowedPeerWeb)) {
        dcloud_fail('PHP-Forwarder erlaubt nur GET/POST auf /api/p2p/ oder /dcloud-site', 403, ['method' => $method, 'path' => $path]);
    }

    $bodyBase64 = (string)($input['body_base64'] ?? ($input['body'] ?? ''));
    if (strlen($bodyBase64) > DCLOUD_DIRECT_PROXY_MAX_ENCODED_BODY_BYTES) {
        dcloud_fail('PHP-Forwarder-Nutzdaten sind zu gross; Mailbox-Relay kann als Fallback verwendet werden', 413);
    }
    $body = '';
    if ($bodyBase64 !== '') {
        $decoded = base64_decode($bodyBase64, true);
        if ($decoded === false) {
            dcloud_fail('PHP-Forwarder-Nutzdaten sind ungueltig base64-kodiert', 400);
        }
        $body = $decoded;
    }

    $peer = dcloud_find_active_peer($targetNodeId);
    $url = dcloud_forward_target_url($peer, $path);
    $headers = dcloud_allowed_forward_headers(is_array($input['headers'] ?? null) ? $input['headers'] : []);
    $timeout = max(1, min(120, (int)($input['timeout_seconds'] ?? DCLOUD_DIRECT_PROXY_TIMEOUT_SECONDS)));
    return [$targetNodeId, $url, $method, $path, $headers, $body, $timeout];
}

function dcloud_direct_proxy_request(array $input): void {
    [$targetNodeId, $url, $method, $_path, $headers, $body, $timeout] = dcloud_decode_direct_proxy_input($input);
    $forwarded = dcloud_perform_direct_proxy_http($url, $method, $headers, $body, $timeout);
    $statusCode = (int)($forwarded['status_code'] ?? 502);
    $responseBody = (string)($forwarded['body'] ?? '');
    $responseHeaders = is_array($forwarded['headers'] ?? null) ? $forwarded['headers'] : [];
    $safeHeaders = dcloud_headers_for_json($responseHeaders);
    $safeHeaders['X-DCloud-Relay-Mode'] = 'direct_proxy';
    dcloud_json_response([
        'ok' => true,
        'proxy_mode' => 'direct_http',
        'target_node_id' => $targetNodeId,
        'response' => [
            'status_code' => $statusCode,
            'headers' => $safeHeaders,
            'body_base64' => base64_encode((string)$responseBody),
        ],
    ]);
}

function dcloud_send_raw_proxy_headers_once(int $statusCode, array $responseHeaders, bool &$sent): void {
    if ($sent) return;
    $sent = true;
    $safeHeaders = dcloud_headers_for_json($responseHeaders);
    if (!headers_sent()) {
        http_response_code($statusCode > 0 ? $statusCode : 502);
        header('Cache-Control: no-store');
        header('X-Accel-Buffering: no');
        header('X-Content-Type-Options: nosniff');
        header('X-DCloud-Relay-Mode: direct_proxy_raw');
        $contentType = $safeHeaders['Content-Type'] ?? ($safeHeaders['content-type'] ?? 'application/octet-stream');
        header('Content-Type: ' . str_replace(["\r", "\n"], ' ', (string)$contentType));
        $contentDisposition = $safeHeaders['Content-Disposition'] ?? ($safeHeaders['content-disposition'] ?? '');
        if ($contentDisposition !== '') {
            header('Content-Disposition: ' . str_replace(["\r", "\n"], ' ', (string)$contentDisposition));
        }
        $contentLength = $safeHeaders['Content-Length'] ?? ($safeHeaders['content-length'] ?? '');
        if ($contentLength !== '' && preg_match('/^\d+$/', (string)$contentLength)) {
            header('Content-Length: ' . (string)$contentLength);
        }
        foreach ($safeHeaders as $name => $value) {
            $lower = strtolower((string)$name);
            if (strncmp($lower, 'x-dcloud-', 9) === 0 && $lower !== 'x-dcloud-relay-mode') {
                header($name . ': ' . str_replace(["\r", "\n"], ' ', (string)$value));
            }
        }
        header('Connection: close');
    }
    @flush();
}

function dcloud_stream_direct_proxy_http(string $url, string $method, array $headers, string $body, int $timeout): void {
    if (!function_exists('curl_init')) {
        $forwarded = dcloud_perform_direct_proxy_http($url, $method, $headers, $body, $timeout);
        $statusCode = (int)($forwarded['status_code'] ?? 502);
        $responseBody = (string)($forwarded['body'] ?? '');
        $responseHeaders = is_array($forwarded['headers'] ?? null) ? $forwarded['headers'] : [];
        dcloud_raw_proxy_response($statusCode, $responseHeaders, $responseBody);
        return;
    }

    @set_time_limit(max(30, $timeout + 15));
    dcloud_clear_all_output_buffers();

    $headerLines = [];
    foreach ($headers as $key => $value) {
        $headerLines[] = $key . ': ' . $value;
    }

    $responseHeaders = [];
    $statusCode = 502;
    $headersSent = false;
    $sawFinalHeaderBlock = false;

    $ch = curl_init($url);
    if ($ch === false) {
        dcloud_fail('PHP-Forwarder konnte cURL nicht initialisieren', 500);
    }
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, DCLOUD_DIRECT_PROXY_CONNECT_TIMEOUT_SECONDS);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    if (defined('CURLOPT_BUFFERSIZE')) {
        curl_setopt($ch, CURLOPT_BUFFERSIZE, 1024 * 1024);
    }
    if (defined('CURLPROTO_HTTP')) {
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
        curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP);
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headerLines);
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($curl, string $line) use (&$responseHeaders, &$statusCode, &$sawFinalHeaderBlock): int {
        $trimmed = trim($line);
        if ($trimmed === '') {
            if ($statusCode >= 200) {
                $sawFinalHeaderBlock = true;
            }
            return strlen($line);
        }
        if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', $trimmed, $matches)) {
            $statusCode = (int)$matches[1];
            $responseHeaders = [];
            $sawFinalHeaderBlock = false;
            return strlen($line);
        }
        if ($statusCode >= 200) {
            $responseHeaders[] = $trimmed;
        }
        return strlen($line);
    });
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($curl, string $chunk) use (&$statusCode, &$responseHeaders, &$headersSent, &$sawFinalHeaderBlock): int {
        if (!$headersSent) {
            dcloud_send_raw_proxy_headers_once($statusCode, $responseHeaders, $headersSent);
        }
        echo $chunk;
        @flush();
        return strlen($chunk);
    });

    $ok = curl_exec($ch);
    $curlErrno = curl_errno($ch);
    $curlError = curl_error($ch);
    $infoStatus = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    if (!$headersSent && $infoStatus > 0) {
        $statusCode = $infoStatus;
    }
    if (($ok === false || $curlErrno !== 0) && !$headersSent) {
        dcloud_fail('PHP-Forwarder konnte Ziel-Peer nicht direkt erreichen', 502, [
            'curl_errno' => $curlErrno,
            'curl_error' => substr($curlError, 0, 160),
        ]);
    }
    if (!$headersSent) {
        dcloud_send_raw_proxy_headers_once($statusCode, $responseHeaders, $headersSent);
    }
    dcloud_finalize_and_exit();
}

function dcloud_raw_proxy_response(int $statusCode, array $responseHeaders, string $responseBody): void {
    dcloud_clear_all_output_buffers();
    $safeHeaders = dcloud_headers_for_json($responseHeaders);
    if (!headers_sent()) {
        http_response_code($statusCode > 0 ? $statusCode : 502);
        header('Cache-Control: no-store');
        header('X-Accel-Buffering: no');
        header('X-Content-Type-Options: nosniff');
        header('X-DCloud-Relay-Mode: direct_proxy_raw');
        $contentType = $safeHeaders['Content-Type'] ?? ($safeHeaders['content-type'] ?? 'application/octet-stream');
        header('Content-Type: ' . str_replace(["\r", "\n"], ' ', (string)$contentType));
        $contentDisposition = $safeHeaders['Content-Disposition'] ?? ($safeHeaders['content-disposition'] ?? '');
        if ($contentDisposition !== '') {
            header('Content-Disposition: ' . str_replace(["\r", "\n"], ' ', (string)$contentDisposition));
        }
        $contentLength = $safeHeaders['Content-Length'] ?? ($safeHeaders['content-length'] ?? '');
        if ($contentLength !== '' && preg_match('/^\d+$/', (string)$contentLength)) {
            header('Content-Length: ' . (string)$contentLength);
        } else {
            header('Content-Length: ' . strlen($responseBody));
        }
        foreach ($safeHeaders as $name => $value) {
            $lower = strtolower((string)$name);
            if (strncmp($lower, 'x-dcloud-', 9) === 0 && $lower !== 'x-dcloud-relay-mode') {
                header($name . ': ' . str_replace(["\r", "\n"], ' ', (string)$value));
            }
        }
        header('Connection: close');
    }
    echo $responseBody;
    dcloud_finalize_and_exit();
}

function dcloud_direct_proxy_request_raw(array $input): void {
    [$_targetNodeId, $url, $method, $_path, $headers, $body, $timeout] = dcloud_decode_direct_proxy_input($input);
    dcloud_stream_direct_proxy_http($url, $method, $headers, $body, $timeout);
}


function dcloud_create_external_download_link(array $input): void {
    $targetNodeIdRaw = dcloud_first_string_value($input, ['target_node_id', 'node_id', 'owner_node_id']);
    if ($targetNodeIdRaw === '') {
        dcloud_fail('Relay-Link-Anfrage ist unvollstaendig: target_node_id fehlt', 400);
    }
    $targetNodeId = dcloud_safe_id($targetNodeIdRaw, 'target_node_id');
    $localToken = dcloud_safe_public_token($input['local_token'] ?? ($input['token'] ?? ''));
    $fileName = dcloud_safe_external_file_name($input['file_name'] ?? 'download.bin');
    $fileSize = max(0, (int)($input['file_size'] ?? 0));
    $now = time();
    $requestedTtl = (int)($input['ttl_seconds'] ?? 3600);
    $requestedTtl = max(1, min(DCLOUD_EXTERNAL_LINK_MAX_TTL_SECONDS, $requestedTtl));
    $requestedExpires = (int)floor((float)($input['expires_at'] ?? ($now + $requestedTtl)));
    $expiresAt = min($now + $requestedTtl, $requestedExpires, $now + DCLOUD_EXTERNAL_LINK_MAX_TTL_SECONDS);
    if ($expiresAt <= $now) {
        dcloud_fail('Relay-Link-Ablaufzeit ist bereits erreicht', 400);
    }

    // Do not require a direct /healthz check during link creation. Many nodes
    // are temporarily slow to accept inbound connections or use firewall rules
    // that become valid only after the relay registration has settled. The link
    // should still be a public relay URL; actual reachability is checked when
    // the recipient opens the link, where we can return a clear download error.
    try {
        dcloud_find_active_peer($targetNodeId);
    } catch (Throwable $ignored) {
        // Keep creating the short-lived relay token. If the node is still not
        // registered when the link is opened, external_download will fail with
        // the normal target-peer message.
    }

    $publicToken = rtrim(strtr(base64_encode(random_bytes(DCLOUD_EXTERNAL_LINK_TOKEN_BYTES)), '+/', '-_'), '=');
    dcloud_cleanup_external_links(true);
    $links = dcloud_read_external_links();
    $links[$publicToken] = [
        'target_node_id' => $targetNodeId,
        'local_token' => $localToken,
        'file_name' => $fileName,
        'file_size' => $fileSize,
        'created_at' => $now,
        'expires_at' => $expiresAt,
        'creator_node_id' => dcloud_safe_id((string)($input['node_id'] ?? $targetNodeId), 'node_id'),
    ];
    dcloud_write_external_links($links);

    $publicUrl = dcloud_current_script_url(['action' => 'external_download', 'token' => $publicToken]);
    dcloud_json_response([
        'ok' => true,
        'public_url' => $publicUrl,
        'url' => $publicUrl,
        'token' => $publicToken,
        'expires_at' => $expiresAt,
        'expiresInSeconds' => max(0, $expiresAt - $now),
        'delivery_mode' => 'reverse_mailbox_stream',
        'message' => 'Relay-Download-Link wurde erstellt',
    ]);
}

function dcloud_external_download_via_relay(string $token): void {
    $publicToken = dcloud_safe_public_token($token);
    dcloud_cleanup_external_links(true);
    $links = dcloud_read_external_links();
    $item = $links[$publicToken] ?? null;
    if (!is_array($item)) {
        dcloud_clear_all_output_buffers();
        http_response_code(410);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        echo 'Dieser dcloud Download-Link ist abgelaufen oder ungueltig.';
        dcloud_finalize_and_exit();
    }
    if ((int)($item['expires_at'] ?? 0) <= time()) {
        unset($links[$publicToken]);
        dcloud_write_external_links($links);
        dcloud_clear_all_output_buffers();
        http_response_code(410);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        echo 'Dieser dcloud Download-Link ist abgelaufen.';
        dcloud_finalize_and_exit();
    }
    $targetNodeId = dcloud_safe_id((string)($item['target_node_id'] ?? ''), 'target_node_id');
    $localToken = dcloud_safe_public_token($item['local_token'] ?? '');
    $fileName = dcloud_safe_external_file_name($item['file_name'] ?? 'download.bin');
    $fileSize = max(0, (int)($item['file_size'] ?? 0));

    // Externe Links muessen auch funktionieren, wenn der dcloud-Node hinter NAT,
    // DS-Lite oder einer Firewall sitzt. Darum wird hier nicht der direkte
    // PHP-Forwarder verwendet. Das Relay legt eine Stream-Anfrage in die normale
    // Mailbox; der Node holt sie aktiv ab und schiebt die Datei in kleinen
    // Paketen zum Relay, waehrend der Browser aus demselben Stream liest.
    dcloud_external_download_via_stream_mailbox($targetNodeId, $localToken, $fileName, $fileSize);
}

function dcloud_register(array $input): void {
    $nodeId = dcloud_safe_id((string)($input['node_id'] ?? ''), 'node_id');
    $peer = $input['peer'] ?? null;

    if (!is_array($peer)) {
        foreach (['public_key', 'name', 'udp_port', 'web_port', 'client_type', 'shared_storage_bytes', 'free_storage_bytes', 'accepts_peer_storage', 'chat_enabled', 'chat_alias', 'relay_url', 'relay_urls'] as $key) {
            if (array_key_exists($key, $input)) {
                $peer = $input;
                break;
            }
        }
    }
    if (!is_array($peer)) {
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
        if (!array_key_exists('chat_enabled', $peer) && array_key_exists('chat_enabled', $existing)) {
            $sanitized['chat_enabled'] = !empty($existing['chat_enabled']);
        }

        $sanitized['public_ip'] = dcloud_public_client_ip();

        foreach (['public_key', 'client_type', 'shared_storage_bytes', 'free_storage_bytes', 'accepts_peer_storage', 'chat_alias', 'relay_url', 'relay_urls', 'relay_tokens', 'lan_addresses', 'web_port', 'udp_port', 'public_ip'] as $key) {
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
            if (!in_array($relayUrl, $relayUrls, true)) $relayUrls[] = $relayUrl;
        }
    }

    dcloud_json_response(array_merge(
        ['ok' => true, 'version' => DCLOUD_RELAY_VERSION, 'peers' => $peers, 'relay_urls' => $relayUrls],
        dcloud_current_relay_token()
    ));
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

    if (!dcloud_path_is_allowed_for_mailbox($method, $path)) {
        dcloud_fail('Nur GET/POST auf /api/p2p/, /dcloud-site oder externe Relay-Stream-Pfade sind erlaubt', 403, ['method' => $method, 'path' => $path]);
    }

    $bodyBase64 = (string)($input['body_base64'] ?? ($input['body'] ?? ''));
    if (strlen($bodyBase64) > DCLOUD_MAX_ENCODED_BODY_BYTES) {
        dcloud_fail('Relay-Nutzdaten sind zu gross', 413);
    }

    $headers = $input['headers'] ?? [];
    if (!is_array($headers)) $headers = [];

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
        sort($files, SORT_STRING);

        $requests = [];
        foreach (array_slice($files, 0, $max) as $file) {
            $payload = dcloud_read_json_file($file, []);
            if ($payload && dcloud_envelope_is_valid($payload)) {
                $requests[] = $payload;
                @unlink($file);
            } else {
                dcloud_log_event('warning', ['message' => 'Ungueltiger Queue-Eintrag wurde verworfen', 'file' => basename($file)]);
                // Keep malformed/incomplete files for a short time so a
                // concurrent writer or transient read does not permanently
                // lose queued relay requests.
                $age = time() - (int)@filemtime($file);
                if ($age > 30) {
                    @unlink($file);
                }
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
    if (!is_array($headers)) $headers = [];

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
    if ($action === '') return 'health';

    $aliases = [
        'ping' => 'health',
        'status' => 'health',
        'announce' => 'register',
        'heartbeat' => 'register',
        'register_peer' => 'register',
        'peer_register' => 'register',
        'enqueue' => 'enqueue_request',
        'send_request' => 'enqueue_request',
        'proxy_request' => 'direct_proxy_request',
        'direct_proxy' => 'direct_proxy_request',
        'direct_proxy_request' => 'direct_proxy_request',
        'direct_proxy_request_raw' => 'direct_proxy_request_raw',
        'direct_proxy_raw' => 'direct_proxy_request_raw',
        'http_forward' => 'direct_proxy_request',
        'forward_http' => 'direct_proxy_request',
        'php_forwarder' => 'direct_proxy_request',
        'create_external_download_link' => 'create_external_download_link',
        'external_link_create' => 'create_external_download_link',
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

    if (!in_array($action, ['poll_requests', 'poll_response', 'direct_proxy_request', 'direct_proxy_request_raw'], true)) {
        dcloud_cleanup_if_due();
    }
    $input['action'] = $action;

    switch ($action) {
        case 'health':
            $health = ['ok' => true, 'version' => DCLOUD_RELAY_VERSION, 'time' => time(), 'token_public' => false];
            if (dcloud_relay_signature_is_valid($input)) {
                $health = array_merge($health, dcloud_current_relay_token(), ['token_public' => false, 'token_delivery' => 'signed-health']);
            }
            dcloud_json_response($health);
            break;

        case 'register':
            dcloud_register($input);
            break;

        case 'enqueue_request':
            dcloud_enqueue_request($input);
            break;

        case 'direct_proxy_request':
            dcloud_direct_proxy_request($input);
            break;

        case 'direct_proxy_request_raw':
            dcloud_direct_proxy_request_raw($input);
            break;

        case 'create_external_download_link':
            dcloud_create_external_download_link($input);
            break;
        case 'external_stream_start':
        case 'external_stream_chunk':
        case 'external_stream_finish':
        case 'external_stream_error':
            dcloud_external_stream_event($input);
            break;

        case 'poll_requests':
            dcloud_poll_requests($input);
            break;

        case 'post_response':
            dcloud_post_response($input);
            break;

        case 'poll_response':
            dcloud_poll_response($input);
            break;

        default:
            dcloud_fail('Unbekannte Relay-Aktion: ' . $action, 400);
    }
} catch (Throwable $exception) {
    dcloud_json_response([
        'ok' => false,
        'message' => 'Relay-Fehler: ' . $exception->getMessage(),
    ], 500);
}
