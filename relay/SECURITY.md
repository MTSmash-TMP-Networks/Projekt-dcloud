# dcloud Relay hardening

The relay is intended as tracker/signaling/fallback endpoint. Large data transfers should prefer direct LAN/public/gateway routes.

Recommended deployment:

1. Put `dcloud_relay.php` in its own `/relay/` directory.
2. Upload the included `.htaccess` next to it on Apache hosts.
3. Do not expose unrelated test applications, vendor directories, `.env` files, or old PHP projects on the same public document root.
4. Keep PHP-FPM memory and body limits aligned with the relay mode:
   - tracker/signaling only: `post_max_size=32M`, `memory_limit=256M`
   - legacy PHP data fallback: higher limits may be required, but this is slower and riskier.
5. If OPcache is enabled, reload PHP-FPM/webserver after replacing `dcloud_relay.php`.

Health check:

```text
https://your-host.example/relay/dcloud_relay.php?action=health
```

Expected version:

```text
1.6.3-hardened-relay
```
