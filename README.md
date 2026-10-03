# PS5 Node Download Helper v2

A dependency-free Node.js helper for this workflow:

1. PS5 uses your Mac/PC as an HTTP proxy.
2. The helper logs real `.pkg` download requests.
3. Click **Download Links** on a captured PKG.
4. The helper keeps the captured URL exact and increments only the final numeric token immediately before `.pkg` (`..._0.pkg` → `..._1.pkg`, or `0.pkg` → `1.pkg`).
5. It probes each generated URL with `Range: bytes=0-0` and stops at the first non-2xx/error.
6. Copy one link or **Copy All Links** into your own download manager.
7. After downloading, choose the local directory containing those PKGs. Filenames must be unchanged.
8. When the PS5 requests a PKG whose filename exists locally, the helper serves the local file with correct HTTP byte-range support.
9. If local mapping cannot safely handle the request, the helper **fails open** and forwards the original request to Sony/CDN normally.

The project does not include a download manager.

## Requirements

- Node.js 20+
- macOS, Linux, or Windows

Check Node:

```bash
node --version
```

## Start

```bash
cd ps5-node-download-helper
npm start
```

Open:

```text
http://127.0.0.1:8081
```

The Overview tab shows the exact LAN proxy endpoint(s), for example:

```text
192.168.1.50:8080
```

Use that IP and port in the PS5 Proxy Server settings.

The proxy starts automatically. You can stop/start it from the dashboard without shutting down the dashboard.

## Dashboard tabs

### Overview

- Proxy RUNNING/STOPPED state
- Start Proxy button
- Stop Proxy button
- Mac/PC LAN IP and proxy port shown as `IP:8080`

### PKG Download Links

After clicking **Download Links** in Logger, the helper:

- keeps the captured URL unchanged for the first probe
- finds the final decimal number directly before `.pkg`
- increments only that number
- preserves every other URL character/query parameter
- probes with a one-byte HTTP Range request
- stops at the first failed/non-2xx URL
- lists all valid links
- provides Copy buttons and Copy All Links

There is a safety limit of 4096 discovered links by default.

### Local Mapping

Choose the directory where your download manager saved the PKGs. The helper recursively scans subdirectories and indexes `.pkg` files by their unchanged filename.

On macOS, **Choose Folder…** opens the native Finder folder chooser using `osascript`. A path can also be pasted manually.

If the same PKG filename exists more than once under the selected directory, it is considered ambiguous and that request falls back to the CDN.

### Logger

Logger shows only PKG traffic:

```text
REMOTE   PS5 PKG request is using Sony/CDN
LOCAL    request was mapped to a local PKG
FALLBACK local mapping failed safely, so original request went to Sony/CDN
```

For LOCAL rows it shows the exact local file used.

For FALLBACK rows it shows the reason.

## Fail-open mapping behavior

When a local directory is enabled, the helper attempts to map each `.pkg` request by the exact requested filename.

Before sending any local response headers, it verifies:

- the local file exists
- exactly one file with that filename exists
- it is a regular readable file
- it is non-empty
- when the expected remote total size has already been learned, local size matches it
- the requested Range can be represented safely
- the local file can actually be opened

If any of those checks fail, the helper does **not** send a local error response. It forwards the original PS5 request upstream unchanged.

Examples:

```text
[FALLBACK] GET http://cdn/.../game_4.pkg -> CDN (Local file not found: game_4.pkg)
```

```text
[FALLBACK] GET http://cdn/.../game_2.pkg -> CDN (Local file size mismatch: local=..., expected=...)
```

A physical disk/read failure that occurs only after response bytes have already started cannot be transparently switched to a different HTTP response mid-stream; such a rare transport failure is logged and the connection is closed so the PS5 can retry.

## Local Range responses

For a PS5 request such as:

```http
Range: bytes=5000000000-5999999999
```

the helper serves only that part of the local PKG and returns:

```text
HTTP/1.1 206 Partial Content
Accept-Ranges: bytes
Content-Range: bytes 5000000000-5999999999/TOTAL_SIZE
Content-Length: ...
```

Large PKGs are streamed from disk and are not loaded into RAM.

## Sequential URL example

Captured URL:

```text
http://cdn.example/path/title_0.pkg?token=abc
```

The helper probes exactly:

```text
http://cdn.example/path/title_0.pkg?token=abc
http://cdn.example/path/title_1.pkg?token=abc
http://cdn.example/path/title_2.pkg?token=abc
...
```

It does not modify `title`, directories, host, query parameters, or other numbers elsewhere in the URL.

For:

```text
http://cdn.example/path/0.pkg
```

it generates:

```text
http://cdn.example/path/0.pkg
http://cdn.example/path/1.pkg
http://cdn.example/path/2.pkg
...
```

## Environment variables

```text
PROXY_HOST=0.0.0.0
PROXY_PORT=8080
DASHBOARD_HOST=127.0.0.1
DASHBOARD_PORT=8081
MAX_LOGS=2000
MAX_PACKAGE_LINKS=4096
PKG_PROBE_TIMEOUT_MS=10000
MAX_SCAN_ENTRIES=100000
```

Example:

```bash
PROXY_PORT=8888 npm start
```

## Notes

This helper is for content you are authorized to download. It does not bypass PSN ownership/entitlement checks or install packages directly on the console.
