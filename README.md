# PS5 Download Proxy v2

![Node.js >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen) ![Dependencies: none](https://img.shields.io/badge/dependencies-none-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-yellow)

Download PS5 games faster on your computer, then let your PS5 install them from there instead of the internet.

## How to use it (simple version)

1. Start the app (see [Start](#start)) and open `http://127.0.0.1:8081` in your browser.
2. **Step 1 · Connect PS5**: type the **Address** and **Port** shown into the PS5 under *Settings → Network → Settings → Set Up Internet Connection → (your network) → Options → Advanced Settings → Proxy Server*.
3. **Step 2 · Find Game**: start the game download on the PS5. It appears in the list. Click **Get Download Links**.
4. **Step 3 · Get Download Links**: click **Copy All Links**, paste them into a download manager, and download them. Keep the file names.
5. **Step 4 · Use My Files**: click **Choose Folder…** and pick the folder with the downloaded files.
6. Restart the download on the PS5. It now copies the files from your computer.
7. When finished, set the PS5's Proxy Server back to **Do Not Use**.

If a file is missing or incomplete, the PS5 just downloads that part from the internet as usual.

## How it works (technical)

A dependency-free Node.js helper for this workflow:

1. PS5 uses your Mac/PC as an HTTP proxy.
2. The helper logs real `.pkg` download requests.
3. Click **Get Download Links** on a captured PKG.
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
git clone https://github.com/Tohid1999/ps5-download-proxy.git
cd ps5-download-proxy
npm start
```

No `npm install` is needed: the helper uses only Node.js built-in modules.

While editing the code, use `npm run dev` instead. It restarts the helper automatically whenever `src/` changes.

Open:

```text
http://127.0.0.1:8081
```

The **Connect PS5** tab shows the address and port to enter on the PS5, for example:

```text
Address  192.168.1.50
Port     8080
```

The proxy starts automatically. You can turn it off and on from the dashboard without closing the dashboard.

## Dashboard tabs

The status badge in the top-right corner shows whether the proxy is off, waiting for the PS5, connected, or sending files from your computer. The tab badges count captured games, found links, and local game files.

### 1 · Connect PS5

- Proxy on/off state with **Turn On** / **Turn Off** buttons
- The computer's network **Address** and **Port**. Home-network addresses (`192.168.x`, `10.x`, `172.16–31.x`) are listed first, and other addresses such as VPNs are shown as alternatives
- Step-by-step PS5 proxy settings instructions
- **Let the PS5 use the internet** switch (on by default). Turning it off refuses every request the PS5 makes to the internet: HTTP gets `403` and HTTPS tunnels are refused. It also cuts connections that are already open. PKGs mapped to your local folder are still served. The switch can only be changed while the proxy is running, and it resets to on when the helper restarts.

### 2 · Find Game

Shows only PKG traffic. The **Coming from** column says where each file came from:

```text
Internet                   (REMOTE)   PS5 PKG request is using Sony/CDN
Your computer              (LOCAL)    request was mapped to a local PKG
Internet (file not used)   (FALLBACK) local mapping failed safely, so the request went to Sony/CDN
```

For local rows it shows the exact local file used. For fallback rows it shows the reason in plain language; hover for the original technical reason. Hover a row for the HTTP status and Range. **Get Download Links** starts link discovery for that PKG.

### 3 · Get Download Links

After you click **Get Download Links** in Find Game, the helper:

- keeps the captured URL unchanged for the first probe
- finds the final decimal number directly before `.pkg`
- increments only that number
- preserves every other URL character/query parameter
- probes with a one-byte HTTP Range request
- stops at the first failed/non-2xx URL
- lists all valid links as numbered parts, with sizes and the total size
- provides Copy buttons and Copy All Links

If no links are found, the captured link has most likely expired; restart the download on the PS5 and try again. There is a safety limit of 4096 discovered links by default.

### 4 · Use My Files

Add one or more directories where your download manager saved the PKGs, for example one folder per game or folders on different drives. The helper recursively scans subdirectories of every folder and indexes `.pkg` files by their unchanged filename.

- **Choose Folder…** opens the native folder chooser (Finder on macOS, `zenity`/`kdialog` on Linux). A path can also be pasted and added with **Add** (or Enter).
- Each folder is listed with its game file count and status, and can be removed on its own with **Remove**.
- **Check Folders Again** re-indexes every folder (use it after new downloads finish). **Remove All Folders** removes all folders from the app; files on disk are never deleted.
- A folder that cannot be scanned (for example an unplugged drive) is shown with its error. The other folders keep working.
- Overlapping folders, such as a folder and its parent, do not count the same file twice.

If the same PKG filename exists more than once across the selected folders, it is considered ambiguous and that request falls back to the CDN.

### Advanced: Network Log

Not needed for downloading games. Shows every request the proxy receives, not only PKG traffic:

- plain HTTP requests: method, full URL, client IP, request and response headers, status, bytes sent/received, duration, and the route taken (`PASSTHROUGH`, `REMOTE`, `LOCAL`, `FALLBACK`)
- HTTPS `CONNECT` tunnels: target host, status, bytes transferred, and duration. The encrypted content is not visible.

Click a row to see its full details. **Delete All** deletes all captured requests. **Save to File** downloads every captured request with full details as JSON.

Use **Add Bookmark** right before each action on the PS5, such as "launching game X". The bookmark (a `MARKER` entry) appears in the list and in the export timeline, so you can see which requests that action caused.

What is recorded:

- plain HTTP: full headers, plus request and response bodies (first 64 KB, decompressed; PKG payloads are skipped), the upstream server IP, and which PS5 connection was reused
- HTTPS tunnels: TLS server name (SNI) and protocols offered, read from the unencrypted ClientHello; upstream IP; bursts of traffic over time in each direction, plus round-trip count and time to first response. The content itself stays encrypted.
- a heuristic `category` per request, such as `psn-account`, `system-ui`, `telemetry` or `game-download`, guessed from the hostname only

The export (`formatVersion: 2`) contains a `fieldGuide`, a per-host summary with the gaps between connections, a readable `timeline`, and every request in chronological order.

Exports are not redacted: they include tokens in URLs and cookies or authorization headers. Treat the file as sensitive.

Requests are saved to `data/requests.json` every few seconds and on shutdown, so they survive restarts. Up to `MAX_REQUEST_LOGS` (default 5000) are kept. Requests still open during a restart are marked `interrupted`. **Delete All** also empties the saved file. The Find Game list is kept in memory only.

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
MAX_REQUEST_LOGS=5000
MAX_BODY_CAPTURE=65536
MAX_PACKAGE_LINKS=4096
PKG_PROBE_TIMEOUT_MS=10000
MAX_SCAN_ENTRIES=100000
```

Example:

```bash
PROXY_PORT=8888 npm start
```

## Testing

`npm test` runs `test-range.sh` (macOS/Linux, needs `bash` and `curl`). It starts the helper on ports 18080/18081, maps a 10 MB dummy PKG, and checks that a proxied Range request returns `206 Partial Content` with exactly the requested bytes. Your `data/settings.json` is backed up and restored.

```bash
npm test
```

## Privacy

Everything the helper stores lives in `data/` (git-ignored): `settings.json` holds your local folder paths and `requests.json` holds captured PS5 traffic, including PSN tokens and cookies. Never commit or share these files or exported request JSON.

## Notes

This helper is for content you are authorized to download. It does not bypass PSN ownership/entitlement checks or install packages directly on the console.

## License

[MIT](LICENSE)
