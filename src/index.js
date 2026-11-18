import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const REQUESTS_FILE = path.join(DATA_DIR, 'requests.json');
const REQUESTS_SAVE_INTERVAL_MS = 3000;

const PROXY_HOST = process.env.PROXY_HOST || '0.0.0.0';
const PROXY_PORT = Number(process.env.PROXY_PORT || 8080);
const DASHBOARD_HOST = process.env.DASHBOARD_HOST || '127.0.0.1';
const DASHBOARD_PORT = Number(process.env.DASHBOARD_PORT || 8081);
const MAX_LOGS = Number(process.env.MAX_LOGS || 2000);
const MAX_REQUEST_LOGS = Number(process.env.MAX_REQUEST_LOGS || 5000);
const MAX_BODY_CAPTURE = Number(process.env.MAX_BODY_CAPTURE || 64 * 1024);
const MAX_FLOW_EVENTS = 300;
const FLOW_MERGE_MS = 50;
const MAX_PACKAGE_LINKS = Number(process.env.MAX_PACKAGE_LINKS || 4096);
const PKG_PROBE_TIMEOUT_MS = Number(process.env.PKG_PROBE_TIMEOUT_MS || 10000);
const MAX_SCAN_ENTRIES = Number(process.env.MAX_SCAN_ENTRIES || 100000);
const DEBUG_PKG_HEADERS = /^(1|true|yes)$/i.test(process.env.DEBUG_PKG_HEADERS || '');

fs.mkdirSync(DATA_DIR, { recursive: true });

let settings = loadJson(SETTINGS_FILE, { localDirectory: null });
let proxyRunning = false;
let proxyLastError = null;
let pkgLogs = [];
let requestLogs = [];
let proxyConnectionCounter = 0;
// When false, the proxy refuses to reach the internet for the PS5. Locally mapped PKGs are still served.
let internetAllowed = true;
const activeUpstreams = new Map();

// Remembers each open upstream connection with its PS5-side counterpart so blocking can cut both.
function trackUpstream(conn, downstream) {
  activeUpstreams.set(conn, downstream);
  conn.on('close', () => activeUpstreams.delete(conn));
}

function setInternetAllowed(allowed) {
  internetAllowed = allowed;
  if (!allowed) {
    for (const [conn, downstream] of activeUpstreams) {
      conn.destroy();
      downstream.destroy();
    }
    activeUpstreams.clear();
  }
  console.log(`[INTERNET] PS5 internet access ${allowed ? 'ALLOWED' : 'BLOCKED'}`);
  return { allowed: internetAllowed };
}
const pkgDiscoveryJobs = new Map();
const remoteMetadata = new Map();
const proxySockets = new Set();
let localPkgIndex = new Map();
let localScan = {
  directory: settings.localDirectory || null,
  directories: [],
  pkgCount: 0,
  duplicateNames: 0,
  scannedEntries: 0,
  scannedAt: null,
  error: null
};

function loadJson(filename, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filename, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') console.error(`Could not read ${filename}:`, error.message);
    return fallback;
  }
}

function saveSettings() {
  const tmp = `${SETTINGS_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(settings, null, 2));
  fs.renameSync(tmp, SETTINGS_FILE);
}

function id() {
  return crypto.randomUUID();
}

function now() {
  return new Date().toISOString();
}

function lanAddresses() {
  const results = [];
  for (const [name, addresses] of Object.entries(os.networkInterfaces())) {
    for (const address of addresses || []) {
      if (address.family === 'IPv4' && !address.internal) {
        results.push({ interface: name, address: address.address });
      }
    }
  }
  return results;
}

function clientIp(socket) {
  return String(socket.remoteAddress || '').replace(/^::ffff:/, '');
}

function redactUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const sensitive = /token|auth|signature|sig|key|credential|session|ticket/i;
    for (const key of [...u.searchParams.keys()]) {
      if (sensitive.test(key)) u.searchParams.set(key, '[REDACTED]');
    }
    return u.toString();
  } catch {
    return rawUrl;
  }
}

function safeHeaders(headers) {
  const blocked = new Set([
    'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
    'x-auth-token', 'x-api-key'
  ]);
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) {
    out[key] = blocked.has(key.toLowerCase()) ? '[REDACTED]' : value;
  }
  return out;
}

function requestUrl(req) {
  if (/^https?:\/\//i.test(req.url || '')) return req.url;
  const host = req.headers.host;
  if (!host) return null;
  return `http://${host}${req.url || '/'}`;
}

function pkgFilenameFromUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const base = path.posix.basename(u.pathname);
    if (!/\.pkg$/i.test(base)) return null;
    try {
      return decodeURIComponent(base);
    } catch {
      return base;
    }
  } catch {
    const withoutQuery = String(rawUrl || '').split(/[?#]/, 1)[0];
    const base = withoutQuery.slice(withoutQuery.lastIndexOf('/') + 1);
    return /\.pkg$/i.test(base) ? base : null;
  }
}

function isPkgUrl(rawUrl) {
  return Boolean(pkgFilenameFromUrl(rawUrl));
}

function addPkgLog(entry) {
  const log = {
    id: id(),
    timestamp: now(),
    action: 'REMOTE',
    method: 'GET',
    status: null,
    url: null,
    displayUrl: null,
    filename: null,
    range: null,
    localFile: null,
    reason: null,
    clientIp: null,
    ...entry
  };
  pkgLogs.unshift(log);
  if (pkgLogs.length > MAX_LOGS) pkgLogs.length = MAX_LOGS;
  return log;
}

// Heuristic guess at what a PS5 request is for, based only on host and URL.
const REQUEST_CATEGORIES = [
  { test: (h) => /(^|\.)np\.dl\.playstation\.net$/.test(h), category: 'psn-platform-content', hint: 'PSN platform content (NP CDN)' },
  { test: (h) => /(^|\.)np\.playstation\.net$/.test(h), category: 'psn-account', hint: 'PSN platform: sign-in, account, entitlement/licence candidate' },
  { test: (h) => /(^|\.)rnps\.dl\.playstation\.net$/.test(h), category: 'system-ui', hint: 'System UI component check' },
  { test: (h) => /update\.playstation\.net$/.test(h), category: 'system-update', hint: 'Firmware update check' },
  { test: (h) => /^ena\.net\.playstation\.net$/.test(h), category: 'connectivity-test', hint: 'Internet connection test' },
  { test: (h) => /telemetry|metrics|analytics/.test(h), category: 'telemetry', hint: 'Telemetry / analytics' },
  { test: (h, u) => isPkgUrl(u || '') || /(^|\.)(gs2|gst)\.[a-z.]*dl\.playstation\.net$/.test(h), category: 'game-download', hint: 'Game/app package download' },
  { test: (h) => /(^|\.)playstation\.(net|com)$/.test(h), category: 'playstation-other', hint: 'Other PlayStation service' }
];

function hostnameOnly(host) {
  return String(host || '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase();
}

function classifyRequest(host, url) {
  const h = hostnameOnly(host);
  if (!h) return { category: null, categoryHint: null };
  const match = REQUEST_CATEGORIES.find((c) => c.test(h, url));
  return match ? { category: match.category, categoryHint: match.hint } : { category: 'other', categoryHint: 'Not a PlayStation domain' };
}

function addRequestLog(entry) {
  const log = {
    id: id(),
    timestamp: now(),
    type: 'HTTP',
    method: null,
    url: null,
    host: null,
    clientIp: null,
    connectionId: null,
    httpVersion: null,
    requestHeaders: {},
    route: null,
    localFile: null,
    reason: null,
    status: null,
    responseHeaders: null,
    upstreamIp: null,
    bytesUp: 0,
    bytesDown: 0,
    durationMs: null,
    state: 'pending',
    error: null,
    ...entry
  };
  if (!('category' in entry)) Object.assign(log, classifyRequest(log.host, log.url));
  requestLogs.unshift(log);
  if (requestLogs.length > MAX_REQUEST_LOGS) requestLogs.length = MAX_REQUEST_LOGS;
  markRequestLogsDirty();
  return log;
}

// The PS5 request log is saved to disk so restarts (including `npm run dev` reloads) keep it.
let requestLogsDirty = false;
let requestLogsSaving = false;

function markRequestLogsDirty() {
  requestLogsDirty = true;
}

function loadRequestLogs() {
  const saved = loadJson(REQUESTS_FILE, null);
  if (!Array.isArray(saved?.requests)) return;
  requestLogs = saved.requests.slice(0, MAX_REQUEST_LOGS).map((log) => (
    log.state === 'pending' ? { ...log, state: 'interrupted', reason: log.reason || 'Helper restarted while this request was open' } : log
  ));
  console.log(`Loaded ${requestLogs.length} saved PS5 request(s)`);
}

async function saveRequestLogs() {
  // Keep saving while requests are open, since their bytes and timing keep changing.
  if (requestLogsSaving || !(requestLogsDirty || requestLogs.some((x) => x.state === 'pending'))) return;
  requestLogsSaving = true;
  requestLogsDirty = false;
  try {
    const tmp = `${REQUESTS_FILE}.tmp`;
    await fs.promises.writeFile(tmp, JSON.stringify({ savedAt: now(), requests: requestLogs }));
    await fs.promises.rename(tmp, REQUESTS_FILE);
  } catch (error) {
    requestLogsDirty = true;
    console.error(`Could not save PS5 requests: ${error.message}`);
  } finally {
    requestLogsSaving = false;
  }
}

function saveRequestLogsSync() {
  try {
    const tmp = `${REQUESTS_FILE}.sync.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ savedAt: now(), requests: requestLogs }));
    fs.renameSync(tmp, REQUESTS_FILE);
  } catch (error) {
    console.error(`Could not save PS5 requests: ${error.message}`);
  }
}

function requestLogSummary(log) {
  const { requestHeaders, responseHeaders, requestBody, responseBody, flow, tls, ...summary } = log;
  return summary;
}

// Groups consecutive same-direction tunnel chunks into bursts; each burst is roughly one TLS message/flight.
function recordFlow(log, started, dir, bytes) {
  const t = Date.now() - started;
  const last = log.flow[log.flow.length - 1];
  if (last && last.dir === dir && t - last.endMs <= FLOW_MERGE_MS) {
    last.bytes += bytes;
    last.chunks++;
    last.endMs = t;
    return;
  }
  if (log.flow.length >= MAX_FLOW_EVENTS) {
    log.flowTruncated = true;
    return;
  }
  log.flow.push({ atMs: t, endMs: t, dir, bytes, chunks: 1 });
}

function summarizeFlow(log) {
  const flow = log.flow || [];
  let roundTrips = 0;
  for (let i = 0; i < flow.length - 1; i++) {
    if (flow[i].dir === 'up' && flow[i + 1].dir === 'down') roundTrips++;
  }
  const firstDown = flow.find((x) => x.dir === 'down');
  log.roundTrips = roundTrips;
  log.firstResponseMs = firstDown ? firstDown.atMs : null;
}

// Reads SNI and ALPN from a TLS ClientHello without decrypting anything.
function parseClientHello(buf) {
  try {
    if (buf.length < 6 || buf[0] !== 0x16 || buf[5] !== 0x01) return null;
    let p = 9 + 2 + 32;
    p += 1 + buf[p];
    p += 2 + buf.readUInt16BE(p);
    p += 1 + buf[p];
    const extEnd = Math.min(buf.length, p + 2 + buf.readUInt16BE(p));
    p += 2;
    const out = { recordVersion: `0x${buf.readUInt16BE(1).toString(16)}`, sni: null, alpn: [] };
    while (p + 4 <= extEnd) {
      const type = buf.readUInt16BE(p);
      const len = buf.readUInt16BE(p + 2);
      const ext = buf.subarray(p + 4, p + 4 + len);
      p += 4 + len;
      if (type === 0 && ext.length > 5) {
        out.sni = ext.subarray(5, 5 + ext.readUInt16BE(3)).toString('ascii');
      } else if (type === 16 && ext.length > 2) {
        for (let q = 2; q < ext.length; q += 1 + ext[q]) out.alpn.push(ext.subarray(q + 1, q + 1 + ext[q]).toString('ascii'));
      }
    }
    return out;
  } catch {
    return null;
  }
}

function headerValue(headers, name) {
  if (!headers) return null;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
  return key ? headers[key] : null;
}

function decodeBody(chunks, totalBytes, headers) {
  if (!chunks.length) return null;
  let buf = Buffer.concat(chunks);
  const truncated = totalBytes > buf.length;
  const encoding = String(headerValue(headers, 'content-encoding') || '').toLowerCase();
  const opts = { finishFlush: zlib.constants.Z_SYNC_FLUSH };
  try {
    if (encoding === 'gzip') buf = zlib.gunzipSync(buf, opts);
    else if (encoding === 'deflate') buf = zlib.inflateSync(buf, opts);
    else if (encoding === 'br') buf = zlib.brotliDecompressSync(buf);
  } catch {}
  const text = buf.toString('utf8');
  const printable = !text.includes('\uFFFD') && !/[\x00-\x08\x0E-\x1F]/.test(text);
  return {
    capturedBytes: chunks.reduce((n, c) => n + c.length, 0),
    totalBytes,
    truncated,
    contentEncoding: encoding || null,
    format: printable ? 'text' : 'base64',
    data: printable ? text : buf.toString('base64')
  };
}

// Records status, headers, byte counts and timing of a proxied HTTP response.
function trackHttpExchange(req, res, log) {
  const started = Date.now();
  const captureResponse = !isPkgUrl(log.url || '');
  const requestChunks = [];
  const responseChunks = [];
  let requestCaptured = 0;
  let responseCaptured = 0;
  req.on('data', (chunk) => {
    log.bytesUp += chunk.length;
    if (requestCaptured < MAX_BODY_CAPTURE) {
      const part = chunk.subarray(0, MAX_BODY_CAPTURE - requestCaptured);
      requestChunks.push(part);
      requestCaptured += part.length;
    }
  });

  const writeHead = res.writeHead;
  res.writeHead = function (status, ...args) {
    log.status = status;
    const headers = args.find((x) => x && typeof x === 'object');
    log.responseHeaders = { ...res.getHeaders(), ...(headers || {}) };
    return writeHead.call(this, status, ...args);
  };
  const countChunk = (chunk, encoding) => {
    if (chunk == null || typeof chunk === 'function') return;
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8');
    log.bytesDown += buf.length;
    if (captureResponse && responseCaptured < MAX_BODY_CAPTURE) {
      const part = buf.subarray(0, MAX_BODY_CAPTURE - responseCaptured);
      responseChunks.push(Buffer.from(part));
      responseCaptured += part.length;
    }
  };
  const captureBodies = () => {
    log.requestBody = decodeBody(requestChunks, log.bytesUp, log.requestHeaders);
    log.responseBody = captureResponse
      ? decodeBody(responseChunks, log.bytesDown, log.responseHeaders)
      : { skipped: 'PKG payload not captured' };
  };
  const write = res.write;
  res.write = function (chunk, encoding, ...rest) {
    countChunk(chunk, encoding);
    return write.call(this, chunk, encoding, ...rest);
  };
  const end = res.end;
  res.end = function (chunk, encoding, ...rest) {
    countChunk(chunk, encoding);
    return end.call(this, chunk, encoding, ...rest);
  };

  res.on('finish', () => {
    log.state = 'complete';
    log.durationMs = Date.now() - started;
    captureBodies();
    markRequestLogsDirty();
  });
  res.on('close', () => {
    if (log.state === 'pending') {
      log.state = 'aborted';
      log.durationMs = Date.now() - started;
      captureBodies();
    }
    if (log.status == null) log.status = res.statusCode;
    markRequestLogsDirty();
  });
}

function findPkgNumberSlot(rawUrl) {
  const match = /(\d+)(?=\.pkg(?:[?#]|$))/i.exec(rawUrl);
  if (!match) return null;
  return {
    start: match.index,
    length: match[1].length,
    raw: match[1],
    value: Number(match[1])
  };
}

function replacePkgNumber(rawUrl, slot, value) {
  const next = slot.length > 1
    ? String(value).padStart(slot.length, '0')
    : String(value);
  return rawUrl.slice(0, slot.start) + next + rawUrl.slice(slot.start + slot.length);
}

function totalSizeFromHeaders(headers, statusCode) {
  const contentRange = String(headers['content-range'] || '');
  const rangeMatch = /\/(\d+)$/.exec(contentRange);
  if (rangeMatch) return Number(rangeMatch[1]);
  if (statusCode === 200 && headers['content-length']) {
    const value = Number(headers['content-length']);
    return Number.isSafeInteger(value) ? value : null;
  }
  return null;
}

function rememberRemoteMetadata(rawUrl, headers, statusCode) {
  if (!isPkgUrl(rawUrl)) return;
  const meta = {
    totalSize: totalSizeFromHeaders(headers, statusCode),
    contentType: headers['content-type'] || 'application/octet-stream',
    etag: headers.etag || null,
    lastModified: headers['last-modified'] || null,
    cacheControl: headers['cache-control'] || null,
    contentDisposition: headers['content-disposition'] || null,
    learnedAt: now()
  };
  remoteMetadata.set(rawUrl, meta);
}

// Mapping folders. `localDirectory` (first folder) is kept in settings for older versions.
function localDirectories() {
  if (Array.isArray(settings.localDirectories)) return settings.localDirectories;
  return settings.localDirectory ? [settings.localDirectory] : [];
}

function saveLocalDirectories(directories) {
  settings.localDirectories = directories;
  settings.localDirectory = directories[0] || null;
  saveSettings();
}

// Walks one folder and returns its .pkg files; throws if the folder cannot be scanned.
function findPkgFiles(directory) {
  const files = [];
  let scannedEntries = 0;

  const stat = fs.statSync(directory);
  if (!stat.isDirectory()) throw new Error('Selected path is not a directory');

  const stack = [directory];
  while (stack.length) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      scannedEntries++;
      if (scannedEntries > MAX_SCAN_ENTRIES) {
        throw new Error(`Directory scan exceeded MAX_SCAN_ENTRIES (${MAX_SCAN_ENTRIES})`);
      }
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!entry.isFile() || !/\.pkg$/i.test(entry.name)) continue;
      files.push({ name: entry.name, full });
    }
  }
  return { files, scannedEntries };
}

// Indexes every mapping folder. A folder that fails to scan is reported but does not stop the others.
function scanLocalDirectories() {
  const directories = localDirectories();
  const index = new Map();
  const seenFiles = new Set();
  const folders = [];
  let scannedEntries = 0;

  for (const directory of directories) {
    try {
      const result = findPkgFiles(directory);
      scannedEntries += result.scannedEntries;
      for (const file of result.files) {
        // Overlapping folders (e.g. a folder and its parent) must not turn one file into a "duplicate".
        let real = file.full;
        try { real = fs.realpathSync(file.full); } catch {}
        if (seenFiles.has(real)) continue;
        seenFiles.add(real);
        const existing = index.get(file.name) || [];
        existing.push(file.full);
        index.set(file.name, existing);
      }
      folders.push({ directory, pkgCount: result.files.length, scannedEntries: result.scannedEntries, error: null });
    } catch (error) {
      folders.push({ directory, pkgCount: 0, scannedEntries: 0, error: error.message });
    }
  }

  let duplicateNames = 0;
  for (const files of index.values()) {
    if (files.length > 1) duplicateNames++;
  }
  const errors = folders.filter((f) => f.error).map((f) => `${f.directory}: ${f.error}`);

  localPkgIndex = index;
  localScan = {
    directory: directories[0] || null,
    directories: folders,
    pkgCount: seenFiles.size,
    duplicateNames,
    scannedEntries,
    scannedAt: now(),
    error: errors.length ? errors.join('; ') : null
  };
  return localScan;
}

function addLocalDirectory(directory) {
  const resolved = path.resolve(String(directory));
  findPkgFiles(resolved); // validate before saving, so a bad path is never stored
  const directories = localDirectories();
  if (!directories.includes(resolved)) saveLocalDirectories([...directories, resolved]);
  return scanLocalDirectories();
}

function removeLocalDirectory(directory) {
  saveLocalDirectories(localDirectories().filter((d) => d !== directory));
  return scanLocalDirectories();
}

function clearLocalDirectory() {
  saveLocalDirectories([]);
  localPkgIndex = new Map();
  localScan = {
    directory: null,
    directories: [],
    pkgCount: 0,
    duplicateNames: 0,
    scannedEntries: 0,
    scannedAt: now(),
    error: null
  };
}

function resolveLocalPackage(rawUrl) {
  if (!localDirectories().length) return { file: null, reason: 'No local PKG directory configured' };
  const filename = pkgFilenameFromUrl(rawUrl);
  if (!filename) return { file: null, reason: 'Request is not a .pkg URL' };
  const matches = localPkgIndex.get(filename) || [];
  if (matches.length === 0) return { file: null, reason: `Local file not found: ${filename}` };
  if (matches.length > 1) return { file: null, reason: `Duplicate local filename is ambiguous: ${filename}` };
  return { file: matches[0], reason: null };
}

function parseSingleRange(header, size) {
  if (!header) return null;
  if (!header.startsWith('bytes=')) return { error: 'Unsupported Range unit' };
  const spec = header.slice(6).trim();
  if (spec.includes(',')) return { error: 'Multiple ranges are not supported locally' };
  const match = /^(\d*)-(\d*)$/.exec(spec);
  if (!match || (match[1] === '' && match[2] === '')) return { error: 'Invalid byte range' };

  let start;
  let end;
  if (match[1] === '') {
    const suffixLength = Number(match[2]);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) return { error: 'Invalid suffix range' };
    start = Math.max(0, size - suffixLength);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] === '' ? size - 1 : Number(match[2]);
  }

  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end)) return { error: 'Invalid byte range' };
  if (start < 0 || end < start || start >= size) return { error: 'Range is outside the local file' };
  end = Math.min(end, size - 1);
  return { start, end };
}

function localResponseHeaders(rawUrl, file, stat) {
  const meta = remoteMetadata.get(rawUrl) || {};
  const headers = {
    'Accept-Ranges': 'bytes',
    'Content-Type': meta.contentType || 'application/octet-stream',
    'X-PS5-Helper-Source': 'local'
  };
  if (meta.etag) headers.ETag = meta.etag;
  if (meta.lastModified) headers['Last-Modified'] = meta.lastModified;
  else headers['Last-Modified'] = stat.mtime.toUTCString();
  if (meta.cacheControl) headers['Cache-Control'] = meta.cacheControl;
  if (meta.contentDisposition) headers['Content-Disposition'] = meta.contentDisposition;
  return headers;
}

function tryServeLocalFile(req, res, rawUrl, file) {
  let stat;
  let fd;
  try {
    stat = fs.statSync(file);
    if (!stat.isFile()) return { served: false, reason: 'Mapped local path is not a regular file' };
    fs.accessSync(file, fs.constants.R_OK);
    if (stat.size <= 0) return { served: false, reason: 'Mapped local file is empty' };

    const meta = remoteMetadata.get(rawUrl);
    if (meta?.totalSize && meta.totalSize !== stat.size) {
      return {
        served: false,
        reason: `Local file size mismatch: local=${stat.size}, expected=${meta.totalSize}`
      };
    }

    const range = parseSingleRange(req.headers.range, stat.size);
    if (range?.error) return { served: false, reason: range.error };

    // Open before sending headers. If this fails, we can safely fall back to the CDN.
    fd = fs.openSync(file, 'r');
    const common = localResponseHeaders(rawUrl, file, stat);

    if (range) {
      const length = range.end - range.start + 1;
      res.writeHead(206, {
        ...common,
        'Content-Range': `bytes ${range.start}-${range.end}/${stat.size}`,
        'Content-Length': String(length)
      });
      if (req.method === 'HEAD') {
        fs.closeSync(fd);
        return { served: true, status: 206, bytes: 0, range };
      }
      const stream = fs.createReadStream(file, { fd, autoClose: true, start: range.start, end: range.end });
      stream.on('error', (error) => {
        console.error(`[LOCAL STREAM ERROR] ${file}: ${error.message}`);
        if (!res.destroyed) res.destroy(error);
      });
      stream.pipe(res);
      return { served: true, status: 206, bytes: length, range };
    }

    res.writeHead(200, {
      ...common,
      'Content-Length': String(stat.size)
    });
    if (req.method === 'HEAD') {
      fs.closeSync(fd);
      return { served: true, status: 200, bytes: 0, range: null };
    }
    const stream = fs.createReadStream(file, { fd, autoClose: true });
    stream.on('error', (error) => {
      console.error(`[LOCAL STREAM ERROR] ${file}: ${error.message}`);
      if (!res.destroyed) res.destroy(error);
    });
    stream.pipe(res);
    return { served: true, status: 200, bytes: stat.size, range: null };
  } catch (error) {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
    return { served: false, reason: error.message };
  }
}

function stripProxyHeaders(headers) {
  const out = { ...headers };
  delete out['proxy-connection'];
  delete out['proxy-authorization'];
  delete out.connection;
  return out;
}

function forwardHttp(req, res, rawUrl, semanticLog = null) {
  let target;
  try {
    target = new URL(rawUrl);
  } catch {
    if (semanticLog) {
      semanticLog.status = 400;
      semanticLog.reason = semanticLog.reason || 'Invalid proxy URL';
    }
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Invalid proxy URL');
    return;
  }

  if (!['http:', 'https:'].includes(target.protocol)) {
    if (semanticLog) semanticLog.status = 400;
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Unsupported protocol');
    return;
  }

  if (!internetAllowed) {
    if (req.requestLog) Object.assign(req.requestLog, { route: 'BLOCKED', reason: 'Internet access blocked from dashboard' });
    if (semanticLog) {
      semanticLog.status = 403;
      semanticLog.upstreamError = 'Internet access blocked from dashboard';
    }
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Internet access is blocked by the PS5 download helper');
    return;
  }

  const transport = target.protocol === 'https:' ? https : http;
  const headers = stripProxyHeaders(req.headers);
  headers.host = target.host;

  const upstream = transport.request({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || (target.protocol === 'https:' ? 443 : 80),
    method: req.method,
    path: `${target.pathname}${target.search}`,
    headers,
    timeout: 120_000
  }, (upstreamRes) => {
    rememberRemoteMetadata(rawUrl, upstreamRes.headers, upstreamRes.statusCode);
    if (req.requestLog) req.requestLog.upstreamIp = upstreamRes.socket?.remoteAddress || null;
    if (semanticLog) {
      semanticLog.status = upstreamRes.statusCode || null;
      semanticLog.totalSize = totalSizeFromHeaders(upstreamRes.headers, upstreamRes.statusCode);
      semanticLog.contentLength = upstreamRes.headers['content-length'] ? Number(upstreamRes.headers['content-length']) : null;
    }

    const responseHeaders = { ...upstreamRes.headers };
    delete responseHeaders['proxy-authenticate'];
    res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
    upstreamRes.pipe(res);
  });

  trackUpstream(upstream, res);
  upstream.on('timeout', () => upstream.destroy(new Error('Upstream timeout')));
  upstream.on('error', (error) => {
    if (req.requestLog) req.requestLog.error = error.message;
    if (semanticLog) {
      semanticLog.status = 502;
      semanticLog.upstreamError = error.message;
    }
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`Proxy upstream error: ${error.message}`);
    } else {
      res.destroy(error);
    }
  });

  req.on('aborted', () => upstream.destroy());
  req.pipe(upstream);
}

// True when a URL points back at this proxy, e.g. a local app polling localhost:8080 directly.
// Forwarding such a request would loop through the proxy until connections run out.
function targetsProxyItself(rawUrl) {
  let target;
  try { target = new URL(rawUrl); } catch { return false; }
  const port = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
  if (port !== PROXY_PORT) return false;
  const hostname = target.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const own = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0', os.hostname().toLowerCase()]);
  for (const x of lanAddresses()) own.add(x.address);
  return own.has(hostname) || hostname.endsWith('.localhost');
}

function handleProxyHttp(req, res) {
  const rawUrl = requestUrl(req);
  if (rawUrl && targetsProxyItself(rawUrl)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('This is the PS5 download helper proxy. Configure it as an HTTP proxy instead of requesting it directly.');
    return;
  }
  let host = req.headers.host || null;
  try { if (rawUrl) host = new URL(rawUrl).host; } catch {}
  const reqLog = addRequestLog({
    type: 'HTTP',
    method: req.method,
    url: rawUrl || req.url,
    host,
    clientIp: clientIp(req.socket),
    connectionId: req.socket.proxyConnectionId ?? null,
    httpVersion: req.httpVersion,
    requestHeaders: { ...req.headers },
    route: 'PASSTHROUGH'
  });
  req.requestLog = reqLog;
  trackHttpExchange(req, res, reqLog);

  if (!rawUrl) {
    reqLog.reason = 'Missing Host header';
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Missing Host header');
    return;
  }

  const filename = pkgFilenameFromUrl(rawUrl);
  if (!filename) {
    forwardHttp(req, res, rawUrl, null);
    return;
  }

  if (DEBUG_PKG_HEADERS) {
    console.log(`\n[PKG REQUEST HEADERS] ${req.method} ${redactUrl(rawUrl)}`);
    console.log(JSON.stringify(safeHeaders(req.headers), null, 2));
    console.log('[END PKG REQUEST HEADERS]\n');
  }

  const base = {
    method: req.method,
    url: rawUrl,
    displayUrl: redactUrl(rawUrl),
    filename,
    range: req.headers.range || null,
    clientIp: clientIp(req.socket)
  };

  if ((req.method === 'GET' || req.method === 'HEAD') && localDirectories().length) {
    const local = resolveLocalPackage(rawUrl);
    if (local.file) {
      const result = tryServeLocalFile(req, res, rawUrl, local.file);
      if (result.served) {
        Object.assign(reqLog, { route: 'LOCAL', localFile: local.file });
        const log = addPkgLog({
          ...base,
          action: 'LOCAL',
          status: result.status,
          localFile: local.file,
          bytes: result.bytes
        });
        console.log(`[LOCAL] ${req.method} ${redactUrl(rawUrl)} -> ${local.file}${base.range ? ` (${base.range})` : ''}`);
        return;
      }

      Object.assign(reqLog, { route: 'FALLBACK', localFile: local.file, reason: result.reason });
      const fallback = addPkgLog({
        ...base,
        action: 'FALLBACK',
        localFile: local.file,
        reason: result.reason
      });
      console.warn(`[FALLBACK] ${req.method} ${redactUrl(rawUrl)} -> CDN (${result.reason})`);
      forwardHttp(req, res, rawUrl, fallback);
      return;
    }

    Object.assign(reqLog, { route: 'FALLBACK', reason: local.reason });
    const fallback = addPkgLog({
      ...base,
      action: 'FALLBACK',
      reason: local.reason
    });
    console.warn(`[FALLBACK] ${req.method} ${redactUrl(rawUrl)} -> CDN (${local.reason})`);
    forwardHttp(req, res, rawUrl, fallback);
    return;
  }

  reqLog.route = 'REMOTE';
  const remote = addPkgLog({ ...base, action: 'REMOTE' });
  console.log(`[REMOTE] ${req.method} ${redactUrl(rawUrl)}`);
  forwardHttp(req, res, rawUrl, remote);
}

function parseConnectTarget(value) {
  if (!value) return null;
  const ipv6 = /^\[([^\]]+)\]:(\d+)$/.exec(value);
  if (ipv6) return { host: ipv6[1], port: Number(ipv6[2]) };
  const idx = value.lastIndexOf(':');
  if (idx <= 0) return { host: value, port: 443 };
  const host = value.slice(0, idx);
  const port = Number(value.slice(idx + 1));
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

const proxyServer = http.createServer(handleProxyHttp);
proxyServer.on('connection', (socket) => {
  socket.proxyConnectionId = ++proxyConnectionCounter;
  proxySockets.add(socket);
  socket.on('close', () => proxySockets.delete(socket));
});
proxyServer.on('connect', (req, clientSocket, head) => {
  const started = Date.now();
  const target = parseConnectTarget(req.url);
  const reqLog = addRequestLog({
    type: 'CONNECT',
    method: req.method,
    url: req.url,
    host: target ? `${target.host}:${target.port}` : req.url,
    clientIp: clientIp(req.socket),
    connectionId: req.socket.proxyConnectionId ?? null,
    httpVersion: req.httpVersion,
    requestHeaders: { ...req.headers },
    route: 'TUNNEL',
    bytesUp: head?.length || 0,
    tls: null,
    flow: []
  });
  let sawFirstClientBytes = false;
  const inspectClientBytes = (chunk) => {
    if (sawFirstClientBytes) return;
    sawFirstClientBytes = true;
    reqLog.tls = parseClientHello(chunk);
    if (reqLog.tls?.sni) reqLog.sni = reqLog.tls.sni;
  };
  if (head?.length) {
    inspectClientBytes(head);
    recordFlow(reqLog, started, 'up', head.length);
  }
  const finishTunnel = () => {
    if (reqLog.state !== 'pending') return;
    reqLog.state = reqLog.error ? 'error' : 'complete';
    reqLog.durationMs = Date.now() - started;
    summarizeFlow(reqLog);
    markRequestLogsDirty();
  };
  clientSocket.on('close', finishTunnel);

  if (!target) {
    Object.assign(reqLog, { status: 400, reason: 'Invalid CONNECT target' });
    clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    return;
  }

  if (!internetAllowed) {
    Object.assign(reqLog, { status: 403, route: 'BLOCKED', reason: 'Internet access blocked from dashboard' });
    finishTunnel();
    // The PS5 may never close its side after a refusal, so close the socket once the 403 is flushed.
    clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n', () => clientSocket.destroy());
    return;
  }

  console.log(`[TLS] CONNECT ${target.host}:${target.port}`);
  const upstreamSocket = net.connect(target.port, target.host, () => {
    reqLog.status = 200;
    clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: ps5-download-proxy\r\n\r\n');
    reqLog.upstreamIp = upstreamSocket.remoteAddress || null;
    clientSocket.on('data', (chunk) => {
      reqLog.bytesUp += chunk.length;
      inspectClientBytes(chunk);
      recordFlow(reqLog, started, 'up', chunk.length);
    });
    upstreamSocket.on('data', (chunk) => {
      reqLog.bytesDown += chunk.length;
      recordFlow(reqLog, started, 'down', chunk.length);
    });
    if (head?.length) upstreamSocket.write(head);
    upstreamSocket.pipe(clientSocket);
    clientSocket.pipe(upstreamSocket);
  });

  trackUpstream(upstreamSocket, clientSocket);
  upstreamSocket.setTimeout(120_000);
  upstreamSocket.on('timeout', () => upstreamSocket.destroy());
  upstreamSocket.on('error', (error) => {
    reqLog.error = error.message;
    if (reqLog.status == null) {
      reqLog.status = 502;
      finishTunnel(); // never connected, so the PS5 may keep its side open; record the failure now
    }
    if (!clientSocket.destroyed) clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
  });
  clientSocket.on('error', () => upstreamSocket.destroy());
});

function startProxy() {
  return new Promise((resolve, reject) => {
    if (proxyRunning || proxyServer.listening) {
      proxyRunning = true;
      return resolve({ running: true });
    }
    proxyLastError = null;
    const onError = (error) => {
      proxyServer.off('listening', onListening);
      proxyLastError = error.message;
      proxyRunning = false;
      reject(error);
    };
    const onListening = () => {
      proxyServer.off('error', onError);
      proxyRunning = true;
      console.log(`PS5 proxy listening on http://${PROXY_HOST}:${PROXY_PORT}`);
      resolve({ running: true });
    };
    proxyServer.once('error', onError);
    proxyServer.once('listening', onListening);
    proxyServer.listen(PROXY_PORT, PROXY_HOST);
  });
}

function stopProxy() {
  return new Promise((resolve) => {
    if (!proxyServer.listening) {
      proxyRunning = false;
      return resolve({ running: false });
    }
    proxyRunning = false;
    proxyServer.close(() => resolve({ running: false }));
    for (const socket of proxySockets) socket.destroy();
  });
}

async function probePkgUrl(rawUrl) {
  const response = await fetch(rawUrl, {
    method: 'GET',
    headers: {
      Range: 'bytes=0-0',
      'Accept-Encoding': 'identity',
      Accept: '*/*'
    },
    redirect: 'follow',
    signal: AbortSignal.timeout(PKG_PROBE_TIMEOUT_MS)
  });
  const result = {
    status: response.status,
    ok: response.ok,
    contentLength: Number(response.headers.get('content-length') || 0) || null,
    contentRange: response.headers.get('content-range') || null,
    contentType: response.headers.get('content-type') || 'application/octet-stream',
    etag: response.headers.get('etag') || null,
    lastModified: response.headers.get('last-modified') || null,
    cacheControl: response.headers.get('cache-control') || null,
    contentDisposition: response.headers.get('content-disposition') || null
  };
  try { await response.body?.cancel(); } catch {}
  return result;
}

function createPkgDiscoveryJob(rawUrl) {
  const slot = findPkgNumberSlot(rawUrl);
  if (!slot || !Number.isSafeInteger(slot.value)) {
    throw new Error('Could not find the final numeric index immediately before .pkg');
  }
  const job = {
    id: id(),
    capturedUrl: rawUrl,
    displayUrl: redactUrl(rawUrl),
    startIndex: slot.value,
    currentIndex: slot.value,
    links: [],
    status: 'running',
    createdAt: now(),
    finishedAt: null,
    stopReason: null,
    stopStatus: null,
    error: null
  };
  pkgDiscoveryJobs.set(job.id, job);
  void runPkgDiscovery(job, slot);
  return job;
}

async function runPkgDiscovery(job, slot) {
  try {
    for (let offset = 0; offset < MAX_PACKAGE_LINKS; offset++) {
      const index = slot.value + offset;
      job.currentIndex = index;
      const candidate = offset === 0 ? job.capturedUrl : replacePkgNumber(job.capturedUrl, slot, index);
      let probe;
      try {
        probe = await probePkgUrl(candidate);
      } catch (error) {
        job.status = 'complete';
        job.stopReason = `Stopped on request error at index ${index}: ${error.message}`;
        job.error = error.message;
        job.finishedAt = now();
        return;
      }

      if (!probe.ok) {
        job.status = 'complete';
        job.stopStatus = probe.status;
        job.stopReason = `Stopped at index ${index}: HTTP ${probe.status}`;
        job.finishedAt = now();
        return;
      }

      const totalMatch = /\/(\d+)$/.exec(probe.contentRange || '');
      const totalSize = totalMatch
        ? Number(totalMatch[1])
        : (probe.status === 200 ? probe.contentLength : null);
      remoteMetadata.set(candidate, {
        totalSize: Number.isSafeInteger(totalSize) ? totalSize : null,
        contentType: probe.contentType,
        etag: probe.etag,
        lastModified: probe.lastModified,
        cacheControl: probe.cacheControl,
        contentDisposition: probe.contentDisposition,
        learnedAt: now()
      });

      job.links.push({
        index,
        url: candidate,
        displayUrl: redactUrl(candidate),
        status: probe.status,
        contentLength: probe.contentLength,
        contentRange: probe.contentRange,
        totalSize: Number.isSafeInteger(totalSize) ? totalSize : null
      });
    }
    job.status = 'complete';
    job.stopReason = `Reached safety limit MAX_PACKAGE_LINKS=${MAX_PACKAGE_LINKS}`;
    job.finishedAt = now();
  } catch (error) {
    job.status = 'error';
    job.error = error.message;
    job.stopReason = error.message;
    job.finishedAt = now();
  }
}

async function chooseDirectoryNative() {
  if (process.platform === 'darwin') {
    const { stdout } = await execFileAsync('osascript', [
      '-e',
      'POSIX path of (choose folder with prompt "Choose the folder containing downloaded PS5 PKG files")'
    ]);
    return stdout.trim().replace(/\/$/, '') || null;
  }

  if (process.platform === 'win32') {
    const script = [
      'Add-Type -AssemblyName System.Windows.Forms;',
      '$d = New-Object System.Windows.Forms.FolderBrowserDialog;',
      '$d.Description = "Choose the folder containing downloaded PS5 PKG files";',
      'if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.SelectedPath }'
    ].join(' ');
    const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-Command', script]);
    return stdout.trim() || null;
  }

  try {
    const { stdout } = await execFileAsync('zenity', ['--file-selection', '--directory', '--title=Choose PS5 PKG folder']);
    return stdout.trim() || null;
  } catch {
    const { stdout } = await execFileAsync('kdialog', ['--getexistingdirectory', process.cwd()]);
    return stdout.trim() || null;
  }
}

function fmtSize(n) {
  if (n == null) return '';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)}${units[i]}`;
}

function buildRequestExport() {
  const rows = [...requestLogs].reverse();
  const t0 = rows.length ? Date.parse(rows[0].timestamp) : null;
  const requests = rows.map((r, i) => ({ seq: i + 1, offsetMs: Date.parse(r.timestamp) - t0, ...r }));

  const hosts = new Map();
  const categories = {};
  const clients = {};
  for (const r of requests) {
    if (r.type === 'MARKER') continue;
    categories[r.category] = (categories[r.category] || 0) + 1;
    const client = clients[r.clientIp] ||= { requests: 0, userAgents: [] };
    client.requests++;
    const ua = headerValue(r.requestHeaders, 'user-agent');
    if (ua && !client.userAgents.includes(ua)) client.userAgents.push(ua);

    const key = hostnameOnly(r.host);
    const h = hosts.get(key) || {
      host: key, category: r.category, categoryHint: r.categoryHint, sni: new Set(), alpn: new Set(),
      upstreamIps: new Set(), requests: 0, tunnels: 0, httpRequests: 0, errors: 0,
      bytesUp: 0, bytesDown: 0, firstSeen: r.timestamp, lastSeen: r.timestamp, offsetsSec: []
    };
    h.requests++;
    if (r.type === 'CONNECT') h.tunnels++; else h.httpRequests++;
    if (r.error) h.errors++;
    h.bytesUp += r.bytesUp || 0;
    h.bytesDown += r.bytesDown || 0;
    h.lastSeen = r.timestamp;
    h.offsetsSec.push(Number((r.offsetMs / 1000).toFixed(3)));
    if (r.sni) h.sni.add(r.sni);
    for (const a of r.tls?.alpn || []) h.alpn.add(a);
    if (r.upstreamIp) h.upstreamIps.add(r.upstreamIp);
    hosts.set(key, h);
  }
  const hostSummary = [...hosts.values()].map((h) => ({
    ...h,
    sni: [...h.sni],
    alpn: [...h.alpn],
    upstreamIps: [...h.upstreamIps],
    gapsSec: h.offsetsSec.slice(1).map((x, i) => Number((x - h.offsetsSec[i]).toFixed(3)))
  })).sort((a, b) => b.requests - a.requests);

  const timeline = requests.map((r) => {
    const t = `+${(r.offsetMs / 1000).toFixed(3)}s`.padEnd(11);
    if (r.type === 'MARKER') return `${t} ===== MARKER: ${r.reason} =====`;
    const target = r.type === 'HTTP' ? `${r.method} ${r.url}` : `CONNECT ${r.host}`;
    const extra = [
      `status=${r.status ?? '-'}`,
      `up=${fmtSize(r.bytesUp)}`,
      `down=${fmtSize(r.bytesDown)}`,
      r.durationMs != null ? `dur=${r.durationMs}ms` : `state=${r.state}`,
      r.roundTrips != null ? `roundTrips=${r.roundTrips}` : null,
      r.error ? `error=${r.error}` : null
    ].filter(Boolean).join(' ');
    return `${t} #${r.seq} [${r.category}] ${target} ${extra}`;
  });

  return {
    formatVersion: 2,
    exportedAt: now(),
    captureStart: rows[0]?.timestamp || null,
    captureEnd: rows.at(-1)?.timestamp || null,
    count: requests.length,
    fieldGuide: {
      offsetMs: 'Milliseconds since the first request in this export',
      bytesUp: 'Bytes sent from the PS5 towards the server',
      bytesDown: 'Bytes sent from the server to the PS5',
      category: 'Heuristic guess from hostname/URL only; not proof of what the request does',
      connectionId: 'PS5-to-proxy TCP connection; HTTP requests with the same id reused one connection',
      sni: 'Server name the PS5 put in its TLS ClientHello (HTTPS tunnels only)',
      'tls.alpn': 'Protocols the PS5 offered (h2 = HTTP/2: many requests may share one tunnel)',
      flow: 'HTTPS tunnels: bursts of encrypted traffic. dir up = PS5->server, down = server->PS5. atMs/endMs are relative to tunnel start. The first 2-3 bursts are the TLS handshake; each later up->down pair is roughly one request/response',
      roundTrips: 'Number of up->down turns in the tunnel, including the TLS handshake',
      firstResponseMs: 'Time until the server first sent data back',
      requestBody: 'Plain-HTTP request body (first MAX_BODY_CAPTURE bytes, decompressed when possible)',
      responseBody: 'Plain-HTTP response body (first MAX_BODY_CAPTURE bytes, decompressed when possible); PKG payloads are skipped',
      MARKER: 'Rows of type MARKER are notes added from the dashboard to mark what you were doing on the PS5'
    },
    limitations: 'HTTPS tunnel contents are encrypted end-to-end between the PS5 and Sony. Only hostnames, timing and sizes are visible for them.',
    clients,
    categories,
    hosts: hostSummary,
    timeline,
    requests
  };
}

function json(res, status, value) {
  const body = JSON.stringify(value, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

async function readJson(req, maxBytes = 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) throw new Error('Request body too large');
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks).toString('utf8');
  return body ? JSON.parse(body) : {};
}

function routePath(req) {
  return new URL(req.url, `http://${req.headers.host || 'localhost'}`);
}

function localFilesForApi(limit = 1000) {
  const rows = [];
  for (const [filename, files] of localPkgIndex.entries()) {
    for (const file of files) {
      let size = null;
      try { size = fs.statSync(file).size; } catch {}
      rows.push({ filename, file, size, duplicate: files.length > 1 });
      if (rows.length >= limit) return rows;
    }
  }
  return rows;
}

const dashboardServer = http.createServer(async (req, res) => {
  try {
    const u = routePath(req);

    if (req.method === 'GET' && u.pathname === '/') {
      const body = dashboardHtml();
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
        'Cache-Control': 'no-store'
      });
      return res.end(body);
    }

    if (req.method === 'GET' && u.pathname === '/api/status') {
      const ips = lanAddresses();
      return json(res, 200, {
        proxy: {
          running: proxyRunning,
          host: PROXY_HOST,
          port: PROXY_PORT,
          lastError: proxyLastError,
          recommended: ips.map((x) => `${x.address}:${PROXY_PORT}`)
        },
        dashboard: { host: DASHBOARD_HOST, port: DASHBOARD_PORT },
        lanAddresses: ips,
        local: localScan,
        node: process.version
      });
    }

    if (req.method === 'POST' && u.pathname === '/api/proxy/start') {
      try {
        return json(res, 200, await startProxy());
      } catch (error) {
        return json(res, 500, { error: error.message });
      }
    }

    if (req.method === 'GET' && u.pathname === '/api/internet') {
      return json(res, 200, { allowed: internetAllowed, proxyRunning });
    }

    if (req.method === 'POST' && u.pathname === '/api/internet') {
      const body = await readJson(req);
      if (typeof body.allowed !== 'boolean') return json(res, 400, { error: 'allowed must be true or false' });
      if (!proxyRunning) return json(res, 409, { error: 'Start the proxy before changing internet access' });
      return json(res, 200, { ...setInternetAllowed(body.allowed), proxyRunning });
    }

    if (req.method === 'POST' && u.pathname === '/api/proxy/stop') {
      return json(res, 200, await stopProxy());
    }

    if (req.method === 'GET' && u.pathname === '/api/pkg-logs') {
      const limit = Math.min(Number(u.searchParams.get('limit') || 500), MAX_LOGS);
      return json(res, 200, pkgLogs.slice(0, limit));
    }

    if (req.method === 'DELETE' && u.pathname === '/api/pkg-logs') {
      pkgLogs = [];
      return json(res, 200, { ok: true });
    }

    if (req.method === 'GET' && u.pathname === '/api/requests') {
      const limit = Math.min(Number(u.searchParams.get('limit') || 500), MAX_REQUEST_LOGS);
      return json(res, 200, { total: requestLogs.length, rows: requestLogs.slice(0, limit).map(requestLogSummary) });
    }

    if (req.method === 'POST' && u.pathname === '/api/requests/marker') {
      const body = await readJson(req);
      const note = String(body.note || '').trim().slice(0, 500);
      if (!note) return json(res, 400, { error: 'note is required' });
      const marker = addRequestLog({
        type: 'MARKER', method: null, host: null, url: null, route: 'MARKER', reason: note,
        state: 'complete', requestHeaders: null, category: 'marker', categoryHint: null
      });
      return json(res, 201, marker);
    }

    if (req.method === 'GET' && u.pathname === '/api/requests/export') {
      const body = JSON.stringify(buildRequestExport(), null, 2);
      const stamp = now().replace(/[:.]/g, '-');
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
        'Content-Disposition': `attachment; filename="ps5-requests-${stamp}.json"`,
        'Cache-Control': 'no-store'
      });
      return res.end(body);
    }

    if (req.method === 'GET' && u.pathname.startsWith('/api/requests/')) {
      const log = requestLogs.find((x) => x.id === u.pathname.slice('/api/requests/'.length));
      if (!log) return json(res, 404, { error: 'Request not found' });
      return json(res, 200, log);
    }

    if (req.method === 'DELETE' && u.pathname === '/api/requests') {
      requestLogs = [];
      saveRequestLogsSync();
      markRequestLogsDirty(); // rewrite again in case an older background save lands after this one
      return json(res, 200, { ok: true });
    }

    if (req.method === 'POST' && u.pathname === '/api/pkg-discovery') {
      const body = await readJson(req);
      if (!body.url || !isPkgUrl(String(body.url))) {
        return json(res, 400, { error: 'A .pkg URL is required' });
      }
      const job = createPkgDiscoveryJob(String(body.url));
      return json(res, 202, job);
    }

    if (req.method === 'GET' && u.pathname === '/api/pkg-discovery') {
      const jobs = [...pkgDiscoveryJobs.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return json(res, 200, jobs);
    }

    if (req.method === 'GET' && u.pathname === '/api/local-directory') {
      return json(res, 200, { ...localScan, directory: localDirectories()[0] || null });
    }

    if (req.method === 'POST' && u.pathname === '/api/local-directory') {
      const body = await readJson(req);
      if (!body.directory) return json(res, 400, { error: 'directory is required' });
      try {
        return json(res, 200, addLocalDirectory(body.directory));
      } catch (error) {
        return json(res, 400, { error: error.message });
      }
    }

    if (req.method === 'POST' && u.pathname === '/api/local-directory/select') {
      try {
        const selected = await chooseDirectoryNative();
        if (!selected) return json(res, 400, { error: 'No directory selected' });
        const scan = addLocalDirectory(selected);
        return json(res, 200, scan);
      } catch (error) {
        return json(res, 400, { error: `Directory chooser failed or was cancelled: ${error.message}` });
      }
    }

    if (req.method === 'POST' && u.pathname === '/api/local-directory/rescan') {
      if (!localDirectories().length) return json(res, 400, { error: 'No local directory configured' });
      return json(res, 200, scanLocalDirectories());
    }

    if (req.method === 'DELETE' && u.pathname === '/api/local-directory') {
      const directory = u.searchParams.get('directory');
      if (directory) return json(res, 200, removeLocalDirectory(directory));
      clearLocalDirectory();
      return json(res, 200, { ok: true });
    }

    if (req.method === 'GET' && u.pathname === '/api/local-files') {
      const limit = Math.min(Number(u.searchParams.get('limit') || 1000), 5000);
      return json(res, 200, localFilesForApi(limit));
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  } catch (error) {
    console.error('Dashboard error:', error);
    if (!res.headersSent) json(res, 500, { error: error.message });
    else res.destroy(error);
  }
});

function dashboardHtml() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>PS5 Download Proxy</title>
<style>
  :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0d1117; color: #e6edf3; }
  main { max-width: 1400px; margin: 0 auto; padding: 28px; }
  h1 { margin: 0 0 6px; font-size: 28px; }
  h2 { margin: 0 0 12px; font-size: 18px; }
  p { color: #9da7b3; }
  code { color: #79c0ff; overflow-wrap: anywhere; }
  button, input { font: inherit; }
  button { background:#21262d; color:#e6edf3; border:1px solid #30363d; border-radius:8px; padding:9px 12px; cursor:pointer; }
  button:hover { border-color:#8b949e; }
  button.primary { background:#238636; border-color:#2ea043; }
  button.danger { background:#6e1a1a; border-color:#a33; }
  button:disabled { opacity:.45; cursor:not-allowed; }
  .switch-row { display:flex; align-items:center; gap:12px; margin-top:16px; padding-top:14px; border-top:1px solid #30363d; }
  .switch { position:relative; width:52px; height:28px; flex:none; }
  .switch input { opacity:0; width:0; height:0; position:absolute; }
  .switch .slider { position:absolute; inset:0; background:#6e1a1a; border:1px solid #a33; border-radius:999px; cursor:pointer; transition:background .15s; }
  .switch .slider::before { content:""; position:absolute; width:20px; height:20px; left:3px; top:3px; background:#e6edf3; border-radius:50%; transition:transform .15s; }
  .switch input:checked + .slider { background:#238636; border-color:#2ea043; }
  .switch input:checked + .slider::before { transform:translateX(24px); }
  .switch input:disabled + .slider { opacity:.45; cursor:not-allowed; }
  .switch input:focus-visible + .slider { outline:2px solid #388bfd; outline-offset:2px; }
  input { width:100%; background:#0d1117; color:#e6edf3; border:1px solid #30363d; border-radius:8px; padding:10px; }
  .tabs { display:flex; gap:8px; margin:24px 0 0; flex-wrap:wrap; }
  .tab.active { background:#1f6feb; border-color:#388bfd; }
  .panel { display:none; }
  .panel.active { display:block; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:12px; padding:18px; margin:18px 0; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:18px; }
  .row { display:flex; gap:9px; align-items:center; flex-wrap:wrap; }
  .grow { flex:1; min-width:260px; }
  .big-config { font-size:25px; font-weight:750; padding:16px; background:#0d1117; border:1px solid #30363d; border-radius:10px; margin:12px 0; }
  .pill { display:inline-block; border:1px solid #30363d; border-radius:999px; padding:3px 9px; }
  .ok { color:#7ee787; }
  .warn { color:#d29922; }
  .bad { color:#ff7b72; }
  .muted { color:#8b949e; }
  .scroll { overflow:auto; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; border-bottom:1px solid #30363d; padding:9px; vertical-align:top; }
  th { position:sticky; top:0; background:#161b22; z-index:1; }
  .urlcell { min-width:220px; max-width:720px; }
  .pathcell { min-width:220px; max-width:600px; }
  .notice { border-left:3px solid #d29922; padding:8px 12px; background:#1b1a14; color:#c9d1d9; }
  .links-list { max-height:520px; overflow:auto; }
  .link-item { display:flex; gap:8px; align-items:flex-start; border-bottom:1px solid #30363d; padding:10px 0; }
  .link-item code { flex:1; }
  .req-row { cursor:pointer; }
  .req-row:hover td { background:#1c2128; }
  .req-row.selected td { background:#1f2a3a; }
  .marker-row td { background:#2a2212; color:#e3b341; font-weight:600; }
  pre.detail { background:#0d1117; border:1px solid #30363d; border-radius:10px; padding:12px; overflow:auto; max-height:520px; font-size:12px; white-space:pre-wrap; overflow-wrap:anywhere; }
  .top { display:flex; justify-content:space-between; align-items:flex-start; gap:18px; flex-wrap:wrap; }
  .top > div:first-child { flex:1 1 380px; }
  .lead { margin:0; font-size:16px; max-width:720px; }
  .top-status { border:1px solid #30363d; border-radius:12px; padding:10px 14px; background:#161b22; font-weight:600; white-space:nowrap; }
  .tab { display:inline-flex; align-items:center; gap:8px; }
  .tab .num { display:inline-grid; place-items:center; width:22px; height:22px; border-radius:50%; background:#30363d; font-size:12px; font-weight:700; }
  .tab.active .num { background:#e6edf3; color:#1f6feb; }
  .tab-advanced { margin-left:auto; color:#8b949e; }
  .tab-advanced.active { color:#fff; }
  .badge { background:#238636; color:#fff; border-radius:999px; padding:1px 8px; font-size:12px; font-weight:700; }
  .addr { display:grid; grid-template-columns:auto 1fr; gap:6px 16px; align-items:center; }
  .addr .label { color:#8b949e; font-size:14px; font-weight:500; }
  .addr .value { font-size:26px; font-weight:750; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; color:#79c0ff; }
  .howto { margin-top:12px; }
  .howto summary { cursor:pointer; color:#58a6ff; font-weight:600; }
  .howto li, .steps li { margin:6px 0; line-height:1.45; }
  .small { font-size:13px; }
  a { color:#58a6ff; }
  .legend { display:flex; gap:18px; flex-wrap:wrap; font-size:13px; color:#9da7b3; margin-bottom:10px; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:6px; vertical-align:middle; }
  .dot-remote { background:#8b949e; } .dot-local { background:#7ee787; } .dot-fallback { background:#d29922; }
  .empty { text-align:center; padding:28px 12px; color:#8b949e; }
  .next { margin-top:14px; padding:10px 12px; border-left:3px solid #2ea043; background:#12261a; }
  .big-state { font-size:15px; margin-bottom:10px; }
  td button { white-space:nowrap; }
  #logRows td:first-child { white-space:nowrap; }
</style>
</head>
<body>
<main>
  <header class="top">
    <div>
      <h1>PS5 Download Proxy</h1>
      <p class="lead">Download PS5 games faster on your computer, then let your PS5 install them from there instead of the internet.</p>
    </div>
    <div id="topStatus" class="top-status">Loading…</div>
  </header>

  <nav class="tabs" aria-label="Steps">
    <button class="tab active" data-tab="overview"><span class="num">1</span> Connect PS5</button>
    <button class="tab" data-tab="logger"><span class="num">2</span> Find Game <span id="loggerBadge" class="badge" hidden></span></button>
    <button class="tab" data-tab="links"><span class="num">3</span> Get Download Links <span id="linksBadge" class="badge" hidden></span></button>
    <button class="tab" data-tab="local"><span class="num">4</span> Use My Files <span id="localBadge" class="badge" hidden></span></button>
    <button class="tab tab-advanced" data-tab="requests">Advanced: Network Log</button>
  </nav>

  <section id="panel-overview" class="panel active">
    <div class="grid">
      <div class="card">
        <h2>Step 1 · Point your PS5 at this computer</h2>
        <div id="proxyState">Loading…</div>
        <div id="proxyConfig"></div>
        <details class="howto" open>
          <summary>Where do I type this on the PS5?</summary>
          <ol>
            <li>On the PS5, open <strong>Settings → Network → Settings → Set Up Internet Connection</strong>.</li>
            <li>Highlight your Wi-Fi or cable network, press the <strong>Options</strong> button, and choose <strong>Advanced Settings</strong>.</li>
            <li>Set <strong>Proxy Server</strong> to <strong>Use</strong>, then enter the <strong>Address</strong> and <strong>Port</strong> shown above.</li>
            <li>Choose <strong>OK</strong>. The PS5 and this computer must be on the same home network.</li>
          </ol>
          <p class="muted small">When you are finished, set Proxy Server back to <strong>Do Not Use</strong>, or the PS5 will lose internet when this app is closed.</p>
        </details>
        <div class="row" style="margin-top:14px">
          <button id="startProxy" class="primary" onclick="proxyAction('start')">Turn On</button>
          <button id="stopProxy" class="danger" onclick="proxyAction('stop')">Turn Off</button>
        </div>
        <div id="proxyMessage" class="muted" style="margin-top:9px"></div>
        <div class="switch-row">
          <label class="switch">
            <input type="checkbox" id="internetToggle" checked disabled onchange="setInternetAccess(this.checked)" aria-label="Let the PS5 use the internet" />
            <span class="slider"></span>
          </label>
          <div>
            <div><strong>Let the PS5 use the internet:</strong> <span id="internetState" class="ok">Yes</span></div>
            <div id="internetHint" class="muted">Turn the proxy on to change this.</div>
          </div>
        </div>
      </div>
      <div class="card">
        <h2>How it works</h2>
        <ol class="steps">
          <li><strong>Connect.</strong> Set up the PS5 with the address on the left (Step 1).</li>
          <li><strong>Start the download on the PS5</strong> like you normally would. It appears in <a href="#" data-goto="logger">Find Game</a>.</li>
          <li><strong>Click “Get Download Links”</strong> next to the game. The app finds every part of the game.</li>
          <li><strong>Copy the links</strong> into a download manager on your computer (for example Free Download Manager or JDownloader) and download them. <em>Don’t rename the files.</em></li>
          <li><strong>Choose the folder</strong> with the downloaded files in <a href="#" data-goto="local">Use My Files</a>.</li>
          <li><strong>Restart the download on the PS5.</strong> It now copies the files from your computer, which is much faster.</li>
        </ol>
        <div class="notice">Safe by design: if a file is missing or not finished, the PS5 simply downloads that part from the internet as usual. Nothing breaks.</div>
      </div>
    </div>
  </section>

  <section id="panel-logger" class="panel">
    <div class="card">
      <div class="row">
        <h2 class="grow">Step 2 · Game downloads seen from your PS5</h2>
        <button onclick="clearLogs()">Clear List</button>
      </div>
      <p>Start a game download on the PS5 and it shows up here within a few seconds. Then click <strong>Get Download Links</strong>.</p>
      <div class="legend">
        <span><span class="dot dot-remote"></span>From the internet</span>
        <span><span class="dot dot-local"></span>From your computer</span>
        <span><span class="dot dot-fallback"></span>From the internet, because your file couldn’t be used (reason shown)</span>
      </div>
      <div class="scroll"><table>
        <thead><tr><th>Time</th><th>Coming from</th><th>Game file</th><th>Details</th><th></th></tr></thead>
        <tbody id="logRows"></tbody>
      </table></div>
      <div id="logEmpty" class="empty">Nothing yet. Make sure Step 1 is done, then start a game download on the PS5.</div>
    </div>
  </section>

  <section id="panel-links" class="panel">
    <div class="card">
      <div class="row">
        <h2 class="grow">Step 3 · Download links for your game</h2>
        <button id="copyAll" class="primary" onclick="copyAllLinks()" disabled>Copy All Links</button>
      </div>
      <p>Large games are split into several files. Copy all links, paste them into your download manager, and save them into one folder. <strong>Keep the original file names.</strong> Links expire after a while, so start downloading soon.</p>
      <div id="discoverySummary" class="muted">Go to <a href="#" data-goto="logger">Find Game</a> and click “Get Download Links” next to a game.</div>
      <div id="discoveryLinks" class="links-list"></div>
      <div id="linksNext" class="next" hidden>Next: when the downloads finish, go to <a href="#" data-goto="local">Use My Files</a>.</div>
    </div>
  </section>

  <section id="panel-local" class="panel">
    <div class="card">
      <h2>Step 4 · Tell the app where your downloaded files are</h2>
      <p>Pick the folder where your download manager saved the game files. Folders inside it are checked too. You can add more than one folder, for example one per game or on another drive.</p>
      <div class="row">
        <button class="primary" onclick="chooseDirectory()">Choose Folder…</button>
        <span class="muted">or paste a path:</span>
        <input id="localDirectory" class="grow" placeholder="e.g. /Users/you/Downloads/MyGame  or  D:\\Games\\MyGame" />
        <button onclick="setDirectory()">Add</button>
      </div>
      <div id="localSummary" class="muted" style="margin-top:10px"></div>
      <div class="scroll" style="margin-top:12px"><table>
        <thead><tr><th>Folder</th><th>Game files</th><th>Status</th><th></th></tr></thead>
        <tbody id="localFolders"></tbody>
      </table></div>
      <div class="row" style="margin-top:12px">
        <button onclick="rescanDirectory()" title="Use this after new files finish downloading">Check Folders Again</button>
        <button onclick="clearDirectory()">Remove All Folders</button>
      </div>
      <div class="notice" style="margin-top:14px">Then restart the download on the PS5. Each file it finds here is sent from your computer. Any file that is missing, unfinished, or found twice is downloaded from the internet as usual.</div>
    </div>
    <div class="card">
      <h2>Game files found</h2>
      <div class="scroll"><table>
        <thead><tr><th>File name</th><th>Location</th><th>Size</th><th>Status</th></tr></thead>
        <tbody id="localRows"></tbody>
      </table></div>
    </div>
  </section>

  <section id="panel-requests" class="panel">
    <div class="notice" style="margin-top:18px">Advanced. You don’t need this tab to download games. It shows everything your PS5 sends over the network, for troubleshooting or research.</div>
    <div class="card">
      <div class="row">
        <h2 class="grow">Network Log</h2>
        <input id="reqFilter" style="width:280px" placeholder="Search by website, address, status…" />
        <button class="danger" onclick="clearRequests()">Delete All</button>
        <button onclick="exportRequests()">Save to File</button>
      </div>
      <div class="row" style="margin-top:10px">
        <input id="markerNote" class="grow" placeholder="Bookmark note, e.g. “opening game X now”" />
        <button onclick="addMarker()">Add Bookmark</button>
      </div>
      <p>Add a bookmark right before you do something on the PS5, so you can see which requests it caused. Click a row for full details. Secure (HTTPS) traffic stays encrypted: only the website name and timing are visible.</p>
      <p class="warn small">⚠ The saved file contains private login tokens and cookies from your PSN account. Don’t share it publicly.</p>
      <div id="reqSummary" class="muted"></div>
      <div class="scroll" style="max-height:560px"><table>
        <thead><tr><th>Time</th><th>Device</th><th>Type</th><th>Method</th><th>Status</th><th>Website / address</th><th>Category</th><th>Route</th><th>↑ Sent</th><th>↓ Received</th><th>Duration</th></tr></thead>
        <tbody id="reqRows"></tbody>
      </table></div>
    </div>
    <div class="card" id="reqDetailCard" style="display:none">
      <div class="row"><h2 class="grow">Request Details</h2><button onclick="selectRequest(null)">Close</button></div>
      <pre class="detail" id="reqDetail"></pre>
    </div>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtBytes = (n) => {
  if (n == null || !Number.isFinite(Number(n))) return '';
  n = Number(n); const units=['B','KB','MB','GB','TB']; let i=0;
  while(n >= 1024 && i < units.length-1){ n/=1024; i++; }
  return n.toFixed(i ? 2 : 0)+' '+units[i];
};
let latestDiscovery = null;
const lastHtml = new Map();
// Only touch the DOM when content changed, so open <details> and text selection survive the 1.5s refresh.
function setHtml(id, html) {
  if (lastHtml.get(id) === html) return false;
  lastHtml.set(id, html); $(id).innerHTML = html; return true;
}
let currentLinks = [];
let lastStatus = null;

async function api(url, options={}) {
  const res = await fetch(url, { ...options, headers: {'Content-Type':'application/json', ...(options.headers||{})} });
  const text = await res.text(); let body; try { body=JSON.parse(text); } catch { body=text; }
  if (!res.ok) throw new Error(body?.error || text || ('HTTP '+res.status));
  return body;
}

function showTab(name) {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(x => x.classList.toggle('active', x.id === 'panel-'+name));
}
document.querySelectorAll('.tab').forEach(x => x.addEventListener('click', () => showTab(x.dataset.tab)));
document.addEventListener('click', (e) => {
  const link = e.target.closest('[data-goto]');
  if (link) { e.preventDefault(); showTab(link.dataset.goto); window.scrollTo(0, 0); }
});

// Turns technical error text into something a non-technical user can act on.
function friendlyError(msg) {
  const m = String(msg || '');
  if (/EADDRINUSE/.test(m)) return 'Another app on this computer is already using this port. Close it (or another copy of this app) and click Turn On again.';
  if (/EACCES|EPERM/.test(m)) return 'This computer did not allow the app to open the port. Try a port number above 1024.';
  if (/ENOENT|no such file/i.test(m)) return 'That folder was not found. Check the path, or the drive may be unplugged.';
  if (/ENOTDIR/.test(m)) return 'That path is a file, not a folder.';
  if (/ETIMEDOUT|timed? ?out/i.test(m)) return 'The server took too long to answer. Check the internet connection and try again.';
  if (/ENOTFOUND|EAI_AGAIN/.test(m)) return 'Could not reach the server. Check the internet connection.';
  if (/ECONNREFUSED|ECONNRESET/.test(m)) return 'The connection was refused or dropped. Try again.';
  return m;
}
const errHtml = (e) => '<span class="bad">'+esc(friendlyError(e?.message ?? e))+'</span>';

async function proxyAction(action) {
  $('proxyMessage').className='muted';
  $('proxyMessage').textContent = action === 'start' ? 'Turning on…' : 'Turning off…';
  try {
    await api('/api/proxy/'+action, {method:'POST', body:'{}'});
    $('proxyMessage').textContent = action === 'start' ? 'On. Your PS5 can connect now.' : 'Off. If the PS5 still uses this proxy, it has no internet until you turn it on again.';
    await refresh();
  } catch(e) {
    $('proxyMessage').className='bad'; $('proxyMessage').textContent=friendlyError(e.message);
  }
}

async function startDiscovery(url) {
  showTab('links');
  setHtml('discoverySummary', 'Looking for all parts of this game…');
  setHtml('discoveryLinks', '');
  currentLinks=[];
  $('copyAll').disabled=true;
  try {
    latestDiscovery = await api('/api/pkg-discovery', {method:'POST', body:JSON.stringify({url})});
  } catch(e) {
    setHtml('discoverySummary', errHtml(e));
  }
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch { window.prompt('Copy these links (Ctrl+C / Cmd+C):', text); return false; }
}

async function copyAllLinks() {
  if (!currentLinks.length) return;
  if (await copyText(currentLinks.map(x => x.url).join('\\n'))) {
    $('copyAll').textContent='Copied! Paste them into your download manager';
    setTimeout(() => $('copyAll').textContent='Copy All Links', 2500);
  }
}

async function chooseDirectory() {
  $('localSummary').textContent='A folder picker window is opening. It may appear behind this browser.';
  try {
    await api('/api/local-directory/select', {method:'POST', body:'{}'});
    await refresh();
  } catch(e) { $('localSummary').innerHTML=errHtml(e); }
}

async function setDirectory() {
  if (!$('localDirectory').value.trim()) { $('localDirectory').focus(); return; }
  try {
    await api('/api/local-directory', {method:'POST', body:JSON.stringify({directory:$('localDirectory').value.trim()})});
    $('localDirectory').value='';
    await refresh();
  } catch(e) { $('localSummary').innerHTML=errHtml(e); }
}

async function rescanDirectory() {
  try { await api('/api/local-directory/rescan', {method:'POST', body:'{}'}); await refresh(); }
  catch(e) { $('localSummary').innerHTML=errHtml(e); }
}

async function clearDirectory() {
  const count = (lastStatus?.local?.directories || []).length;
  if (!count) return;
  if (!confirm('Remove '+(count > 1 ? 'all '+count+' folders' : 'this folder')+' from the app? Your files are NOT deleted.')) return;
  await api('/api/local-directory', {method:'DELETE'});
  $('localDirectory').value='';
  await refresh();
}

$('localFolders').addEventListener('click', async (e) => {
  const btn = e.target.closest('.remove-folder');
  if (!btn) return;
  try { await api('/api/local-directory?directory='+encodeURIComponent(btn.dataset.dir), {method:'DELETE'}); await refresh(); }
  catch(err) { $('localSummary').innerHTML=errHtml(err); }
});
$('localDirectory').addEventListener('keydown', (e) => { if (e.key === 'Enter') setDirectory(); });

let requestRows = [];
let selectedRequestId = null;

async function addMarker() {
  const note = $('markerNote').value.trim();
  if (!note) return $('markerNote').focus();
  try {
    await api('/api/requests/marker', {method:'POST', body:JSON.stringify({note})});
    $('markerNote').value = '';
    await refreshRequests();
  } catch(e) { $('reqSummary').innerHTML='<span class="bad">'+esc(e.message)+'</span>'; }
}
$('markerNote').addEventListener('keydown', (e) => { if (e.key === 'Enter') addMarker(); });

async function clearRequests() {
  if (!confirm('Delete the whole network log? This cannot be undone.')) return;
  await api('/api/requests', {method:'DELETE'});
  selectRequest(null);
  await refreshRequests();
}

function exportRequests() {
  const a = document.createElement('a');
  a.href = '/api/requests/export';
  document.body.appendChild(a); a.click(); a.remove();
}

async function selectRequest(reqId) {
  selectedRequestId = reqId;
  $('reqDetailCard').style.display = reqId ? '' : 'none';
  renderRequests();
  if (!reqId) return;
  $('reqDetail').textContent = 'Loading…';
  try { $('reqDetail').textContent = JSON.stringify(await api('/api/requests/'+encodeURIComponent(reqId)), null, 2); }
  catch(e) { $('reqDetail').textContent = e.message; }
}

function renderRequests(data) {
  if (data) {
    requestRows = data.rows || [];
    $('reqSummary').textContent = data.total ? data.total+' request(s) recorded'+(data.total > requestRows.length ? ' · showing the latest '+requestRows.length : '') : 'Nothing recorded yet. Use the PS5 while it is connected through this app.';
  }
  const q = $('reqFilter').value.trim().toLowerCase();
  const rows = q ? requestRows.filter(r => [r.host, r.url, r.clientIp, r.method, r.status, r.type, r.route, r.category, r.sni, r.reason].join(' ').toLowerCase().includes(q)) : requestRows;
  $('reqRows').innerHTML = rows.map(r => {
    if (r.type === 'MARKER') return '<tr class="req-row marker-row'+(r.id===selectedRequestId?' selected':'')+'" data-id="'+esc(r.id)+'"><td>'+esc((r.timestamp||'').replace('T',' ').replace('Z',''))+'</td><td colspan="10">▶ MARKER: '+esc(r.reason)+'</td></tr>';
    const statusCls = r.error || r.status >= 400 ? 'bad' : r.status >= 300 ? 'warn' : r.status ? 'ok' : 'muted';
    const routeCls = r.route === 'LOCAL' ? 'ok' : r.route === 'FALLBACK' ? 'warn' : 'muted';
    const status = r.error ? (r.status || 'ERR')+' · '+r.error : (r.status ?? '…');
    return '<tr class="req-row'+(r.id===selectedRequestId?' selected':'')+'" data-id="'+esc(r.id)+'"><td>'+esc((r.timestamp||'').replace('T',' ').replace('Z',''))+'</td><td>'+esc(r.clientIp)+'</td><td>'+esc(r.type)+'</td><td>'+esc(r.method)+'</td><td class="'+statusCls+'">'+esc(status)+'</td><td class="urlcell"><strong>'+esc(r.host)+'</strong>'+(r.type==='HTTP'?'<br><code>'+esc(r.url)+'</code>':'')+'</td><td title="'+esc(r.categoryHint)+'">'+esc(r.category)+'</td><td class="'+routeCls+'">'+esc(r.route)+'</td><td>'+esc(fmtBytes(r.bytesUp))+'</td><td>'+esc(fmtBytes(r.bytesDown))+'</td><td>'+(r.durationMs==null?esc(r.state):esc(r.durationMs+' ms'))+'</td></tr>';
  }).join('');
}
$('reqRows').addEventListener('click', (e) => {
  const row = e.target.closest('.req-row');
  if (row) selectRequest(row.dataset.id === selectedRequestId ? null : row.dataset.id);
});
$('reqFilter').addEventListener('input', () => renderRequests());

async function clearLogs() {
  await api('/api/pkg-logs', {method:'DELETE'});
  await refresh();
}

function renderDiscovery(jobs) {
  if (latestDiscovery) {
    const updated = jobs.find(j => j.id === latestDiscovery.id);
    if (updated) latestDiscovery = updated;
  } else if (jobs.length) {
    latestDiscovery = jobs[0];
  }
  const job=latestDiscovery;
  if (!job) {
    setHtml('discoverySummary', 'Go to <a href="#" data-goto="logger">Find Game</a> and click “Get Download Links” next to a game.');
    setHtml('discoveryLinks', '');
    $('linksNext').hidden=true; $('linksBadge').hidden=true;
    currentLinks=[]; $('copyAll').disabled=true; return;
  }
  currentLinks=job.links || [];
  $('copyAll').disabled=!currentLinks.length;
  const n=currentLinks.length;
  const totalBytes=currentLinks.reduce((sum,x) => sum+(x.totalSize||0), 0);
  const parts=n+' file'+(n===1?'':'s')+(totalBytes ? ' · about '+fmtBytes(totalBytes)+' in total' : '');
  let headline, cls;
  if (job.status === 'running') { headline='Searching… found '+parts+' so far.'; cls='warn'; }
  else if (job.status === 'error' || (!n && job.error)) { headline='Could not check the links: '+friendlyError(job.error || job.stopReason); cls='bad'; }
  else if (!n) { headline='No game files were found at this link. It has probably expired. Start the download on the PS5 again, then click “Get Download Links” on the new entry.'; cls='bad'; }
  else { headline='Done. Found '+(n > 1 ? 'all ' : '')+parts+'.'; cls='ok'; }
  setHtml('discoverySummary', '<div class="big-state '+cls+'"><strong>'+esc(headline)+'</strong></div><details class="muted small"><summary>Technical details</summary>Original link: <code>'+esc(job.displayUrl)+'</code><br>'+esc(job.stopReason || '')+'</details>');
  setHtml('discoveryLinks', currentLinks.map((x,i) => '<div class="link-item"><span class="pill">Part '+(i+1)+'</span><code>'+esc(x.url)+'</code>'+(x.totalSize?'<span class="muted small" style="white-space:nowrap">'+esc(fmtBytes(x.totalSize))+'</span>':'')+'<button class="copy-one" data-i="'+i+'">Copy</button></div>').join(''));
  $('linksNext').hidden = job.status === 'running' || !n;
  $('linksBadge').hidden = !n; $('linksBadge').textContent = n;
}

let currentLogs = [];
$('discoveryLinks').addEventListener('click', async (e) => {
  const btn = e.target.closest('.copy-one');
  if (!btn) return;
  if (await copyText(currentLinks[Number(btn.dataset.i)].url)) { btn.textContent='Copied!'; setTimeout(()=>btn.textContent='Copy',1200); }
});
$('logRows').addEventListener('click', (e) => {
  const btn = e.target.closest('.discover-btn');
  if (btn && currentLogs[Number(btn.dataset.i)]) startDiscovery(currentLogs[Number(btn.dataset.i)].url);
});
// Plain-language version of the server's fallback reasons; the original is kept as a tooltip.
function friendlyReason(r) {
  r = String(r || '');
  if (/^Local file not found/.test(r)) return 'You don’t have this file in your folders yet.';
  if (/^Duplicate local filename/.test(r)) return 'This file is in your folders more than once, so it wasn’t used. Keep only one copy.';
  if (/size mismatch/.test(r)) return 'Your copy is unfinished or damaged (wrong size). Download it again.';
  if (/is empty/.test(r)) return 'Your copy of this file is empty. Download it again.';
  if (/not a regular file/.test(r)) return 'Something with this name exists, but it isn’t a normal file.';
  if (/blocked from dashboard/.test(r)) return 'Blocked because internet access is turned off in Step 1.';
  return r;
}
const SOURCE_LABEL = { LOCAL: 'Your computer', REMOTE: 'Internet', FALLBACK: 'Internet (file not used)' };
const fmtTime = (iso) => { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleTimeString(); };

function renderLogs(logs) {
  $('logEmpty').hidden = logs.length > 0;
  $('loggerBadge').hidden = !logs.length; $('loggerBadge').textContent = logs.length;
  setHtml('logRows', logs.map((l,i) => {
    const cls=l.action==='LOCAL'?'ok':l.action==='FALLBACK'?'warn':'muted';
    const details=l.action==='LOCAL'
      ? '<span class="muted small">Sent from</span> <code>'+esc(l.localFile)+'</code>'
      : l.reason ? '<span class="warn" title="'+esc(l.reason)+'">'+esc(friendlyReason(l.reason))+'</span>' : '<span class="muted">Downloading from PlayStation servers</span>';
    const action=(l.action==='REMOTE' || l.action==='FALLBACK') && l.url ? '<button class="discover-btn primary" data-i="'+i+'">Get Download Links</button>' : '';
    const tech='Server status: '+(l.status ?? 'waiting')+(l.range ? ' · Range: '+l.range : '');
    return '<tr title="'+esc(tech)+'"><td>'+esc(fmtTime(l.timestamp))+'</td><td class="'+cls+'"><strong>'+esc(SOURCE_LABEL[l.action] || l.action)+'</strong></td><td class="urlcell"><strong>'+esc(l.filename)+'</strong><details class="small muted"><summary>Full link</summary><code>'+esc(l.displayUrl||l.url)+'</code></details></td><td class="pathcell">'+details+'</td><td>'+action+'</td></tr>';
  }).join(''));
  currentLogs = logs;
}

async function refresh() {
  try {
    const [status, logs, discoveries, localFiles] = await Promise.all([
      api('/api/status'), api('/api/pkg-logs?limit=500'), api('/api/pkg-discovery'), api('/api/local-files?limit=1500')
    ]);
    lastStatus=status;
    const running=status.proxy.running;
    $('proxyState').innerHTML=(running
      ? '<div class="big-state ok"><strong>● On</strong> and waiting for your PS5</div>'
      : '<div class="big-state bad"><strong>● Off</strong>. Click <strong>Turn On</strong> below.</div>')
      +(status.proxy.lastError?'<div class="bad small">'+esc(friendlyError(status.proxy.lastError))+'</div>':'');
    // Home routers almost always hand out 192.168.x / 10.x / 172.16-31.x; VPN and bridge addresses go last.
    const rank = (a) => /^192\\.168\\./.test(a) ? 0 : /^10\\./.test(a) ? 1 : /^172\\.(1[6-9]|2\\d|3[01])\\./.test(a) ? 2 : 3;
    const ips=[...(status.lanAddresses || [])].sort((x, y) => rank(x.address) - rank(y.address));
    $('proxyConfig').innerHTML=ips.length
      ? '<div class="big-config addr"><span class="label">Address</span><span class="value">'+esc(ips[0].address)+'</span><span class="label">Port</span><span class="value">'+esc(status.proxy.port)+'</span></div>'
        +(ips.length > 1 ? '<div class="muted small">If that address doesn’t work, try: '+ips.slice(1).map(x => '<code>'+esc(x.address)+'</code>').join(', ')+' (same port).</div>' : '')
      : '<div class="big-config bad" style="font-size:16px">This computer isn’t connected to a network. Connect it to the same Wi-Fi or router as your PS5.</div>';
    $('startProxy').disabled=running; $('stopProxy').disabled=!running;

    const local=status.local || {};
    const folders = local.directories || [];
    $('localBadge').hidden = !local.pkgCount; $('localBadge').textContent = local.pkgCount || '';
    $('localSummary').innerHTML=folders.length
      ? '<span class="ok">✓ '+esc(local.pkgCount)+' game file(s) ready</span> in '+esc(folders.length)+' folder(s)'
        +(local.duplicateNames?' · <span class="warn">'+esc(local.duplicateNames)+' file name(s) found twice, which won’t be used</span>':'')
        +(local.error?' · <span class="bad">some folders could not be read</span>':'')
      : '<span class="muted">No folder chosen yet. Until you choose one, the PS5 downloads everything from the internet.</span>';
    $('localFolders').innerHTML=folders.length ? folders.map(f => '<tr><td class="pathcell"><code>'+esc(f.directory)+'</code></td><td>'+esc(f.pkgCount)+'</td><td class="'+(f.error?'bad':f.pkgCount?'ok':'warn')+'">'+(f.error?esc(friendlyError(f.error)):f.pkgCount?'Ready':'No game files in here')+'</td><td><button class="remove-folder" data-dir="'+esc(f.directory)+'">Remove</button></td></tr>').join('')
      : '<tr><td colspan="4" class="empty">No folders yet. Click “Choose Folder…”.</td></tr>';
    $('localRows').innerHTML=localFiles.length ? localFiles.map(f => '<tr><td>'+esc(f.filename)+'</td><td><code>'+esc(f.file)+'</code></td><td>'+esc(fmtBytes(f.size))+'</td><td class="'+(f.duplicate?'warn':'ok')+'">'+(f.duplicate?'Found twice, not used':'Ready')+'</td></tr>').join('')
      : '<tr><td colspan="4" class="empty">No game files found yet.</td></tr>';

    const served = logs.filter(l => l.action === 'LOCAL').length;
    $('topStatus').innerHTML = !running
      ? '<span class="bad">● Proxy is off</span>'
      : served ? '<span class="ok">● Sending files from your computer ('+served+')</span>'
      : logs.length ? '<span class="ok">● PS5 connected</span>'
      : '<span class="warn">● On, waiting for the PS5</span>';

    renderLogs(logs);
    renderDiscovery(discoveries);
  } catch(e) { console.error(e); }
}

// Polled separately so a failure here never affects the original tabs.
async function refreshRequests() {
  try { renderRequests(await api('/api/requests?limit=500')); }
  catch(e) { $('reqSummary').innerHTML='<span class="bad">'+esc(e.message)+'</span>'; }
}

refresh(); setInterval(refresh, 1500);
refreshRequests(); setInterval(refreshRequests, 1500);

let internetBusy = false;
function renderInternet(state) {
  const toggle = $('internetToggle');
  toggle.checked = state.allowed;
  toggle.disabled = !state.proxyRunning || internetBusy;
  $('internetState').textContent = state.allowed ? 'Yes' : 'No, blocked';
  $('internetState').className = state.allowed ? 'ok' : 'bad';
  $('internetHint').textContent = !state.proxyRunning
    ? 'Turn the proxy on to change this.'
    : state.allowed
      ? 'Normal. Turn this off to keep the PS5 offline (for example, to stop updates).'
      : 'The PS5 is offline. Game files from your folders are still sent. This switches back on when the app restarts.';
}

async function setInternetAccess(allowed) {
  internetBusy = true;
  $('internetToggle').disabled = true;
  try { renderInternet(await api('/api/internet', {method:'POST', body:JSON.stringify({allowed})})); }
  catch(e) { $('internetHint').innerHTML = '<span class="bad">'+esc(e.message)+'</span>'; }
  finally { internetBusy = false; await refreshInternet(); }
}

async function refreshInternet() {
  if (internetBusy) return;
  try { renderInternet(await api('/api/internet')); } catch(e) { console.error(e); }
}
refreshInternet(); setInterval(refreshInternet, 1500);
</script>
</body>
</html>`;
}

loadRequestLogs();
setInterval(() => { void saveRequestLogs(); }, REQUESTS_SAVE_INTERVAL_MS).unref();
process.on('exit', saveRequestLogsSync);

if (localDirectories().length) {
  scanLocalDirectories();
  console.log(`Indexed ${localScan.pkgCount} local PKG(s) from ${localDirectories().length} folder(s)`);
  if (localScan.error) console.warn(`Could not scan some local folders: ${localScan.error}`);
}

dashboardServer.listen(DASHBOARD_PORT, DASHBOARD_HOST, async () => {
  console.log(`Dashboard: http://${DASHBOARD_HOST}:${DASHBOARD_PORT}`);
  const ips = lanAddresses();
  if (ips.length) console.log(`PS5 proxy address(es): ${ips.map((x) => `${x.address}:${PROXY_PORT}`).join(', ')}`);
  try {
    await startProxy();
  } catch (error) {
    console.error(`Proxy did not start automatically: ${error.message}`);
  }
});

async function shutdown() {
  console.log('\nShutting down…');
  try { await stopProxy(); } catch {}
  dashboardServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
