import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');

const PROXY_HOST = process.env.PROXY_HOST || '0.0.0.0';
const PROXY_PORT = Number(process.env.PROXY_PORT || 8080);
const DASHBOARD_HOST = process.env.DASHBOARD_HOST || '127.0.0.1';
const DASHBOARD_PORT = Number(process.env.DASHBOARD_PORT || 8081);
const MAX_LOGS = Number(process.env.MAX_LOGS || 2000);
const MAX_PACKAGE_LINKS = Number(process.env.MAX_PACKAGE_LINKS || 4096);
const PKG_PROBE_TIMEOUT_MS = Number(process.env.PKG_PROBE_TIMEOUT_MS || 10000);
const MAX_SCAN_ENTRIES = Number(process.env.MAX_SCAN_ENTRIES || 100000);
const DEBUG_PKG_HEADERS = /^(1|true|yes)$/i.test(process.env.DEBUG_PKG_HEADERS || '');

fs.mkdirSync(DATA_DIR, { recursive: true });

let settings = loadJson(SETTINGS_FILE, { localDirectory: null });
let proxyRunning = false;
let proxyLastError = null;
let pkgLogs = [];
const pkgDiscoveryJobs = new Map();
const remoteMetadata = new Map();
const proxySockets = new Set();
let localPkgIndex = new Map();
let localScan = {
  directory: settings.localDirectory || null,
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

function scanLocalDirectory(directory) {
  const index = new Map();
  let pkgCount = 0;
  let duplicateNames = 0;
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
      pkgCount++;
      const existing = index.get(entry.name) || [];
      existing.push(full);
      index.set(entry.name, existing);
    }
  }

  for (const files of index.values()) {
    if (files.length > 1) duplicateNames++;
  }

  localPkgIndex = index;
  localScan = {
    directory,
    pkgCount,
    duplicateNames,
    scannedEntries,
    scannedAt: now(),
    error: null
  };
  return localScan;
}

function setLocalDirectory(directory) {
  const resolved = path.resolve(String(directory));
  const result = scanLocalDirectory(resolved);
  settings.localDirectory = resolved;
  saveSettings();
  return result;
}

function clearLocalDirectory() {
  settings.localDirectory = null;
  saveSettings();
  localPkgIndex = new Map();
  localScan = {
    directory: null,
    pkgCount: 0,
    duplicateNames: 0,
    scannedEntries: 0,
    scannedAt: now(),
    error: null
  };
}

function resolveLocalPackage(rawUrl) {
  if (!settings.localDirectory) return { file: null, reason: 'No local PKG directory configured' };
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

  upstream.on('timeout', () => upstream.destroy(new Error('Upstream timeout')));
  upstream.on('error', (error) => {
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

function handleProxyHttp(req, res) {
  const rawUrl = requestUrl(req);
  if (!rawUrl) {
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

  if ((req.method === 'GET' || req.method === 'HEAD') && settings.localDirectory) {
    const local = resolveLocalPackage(rawUrl);
    if (local.file) {
      const result = tryServeLocalFile(req, res, rawUrl, local.file);
      if (result.served) {
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

    const fallback = addPkgLog({
      ...base,
      action: 'FALLBACK',
      reason: local.reason
    });
    console.warn(`[FALLBACK] ${req.method} ${redactUrl(rawUrl)} -> CDN (${local.reason})`);
    forwardHttp(req, res, rawUrl, fallback);
    return;
  }

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
  proxySockets.add(socket);
  socket.on('close', () => proxySockets.delete(socket));
});
proxyServer.on('connect', (req, clientSocket, head) => {
  const target = parseConnectTarget(req.url);
  if (!target) {
    clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    return;
  }

  console.log(`[TLS] CONNECT ${target.host}:${target.port}`);
  const upstreamSocket = net.connect(target.port, target.host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: ps5-node-download-helper\r\n\r\n');
    if (head?.length) upstreamSocket.write(head);
    upstreamSocket.pipe(clientSocket);
    clientSocket.pipe(upstreamSocket);
  });

  upstreamSocket.setTimeout(120_000);
  upstreamSocket.on('timeout', () => upstreamSocket.destroy());
  upstreamSocket.on('error', () => {
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
      return json(res, 200, { ...localScan, directory: settings.localDirectory || null });
    }

    if (req.method === 'POST' && u.pathname === '/api/local-directory') {
      const body = await readJson(req);
      if (!body.directory) return json(res, 400, { error: 'directory is required' });
      try {
        return json(res, 200, setLocalDirectory(body.directory));
      } catch (error) {
        localScan.error = error.message;
        return json(res, 400, { error: error.message });
      }
    }

    if (req.method === 'POST' && u.pathname === '/api/local-directory/select') {
      try {
        const selected = await chooseDirectoryNative();
        if (!selected) return json(res, 400, { error: 'No directory selected' });
        const scan = setLocalDirectory(selected);
        return json(res, 200, scan);
      } catch (error) {
        return json(res, 400, { error: `Directory chooser failed or was cancelled: ${error.message}` });
      }
    }

    if (req.method === 'POST' && u.pathname === '/api/local-directory/rescan') {
      if (!settings.localDirectory) return json(res, 400, { error: 'No local directory configured' });
      try {
        return json(res, 200, scanLocalDirectory(settings.localDirectory));
      } catch (error) {
        localScan.error = error.message;
        return json(res, 400, { error: error.message });
      }
    }

    if (req.method === 'DELETE' && u.pathname === '/api/local-directory') {
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
<title>PS5 Node Download Helper</title>
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
  .urlcell { min-width:390px; max-width:720px; }
  .pathcell { min-width:320px; max-width:600px; }
  .notice { border-left:3px solid #d29922; padding:8px 12px; background:#1b1a14; color:#c9d1d9; }
  .links-list { max-height:520px; overflow:auto; }
  .link-item { display:flex; gap:8px; align-items:flex-start; border-bottom:1px solid #30363d; padding:10px 0; }
  .link-item code { flex:1; }
</style>
</head>
<body>
<main>
  <h1>PS5 Node Download Helper</h1>
  <p>Capture PKG links, enumerate sequential PKG URLs, and automatically serve downloaded PKGs back to the PS5 by filename.</p>

  <div class="tabs">
    <button class="tab active" data-tab="overview">Overview</button>
    <button class="tab" data-tab="links">PKG Download Links</button>
    <button class="tab" data-tab="local">Local Mapping</button>
    <button class="tab" data-tab="logger">Logger</button>
  </div>

  <section id="panel-overview" class="panel active">
    <div class="grid">
      <div class="card">
        <h2>Proxy</h2>
        <div id="proxyState">Loading…</div>
        <div id="proxyConfig"></div>
        <div class="row">
          <button id="startProxy" class="primary" onclick="proxyAction('start')">Start Proxy</button>
          <button id="stopProxy" class="danger" onclick="proxyAction('stop')">Stop Proxy</button>
        </div>
        <div id="proxyMessage" class="muted" style="margin-top:9px"></div>
      </div>
      <div class="card">
        <h2>Workflow</h2>
        <ol>
          <li>Start the proxy and configure the PS5 with the shown <strong>Mac-IP:8080</strong>.</li>
          <li>Start the PS5 game download.</li>
          <li>The Logger captures the first <code>.pkg</code> URL.</li>
          <li>Click <strong>Download Links</strong> to enumerate the sequential PKG URLs.</li>
          <li>Download those URLs with your preferred download manager.</li>
          <li>In Local Mapping, select the folder containing the unchanged PKG filenames.</li>
          <li>Resume/restart the PS5 download. Matching files are served locally.</li>
        </ol>
      </div>
    </div>
  </section>

  <section id="panel-links" class="panel">
    <div class="card">
      <div class="row">
        <h2 class="grow">Sequential PKG Links</h2>
        <button id="copyAll" onclick="copyAllLinks()" disabled>Copy All Links</button>
      </div>
      <p>The helper changes only the final numeric token immediately before <code>.pkg</code>. Everything else in the captured URL stays unchanged. It probes each next URL with a one-byte Range request and stops on the first HTTP error/non-2xx response.</p>
      <div id="discoverySummary" class="muted">Click “Download Links” beside a captured PKG in Logger.</div>
      <div id="discoveryLinks" class="links-list"></div>
    </div>
  </section>

  <section id="panel-local" class="panel">
    <div class="card">
      <h2>Downloaded PKG Folder</h2>
      <p>Select the directory containing the PKG files downloaded by your download manager. Filenames must remain unchanged. Subdirectories are scanned too.</p>
      <div class="row">
        <input id="localDirectory" class="grow" placeholder="/Users/you/Downloads/PS5Game" />
        <button onclick="chooseDirectory()">Choose Folder…</button>
        <button onclick="setDirectory()">Use Path</button>
        <button onclick="rescanDirectory()">Rescan Files</button>
        <button onclick="clearDirectory()">Disable Mapping</button>
      </div>
      <div id="localSummary" class="muted" style="margin-top:10px"></div>
      <div class="notice" style="margin-top:14px">Fail-open behavior: if a requested PKG is missing, duplicated, unreadable, incomplete/size-mismatched, or its Range cannot be served locally, the original PS5 request is forwarded to the CDN normally.</div>
    </div>
    <div class="card">
      <h2>Indexed Local PKGs</h2>
      <div class="scroll"><table>
        <thead><tr><th>Filename</th><th>Local path</th><th>Size</th><th>State</th></tr></thead>
        <tbody id="localRows"></tbody>
      </table></div>
    </div>
  </section>

  <section id="panel-logger" class="panel">
    <div class="card">
      <div class="row">
        <h2 class="grow">PKG Logger</h2>
        <button onclick="clearLogs()">Clear Logger</button>
      </div>
      <p><span class="ok">LOCAL</span> means the PKG was served from your selected directory. <span class="warn">FALLBACK</span> means local mapping could not safely handle it and the request was sent to the CDN. REMOTE means no local directory was enabled yet.</p>
      <div class="scroll"><table>
        <thead><tr><th>Time</th><th>Action</th><th>Status</th><th>PKG / URL</th><th>Range</th><th>Local mapping / reason</th><th></th></tr></thead>
        <tbody id="logRows"></tbody>
      </table></div>
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

async function proxyAction(action) {
  $('proxyMessage').textContent = action === 'start' ? 'Starting…' : 'Stopping…';
  try {
    await api('/api/proxy/'+action, {method:'POST', body:'{}'});
    $('proxyMessage').textContent = action === 'start' ? 'Proxy started.' : 'Proxy stopped.';
    await refresh();
  } catch(e) {
    $('proxyMessage').className='bad'; $('proxyMessage').textContent=e.message;
  }
}

async function startDiscovery(url) {
  showTab('links');
  $('discoverySummary').textContent='Probing sequential PKG links…';
  $('discoveryLinks').innerHTML='';
  currentLinks=[];
  $('copyAll').disabled=true;
  try {
    latestDiscovery = await api('/api/pkg-discovery', {method:'POST', body:JSON.stringify({url})});
  } catch(e) {
    $('discoverySummary').innerHTML='<span class="bad">'+esc(e.message)+'</span>';
  }
}

async function copyText(text) {
  await navigator.clipboard.writeText(text);
}

async function copyAllLinks() {
  if (!currentLinks.length) return;
  await copyText(currentLinks.map(x => x.url).join('\\n'));
  $('copyAll').textContent='Copied!';
  setTimeout(() => $('copyAll').textContent='Copy All Links', 1000);
}

async function chooseDirectory() {
  $('localSummary').textContent='Opening folder chooser…';
  try {
    const result = await api('/api/local-directory/select', {method:'POST', body:'{}'});
    $('localDirectory').value=result.directory || '';
    await refresh();
  } catch(e) { $('localSummary').innerHTML='<span class="bad">'+esc(e.message)+'</span>'; }
}

async function setDirectory() {
  try {
    await api('/api/local-directory', {method:'POST', body:JSON.stringify({directory:$('localDirectory').value})});
    await refresh();
  } catch(e) { $('localSummary').innerHTML='<span class="bad">'+esc(e.message)+'</span>'; }
}

async function rescanDirectory() {
  try { await api('/api/local-directory/rescan', {method:'POST', body:'{}'}); await refresh(); }
  catch(e) { $('localSummary').innerHTML='<span class="bad">'+esc(e.message)+'</span>'; }
}

async function clearDirectory() {
  await api('/api/local-directory', {method:'DELETE'});
  $('localDirectory').value='';
  await refresh();
}

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
    $('discoverySummary').textContent='Click “Download Links” beside a captured PKG in Logger.';
    $('discoveryLinks').innerHTML='';
    currentLinks=[]; $('copyAll').disabled=true; return;
  }
  currentLinks=job.links || [];
  $('copyAll').disabled=!currentLinks.length;
  const progress = job.status === 'running'
    ? 'Scanning index '+job.currentIndex+' · found '+currentLinks.length+' valid link(s)…'
    : 'Found '+currentLinks.length+' valid link(s). '+(job.stopReason || '');
  $('discoverySummary').innerHTML='<div><strong>'+esc(job.status.toUpperCase())+'</strong> · '+esc(progress)+'</div><div class="muted" style="margin-top:5px">Captured: <code>'+esc(job.displayUrl)+'</code></div>';
  $('discoveryLinks').innerHTML=currentLinks.map((x,i) => '<div class="link-item"><span class="pill">#'+esc(x.index)+'</span><code>'+esc(x.url)+'</code><button class="copy-one" data-i="'+i+'">Copy</button></div>').join('');
  document.querySelectorAll('.copy-one').forEach(btn => btn.addEventListener('click', async () => {
    await copyText(currentLinks[Number(btn.dataset.i)].url); btn.textContent='Copied!'; setTimeout(()=>btn.textContent='Copy',800);
  }));
}

function renderLogs(logs) {
  $('logRows').innerHTML=logs.map((l,i) => {
    const cls=l.action==='LOCAL'?'ok':l.action==='FALLBACK'?'warn':'';
    const details=l.action==='LOCAL' ? '<code>'+esc(l.localFile)+'</code>' : (l.reason ? '<span class="warn">'+esc(l.reason)+'</span>' : '<span class="muted">Sony/CDN</span>');
    const action=(l.action==='REMOTE' || l.action==='FALLBACK') && l.url ? '<button class="discover-btn" data-i="'+i+'">Download Links</button>' : '';
    const status=l.status == null ? '…' : l.status;
    return '<tr><td>'+esc((l.timestamp||'').replace('T',' ').replace('Z',''))+'</td><td class="'+cls+'"><strong>'+esc(l.action)+'</strong></td><td>'+esc(status)+'</td><td class="urlcell"><strong>'+esc(l.filename)+'</strong><br><code>'+esc(l.displayUrl||l.url)+'</code></td><td>'+esc(l.range||'')+'</td><td class="pathcell">'+details+'</td><td>'+action+'</td></tr>';
  }).join('');
  document.querySelectorAll('.discover-btn').forEach(btn => btn.addEventListener('click', () => startDiscovery(logs[Number(btn.dataset.i)].url)));
}

async function refresh() {
  try {
    const [status, logs, discoveries, localFiles] = await Promise.all([
      api('/api/status'), api('/api/pkg-logs?limit=500'), api('/api/pkg-discovery'), api('/api/local-files?limit=1500')
    ]);
    lastStatus=status;
    const running=status.proxy.running;
    $('proxyState').innerHTML='<span class="pill '+(running?'ok':'bad')+'">'+(running?'RUNNING':'STOPPED')+'</span>'+(status.proxy.lastError?' <span class="bad">'+esc(status.proxy.lastError)+'</span>':'');
    const rec=status.proxy.recommended || [];
    $('proxyConfig').innerHTML=rec.length
      ? rec.map(x => '<div class="big-config"><code>'+esc(x)+'</code></div>').join('')+'<div class="muted">Use one of these as the PS5 Proxy Server address/port.</div>'
      : '<div class="big-config bad">No LAN IPv4 address detected</div>';
    $('startProxy').disabled=running; $('stopProxy').disabled=!running;

    const local=status.local || {};
    if (local.directory && !$('localDirectory').value) $('localDirectory').value=local.directory;
    $('localSummary').innerHTML=local.directory
      ? '<span class="ok">Mapping enabled</span> · <code>'+esc(local.directory)+'</code> · '+esc(local.pkgCount)+' PKG(s) indexed · '+esc(local.duplicateNames)+' duplicate filename(s)'+(local.error?' · <span class="bad">'+esc(local.error)+'</span>':'')
      : '<span class="muted">No local directory selected. PKG requests will use the CDN normally.</span>';
    $('localRows').innerHTML=localFiles.map(f => '<tr><td>'+esc(f.filename)+'</td><td><code>'+esc(f.file)+'</code></td><td>'+esc(fmtBytes(f.size))+'</td><td class="'+(f.duplicate?'warn':'ok')+'">'+(f.duplicate?'duplicate / fallback':'ready')+'</td></tr>').join('');

    renderLogs(logs);
    renderDiscovery(discoveries);
  } catch(e) { console.error(e); }
}

refresh(); setInterval(refresh, 1500);
</script>
</body>
</html>`;
}

if (settings.localDirectory) {
  try {
    scanLocalDirectory(settings.localDirectory);
    console.log(`Indexed ${localScan.pkgCount} local PKG(s) from ${settings.localDirectory}`);
  } catch (error) {
    localScan.error = error.message;
    console.warn(`Could not scan saved local directory: ${error.message}`);
  }
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
