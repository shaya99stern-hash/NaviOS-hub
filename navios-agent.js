#!/usr/bin/env node
/**
 * NaviOS Hub — companion agent
 * ---------------------------------------------------------------------------
 * Runs on the computer the iPhone plugs into. Detects attach over USB, drives
 * navios_bridge.py (pymobiledevice3), and exposes a token-authenticated
 * WebSocket to the NaviOS Hub PWA on the phone.
 *
 * Node owns transport, auth, discovery, push and job bookkeeping.
 * Python owns the device. Every device capability lives in navios_bridge.py.
 *
 *   pip install "pymobiledevice3>=4.14" pycryptodome
 *   npm  i ws web-push bonjour-service
 *   node navios-agent.js --port 8787
 */

import { WebSocketServer } from 'ws';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, createReadStream, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import webpush from 'web-push';
import { Bonjour } from 'bonjour-service';

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv;
const PORT = Number(argv.includes('--port') ? argv[argv.indexOf('--port') + 1] : 8787);
const PY = argv.includes('--python') ? argv[argv.indexOf('--python') + 1] : 'python3';
const STATE_DIR = join(homedir(), '.navios-hub');
const STATE_FILE = join(STATE_DIR, 'agent.json');

if (!existsSync(STATE_DIR)) mkdirSync(STATE_DIR, { recursive: true });
const state = existsSync(STATE_FILE)
  ? JSON.parse(readFileSync(STATE_FILE, 'utf8'))
  : { token: randomBytes(16).toString('hex'), vapid: webpush.generateVAPIDKeys(), subs: [] };
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
save();
webpush.setVapidDetails('mailto:agent@navios.local', state.vapid.publicKey, state.vapid.privateKey);

/* ── bridge: one long-lived python process, JSON lines both ways ──────────── */
class Bridge {
  constructor() { this.seq = 0; this.pending = new Map(); this.ready = null; this.start(); }

  start() {
    this.proc = spawn(PY, [join(HERE, 'navios_bridge.py')], { stdio: ['pipe', 'pipe', 'pipe'] });
    this.ready = new Promise(res => { this.markReady = res; });
    createInterface({ input: this.proc.stdout }).on('line', line => {
      let m; try { m = JSON.parse(line); } catch { return; }
      if (m.ready) { this.commands = m.commands; return this.markReady(m); }
      const p = this.pending.get(m.id);
      if (!p) return;
      if (m.stream !== undefined) return p.onLine?.(m.stream);
      this.pending.delete(m.id);
      m.ok ? p.resolve(m.data) : p.reject(new Error(m.error || 'bridge error'));
    });
    this.proc.stderr.on('data', b => process.stderr.write('[bridge] ' + b));
    this.proc.on('exit', c => {
      console.error(`[bridge] exited (${c}) — restarting in 1s`);
      for (const p of this.pending.values()) p.reject(new Error('bridge restarted'));
      this.pending.clear();
      setTimeout(() => this.start(), 1000);
    });
  }

  async call(cmd, args = {}, onLine) {
    await this.ready;
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onLine });
      this.proc.stdin.write(JSON.stringify({ id, cmd, ...args }) + '\n');
    });
  }
}
const bridge = new Bridge();

/* ── attach watcher ──────────────────────────────────────────────────────── */
let attached = new Map();

async function poll() {
  let list = [];
  try { list = await bridge.call('devices'); } catch { return; }
  const now = new Map(list.map(d => [d.udid, d]));
  for (const [udid, d] of now) {
    const was = attached.get(udid);
    if (!was) onAttach(udid, d);
    else if (was.trusted !== d.trusted) broadcast({ type: 'device.trust', udid, trusted: d.trusted, device: d });
  }
  for (const udid of attached.keys()) if (!now.has(udid)) broadcast({ type: 'device.detached', udid });
  attached = now;
}
setInterval(poll, 1500);
poll();

async function onAttach(udid, d) {
  // Pull the expensive-but-instant panel data up front so the phone renders
  // a full dashboard the moment it connects, not a spinner.
  let device = null, batt = null;
  try { device = await bridge.call('info', { udid }); } catch {}
  try { batt = await bridge.call('battery.read', { udid }); } catch {}
  broadcast({ type: 'device.attached', udid, device: device || d, battery: batt, trusted: !!device });

  const payload = JSON.stringify({
    title: (device?.name || d.name || 'iPhone') + ' connected',
    body: device
      ? `${device.marketing} · iOS ${device.ios} · battery ${batt?.health ?? '—'}% health — tap for full control`
      : 'Tap Trust on the phone to unlock the full toolkit.',
    url: './NaviOS Hub App.dc.html?autoscan=1&udid=' + udid
  });
  for (const sub of state.subs) webpush.sendNotification(sub, payload).catch(() => {});
}

/* ── transport ───────────────────────────────────────────────────────────── */
const clients = new Set();
const broadcast = m => { const s = JSON.stringify(m); clients.forEach(c => c.readyState === 1 && c.send(s)); };
const okToken = t => {
  const a = Buffer.from(String(t || '')), b = Buffer.from(state.token);
  return a.length === b.length && timingSafeEqual(a, b);
};

const http = createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type,authorization');
  if (req.method === 'OPTIONS') return res.end();
  const url = new URL(req.url, 'http://x');

  if (url.pathname === '/hello')
    return res.end(JSON.stringify({
      agent: 'navios-hub', version: 2, vapid: state.vapid.publicKey,
      devices: [...attached.values()], commands: bridge.commands || []
    }));

  if (url.pathname === '/subscribe' && req.method === 'POST') {
    let body = ''; req.on('data', d => body += d);
    return req.on('end', () => {
      try { state.subs.push(JSON.parse(body)); save(); res.end('{"ok":true}'); }
      catch { res.statusCode = 400; res.end('{"ok":false}'); }
    });
  }

  // Streams a produced artifact (pcap, extracted photo, backup file) to the phone.
  if (url.pathname === '/file' && okToken(url.searchParams.get('token'))) {
    const p = url.searchParams.get('path');
    if (!p || !existsSync(p)) { res.statusCode = 404; return res.end('{}'); }
    res.setHeader('Content-Length', statSync(p).size);
    res.setHeader('Content-Disposition', 'attachment');
    return createReadStream(p).pipe(res);
  }

  res.statusCode = 404; res.end('{}');
});

const wss = new WebSocketServer({ server: http, path: '/ws' });
wss.on('connection', (ws, req) => {
  if (!okToken(new URL(req.url, 'http://x').searchParams.get('token'))) return ws.close(4401, 'bad token');
  clients.add(ws);
  ws.send(JSON.stringify({
    type: 'hello', version: 2, devices: [...attached.values()], commands: bridge.commands || []
  }));

  ws.on('message', async raw => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    const udid = m.udid || [...attached.keys()][0];
    const send = o => ws.readyState === 1 && ws.send(JSON.stringify({ id: m.id, cmd: m.cmd, ...o }));
    if (m.cmd === 'ping') return send({ type: 'pong', ok: true, data: { t: Date.now() } });
    try {
      const data = await bridge.call(m.cmd, { ...m.args, udid }, line => send({ type: 'stream', line }));
      send({ type: m.cmd + '.result', ok: true, data });
    } catch (e) {
      send({ type: m.cmd + '.result', ok: false, error: String(e.message || e) });
    }
  });

  ws.on('close', () => clients.delete(ws));
});

http.listen(PORT, () => {
  new Bonjour().publish({ name: 'NaviOS Hub Agent', type: 'navios', port: PORT, txt: { v: '2' } });
  console.log(`\n  NaviOS Hub agent v2 on :${PORT}`);
  console.log(`  Pair the phone with:\n\n    ws://<this-computer>.local:${PORT}/ws?token=${state.token}\n`);
});
