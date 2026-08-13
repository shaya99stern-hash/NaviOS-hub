# NaviOS Hub — companion agent

The phone half of NaviOS Hub is a PWA. Safari can read storage, sensors, network
and display; it cannot read the USB bus, the battery gas gauge, the serial
number, backups, configuration profiles or the system log. Those live behind
Apple's `lockdownd` services and are only reachable from a **paired host** over
usbmux — hence this agent.

Two processes:

- **`navios-agent.js`** — transport. Bonjour discovery, token auth, WebSocket,
  Web Push, artifact download, attach/detach watching.
- **`navios_crypto.py`** — the encrypted-backup engine: Apple keybag, class
  keys, per-file AES. No third-party backup library.
- **`navios_bridge.py`** — the device engine. Every device capability, over
  [pymobiledevice3](https://github.com/doronz88/pymobiledevice3), which is the
  only client that reaches both classic lockdownd services *and* the iOS 17+
  RemoteXPC/DVT instruments (live process table, per-process CPU, packet
  capture). libimobiledevice cannot reach those.

## Install

```sh
cd agent
npm run setup            # pip -r requirements.txt + npm install
pipx install mvt         # optional — full spyware pass
npm start -- --port 8787
```

It prints a pairing URL. Open **NaviOS Hub** on the phone → Settings → paste it.
The token lives in `~/.navios-hub/agent.json` (mode 600).

For live process/network instruments on **iOS 17+**, also run once:

```sh
sudo pymobiledevice3 remote tunneld
```

## Against iMazing

| Capability | iMazing | NaviOS Hub |
| --- | --- | --- |
| Device identity, IMEI, ECID, activation | ✅ | ✅ `info` |
| Battery % and cycle count | ✅ | ✅ `battery.read` — **plus** design vs nominal capacity, instantaneous amperage/watts, voltage, lifetime temperature envelope, cell serial, chem ID, projected cycles to 80% |
| Backups, incremental + encrypted | ✅ | ✅ `backup.run`, `backup.encrypt` |
| **Read *encrypted* backups** | ✅ | ✅ `backup.open` with a password — full Apple keybag implementation (TLV parse, iOS 10.2+ double-round KDF, RFC 3394 class-key unwrap, per-file AES-256-CBC). Every extractor below works on encrypted backups, which is the only place Keychain, Health and call history exist |
| **Keychain / saved Wi-Fi & app passwords** | partial | ✅ `backup.keychain` |
| **Decrypt a backup to a plain tree** | ❌ | ✅ `backup.decrypt` |
| Browse/extract messages, contacts, calls, Safari, notes, photos | ✅ | ✅ `backup.messages` / `.chats` / `.contacts` / `.calls` / `.safari` / `.notes` / `.photos` / `.extract` — read straight out of `Manifest.db`, no unpack step |
| App install / uninstall / list | ✅ | ✅ `app.install`, `app.uninstall`, `apps.list` — **plus** per-app entitlements, URL schemes, background modes and privacy-usage strings |
| File system + per-app documents | ✅ | ✅ `fs.list/read/write/rm/mkdir`, AFC and House Arrest |
| Spyware analyzer (MVT) | ✅ | ✅ `spyware.scan` |
| **Live security audit, no backup needed** | ❌ | ✅ `audit` — MDM profiles, enterprise provisioning, sandbox-escaping entitlements, suspect URL schemes, unsigned apps, scored |
| **Configuration profile removal** | ❌ | ✅ `profiles`, `profile.remove` |
| **Live process table + per-process CPU/memory** | ❌ | ✅ `proclist`, `sysmon` |
| **On-device packet capture → real .pcap** | ❌ | ✅ `pcap` — every connection every app makes, openable in Wireshark |
| **Per-process live network flows** | ❌ | ✅ `netstat` |
| **Structured system log with predicates** | partial | ✅ `syslog` via `os_trace` |
| **MobileGestalt / IORegistry raw queries** | ❌ | ✅ `gestalt`, `nand` |
| **GPS simulation** | ❌ | ✅ `location.simulate` |
| **Thermal / network condition inducer** | ❌ | ✅ `condition` |
| Screenshot, wallpaper, app icons | partial | ✅ `screenshot`, `wallpaper`, `app.icon` |
| Crash reports | ✅ | ✅ `crashes` |
| Power: sleep / restart / shutdown | ✅ | ✅ `power` |
| Wireless sync toggle | ✅ | ✅ `wifi.enable` |

## Over Wi-Fi

`wifi.enable` sets `EnableWifiConnections` on the device. After one USB pair it
advertises `_apple-mobdev2._tcp` over Bonjour and usbmuxd routes to it
wirelessly — every command above then works with the cable unplugged, on the
same network. The cable makes it faster and unlocks the DVT instruments; it is
not required for the rest.

## Auto-activate

`poll()` diffs the device list every 1.5s. On a new UDID the agent pre-fetches
identity **and** battery, broadcasts `device.attached` with both, and sends a
Web Push — so the phone renders a full dashboard on connect instead of a
spinner, even if the app was closed (iOS 16.4+, home-screen install required).

## Protocol

```
→ { id, cmd, udid?, args? }              over ws://host:8787/ws?token=…
← { id, cmd, type:"<cmd>.result", ok, data | error }
← { id, cmd, type:"stream", line }       backup progress, MVT, pcap, syslog
← { type:"device.attached"|"device.detached"|"device.trust", udid, device, battery }
GET /hello                               unauthenticated discovery + command list
GET /file?token=…&path=…                 download a produced artifact
```

`GET /hello` returns the live command list, so the PWA never hard-codes it — new
bridge commands appear in the app without a client update.

## Safety

- Binds the LAN, not the internet. Do not port-forward it.
- Every socket needs the token; there is no unauthenticated command path.
- Backups, captures and MVT output stay on the computer. Nothing is uploaded.
- `power shutdown`, `profile.remove`, `app.uninstall` and `fs.rm` are real.
  There is no undo.
- A clean `audit` or `spyware.scan` is not proof of a clean device.
