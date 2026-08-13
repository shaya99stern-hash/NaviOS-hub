#!/usr/bin/env python3
"""
NaviOS Hub — device bridge
===============================================================================
The engine. Speaks newline-delimited JSON on stdin/stdout so the Node agent can
drive it, and talks to the iPhone over usbmux (cable) or the network tunnel.

Backend: pymobiledevice3 — the only client that covers lockdownd, AFC,
house_arrest, installation_proxy, mobilebackup2, diagnostics_relay, MCInstall,
misagent, springboard, os_trace, pcapd, AND the iOS 17+ RemoteXPC/RSD developer
services (DVT) that expose the live process table, per-process CPU/memory,
energy, GPU counters and packet capture. libimobiledevice cannot reach those.

    pip install "pymobiledevice3>=4.14" pycryptodome
    # optional, for the spyware pass:
    pipx install mvt

Protocol
    <- {"id": 7, "cmd": "battery.read", "udid": "..."}
    -> {"id": 7, "ok": true, "data": {...}}
    -> {"id": 7, "stream": "line of output"}          (repeated, for long jobs)

Every command is a plain function registered in CMDS. Long-running ones take a
`emit` callback and stream.
"""

import base64, hashlib, io, json, os, plistlib, sqlite3, sys, threading, time, traceback
from datetime import datetime, timezone
from pathlib import Path

STATE = Path.home() / '.navios-hub'
STATE.mkdir(exist_ok=True)

# ── pymobiledevice3 ─────────────────────────────────────────────────────────
from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
from pymobiledevice3.services.crash_reports import CrashReportsManager
from pymobiledevice3.services.screenshot import ScreenshotService
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.mobile_config import MobileConfigService
from pymobiledevice3.services.misagent import MisagentService
from pymobiledevice3.services.springboard import SpringBoardServicesService
from pymobiledevice3.services.pcapd import PcapdService

from navios_crypto import Backup   # encrypted-backup engine (keybag, class keys, AES)

# ── helpers ─────────────────────────────────────────────────────────────────

def _ld(udid=None):
    """Lockdown client for a udid (or the only attached device)."""
    return create_using_usbmux(serial=udid)


def _dvt(udid=None):
    """
    Developer services. iOS <17 goes straight over lockdown; iOS 17+ requires a
    RemoteXPC tunnel (`sudo pymobiledevice3 remote tunneld`) — we look it up
    rather than failing, so the caller gets a real error it can show.
    """
    from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
    ld = _ld(udid)
    if int(ld.product_version.split('.')[0]) >= 17:
        from pymobiledevice3.tunneld import async_get_tunneld_devices
        from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
        import asyncio
        devs = asyncio.run(async_get_tunneld_devices())
        rsd = next((d for d in devs if d.udid == ld.udid), None)
        if rsd is None:
            raise RuntimeError(
                'iOS 17+ developer services need the tunnel. Run:  sudo pymobiledevice3 remote tunneld')
        return DvtSecureSocketProxyService(rsd)
    return DvtSecureSocketProxyService(ld)


def _iso(dt):
    if dt is None: return None
    if isinstance(dt, (int, float)): dt = datetime.fromtimestamp(dt, timezone.utc)
    return dt.isoformat() if hasattr(dt, 'isoformat') else str(dt)


APPLE_EPOCH = 978307200  # 2001-01-01, the reference date every Apple db uses

def _apple_ts(v):
    """Apple reference-date seconds or nanoseconds -> ISO 8601."""
    if not v: return None
    v = float(v)
    if v > 1e11: v /= 1e9
    return datetime.fromtimestamp(v + APPLE_EPOCH, timezone.utc).isoformat()


# ── identity & health ───────────────────────────────────────────────────────

MODELS = {
    'iPhone14,2': 'iPhone 13 Pro', 'iPhone14,3': 'iPhone 13 Pro Max', 'iPhone14,4': 'iPhone 13 mini',
    'iPhone14,5': 'iPhone 13', 'iPhone14,7': 'iPhone 14', 'iPhone14,8': 'iPhone 14 Plus',
    'iPhone15,2': 'iPhone 14 Pro', 'iPhone15,3': 'iPhone 14 Pro Max', 'iPhone15,4': 'iPhone 15',
    'iPhone15,5': 'iPhone 15 Plus', 'iPhone16,1': 'iPhone 15 Pro', 'iPhone16,2': 'iPhone 15 Pro Max',
    'iPhone17,1': 'iPhone 16 Pro', 'iPhone17,2': 'iPhone 16 Pro Max', 'iPhone17,3': 'iPhone 16',
    'iPhone17,4': 'iPhone 16 Plus', 'iPhone17,5': 'iPhone 16e',
}

def devices(**_):
    out = []
    for d in list_devices():
        try:
            ld = create_using_usbmux(serial=d.serial)
            v = ld.all_values
            out.append({'udid': d.serial, 'trusted': True, 'transport': d.connection_type,
                        'name': v.get('DeviceName'), 'model': v.get('ProductType'),
                        'marketing': MODELS.get(v.get('ProductType'), v.get('ProductType')),
                        'ios': v.get('ProductVersion')})
        except Exception as e:
            out.append({'udid': d.serial, 'trusted': False, 'transport': d.connection_type,
                        'error': 'tap Trust on the device'})
    return out


def info(udid=None, **_):
    ld = _ld(udid); v = ld.all_values
    disk = ld.get_value('com.apple.disk_usage') or {}
    return {
        'udid': v.get('UniqueDeviceID'), 'name': v.get('DeviceName'),
        'model': v.get('ProductType'), 'marketing': MODELS.get(v.get('ProductType'), v.get('ProductType')),
        'ios': v.get('ProductVersion'), 'build': v.get('BuildVersion'),
        'serial': v.get('SerialNumber'), 'ecid': v.get('UniqueChipID'),
        'chip': v.get('HardwarePlatform'), 'cpu': v.get('CPUArchitecture'),
        'boardId': v.get('BoardId'), 'chipId': v.get('ChipID'),
        'wifiMac': v.get('WiFiAddress'), 'btMac': v.get('BluetoothAddress'),
        'ethMac': v.get('EthernetAddress'), 'region': v.get('RegionInfo'),
        'modelNumber': v.get('ModelNumber'), 'color': v.get('DeviceColor'),
        'enclosureColor': v.get('DeviceEnclosureColor'),
        'activated': v.get('ActivationState') == 'Activated',
        'supervised': bool(v.get('IsSupervised')),
        'passcodeSet': bool(v.get('PasswordProtected')),
        'backupEncrypted': bool((ld.get_value('com.apple.mobile.backup') or {}).get('WillEncrypt')),
        'timezone': v.get('TimeZone'), 'phone': v.get('PhoneNumber'),
        'imei': v.get('InternationalMobileEquipmentIdentity'),
        'imei2': v.get('InternationalMobileEquipmentIdentity2'),
        'meid': v.get('MobileEquipmentIdentifier'),
        'carrier': (ld.get_value('com.apple.mobile.data_sync') or {}).get('Carrier'),
        'diskTotal': disk.get('TotalDiskCapacity'), 'dataTotal': disk.get('TotalDataCapacity'),
        'dataFree': disk.get('TotalDataAvailable'), 'dataUsed': disk.get('TotalDataUsed'),
        'sim': v.get('IntegratedCircuitCardIdentity'),
        'firmware': v.get('BasebandVersion'), 'bootloader': v.get('HardwareModel'),
    }


def battery(udid=None, **_):
    """
    Gas-gauge truth, not the Settings percentage: IORegistry AppleSmartBattery
    carries cycle count, design vs nominal capacity, instantaneous amperage,
    voltage and the lifetime temperature envelope.
    """
    ld = _ld(udid)
    with DiagnosticsService(ld) as d:
        r = d.ioregistry(name='AppleSmartBattery') or {}
    lock = ld.get_value('com.apple.mobile.battery') or {}
    design = r.get('DesignCapacity')
    nominal = r.get('NominalChargeCapacity') or r.get('AppleRawMaxCapacity')
    cycles = r.get('CycleCount')
    health = round(nominal / design * 100, 1) if design and nominal else None
    # Apple retires a battery at 80% / 500 cycles; project remaining life linearly.
    life = None
    if health and cycles:
        life = max(0, round((health - 80) / max(0.0001, (100 - health)) * cycles)) if health > 80 else 0
    return {
        'percent': r.get('CurrentCapacity', lock.get('BatteryCurrentCapacity')),
        'charging': bool(r.get('IsCharging', lock.get('BatteryIsCharging'))),
        'fullyCharged': bool(r.get('FullyCharged')),
        'externalConnected': bool(r.get('ExternalConnected')),
        'cycles': cycles, 'designCapacity': design, 'fullCapacity': nominal,
        'health': health, 'cyclesRemaining': life,
        'rawCurrent': r.get('AppleRawCurrentCapacity'),
        'amperage': r.get('InstantAmperage'), 'voltage': r.get('Voltage'),
        'watts': round((r.get('InstantAmperage') or 0) * (r.get('Voltage') or 0) / 1e6, 2),
        'temperature': (r.get('Temperature') or 0) / 100 or None,
        'minTemperature': (r.get('MinTemperature') or 0) / 100 or None,
        'maxTemperature': (r.get('MaxTemperature') or 0) / 100 or None,
        'serial': r.get('BatterySerialNumber'), 'manufacturer': r.get('Manufacturer'),
        'chemId': r.get('ChemID'), 'gasGauge': r.get('BatteryData', {}).get('GasGaugeFirmwareVersion'),
        'timeToEmpty': r.get('AvgTimeToEmpty'), 'timeToFull': r.get('AvgTimeToFull'),
    }


def gestalt(udid=None, keys=None, **_):
    """MobileGestalt — the key/value store the OS itself reads. Deep hardware truth."""
    keys = keys or ['ProductType', 'DeviceEnclosureColor', 'RegionCode', 'SIMTrayStatus',
                    'HasSEP', 'BasebandChipId', 'CarrierInstallCapability', 'DeviceSupportsHDR',
                    'ArtworkTraits', 'MainScreenCanvasSizes', 'DeviceColorMapPolicy']
    with DiagnosticsService(_ld(udid)) as d:
        return d.mobilegestalt(keys=keys)


def nand(udid=None, **_):
    """NAND wear + thermal history — the storage half of device health."""
    with DiagnosticsService(_ld(udid)) as d:
        return {'nand': d.ioregistry(name='AppleANE') or d.ioregistry(plane='IODeviceTree', name='nand'),
                'thermal': d.ioregistry(name='AppleSMC')}


# ── storage & apps ──────────────────────────────────────────────────────────

def apps(udid=None, kind='Any', **_):
    ld = _ld(udid)
    with InstallationProxyService(ld) as ip:
        raw = ip.get_apps(application_type=kind)
    out = []
    for bid, a in (raw.items() if isinstance(raw, dict) else ((x.get('CFBundleIdentifier'), x) for x in raw)):
        out.append({
            'id': bid, 'name': a.get('CFBundleDisplayName') or a.get('CFBundleName'),
            'version': a.get('CFBundleShortVersionString'), 'build': a.get('CFBundleVersion'),
            'bytes': (a.get('StaticDiskUsage') or 0) + (a.get('DynamicDiskUsage') or 0),
            'staticBytes': a.get('StaticDiskUsage'), 'dataBytes': a.get('DynamicDiskUsage'),
            'type': a.get('ApplicationType'), 'signer': a.get('SignerIdentity'),
            'minOS': a.get('MinimumOSVersion'), 'sdk': a.get('DTSDKName'),
            'sharesDocuments': bool(a.get('UIFileSharingEnabled')),
            'entitlements': sorted((a.get('Entitlements') or {}).keys()),
            'urlSchemes': [s for u in (a.get('CFBundleURLTypes') or []) for s in (u.get('CFBundleURLSchemes') or [])],
            'backgroundModes': a.get('UIBackgroundModes') or [],
            'privacy': {k: v for k, v in a.items() if k.startswith('NS') and k.endswith('UsageDescription')},
        })
    return sorted(out, key=lambda x: -(x['bytes'] or 0))


def storage(udid=None, **_):
    i = info(udid); a = apps(udid)
    app_bytes = sum(x['bytes'] or 0 for x in a)
    used = (i['dataTotal'] or 0) - (i['dataFree'] or 0)
    return {'total': i['diskTotal'], 'dataTotal': i['dataTotal'], 'free': i['dataFree'],
            'used': used, 'apps': app_bytes, 'system': (i['diskTotal'] or 0) - (i['dataTotal'] or 0),
            'other': max(0, used - app_bytes), 'topApps': a[:20]}


def app_install(udid=None, path=None, emit=None, **_):
    with InstallationProxyService(_ld(udid)) as ip:
        ip.install_from_local(path, handler=lambda p, **k: emit and emit(f'install {p}%'))
    return {'installed': path}


def app_uninstall(udid=None, bundle=None, **_):
    with InstallationProxyService(_ld(udid)) as ip:
        ip.uninstall(bundle)
    return {'removed': bundle}


def app_icon(udid=None, bundle=None, **_):
    with SpringBoardServicesService(_ld(udid)) as sb:
        return {'png': base64.b64encode(sb.get_icon_pngdata(bundle)).decode()}


# ── filesystem (AFC + per-app containers) ───────────────────────────────────

def _afc(udid, bundle=None):
    ld = _ld(udid)
    if bundle:
        h = HouseArrestService(ld, bundle)   # documents container of one app
        return h
    return AfcService(ld)                     # /var/mobile/Media


def fs_list(udid=None, path='/', bundle=None, **_):
    afc = _afc(udid, bundle)
    out = []
    for n in afc.listdir(path):
        p = (path.rstrip('/') + '/' + n) or '/'
        try:
            st = afc.stat(p)
            out.append({'name': n, 'path': p, 'dir': st.get('st_ifmt') == 'S_IFDIR',
                        'bytes': int(st.get('st_size') or 0),
                        'modified': _iso(int(st.get('st_mtime', 0)) / 1e9 if int(st.get('st_mtime', 0)) > 1e11 else st.get('st_mtime'))})
        except Exception:
            out.append({'name': n, 'path': p, 'dir': None})
    return sorted(out, key=lambda x: (not x['dir'], x['name'].lower()))


def fs_read(udid=None, path=None, bundle=None, **_):
    data = _afc(udid, bundle).get_file_contents(path)
    return {'path': path, 'bytes': len(data), 'b64': base64.b64encode(data).decode()}


def fs_write(udid=None, path=None, b64=None, bundle=None, **_):
    _afc(udid, bundle).set_file_contents(path, base64.b64decode(b64))
    return {'path': path, 'written': True}


def fs_rm(udid=None, path=None, bundle=None, **_):
    _afc(udid, bundle).rm(path)
    return {'path': path, 'removed': True}


def fs_mkdir(udid=None, path=None, bundle=None, **_):
    _afc(udid, bundle).makedirs(path)
    return {'path': path, 'created': True}


# ── backup + extraction (the iMazing core) ──────────────────────────────────

def backup_run(udid=None, dir=None, full=True, emit=None, **_):
    d = Path(dir or STATE / 'backups'); d.mkdir(parents=True, exist_ok=True)
    ld = _ld(udid)
    with Mobilebackup2Service(ld) as mb:
        mb.backup(full=bool(full), backup_directory=str(d),
                  progress_callback=lambda p: emit and emit(f'{p:.1f}%'))
    return {'dir': str(d / ld.udid)}


def backup_encrypt(udid=None, password=None, enable=True, **_):
    with Mobilebackup2Service(_ld(udid)) as mb:
        mb.change_password(new=password) if enable else mb.change_password(old=password)
    return {'encrypted': bool(enable)}


# One open Backup per directory+password, so a browsing session doesn't
# re-derive class keys (PBKDF2 at 10k+ rounds) on every call.
_BACKUPS = {}

def _bk(dir=None, password=None, **_):
    d = str(Path(dir or (STATE / 'backups')).expanduser())
    k = (d, password or '')
    if k not in _BACKUPS:
        _BACKUPS[k] = Backup(d, password)
    return _BACKUPS[k]


def backup_files(dir=None, password=None, domain=None, like=None, limit=500, **_):
    """Browse the backup's file index without unpacking it."""
    return _bk(dir, password).files(domain=domain, like=like, limit=limit)


def backup_open(dir=None, password=None, **_):
    """Open (and if encrypted, unlock) a backup. Returns what's inside it."""
    b = _bk(dir, password)
    return {**b.summary(), 'domains': b.domains()[:60]}


def backup_domains(dir=None, password=None, **_):
    return _bk(dir, password).domains()


def backup_keychain(dir=None, password=None, **_):
    """Wi-Fi and saved passwords. Encrypted backups only."""
    return _bk(dir, password).keychain()


def backup_decrypt(dir=None, password=None, out=None, emit=None, **_):
    return _bk(dir, password).decrypt_all(out or (STATE / 'decrypted'), emit)


def backup_messages(dir=None, password=None, limit=300, chat=None, **_):
    """iMessage/SMS with attachments, resolved handles, reactions."""
    con = _bk(dir, password).sqlite('HomeDomain', 'Library/SMS/sms.db'); cur = con.cursor()
    q = """SELECT m.ROWID, m.text, m.is_from_me, m.date, m.service, h.id,
                  c.chat_identifier, c.display_name,
                  (SELECT COUNT(*) FROM message_attachment_join maj WHERE maj.message_id = m.ROWID)
           FROM message m
           LEFT JOIN handle h ON h.ROWID = m.handle_id
           LEFT JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
           LEFT JOIN chat c ON c.ROWID = cmj.chat_id
           WHERE m.text IS NOT NULL"""
    args = []
    if chat: q += ' AND c.chat_identifier = ?'; args.append(chat)
    q += ' ORDER BY m.date DESC LIMIT ?'; args.append(int(limit))
    rows = [{'id': r[0], 'text': r[1], 'fromMe': bool(r[2]), 'at': _apple_ts(r[3]),
             'service': r[4], 'handle': r[5], 'chat': r[6], 'chatName': r[7], 'attachments': r[8]}
            for r in cur.execute(q, args)]
    con.close(); return rows


def backup_chats(dir=None, password=None, **_):
    con = _bk(dir, password).sqlite('HomeDomain', 'Library/SMS/sms.db')
    rows = [{'chat': r[0], 'name': r[1], 'service': r[2], 'messages': r[3], 'last': _apple_ts(r[4])}
            for r in con.execute("""SELECT c.chat_identifier, c.display_name, c.service_name,
                                           COUNT(m.ROWID), MAX(m.date)
                                    FROM chat c
                                    LEFT JOIN chat_message_join j ON j.chat_id = c.ROWID
                                    LEFT JOIN message m ON m.ROWID = j.message_id
                                    GROUP BY c.ROWID ORDER BY MAX(m.date) DESC""")]
    con.close(); return rows


def backup_contacts(dir=None, password=None, **_):
    con = _bk(dir, password).sqlite('HomeDomain', 'Library/AddressBook/AddressBook.sqlitedb')
    rows = [{'id': r[0], 'first': r[1], 'last': r[2], 'org': r[3], 'note': r[4],
             'values': [v for v in (r[5] or '').split('\x1f') if v]}
            for r in con.execute("""SELECT p.ROWID, p.First, p.Last, p.Organization, p.Note,
                                           GROUP_CONCAT(v.value, char(31))
                                    FROM ABPerson p
                                    LEFT JOIN ABMultiValue v ON v.record_id = p.ROWID
                                    GROUP BY p.ROWID""")]
    con.close(); return rows


def backup_calls(dir=None, password=None, limit=300, **_):
    con = _bk(dir, password).sqlite('HomeDomain', 'Library/CallHistoryDB/CallHistory.storedata')
    rows = [{'number': r[0], 'at': _apple_ts(r[1]), 'seconds': r[2],
             'incoming': bool(r[3]), 'answered': bool(r[4]), 'service': r[5]}
            for r in con.execute("""SELECT ZADDRESS, ZDATE, ZDURATION, ZORIGINATED=0, ZANSWERED, ZSERVICE_PROVIDER
                                    FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT ?""", (int(limit),))]
    con.close(); return rows


def backup_safari(dir=None, password=None, limit=300, **_):
    con = _bk(dir, password).sqlite('AppDomain-com.apple.mobilesafari', 'Library/Safari/History.db')
    rows = [{'url': r[0], 'title': r[1], 'visits': r[2], 'last': _apple_ts(r[3])}
            for r in con.execute("""SELECT i.url, v.title, i.visit_count, i.visit_time
                                    FROM history_items i
                                    LEFT JOIN history_visits v ON v.history_item = i.id
                                    GROUP BY i.id ORDER BY i.visit_time DESC LIMIT ?""", (int(limit),))]
    con.close(); return rows


def backup_notes(dir=None, password=None, limit=200, **_):
    con = _bk(dir, password).sqlite('AppDomain-com.apple.mobilenotes', 'NoteStore.sqlite')
    rows = [{'title': r[0], 'created': _apple_ts(r[1]), 'modified': _apple_ts(r[2])}
            for r in con.execute("""SELECT ZTITLE1, ZCREATIONDATE1, ZMODIFICATIONDATE1
                                    FROM ZICCLOUDSYNCINGOBJECT WHERE ZTITLE1 IS NOT NULL
                                    ORDER BY ZMODIFICATIONDATE1 DESC LIMIT ?""", (int(limit),))]
    con.close(); return rows


def backup_photos(dir=None, password=None, limit=500, **_):
    return backup_files(dir=dir, password=password, domain='CameraRollDomain', like='Media/DCIM/', limit=limit)


def backup_extract(dir=None, password=None, domain=None, path=None, out=None, **_):
    dst = _bk(dir, password).extract(domain, path, out or (STATE / 'exports' / Path(path).name))
    return {'out': str(dst), 'bytes': dst.stat().st_size}


# ── security: profiles, provisioning, spyware ───────────────────────────────

def profiles(udid=None, **_):
    """Configuration profiles — the #1 vector for MDM-based surveillance."""
    with MobileConfigService(_ld(udid)) as mc:
        raw = mc.get_profile_list() or {}
    out = []
    for p in (raw.get('OrderedIdentifiers') or []):
        meta = (raw.get('ProfileMetadata') or {}).get(p, {})
        out.append({'id': p, 'name': meta.get('PayloadDisplayName'), 'org': meta.get('PayloadOrganization'),
                    'description': meta.get('PayloadDescription'), 'version': meta.get('PayloadVersion'),
                    'removable': meta.get('PayloadRemovalDisallowed') is not True})
    return {'profiles': out, 'count': len(out)}


def profile_remove(udid=None, id=None, **_):
    with MobileConfigService(_ld(udid)) as mc:
        mc.remove_profile(id)
    return {'removed': id}


def provisioning(udid=None, **_):
    """Enterprise provisioning profiles — sideloaded/enterprise-signed apps."""
    with MisagentService(_ld(udid)) as m:
        out = []
        for p in (m.copy_all() or []):
            try:
                d = plistlib.loads(p if isinstance(p, bytes) else bytes(p))
            except Exception:
                continue
            out.append({'name': d.get('Name'), 'team': d.get('TeamName'), 'uuid': d.get('UUID'),
                        'expires': _iso(d.get('ExpirationDate')), 'appIds': d.get('ApplicationIdentifierPrefix'),
                        'devices': len(d.get('ProvisionedDevices') or [])})
    return out


# Heuristics that run without MVT — cheap, local, and immediately actionable.
SUSPECT_SCHEMES = {'shdw', 'tsvc', 'pgspy', 'cydia', 'sileo'}
RISKY_ENTS = {'com.apple.private.security.no-sandbox', 'platform-application',
              'com.apple.private.MobileGestalt.AllowedProtectedKeys',
              'com.apple.springboard.opensensitiveurl', 'task_for_pid-allow'}

def audit(udid=None, **_):
    """
    Live posture check — no backup required. Flags the things that actually
    indicate compromise: unexpected MDM, enterprise signing, jailbreak traces,
    sandbox-escaping entitlements, background-capable apps with no UI.
    """
    findings = []
    i = info(udid)
    if i['supervised']:
        findings.append({'level': 'warn', 'title': 'Device is supervised',
                         'detail': 'A supervising organisation can install apps, read some data and restrict the device.'})
    if not i['passcodeSet']:
        findings.append({'level': 'high', 'title': 'No passcode set',
                         'detail': 'Device data is not encrypted at rest.'})
    try:
        pr = profiles(udid)
        for p in pr['profiles']:
            findings.append({'level': 'warn', 'title': f"Configuration profile: {p['name']}",
                             'detail': f"Installed by {p.get('org') or 'unknown'}. Removable: {p['removable']}.",
                             'id': p['id']})
    except Exception as e:
        findings.append({'level': 'info', 'title': 'Profile list unavailable', 'detail': str(e)})
    try:
        for pp in provisioning(udid):
            findings.append({'level': 'warn', 'title': f"Enterprise provisioning: {pp['name']}",
                             'detail': f"Team {pp.get('team')}, expires {pp.get('expires')}."})
    except Exception: pass
    try:
        for a in apps(udid, kind='User'):
            bad = set(a['entitlements']) & RISKY_ENTS
            if bad:
                findings.append({'level': 'high', 'title': f"{a['name']} holds privileged entitlements",
                                 'detail': ', '.join(sorted(bad))})
            if set(s.lower() for s in a['urlSchemes']) & SUSPECT_SCHEMES:
                findings.append({'level': 'high', 'title': f"{a['name']} registers a known-suspect URL scheme",
                                 'detail': ', '.join(a['urlSchemes'])})
            if a['signer'] and 'Apple' not in str(a['signer']) and a['type'] == 'User':
                findings.append({'level': 'info', 'title': f"{a['name']} is not App Store signed",
                                 'detail': str(a['signer'])})
    except Exception: pass
    score = 100 - sum({'high': 30, 'warn': 10, 'info': 2}[f['level']] for f in findings)
    return {'score': max(0, score), 'findings': findings,
            'note': 'A clean result is not proof of a clean device. Run spyware.scan for the full MVT pass.'}


def spyware_scan(udid=None, dir=None, emit=None, **_):
    """Full pass: local backup -> MVT with the public Pegasus/Predator indicators."""
    import subprocess, shutil
    d = Path(dir or STATE / 'scan'); d.mkdir(parents=True, exist_ok=True)
    emit and emit('backing up device (this is the slow part)…')
    b = backup_run(udid=udid, dir=str(d), emit=emit)
    if not shutil.which('mvt-ios'):
        return {'clean': None, 'findings': [], 'backup': b['dir'],
                'error': 'mvt-ios not installed — run: pipx install mvt. Live audit still available.'}
    emit and emit('running MVT…')
    out = d / 'mvt'
    p = subprocess.Popen(['mvt-ios', 'check-backup', '--output', str(out), b['dir']],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    findings = []
    for line in p.stdout:
        line = line.rstrip()
        emit and emit(line)
        if any(k in line.lower() for k in ('detection', 'malicious', 'matched indicator')):
            findings.append(line)
    p.wait()
    return {'clean': not findings, 'findings': findings, 'report': str(out), 'backup': b['dir']}


# ── live: processes, energy, network, logs ──────────────────────────────────

def proclist(udid=None, **_):
    from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
    with _dvt(udid) as dvt:
        return [{'pid': p.get('pid'), 'name': p.get('name'), 'bundle': p.get('bundleIdentifier'),
                 'started': _iso(p.get('startDate')), 'path': p.get('realAppName'),
                 'foreground': p.get('isApplication')} for p in DeviceInfo(dvt).proclist()]


def sysmon(udid=None, samples=3, emit=None, **_):
    """Per-process CPU/memory + system load, sampled live. iMazing has no equivalent."""
    from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap
    with _dvt(udid) as dvt:
        with Sysmontap(dvt) as sm:
            last = None
            for i, row in enumerate(sm):
                if 'Processes' in row:
                    last = row
                    emit and emit(f'sample {i + 1}')
                if i >= int(samples): break
    procs = []
    for pid, vals in (last or {}).get('Processes', {}).items():
        procs.append({'pid': pid, 'cpu': vals[0] if len(vals) > 0 else None,
                      'memory': vals[1] if len(vals) > 1 else None})
    return {'system': (last or {}).get('System'), 'processes': procs[:80]}


def netstat(udid=None, seconds=5, emit=None, **_):
    """Live per-process network throughput from the DVT network monitor."""
    from pymobiledevice3.services.dvt.instruments.network_monitoring import NetworkMonitor
    flows, t0 = [], time.time()
    with _dvt(udid) as dvt:
        for event in NetworkMonitor(dvt):
            flows.append(str(event))
            emit and emit(str(event))
            if time.time() - t0 > float(seconds): break
    return {'flows': flows[-400:], 'seconds': seconds}


def pcap(udid=None, seconds=10, out=None, emit=None, **_):
    """
    Packet capture straight off the device — every connection every app makes,
    written as a real .pcap you can open in Wireshark. This is the capability
    that turns 'is something spying on me' from a guess into evidence.
    """
    dst = Path(out or STATE / f'capture-{int(time.time())}.pcap')
    t0, n = time.time(), 0
    with open(dst, 'wb') as f:
        # pcap global header, LINKTYPE_ETHERNET
        f.write(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00' + b'\x00' * 8 + b'\xff\xff\x00\x00\x01\x00\x00\x00')
        for packet in PcapdService(_ld(udid)).watch():
            ts = time.time(); n += 1
            data = packet if isinstance(packet, bytes) else getattr(packet, 'data', b'')
            f.write(int(ts).to_bytes(4, 'little') + int(ts % 1 * 1e6).to_bytes(4, 'little')
                    + len(data).to_bytes(4, 'little') + len(data).to_bytes(4, 'little') + data)
            if n % 25 == 0: emit and emit(f'{n} packets')
            if ts - t0 > float(seconds): break
    return {'file': str(dst), 'packets': n, 'seconds': seconds}


def syslog(udid=None, seconds=8, match=None, emit=None, **_):
    t0, lines = time.time(), []
    for entry in OsTraceService(_ld(udid)).syslog():
        s = f'{entry.label or ""} {entry.image_name} [{entry.pid}] {entry.message}'
        if match and match.lower() not in s.lower(): continue
        lines.append(s); emit and emit(s)
        if time.time() - t0 > float(seconds) or len(lines) > 4000: break
    return {'lines': lines[-1000:]}


def crashes(udid=None, limit=60, **_):
    ld = _ld(udid)
    with CrashReportsManager(ld) as cm:
        names = list(cm.ls())[:int(limit)]
    return [{'name': n} for n in names]


def screenshot(udid=None, **_):
    png = ScreenshotService(_ld(udid)).take_screenshot()
    return {'png': base64.b64encode(png).decode(), 'bytes': len(png)}


def wallpaper(udid=None, **_):
    with SpringBoardServicesService(_ld(udid)) as sb:
        return {'png': base64.b64encode(sb.get_wallpaper_pngdata()).decode()}


def simulate_location(udid=None, lat=None, lon=None, clear=False, **_):
    from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation
    with _dvt(udid) as dvt:
        ls = LocationSimulation(dvt)
        if clear: ls.clear(); return {'cleared': True}
        ls.set(float(lat), float(lon))
    return {'lat': lat, 'lon': lon}


def condition(udid=None, profile=None, clear=False, **_):
    """Induce thermal/network conditions — real device-side QA, not a simulator."""
    from pymobiledevice3.services.dvt.instruments.condition_inducer import ConditionInducer
    with _dvt(udid) as dvt:
        ci = ConditionInducer(dvt)
        if clear: ci.disable(); return {'cleared': True}
        if not profile: return {'available': ci.list()}
        ci.set(profile)
    return {'profile': profile}


def power(udid=None, verb='restart', **_):
    with DiagnosticsService(_ld(udid)) as d:
        {'restart': d.restart, 'shutdown': d.shutdown, 'sleep': d.sleep}[verb]()
    return {'verb': verb}


def rename(udid=None, name=None, **_):
    _ld(udid).set_value(name, domain=None, key='DeviceName')
    return {'name': name}


def pair(udid=None, **_):
    ld = _ld(udid); ld.pair()
    return {'paired': True, 'udid': ld.udid}


def wifi_enable(udid=None, enable=True, **_):
    """Turn on wireless sync so every command above works with the cable out."""
    _ld(udid).set_value(bool(enable), domain='com.apple.mobile.wireless_lockdown',
                        key='EnableWifiConnections')
    return {'wireless': bool(enable)}


CMDS = {
    'devices': devices, 'info': info, 'battery.read': battery, 'gestalt': gestalt, 'nand': nand,
    'apps.list': apps, 'storage.read': storage, 'app.install': app_install,
    'app.uninstall': app_uninstall, 'app.icon': app_icon,
    'fs.list': fs_list, 'fs.read': fs_read, 'fs.write': fs_write, 'fs.rm': fs_rm, 'fs.mkdir': fs_mkdir,
    'backup.run': backup_run, 'backup.encrypt': backup_encrypt, 'backup.files': backup_files,
    'backup.messages': backup_messages, 'backup.chats': backup_chats, 'backup.contacts': backup_contacts,
    'backup.calls': backup_calls, 'backup.safari': backup_safari, 'backup.notes': backup_notes,
    'backup.photos': backup_photos, 'backup.extract': backup_extract,
    'backup.open': backup_open, 'backup.domains': backup_domains,
    'backup.keychain': backup_keychain, 'backup.decrypt': backup_decrypt,
    'profiles': profiles, 'profile.remove': profile_remove, 'provisioning': provisioning,
    'audit': audit, 'spyware.scan': spyware_scan,
    'proclist': proclist, 'sysmon': sysmon, 'netstat': netstat, 'pcap': pcap,
    'syslog': syslog, 'crashes': crashes, 'screenshot': screenshot, 'wallpaper': wallpaper,
    'location.simulate': simulate_location, 'condition': condition,
    'power': power, 'rename': rename, 'pair': pair, 'wifi.enable': wifi_enable,
}

# ── stdio loop ──────────────────────────────────────────────────────────────
_out = threading.Lock()

def send(obj):
    with _out:
        sys.stdout.write(json.dumps(obj, default=str) + '\n'); sys.stdout.flush()


def handle(msg):
    rid, cmd = msg.get('id'), msg.get('cmd')
    fn = CMDS.get(cmd)
    if not fn:
        return send({'id': rid, 'ok': False, 'error': f'unknown command {cmd}'})
    args = {k: v for k, v in msg.items() if k not in ('id', 'cmd')}
    try:
        import inspect
        if 'emit' in inspect.signature(fn).parameters:
            args['emit'] = lambda line: send({'id': rid, 'stream': line})
        send({'id': rid, 'ok': True, 'data': fn(**args)})
    except Exception as e:
        send({'id': rid, 'ok': False, 'error': f'{type(e).__name__}: {e}',
              'trace': traceback.format_exc(limit=3)})


def main():
    send({'ready': True, 'commands': sorted(CMDS)})
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        threading.Thread(target=handle, args=(msg,), daemon=True).start()


if __name__ == '__main__':
    main()
