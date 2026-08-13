#!/usr/bin/env python3
"""
NaviOS Hub — encrypted backup engine
===============================================================================
iOS encrypted backups are where the data that matters actually lives: Keychain,
Health, call history, Safari history and saved passwords are *silently dropped*
from unencrypted backups. Reading them means implementing Apple's backup keybag
end to end. This module does that.

Format (per file, all little details load-bearing):

  Manifest.plist
    ├─ IsEncrypted        bool
    ├─ BackupKeyBag       TLV blob — the keybag
    └─ ManifestKey        4-byte protection class || wrapped AES key for Manifest.db

  Keybag TLV: 4-byte ASCII tag, 4-byte big-endian length, value.
    VERS TYPE UUID HMCK WRAP SALT ITER      — header
    DPWT DPIC DPSL                          — iOS 10.2+ double-round KDF params
    CLAS WRAP WPKY KTYP PBKY                — repeated, one run per class

  Key derivation
    iOS 10.2+ : PBKDF2-SHA256(pw, DPSL, DPIC) -> PBKDF2-SHA1(that, SALT, ITER)
    earlier   : PBKDF2-SHA1(pw, SALT, ITER)

  Per class: if WRAP & 2, RFC 3394 AES-unwrap WPKY with the derived key.
  Per file : the Files.file blob is an NSKeyedArchiver plist; its EncryptionKey
             is 4-byte class || wrapped key. Unwrap with that class key, then
             AES-256-CBC with a zero IV, then truncate to the recorded Size.

    pip install pycryptodome
"""

import hashlib, plistlib, shutil, sqlite3, struct
from pathlib import Path

from Crypto.Cipher import AES

# ── RFC 3394 AES key unwrap ─────────────────────────────────────────────────
IV = 0xA6A6A6A6A6A6A6A6


def aes_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """RFC 3394 key unwrap. Returns the unwrapped key, or raises on IV mismatch."""
    n = len(wrapped) // 8 - 1
    a = int.from_bytes(wrapped[:8], 'big')
    r = [int.from_bytes(wrapped[8 * (i + 1):8 * (i + 2)], 'big') for i in range(n)]
    dec = AES.new(kek, AES.MODE_ECB)
    for j in range(5, -1, -1):
        for i in range(n - 1, -1, -1):
            t = n * j + i + 1
            b = dec.decrypt(((a ^ t) << 64 | r[i]).to_bytes(16, 'big'))
            a = int.from_bytes(b[:8], 'big')
            r[i] = int.from_bytes(b[8:], 'big')
    if a != IV:
        raise ValueError('key unwrap failed — wrong backup password')
    return b''.join(x.to_bytes(8, 'big') for x in r)


# ── keybag ──────────────────────────────────────────────────────────────────
CLASS_TAGS = {'CLAS', 'WRAP', 'WPKY', 'KTYP', 'PBKY'}


class Keybag:
    def __init__(self, blob: bytes):
        self.attrs, self.classes, cur = {}, {}, None
        i = 0
        while i + 8 <= len(blob):
            tag = blob[i:i + 4].decode('ascii', 'replace')
            ln = struct.unpack('>I', blob[i + 4:i + 8])[0]
            val = blob[i + 8:i + 8 + ln]
            i += 8 + ln
            if ln == 4:
                val_int = struct.unpack('>I', val)[0]
            else:
                val_int = None
            if tag == 'CLAS':
                cur = val_int
                self.classes[cur] = {}
            elif tag in CLASS_TAGS and cur is not None:
                self.classes[cur][tag] = val_int if ln == 4 else val
            else:
                self.attrs[tag] = val_int if ln == 4 else val
        self.unlocked = False

    def unlock(self, password: str):
        pw = password.encode('utf-8')
        salt, iters = self.attrs['SALT'], self.attrs['ITER']
        if 'DPSL' in self.attrs and 'DPIC' in self.attrs:
            # iOS 10.2+ : SHA256 pre-round, then the classic SHA1 round.
            pw = hashlib.pbkdf2_hmac('sha256', pw, self.attrs['DPSL'], self.attrs['DPIC'], 32)
        key = hashlib.pbkdf2_hmac('sha1', pw, salt, iters, 32)
        ok = 0
        for cid, c in self.classes.items():
            if c.get('WPKY') and (c.get('WRAP', 0) & 2):
                try:
                    c['KEY'] = aes_unwrap(key, c['WPKY']); ok += 1
                except ValueError:
                    pass
        if not ok:
            raise ValueError('wrong backup password — no class key unwrapped')
        self.unlocked = True
        return self

    def unwrap_file_key(self, blob: bytes) -> bytes:
        """blob = 4-byte protection class || wrapped key."""
        cid = struct.unpack('<I', blob[:4])[0]
        c = self.classes.get(cid)
        if not c or 'KEY' not in c:
            raise ValueError(f'no key for protection class {cid} (keybag locked?)')
        return aes_unwrap(c['KEY'], blob[4:])


def _decrypt(data: bytes, key: bytes, size=None) -> bytes:
    out = AES.new(key, AES.MODE_CBC, b'\x00' * 16).decrypt(data)
    if size is not None:
        return out[:size]
    pad = out[-1]                      # PKCS#7 when no recorded size
    return out[:-pad] if 1 <= pad <= 16 else out


# ── backup ──────────────────────────────────────────────────────────────────
class Backup:
    """
    An on-disk backup directory, encrypted or not. Same API either way — the
    rest of the bridge never has to care which it is holding.
    """

    def __init__(self, path, password=None):
        self.dir = Path(path)
        mp = self.dir / 'Manifest.plist'
        if not mp.exists():
            raise RuntimeError(f'not a backup directory: {self.dir}')
        self.manifest = plistlib.loads(mp.read_bytes())
        self.encrypted = bool(self.manifest.get('IsEncrypted'))
        self.info = plistlib.loads((self.dir / 'Info.plist').read_bytes()) \
            if (self.dir / 'Info.plist').exists() else {}
        self.keybag = None
        self._db = None
        if self.encrypted:
            if not password:
                raise RuntimeError('backup is encrypted — password required')
            self.keybag = Keybag(self.manifest['BackupKeyBag']).unlock(password)

    # -- Manifest.db ---------------------------------------------------------
    def db(self):
        if self._db: return self._db
        src = self.dir / 'Manifest.db'
        if not src.exists():
            raise RuntimeError('Manifest.db missing (backup incomplete?)')
        if self.encrypted:
            key = self.keybag.unwrap_file_key(self.manifest['ManifestKey'])
            plain = _decrypt(src.read_bytes(), key)
            tmp = self.dir / '.Manifest.decrypted.db'
            tmp.write_bytes(plain)
            self._db = sqlite3.connect(f'file:{tmp}?mode=ro', uri=True)
        else:
            self._db = sqlite3.connect(f'file:{src}?mode=ro', uri=True)
        self._db.row_factory = sqlite3.Row
        return self._db

    # -- file access ---------------------------------------------------------
    def _row(self, domain, rel):
        return self.db().execute(
            'SELECT fileID, file FROM Files WHERE domain=? AND relativePath=?', (domain, rel)).fetchone()

    @staticmethod
    def _meta(blob):
        """NSKeyedArchiver blob -> (size, encryption-key-blob or None)."""
        p = plistlib.loads(blob)
        objs = p['$objects']
        top = objs[1]
        size = top.get('Size')
        ek = top.get('EncryptionKey')
        keyblob = None
        if ek is not None:
            idx = ek.data if hasattr(ek, 'data') else ek
            raw = objs[idx]
            keyblob = raw['NS.data'] if isinstance(raw, dict) else raw
        return size, keyblob

    def read(self, domain, rel) -> bytes:
        """Decrypted contents of one backed-up file."""
        row = self._row(domain, rel)
        if not row:
            raise FileNotFoundError(f'{domain}:{rel} not in this backup')
        fid = row['fileID']
        blob = self.dir / fid[:2] / fid
        if not blob.exists():
            raise FileNotFoundError(f'{fid} missing from backup directory')
        data = blob.read_bytes()
        if not self.encrypted:
            return data
        size, keyblob = self._meta(row['file'])
        if keyblob is None:
            return data
        return _decrypt(data, self.keybag.unwrap_file_key(keyblob), size)

    def extract(self, domain, rel, out) -> Path:
        out = Path(out); out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(self.read(domain, rel))
        return out

    def sqlite(self, domain, rel) -> sqlite3.Connection:
        """
        Open a backed-up SQLite database read-only, decrypting to a scratch file
        first when the backup is encrypted. Used by every extractor.
        """
        if not self.encrypted:
            row = self._row(domain, rel)
            if not row: raise FileNotFoundError(f'{domain}:{rel} not in this backup')
            p = self.dir / row['fileID'][:2] / row['fileID']
        else:
            p = self.dir / '.decrypted' / (domain + '_' + rel.replace('/', '_'))
            if not p.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(self.read(domain, rel))
            # SQLite needs its sidecars; pull them when the db was WAL-mode.
            for suffix in ('-wal', '-shm'):
                try:
                    side = p.parent / (p.name + suffix)
                    if not side.exists():
                        side.write_bytes(self.read(domain, rel + suffix))
                except Exception:
                    pass
        con = sqlite3.connect(f'file:{p}?mode=ro', uri=True)
        con.row_factory = sqlite3.Row
        return con

    def files(self, domain=None, like=None, limit=1000):
        q = 'SELECT fileID, domain, relativePath, flags, file FROM Files WHERE 1=1'
        a = []
        if domain: q += ' AND domain = ?'; a.append(domain)
        if like:   q += ' AND relativePath LIKE ?'; a.append(f'%{like}%')
        q += ' ORDER BY domain, relativePath LIMIT ?'; a.append(int(limit))
        out = []
        for r in self.db().execute(q, a):
            size = None
            try: size, _ = self._meta(r['file'])
            except Exception: pass
            out.append({'id': r['fileID'], 'domain': r['domain'], 'path': r['relativePath'],
                        'dir': r['flags'] == 2, 'bytes': size})
        return out

    def domains(self):
        return [{'domain': r['domain'], 'files': r['n'], 'bytes': r['b'] or 0}
                for r in self.db().execute(
                    'SELECT domain, COUNT(*) n, SUM(0) b FROM Files GROUP BY domain ORDER BY n DESC')]

    # -- keychain ------------------------------------------------------------
    def keychain(self):
        """
        Saved Wi-Fi passwords, internet/generic passwords and certificates.
        Encrypted backups only — this is the single biggest reason to encrypt.
        """
        if not self.encrypted:
            raise RuntimeError('keychain is only present in encrypted backups')
        raw = self.read('KeychainDomain', 'keychain-backup.plist')
        p = plistlib.loads(raw)
        out = {}
        for section, label in (('genp', 'generic'), ('inet', 'internet'), ('cert', 'certificates'), ('keys', 'keys')):
            items = []
            for it in (p.get(section) or []):
                d = dict(it)
                data = d.get('v_Data')
                if isinstance(data, bytes) and section in ('genp', 'inet'):
                    try:
                        wrapped = d.get('v_PersistentRef') or data
                        d['password'] = _decrypt(data, self.keybag.unwrap_file_key(wrapped)).decode('utf-8', 'replace') \
                            if d.get('v_PersistentRef') else data.decode('utf-8', 'replace')
                    except Exception:
                        d['password'] = None
                items.append({'account': d.get('acct'), 'service': d.get('svce') or d.get('srvr'),
                              'password': d.get('password'), 'label': d.get('labl'),
                              'created': str(d.get('cdat')), 'modified': str(d.get('mdat')),
                              'accessGroup': d.get('agrp')})
            out[label] = items
        return out

    def summary(self):
        i = self.info
        return {'dir': str(self.dir), 'encrypted': self.encrypted,
                'device': i.get('Device Name'), 'product': i.get('Product Name'),
                'ios': i.get('Product Version'), 'build': i.get('Build Version'),
                'serial': i.get('Serial Number'), 'imei': i.get('IMEI'),
                'udid': i.get('Unique Identifier') or i.get('Target Identifier'),
                'lastBackup': str(i.get('Last Backup Date')),
                'apps': len(i.get('Installed Applications') or []),
                'files': self.db().execute('SELECT COUNT(*) c FROM Files').fetchone()['c']}

    def decrypt_all(self, out, emit=None):
        """Write the whole backup out as a plain directory tree."""
        out = Path(out); out.mkdir(parents=True, exist_ok=True)
        n = 0
        for f in self.files(limit=10 ** 7):
            if f['dir'] or not f['path']: continue
            try:
                dst = out / f['domain'] / f['path']
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(self.read(f['domain'], f['path']))
                n += 1
                if emit and n % 200 == 0: emit(f'{n} files')
            except Exception:
                continue
        return {'out': str(out), 'files': n}
