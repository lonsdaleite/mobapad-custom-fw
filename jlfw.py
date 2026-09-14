#!/usr/bin/env python3
"""Mobapad M12 HD firmware image tool: fetch, decrypt, verify, rebuild, re-encrypt, recover the key.

The OTA `.bin` is a JieLi (br23 / AC695x) flash image XORed with a keystream. For byte `i`:

    pad[i] = KEY[i % 32]  ^  lowbyte( ((i >> 5) << 3 & 0xFFFF) * x**(i % 32)  mod  0x1021 )

i.e. a 16-bit CRC-16/CCITT LFSR (poly 0x1021) seeded per 32-byte block with the block's word
index, clocked one bit per byte, plus a fixed 32-byte key. `KEY` below is the M12 HD key; it is
shared by every M12-HD-L / M12-HD-R build. Other Mobapad families use other keys, see `recover-key`.

Plaintext layout (offsets in the file), see FIRMWARE.md:

    0x000  entry 'app_area_head'   w0=crc16(entry[2:32])  w1=crc16(file[32:])
    0x020  entry 'app.bin'         w0=crc16(entry[2:32])  w1=crc16(app.bin data)
    0x040  entry 'cfg_tool.bin'    w0=crc16(entry[2:32])  w1=crc16(cfg_tool data)
    0x060  area entries VM / PRCT / BTIF (w0=crc16(entry[2:32]), w1=0xFFFF), then 0xFF padding
    0x120  app.bin data (code), then cfg_tool.bin data at the offset given in its entry

Entry: <H w0, <H w1, <I addr, <I size, <H flags, <H index, 16s name.
CRC-16 is CRC-16/XMODEM: poly 0x1021, init 0, no reflection, no final xor.

Usage:
    jlfw.py fetch [DEVICE ...]              list builds on the update server and download them to firmware/
                                            (default devices: "MOBAPAD M12-HD-L" "MOBAPAD M12-HD-R")
    jlfw.py decrypt  in.bin out.dec.bin
    jlfw.py encrypt  in.dec.bin out.bin
    jlfw.py info     image                  header entries with CRC verification (either form)
    jlfw.py fixcrc   in.dec.bin out.dec.bin recompute every header CRC after a patch
    jlfw.py otacrc   in.bin                 CRC-16/XMODEM of the ciphertext, what OTA command 0x50 carries
    jlfw.py recover-key a.bin [b.bin ...]   derive the 32-byte key for another device family
                                            (encrypted images of one family; more images = better)
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import struct
import sys
import time
import urllib.request

KEY = bytes.fromhex("0f3f7eddba74e8f1e2c4883143a74e9c3870c1a3468c181103060c183060e1c2")
POLY = 0x1021

API_URL = "https://cloud.mopaigame.com/v1/"
DEFAULT_DEVICES = ("MOBAPAD M12-HD-L", "MOBAPAD M12-HD-R")
FIRMWARE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "firmware")


# ----------------------------------------------------------------------------- crypto primitives

def crc16(data: bytes, crc: int = 0) -> int:
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ POLY) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def lfsr_block(block_index: int) -> bytes:
    """The key-independent half of the pad for one 32-byte block."""
    r = (block_index << 3) & 0xFFFF
    out = bytearray(32)
    for c in range(32):
        out[c] = r & 0xFF
        r <<= 1
        if r & 0x10000:
            r ^= 0x11021
    return bytes(out)


_LFSR_CACHE: dict[int, bytes] = {}


def pad(offset: int, length: int, key: bytes = KEY) -> bytes:
    out = bytearray()
    i = offset
    while i < offset + length:
        b = i >> 5
        ks = _LFSR_CACHE.get(b)
        if ks is None:
            ks = _LFSR_CACHE[b] = lfsr_block(b)
        c = i & 31
        take = min(32 - c, offset + length - i)
        out += bytes(ks[j] ^ key[j] for j in range(c, c + take))
        i += take
    return bytes(out)


def xor_image(data: bytes, key: bytes = KEY) -> bytes:
    return bytes(a ^ b for a, b in zip(data, pad(0, len(data), key)))


decrypt = encrypt = xor_image  # symmetric


def is_plain(data: bytes) -> bool:
    return data[16:29] == b"app_area_head"


# ----------------------------------------------------------------------------- header

def parse_entry(e: bytes) -> dict:
    w0, w1, addr, size, flags, index = struct.unpack_from("<HHIIHH", e, 0)
    name = e[16:32].split(b"\0")[0].decode("ascii", "replace")
    return dict(w0=w0, w1=w1, addr=addr, size=size, flags=flags, index=index, name=name)


def entries(pt: bytes) -> list[dict]:
    """Header entries: the app_area_head list plus the area table, up to where app.bin data starts."""
    out = []
    limit = parse_entry(pt[32:64])["addr"] if pt[48:55] == b"app.bin" else 0x120
    for off in range(0, limit, 32):
        e = pt[off:off + 32]
        if e[16] == 0xFF:
            break
        d = parse_entry(e)
        d["off"] = off
        out.append(d)
    return out


def area_extent(pt: bytes) -> int:
    """End offset the app_area_head CRC covers: its declared size.

    On 0.20 and later this is the whole file. On 0.14 the file carries a further
    `tone` area after it which the head CRC does not cover.
    """
    head = parse_entry(pt[0:32])
    return head["size"] if 32 < head["size"] <= len(pt) else len(pt)


def info(pt: bytes) -> None:
    extent = area_extent(pt)
    for d in entries(pt):
        crc_hdr = crc16(pt[d["off"] + 2:d["off"] + 32])
        line = (f"{d['off']:#06x} {d['name']:16s} addr={d['addr']:#010x} size={d['size']:#9x}"
                f" flags={d['flags']:#06x} idx={d['index']} w0={d['w0']:04x}({'ok' if crc_hdr == d['w0'] else 'BAD'})")
        if d["name"] == "app_area_head":
            ok = crc16(pt[32:extent]) == d["w1"]
            line += f" w1={d['w1']:04x}({'ok' if ok else 'BAD'} crc of area[32:{extent:#x}])"
        elif d["w1"] != 0xFFFF:
            ok = crc16(pt[d["addr"]:d["addr"] + d["size"]]) == d["w1"]
            line += f" w1={d['w1']:04x}({'ok' if ok else 'BAD'} crc of data)"
        print(line)


def fixcrc(pt: bytes) -> bytes:
    buf = bytearray(pt)
    ents = entries(pt)
    # data CRCs first (app.bin, cfg_tool.bin), then each entry header, then the head's w1 and w0
    for d in ents:
        if d["name"] != "app_area_head" and d["w1"] != 0xFFFF:
            struct.pack_into("<H", buf, d["off"] + 2, crc16(buf[d["addr"]:d["addr"] + d["size"]]))
    for d in ents:
        if d["name"] != "app_area_head":
            struct.pack_into("<H", buf, d["off"], crc16(buf[d["off"] + 2:d["off"] + 32]))
    struct.pack_into("<H", buf, 2, crc16(buf[32:area_extent(bytes(buf))]))
    struct.pack_into("<H", buf, 0, crc16(buf[2:32]))
    return bytes(buf)


# ----------------------------------------------------------------------------- update server

def fetch(devices: list[str]) -> None:
    os.makedirs(FIRMWARE_DIR, exist_ok=True)
    for dev in devices:
        body = json.dumps({"model": "firmware", "action": "upgrade", "token": "",
                           "timestamp": int(time.time() * 1000),
                           "data": {"device": dev, "version": None, "beta": "0"}}).encode()
        req = urllib.request.Request(API_URL, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.load(r)
        builds = resp.get("data") or []
        print(f"{dev}: {len(builds)} build(s)")
        for fw in builds:
            name = fw["path"].rsplit("/", 1)[-1]
            dst = os.path.join(FIRMWARE_DIR, name)
            note = (fw.get("info_en") or "").replace("\n", " | ")
            print(f"  {fw['version']:>6}  {fw['date']}  {name}  {note}")
            if os.path.exists(dst) and hashlib.md5(open(dst, "rb").read()).hexdigest().upper() == fw["md5"].upper():
                continue
            with urllib.request.urlopen(fw["path"], timeout=120) as r:
                data = r.read()
            if hashlib.md5(data).hexdigest().upper() != fw["md5"].upper():
                print(f"    md5 mismatch, not saved")
                continue
            open(dst, "wb").write(data)
            print(f"    saved {len(data)} bytes")


# ----------------------------------------------------------------------------- key recovery

def recover_key(images: list[bytes]) -> bytes:
    """Recover the 32-byte key of a device family from its encrypted images.

    Anchor: bytes 8..11 of the first entry hold the file length (LE32), so key[8..11] is read
    straight off the file. Every even column of a 32-byte block then carries the same plaintext
    byte distribution (low bytes of 16-bit code words) and every odd column another one, so each
    remaining key byte is the XOR shift that best aligns that column's histogram with column 8
    (even) or column 9 (odd). Wrong key bytes never decode `app_area_head`, which is the check.
    """
    stripped = []
    anchors = collections.Counter()
    for img in images:
        s = bytes(img[i] ^ lfsr_block(i >> 5)[i & 31] for i in range(len(img)))
        stripped.append(s)
        anchors[bytes(s[8 + j] ^ ((len(img) >> (8 * j)) & 0xFF) for j in range(4))] += 1
    k8 = anchors.most_common(1)[0][0]
    cols = [[] for _ in range(32)]
    for s in stripped:
        for c in range(32):
            cols[c].extend(s[128 + c::32])

    def hist(vals: list[int], k: int) -> list[float]:
        h = [0] * 256
        for v in vals:
            h[v ^ k] += 1
        n = len(vals)
        return [x / n for x in h]

    refs = {0: hist(cols[8], k8[0]), 1: hist(cols[9], k8[1])}
    key = bytearray(32)
    for c in range(32):
        if 8 <= c < 12:
            key[c] = k8[c - 8]
            continue
        ref = refs[c % 2]
        cnt = collections.Counter(cols[c])
        n = len(cols[c])
        best = max(range(256), key=lambda k: sum(math.sqrt(ref[v ^ k] * cnt[v] / n) for v in cnt))
        key[c] = best
    return bytes(key)


# ----------------------------------------------------------------------------- cli

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "fetch":
        fetch(argv[2:] or list(DEFAULT_DEVICES))
        return 0
    if cmd == "recover-key":
        images = [open(p, "rb").read() for p in argv[2:]]
        if not images:
            print(__doc__)
            return 2
        key = recover_key(images)
        print("key:", key.hex())
        for p, img in zip(argv[2:], images):
            print(f"  {p}: {'decodes app_area_head' if is_plain(xor_image(img, key)) else 'DOES NOT decode, key wrong'}")
        return 0
    if len(argv) < 3:
        print(__doc__)
        return 2
    src = argv[2]
    data = open(src, "rb").read()
    if cmd == "decrypt":
        open(argv[3], "wb").write(decrypt(data))
    elif cmd == "encrypt":
        open(argv[3], "wb").write(encrypt(data))
    elif cmd == "info":
        pt = data if is_plain(data) else decrypt(data)
        print("plaintext" if is_plain(data) else "ciphertext (decrypted for parsing)", len(data), "bytes")
        info(pt)
    elif cmd == "fixcrc":
        open(argv[3], "wb").write(fixcrc(data))
    elif cmd == "otacrc":
        print(f"{crc16(data):04x}")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
