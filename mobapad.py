#!/usr/bin/env python3
"""Mobapad M12 HD (codename SZX3HD) BLE client.

Implements the "KR" protocol documented in ../PROTOCOL.md over a raw ATT
socket -- see att.py for why BlueZ/bleak cannot be used for the command channel.

    python3 mobapad.py scan
    python3 mobapad.py all      --address A0:58:5F:B0:58:11
    python3 mobapad.py info     --name "Mobapad M12-HD-L"
    python3 mobapad.py caps     --address A0:58:5F:B0:58:11
    python3 mobapad.py remaps   --address A0:58:5F:B0:58:11
    python3 mobapad.py config   --address A0:58:5F:B0:58:11
    python3 mobapad.py macros   --address A0:58:5F:B0:58:11
    python3 mobapad.py gyro     --address A0:58:5F:B0:58:11
    python3 mobapad.py raw      --address ... --cmd 0x86 --data 01,00

Scanning still uses bleak (advertisements are fine); everything else goes
through att.py. Device discovery must match on AdvertisementData.local_name,
not device.name -- the M12 HD only puts its name in the scan response.
"""

from __future__ import annotations

import argparse
import sys
import time

from att import Att, AttError, Handles, LinkLost, connect, find_ranges

CHUNK = 20          # negotiated ATT MTU is 23, so 20 payload bytes
REPLY_WAIT = 1.5    # seconds to gather notifications after a command

# --- key codes (LatestManager) ------------------------------------------------

KEYS: dict[str, int] = {
    "M1": 0x01, "M2": 0x02, "M3": 0x03, "M4": 0x04,
    "M5": 0x05, "M6": 0x06, "M7": 0x07, "M8": 0x08, "M9": 0x09,
    "SL_L": 0x11, "SR_L": 0x12, "SL_R": 0x13, "SR_R": 0x14,
    "SET_L": 0x21, "SET_R": 0x22,
    "A": 0xA0, "B": 0xA1, "X": 0xA2, "Y": 0xA3,
    "L": 0xA4, "ZL": 0xA5, "L3": 0xA6,
    "R": 0xA7, "ZR": 0xA8, "R3": 0xA9,
    "MINUS": 0xAA, "PLUS": 0xAB, "MENU": 0xAC, "HOME": 0xAD,
    "TURBO_R": 0xAE, "TURBO_L": 0xAF,
    "DPAD": 0xD0, "LEFT": 0xD1, "RIGHT": 0xD2, "UP": 0xD3, "DOWN": 0xD4,
    "UPLEFT": 0xD5, "UPRIGHT": 0xD6, "DOWNLEFT": 0xD7, "DOWNRIGHT": 0xD8,
    "LSTICK": 0xE0, "LSTICK_L": 0xE1, "LSTICK_R": 0xE2,
    "LSTICK_U": 0xE3, "LSTICK_D": 0xE4,
    "RSTICK": 0xF0, "RSTICK_L": 0xF1, "RSTICK_R": 0xF2,
    "RSTICK_U": 0xF3, "RSTICK_D": 0xF4,
}
KEY_NAMES = {v: k for k, v in KEYS.items()}


NAME_PREFIXES = ("Mobapad M12-HD", "Mobapad-M12-HD", "MOBAPAD M12-HD")

# per-family chunked-response header layout: (total_idx, seq_idx, payload_start)
# verified on hardware for 0x86, 0x77 and 0x6C
CHUNK_LAYOUT: dict[int, tuple[int, int, int]] = {
    0x50: (2, 3, 4),
    0x86: (3, 4, 5),
    0x77: (3, 4, 5),
    0x79: (3, 4, 5),
    0x6C: (4, 5, 6),
}


def key_code(s: str) -> int:
    s = s.strip()
    if s.upper() in KEYS:
        return KEYS[s.upper()]
    return int(s, 0)


def key_name(code: int) -> str:
    return KEY_NAMES.get(code, f"0x{code:02X}")


def hexs(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


class Pad:
    """One M12 HD half, over a raw ATT channel."""

    def __init__(self, att: Att, handles: Handles, verbose: bool = False):
        self.att = att
        self.h = handles
        self.verbose = verbose
        self._sn = 0

    # -- framing ------------------------------------------------------------

    def _frame(self, cmd: int, content: bytes = b"") -> bytes:
        sn = self._sn & 0xFF
        self._sn = (self._sn + 1) & 0xFF
        return bytes([(len(content) + 3) & 0xFF, cmd & 0xFF]) + content + bytes([sn])

    def subscribe(self) -> None:
        self.att.notify_handle = self.h.notify
        self.att.write_req(self.h.cccd, b"\x01\x00")

    def send(self, cmd: int, content: bytes = b"", wait: float = REPLY_WAIT) -> list[bytes]:
        """Write a command frame and gather whatever comes back."""
        frame = self._frame(cmd, content)
        if self.verbose:
            print(f"  -> {hexs(frame)}", file=sys.stderr)
        for i in range(0, len(frame), CHUNK):
            self.att.write_cmd(self.h.cmd, frame[i:i + CHUNK])
        replies = [r for r in self.att.collect(wait) if r and r[1] == (cmd & 0xFF)]
        if self.verbose:
            for r in replies:
                print(f"  <- {hexs(r)}", file=sys.stderr)
        return replies

    def one(self, cmd: int, content: bytes = b"") -> bytes | None:
        replies = self.send(cmd, content)
        return replies[0] if replies else None

    def chunked(self, cmd: int, content: bytes = b"") -> bytes | None:
        """Reassemble a multi-frame answer; None when the command is unsupported."""
        total_i, seq_i, start = CHUNK_LAYOUT.get(cmd, (3, 4, 5))
        replies = self.send(cmd, content, wait=REPLY_WAIT + 1.0)
        if not replies:
            return None
        # a single short frame (or a 0xFF header) is not a chunked answer
        first = replies[0]
        if len(first) <= start or first[total_i] in (0x00, 0xFF):
            return first[start:len(first) - 1] if len(first) > start else b""
        parts: dict[int, bytes] = {}
        for r in replies:
            if len(r) <= start:
                continue
            parts[r[seq_i]] = r[start:len(r) - 1]
        return b"".join(parts[k] for k in sorted(parts))

    # -- queries ------------------------------------------------------------

    def device_information(self) -> dict:
        """Standard 180A service. The KR 0x84/0x61 info commands are dead here."""
        ranges = find_ranges(self.att)
        out: dict[str, str] = {}
        rng = ranges.get("180a")
        if not rng:
            return out
        start = rng[0]
        labels = ("firmware", "manufacturer", "pnp_id")
        for i, label in enumerate(labels):
            val = self.att.read_optional(start + 2 + i * 2)
            if val is None:
                continue
            out[label] = val.hex() if label == "pnp_id" else val.decode("utf-8", "replace").strip("\x00")
        return out

    def handle_mode(self) -> int | None:
        f = self.one(0x87, bytes([0x02]))
        return f[3] if f and len(f) > 3 else None

    def device_type(self) -> bytes | None:
        f = self.one(0x30)
        return f[2:len(f) - 1] if f else None

    def battery(self) -> dict | None:
        f = self.one(0x31)
        if not f or len(f) < 7:
            return None
        return {"percent": f[5], "charging": bool(f[3]), "low": bool(f[6])}

    def sleep_time(self) -> int | None:
        f = self.one(0x32, bytes([0x01, 0x00]))
        return f[2] if f and len(f) > 2 else None

    def appearance(self) -> int | None:
        f = self.one(0x44)
        return f[2] if f and len(f) > 2 else None

    def turbo_support(self) -> dict | None:
        p = self.chunked(0x86, bytes([0x01, 0x00]))
        if not p or len(p) < 3:
            return None
        return {
            "semi_auto": bool(p[0] & 0x01),
            "full_auto": bool(p[0] & 0x02),
            "max_rate": p[1],
            "min_rate": p[2],
            "keys": [key_name(k) for k in p[3:]],
        }

    def remap_support(self) -> dict | None:
        p = self.chunked(0x86, bytes([0x02, 0x00]))
        if not p:
            return None
        return {
            "handle": bool(p[0] & 0x01),
            "mouse": bool(p[0] & 0x02),
            "keyboard": bool(p[0] & 0x04),
            "media": bool(p[0] & 0x08),
            "keys": [key_name(k) for k in p[1:]],
        }

    def macro_support(self) -> dict | None:
        """0x86 sub 3. Like subs 1 and 2: a flag byte, then the eligible keys."""
        p = self.chunked(0x86, bytes([0x03, 0x00]))
        if not p:
            return None
        return {"supported": bool(p[0] & 0x01), "keys": [key_name(k) for k in p[1:]]}

    def remap_targets(self) -> list[str] | None:
        """0x86 sub 4 -- the keys a mapping may point at."""
        p = self.chunked(0x86, bytes([0x04, 0x00]))
        return [key_name(k) for k in p] if p else None

    def macro_record_keys(self) -> list[str] | None:
        p = self.chunked(0x86, bytes([0x05, 0x00]))
        return [key_name(k) for k in p] if p else None

    def macro_keys(self) -> list[str] | None:
        """0x4D -- the keys that can hold a macro."""
        f = self.one(0x4D)
        if not f or len(f) < 4:
            return None
        return [key_name(k) for k in f[3:len(f) - 1]]

    def get_remaps(self) -> list[dict] | None:
        """0x6C sub 17 -- all multi-key mappings."""
        p = self.chunked(0x6C, bytes([0x11, 0x00]))
        if not p:
            return None
        out: list[dict] = []
        i = 1
        limit = p[0]
        while i + 1 < limit and i + 1 < len(p):
            original, type_num = p[i], p[i + 1]
            i += 2
            groups = []
            for _ in range(type_num):
                if i + 1 >= len(p):
                    break
                gtype, knum = p[i], p[i + 1]
                i += 2
                groups.append({"type": gtype, "keys": [key_name(k) for k in p[i:i + knum]]})
                i += knum
            out.append({"key": key_name(original), "groups": groups})
        return out

    def get_macro(self, index: int = 0) -> dict | None:
        """0x79 sub 1 -- the macro stored on a key. Layout verified on hardware."""
        p = self.chunked(0x79, bytes([0x01, index & 0xFF]))
        if not p or len(p) < 7:
            return None
        out = {
            "key": key_name(p[0]),
            "method": p[1],
            "cycle_ms": (p[4] << 8) | p[5],
            "steps": [],
        }
        i = 7
        for _ in range(p[6]):
            if i + 5 >= len(p):
                break
            knum = p[i + 5]
            out["steps"].append({
                "step": p[i],
                "hold_ms": (p[i + 1] << 8) | p[i + 2],
                "interval_ms": (p[i + 3] << 8) | p[i + 4],
                "keys": [key_name(k) for k in p[i + 6:i + 6 + knum]],
            })
            i += 6 + knum
        out["total_hold_ms"] = sum(s["hold_ms"] + s["interval_ms"] for s in out["steps"])
        return out

    def gyro_axis_exchange(self) -> int | None:
        """0x6A sub 42. The only gyro query this model answers."""
        f = self.one(0x6A, bytes([0x2A, 0x00]))
        return f[4] if f and len(f) > 4 else None

    def full_config(self) -> bytes | None:
        """0x77 sub 8 -- trigger + rocker + gyro + vibration in one blob."""
        return self.chunked(0x77, bytes([0x08, 0x00]))

    def lighting(self) -> bytes | None:
        p = self.chunked(0x82, bytes([0x06, 0x00]))
        return p

    # -- setters (unverified on hardware; writes persist in firmware) --------

    def macro_session_begin(self) -> bytes | None:
        return self.one(0x36, bytes([0x01, 0x00]))

    def macro_session_end(self) -> bytes | None:
        return self.one(0x34)

    def set_remap(self, original: int, targets: list[int], group_type: int = 0) -> int:
        if len(targets) > 5:
            raise ValueError("at most 5 target keys")
        content = bytearray([0x10, 0x00, original & 0xFF])
        if targets:
            content += bytes([1, group_type & 0xFF, len(targets)])
            content += bytes(t & 0xFF for t in targets)
        else:
            content += bytes([1])
        f = self.one(0x6C, bytes(content))
        return f[4] if f and len(f) > 4 else -1

    def set_turbo(self, key: int, mode: int, rate: int) -> int:
        f = self.one(0x37, bytes([key & 0xFF, mode & 0xFF, rate & 0xFF]))
        return f[2] if f and len(f) > 2 else -1

    def set_gyro_axis_exchange(self, value: int) -> int:
        f = self.one(0x6A, bytes([0x29, 0x00, value & 0xFF]))
        return f[4] if f and len(f) > 4 else -1

    def gyro_config(self, motion_switch: int, method: int, key: int, sensitivity: int,
                    mapper_switch: int = 0, dead_zone: int = 0, mapper_model: int = 0) -> int:
        content = bytes([motion_switch, mapper_switch, method, key, dead_zone]) \
            + sensitivity.to_bytes(2, "big") + bytes([mapper_model])
        f = self.one(0x5B, content)
        return f[2] if f and len(f) > 2 else -1

    def set_mode(self, mode: int) -> int:
        f = self.one(0x01, bytes([mode & 0xFF]))
        return f[2] if f and len(f) > 2 else -1


# --- 0x77 sub 8 blob ----------------------------------------------------------


# --- connection ---------------------------------------------------------------


def resolve_address(name: str | None, address: str | None, timeout: float = 20.0) -> str:
    if address:
        return address
    import asyncio

    from bleak import BleakScanner

    needle = (name or "M12-HD").lower()

    async def run() -> str:
        loop = asyncio.get_running_loop()
        found: asyncio.Future = loop.create_future()

        def cb(device, adv):
            if found.done():
                return
            names = [n for n in (adv.local_name, device.name) if n]
            if any(needle in n.lower() for n in names):
                found.set_result(device.address)

        print(f"scanning for {name or 'M12-HD'} …", file=sys.stderr)
        async with BleakScanner(cb):
            try:
                return await asyncio.wait_for(found, timeout)
            except asyncio.TimeoutError:
                raise SystemExit("device not found -- wake the half and retry")

    return asyncio.run(run())


def open_pad(args) -> Pad:
    address = resolve_address(args.name, args.address, timeout=args.wait)
    print(f"connecting to {address} (press the half's button if it is asleep) …",
          file=sys.stderr)
    sock = connect(address, wait=args.wait)
    att = Att(sock, verbose=args.verbose)
    ranges = find_ranges(att)
    if "ff00" not in ranges:
        raise SystemExit(f"no FF00 command service; services seen: {sorted(ranges)}")
    start, end = ranges["ff00"]
    if end - start + 1 != 6:
        print(f"warning: FF00 spans {end - start + 1} handles, expected 6", file=sys.stderr)
    handles = Handles(start)
    if args.verbose:
        print(f"  FF00 0x{start:04X}-0x{end:04X}  {handles}", file=sys.stderr)
    pad = Pad(att, handles, verbose=args.verbose)
    pad.subscribe()
    return pad


# --- CLI ----------------------------------------------------------------------


def show(label: str, value) -> None:
    print(f"{label:>18}: {value if value is not None else '(unsupported)'}")


def cmd_scan(_args) -> None:
    import asyncio

    from bleak import BleakScanner

    seen: dict[str, dict] = {}

    def cb(device, adv):
        row = seen.setdefault(device.address, {"names": set(), "rssi": None, "svcs": set()})
        for n in (adv.local_name, device.name):
            if n:
                row["names"].add(n)
        row["svcs"].update(u.lower() for u in (adv.service_uuids or []))
        row["rssi"] = adv.rssi

    async def run():
        async with BleakScanner(cb):
            await asyncio.sleep(12.0)

    asyncio.run(run())
    for addr, r in sorted(seen.items(), key=lambda kv: -(kv[1]["rssi"] or -999)):
        names = ", ".join(sorted(r["names"])) or "(unnamed)"
        mark = " <== M12 HD" if any(n.startswith(NAME_PREFIXES) for n in r["names"]) else ""
        print(f"{addr}  rssi={r['rssi']:>4}  {names}{mark}")


def cmd_info(args) -> None:
    pad = open_pad(args)
    for k, v in pad.device_information().items():
        show(k, v)
    show("handle mode", pad.handle_mode())
    show("device type", hexs(pad.device_type() or b"") or None)
    show("appearance", pad.appearance())
    show("sleep time", pad.sleep_time())
    bat = pad.battery()
    show("battery", f"{bat['percent']}%  charging={bat['charging']}  low={bat['low']}"
         if bat else None)


def cmd_caps(args) -> None:
    pad = open_pad(args)
    show("turbo", pad.turbo_support())
    show("remap", pad.remap_support())
    show("remap targets", pad.remap_targets())
    show("macro keys (0x86)", pad.macro_support())
    show("macro keys (0x4D)", pad.macro_keys())
    show("macro record", pad.macro_record_keys())


def cmd_remaps(args) -> None:
    pad = open_pad(args)
    rows = pad.get_remaps()
    if rows is None:
        print("(no answer)")
        return
    for row in rows:
        targets = ", ".join(
            f"type{g['type']}:{'+'.join(g['keys'])}" for g in row["groups"]
        ) or "(unbound)"
        default = " (default)" if targets == f"type0:{row['key']}" else ""
        print(f"{row['key']:>10} -> {targets}{default}")


def cmd_config(args) -> None:
    import blob as blob_mod

    pad = open_pad(args)
    raw = pad.full_config()
    if not raw:
        print("(no answer)")
        return
    if args.verbose:
        print(f"raw ({len(raw)} bytes): {hexs(raw)}\n")
    try:
        print(blob_mod.report(raw, key_name))
    except (IndexError, ValueError) as e:
        print(f"decode failed ({e}); raw bytes: {hexs(raw)}")


def show_macro(m: dict | None) -> None:
    if not m:
        print("no macro stored")
        return
    print(f"{m['key']} -- method {m['method']}, cycle {m['cycle_ms']} ms, "
          f"{len(m['steps'])} steps, {m['total_hold_ms'] / 1000:.1f} s total")
    if len(m["steps"]) > 6:
        rows = m["steps"][:3] + [None] + m["steps"][-2:]
    else:
        rows = m["steps"]
    for s in rows:
        if s is None:
            print("      …")
            continue
        print(f"  {s['step']:>3}  {'+'.join(s['keys']):<10} hold={s['hold_ms']:>6} ms  "
              f"interval={s['interval_ms']} ms")
    if len(m["steps"]) >= 2:
        print("\ntwo or more steps, so this macro latches: one press starts it, "
              "another stops it early")
    else:
        print("\nsingle step -- the hold time will be ignored and the output "
              "will just follow the button")


def cmd_macros(args) -> None:
    pad = open_pad(args)
    show_macro(pad.get_macro())


def cmd_gyro(args) -> None:
    pad = open_pad(args)
    show("axis exchange", pad.gyro_axis_exchange())
    print("\nthe other 0x6A queries (mapping type, horizontal axial, X:Y ratio,\n"
          "outer dead zone) are silent on this model -- see PROTOCOL.md")


def cmd_all(args) -> None:
    try:
        _cmd_all(args)
    except LinkLost as e:
        print(f"\n!! {e}\n   everything above was read successfully; "
              "wake the half and re-run to get the rest", file=sys.stderr)


def _cmd_all(args) -> None:
    pad = open_pad(args)
    print("== device ==")
    for k, v in pad.device_information().items():
        show(k, v)
    show("handle mode", pad.handle_mode())
    bat = pad.battery()
    show("battery", f"{bat['percent']}%  charging={bat['charging']}" if bat else None)
    show("sleep time", pad.sleep_time())

    print("\n== capabilities ==")
    show("turbo", pad.turbo_support())
    show("remap", pad.remap_support())
    show("remap targets", pad.remap_targets())
    show("macro keys", pad.macro_support())

    print("\n== mappings ==")
    rows = pad.get_remaps() or []
    for row in rows:
        targets = ", ".join(f"{'+'.join(g['keys'])}" for g in row["groups"]) or "(unbound)"
        mark = "" if targets == row["key"] else "   <-- customised"
        print(f"{row['key']:>10} -> {targets}{mark}")

    print("\n== macro ==")
    show_macro(pad.get_macro())

    print("\n== gyro ==")
    show("axis exchange", pad.gyro_axis_exchange())

    raw = pad.full_config()
    if raw:
        import blob as blob_mod
        print("\n== stored configuration ==")
        try:
            print(blob_mod.report(raw, key_name))
        except (IndexError, ValueError) as e:
            print(f"  decode failed ({e}); raw: {hexs(raw)}")


def cmd_raw(args) -> None:
    pad = open_pad(args)
    data = bytes(int(x, 0) for x in args.data.split(",")) if args.data else b""
    cmd = int(args.cmd, 0)
    if args.chunked:
        p = pad.chunked(cmd, data)
        print("payload:", hexs(p) if p else "(no answer)")
    else:
        for r in pad.send(cmd, data):
            print("reply:", hexs(r))


def cmd_sweep(args) -> None:
    """Fire every query in a list and record which ones answer."""
    pad = open_pad(args)
    probes: list[tuple[str, int, bytes]] = [
        ("0x30 device type", 0x30, b""),
        ("0x31 battery", 0x31, b""),
        ("0x32 sleep time", 0x32, bytes([0x01, 0x00])),
        ("0x44 appearance", 0x44, b""),
        ("0x4A lighting effect", 0x4A, b""),
        ("0x4D macro keys", 0x4D, b""),
        ("0x61 device info", 0x61, b""),
        ("0x64 trigger/vibration", 0x64, b""),
        ("0x66 switch settings", 0x66, b""),
        ("0x84 handle info", 0x84, bytes([0x00, 0x00])),
        ("0x86/1 turbo", 0x86, bytes([0x01, 0x00])),
        ("0x86/2 remap", 0x86, bytes([0x02, 0x00])),
        ("0x86/3 macro", 0x86, bytes([0x03, 0x00])),
        ("0x86/4 remap targets", 0x86, bytes([0x04, 0x00])),
        ("0x86/5 macro record", 0x86, bytes([0x05, 0x00])),
        ("0x86/6 uptime", 0x86, bytes([0x06, 0x00])),
        ("0x86/8 gyro trigger", 0x86, bytes([0x08, 0x00])),
        ("0x86/9 gyro mapping mode", 0x86, bytes([0x09, 0x00])),
        ("0x87/2 handle mode", 0x87, bytes([0x02])),
        ("0x6A/10 gyro mapping type", 0x6A, bytes([0x0A, 0x00])),
        ("0x6A/27 gyro horiz axial", 0x6A, bytes([0x1B, 0x00])),
        ("0x6A/35 gyro X:Y ratio", 0x6A, bytes([0x23, 0x00])),
        ("0x6A/37 gyro outer dz", 0x6A, bytes([0x25, 0x00])),
        ("0x6A/42 gyro axis exch", 0x6A, bytes([0x2A, 0x00])),
        ("0x6C/17 remaps", 0x6C, bytes([0x11, 0x00])),
        ("0x77/1 macro config", 0x77, bytes([0x01, 0x00])),
        ("0x77/8 full config", 0x77, bytes([0x08, 0x00])),
        ("0x82/6 lighting", 0x82, bytes([0x06, 0x00])),
        ("0x38 macro config", 0x38, b""),
        ("0x5C macro profiles", 0x5C, b""),
    ]
    for label, cmd, content in probes:
        replies = pad.send(cmd, content, wait=1.2)
        if not replies:
            print(f"{label:<28} silent")
        else:
            head = hexs(replies[0])
            extra = f"  (+{len(replies) - 1} more frames)" if len(replies) > 1 else ""
            print(f"{label:<28} {head}{extra}")
        time.sleep(0.2)


def require_confirm(args, what: str) -> None:
    if not args.confirm:
        raise SystemExit(f"refusing to {what} without --confirm: "
                         "writes persist in the half's firmware")


def cmd_set_remap(args) -> None:
    require_confirm(args, "change a key mapping")
    targets = [key_code(k) for k in args.to.split(",")] if args.to else []
    pad = open_pad(args)
    pad.macro_session_begin()
    print("result:", pad.set_remap(key_code(args.key), targets, args.type), "(0 = ok)")
    pad.macro_session_end()


def cmd_set_turbo(args) -> None:
    require_confirm(args, "change turbo")
    mode = {"semi": 0, "auto": 1, "off": 2}[args.mode]
    pad = open_pad(args)
    sup = pad.turbo_support()
    print("support:", sup)
    rate = args.rate
    if sup and rate:
        rate = max(sup["min_rate"], min(sup["max_rate"], rate))
    pad.macro_session_begin()
    print("result:", pad.set_turbo(key_code(args.key), mode, rate or 0), "(0 = ok)")
    pad.macro_session_end()


def cmd_gyro_set(args) -> None:
    require_confirm(args, "change gyro settings")
    pad = open_pad(args)
    pad.macro_session_begin()
    if args.axis_swap is not None:
        print("axis exchange ->", pad.set_gyro_axis_exchange(args.axis_swap))
    if args.sensitivity is not None:
        print("gyro config   ->", pad.gyro_config(args.enable, args.method,
                                                  key_code(args.key) if args.key else 0,
                                                  args.sensitivity))
    pad.macro_session_end()


def cmd_watch(args) -> None:
    """Not read-only: entering a reporting mode is a 0x01 write."""
    require_confirm(args, "switch the half into reporting mode")
    pad = open_pad(args)
    print(f"switching to mode {args.mode} …")
    pad.set_mode(args.mode)
    print("watching, Ctrl-C to stop")
    try:
        while True:
            for frame in pad.att.collect(1.0):
                print(hexs(frame))
    except KeyboardInterrupt:
        pass
    finally:
        pad.set_mode(0)


def main() -> None:
    # shared options, accepted on either side of the subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--name", help='BLE name, e.g. "Mobapad M12-HD-L"')
    common.add_argument("--address", help="BLE MAC (skips scanning)")
    common.add_argument("--wait", type=float, default=40.0,
                        help="seconds to wait for the half to advertise")
    common.add_argument("-v", "--verbose", action="store_true", help="dump raw frames")
    common.add_argument("--confirm", action="store_true",
                        help="required by every command that writes to the firmware")

    p = argparse.ArgumentParser(description=__doc__, parents=[common],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name: str, **kw):
        return sub.add_parser(name, parents=[common], **kw)

    add("scan").set_defaults(fn=cmd_scan)
    add("all", help="everything read-only, in one connection").set_defaults(fn=cmd_all)
    add("info").set_defaults(fn=cmd_info)
    add("caps").set_defaults(fn=cmd_caps)
    add("remaps").set_defaults(fn=cmd_remaps)
    add("config", help="0x77/8 blob: turbo table + undecoded tail").set_defaults(fn=cmd_config)
    add("macros", help="the macro stored on a key").set_defaults(fn=cmd_macros)
    add("gyro").set_defaults(fn=cmd_gyro)
    add("sweep", help="probe every known query, report which answer").set_defaults(fn=cmd_sweep)

    r = add("raw")
    r.add_argument("--cmd", required=True, help="command id, e.g. 0x86")
    r.add_argument("--data", default="", help="comma-separated content bytes")
    r.add_argument("--chunked", action="store_true")
    r.set_defaults(fn=cmd_raw)

    s = add("set-remap", help="WRITES firmware")
    s.add_argument("--key", required=True)
    s.add_argument("--to", default="", help="comma-separated targets (<=5); empty unbinds")
    s.add_argument("--type", type=int, default=0)
    s.set_defaults(fn=cmd_set_remap)

    t = add("set-turbo", help="WRITES firmware")
    t.add_argument("--key", required=True)
    t.add_argument("--mode", choices=["semi", "auto", "off"], required=True)
    t.add_argument("--rate", type=int, default=0)
    t.set_defaults(fn=cmd_set_turbo)

    g = add("gyro-set", help="WRITES firmware")
    g.add_argument("--axis-swap", type=int)
    g.add_argument("--sensitivity", type=int)
    g.add_argument("--enable", type=int, default=1)
    g.add_argument("--method", type=int, default=0)
    g.add_argument("--key", default="")
    g.set_defaults(fn=cmd_gyro_set)

    w = add("watch", help="WRITES firmware (mode switch)")
    w.add_argument("--mode", type=int, default=4)
    w.set_defaults(fn=cmd_watch)

    args = p.parse_args()
    try:
        args.fn(args)
    except AttError as e:
        raise SystemExit(f"ATT: {e}")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
