#!/usr/bin/env python3
"""OTA-flash an M12 HD half over BLE, the way the vendor app does it.

    python3 tools/otaflash.py plan  IMAGE                            # offline: checks, frames
    python3 tools/otaflash.py probe --address MAC                    # connect, identify, send nothing
    python3 tools/otaflash.py flash IMAGE --address MAC              # dry run: connects, writes nothing
    python3 tools/otaflash.py flash IMAGE --address MAC --confirm    # the real thing

IMAGE is an encrypted `.bin` (as served by the update server or built by `patch_axis_usb.py`) or
the decrypted plaintext; both are recognised. `plan` never touches the radio. A `flash` without
`--confirm` connects, identifies the half, runs every safety check and stops before frame 0x50.

The wire format below is what the vendor app was **observed** sending on both halves
(captures/ — Android HCI snoops of a 0.33 → 0.29 → 0.33 round trip per half, parsed with
`tools/btsnoop.py`). All four flashes match and the streamed bytes were identical to the
downloaded images, so this is the real protocol, not a reading of the app's classes.

OTA lives on its own GATT service, not on the FF00 command channel:

    FF10 service, handles 0x000C-0x0011 on both halves
      FF11  control   value 0x000E (write-without-response + notify), CCCD 0x000F
      FF12  data      value 0x0011 (write-without-response)

Control frames are `[total_len, id_lo, id_hi, content…]`, no SN byte; the device answers on the
same characteristic with the same header:

    -> 0x50  [crc16_xmodem(ciphertext) BE16, len(ciphertext) BE24]     <- [status]
    -> 0x51  []                                                        <- [block_size BE16]  (400)
       data: the ciphertext, raw, written to FF12 in 20-byte write commands, `block_size` bytes
       at a time; after each block the device notifies
                                                                       <- 0x52 [status, received BE32]
       and only then does the next block go out. The app never sends a 0x52 frame.
    -> 0x53  []                                                        <- [status]  (~1.5 s later)

The device then reboots into the new image once the link drops. There is no resume: a broken run
means starting again from 0x50. What happens to a half that is powered off mid-transfer is not
established (FIRMWARE.md), so mind the battery and stay close to the adapter.
"""

from __future__ import annotations

import argparse
import os
import re
import select
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import jlfw  # noqa: E402
from att import Att, AttError, Handles, LinkLost, connect, find_ranges  # noqa: E402

ATT_PAYLOAD = 20          # negotiated MTU is 23; the app writes 20-byte chunks too
ATT_NOTIFY, ATT_INDICATE = 0x1B, 0x1D
CMD_READY, CMD_BLOCK, CMD_PROGRESS, CMD_DONE = 0x50, 0x51, 0x52, 0x53
OBSERVED_BLOCK = 400      # what the device answered to 0x51 in every capture
MIN_BATTERY = 50          # refuse below this; losing power mid-write is the classic brick


# ----------------------------------------------------------------------------- image checks

def load_image(path: str) -> tuple[bytes, bytes, str]:
    """Return (ciphertext, plaintext, half) for an image given in either form."""
    data = open(path, "rb").read()
    if jlfw.is_plain(data):
        plain, cipher = data, jlfw.encrypt(data)
    else:
        plain, cipher = jlfw.decrypt(data), data
    if not jlfw.is_plain(plain):
        raise SystemExit(f"{path}: not an M12 HD firmware image")
    m = re.search(rb"Mobapad M12-HD-([LR])", plain)
    if not m:
        raise SystemExit(f"{path}: no 'Mobapad M12-HD-L/R' marker; refusing to flash an unknown image")
    return cipher, plain, m.group(1).decode()


def check_image(plain: bytes) -> list[str]:
    """Every header CRC must verify, or the device will reject (or worse, accept) a broken image."""
    problems = []
    extent = jlfw.area_extent(plain)
    for d in jlfw.entries(plain):
        if jlfw.crc16(plain[d["off"] + 2:d["off"] + 32]) != d["w0"]:
            problems.append(f"{d['name']}: header CRC w0 mismatch")
        if d["name"] == "app_area_head":
            if jlfw.crc16(plain[32:extent]) != d["w1"]:
                problems.append("app_area_head: area CRC w1 mismatch")
        elif d["flags"] & 0xFF00 == 0xFF00:
            # Payload entries (flags 0xFF8x) carry a file offset in `addr`. The area entries
            # (flags 0x8xxx) carry a flash address instead, so slicing the file by it is
            # meaningless — Python would silently return a short slice and a bogus CRC.
            if d["addr"] + d["size"] > len(plain):
                problems.append(f"{d['name']}: extends past end of file")
            elif jlfw.crc16(plain[d["addr"]:d["addr"] + d["size"]]) != d["w1"]:
                problems.append(f"{d['name']}: data CRC w1 mismatch")
    if extent != len(plain):
        problems.append(f"declared area extent {extent:#x} is not the file length {len(plain):#x}; "
                        "bytes outside it are covered by no checksum")
    return problems


# ----------------------------------------------------------------------------- framing

def ota_frame(cmd: int, content: bytes = b"") -> bytes:
    total = len(content) + 3
    if total > 0xFF:
        raise ValueError("OTA frame longer than the length byte can express")
    return bytes([total, cmd & 0xFF, (cmd >> 8) & 0xFF]) + content


def ready_content(cipher: bytes) -> bytes:
    crc = jlfw.crc16(cipher)
    n = len(cipher)
    return bytes([crc >> 8, crc & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def hexs(b: bytes | None) -> str:
    return " ".join(f"{x:02X}" for x in b) if b else "(nothing)"


def be(b: bytes) -> int:
    n = 0
    for x in b:
        n = n << 8 | x
    return n


# ----------------------------------------------------------------------------- link

class OtaHandles:
    """The FF10 range is six handles: service, char decl, FF11 value, its CCCD, char decl, FF12 value."""

    def __init__(self, start: int, end: int):
        if end - start != 5:
            raise SystemExit(f"FF10 service spans {end - start + 1} handles, expected 6; "
                             "the layout differs from the captured device, refusing to guess")
        self.ctrl = start + 2
        self.ctrl_cccd = start + 3
        self.data = start + 5


class OtaLink:
    """The OTA control channel: frames out on FF11, replies back on FF11 notifications."""

    def __init__(self, att: Att, h: OtaHandles, verbose: bool = False, dry_run: bool = False):
        self.att, self.h, self.verbose, self.dry_run = att, h, verbose, dry_run
        self.last_other: bytes | None = None

    def await_reply(self, cmd: int, timeout: float) -> bytes | None:
        """Return the content of the first FF11 notification echoing `cmd`, or None on timeout.

        Other notifications (KR events on FF02, anything unexpected on FF11) are kept in
        `last_other` so an abort message can show what did arrive.
        """
        self.last_other = None
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                return None
            r, _, _ = select.select([self.att.sock], [], [], left)
            if not r:
                return None
            try:
                pdu = self.att.sock.recv(1024)
            except OSError as e:
                raise LinkLost(f"link dropped while reading: {e}") from e
            if not pdu:
                raise LinkLost("link closed by the device")
            if pdu[0] not in (ATT_NOTIFY, ATT_INDICATE) or len(pdu) < 3:
                continue
            handle = pdu[1] | pdu[2] << 8
            body = pdu[3:]
            if self.verbose:
                print(f"  <- [{handle:#06x}] {hexs(body)}", file=sys.stderr)
            if handle == self.h.ctrl and len(body) >= 3 and body[1] | body[2] << 8 == cmd:
                return body[3:]
            self.last_other = body

    def control(self, cmd: int, content: bytes = b"", timeout: float = 5.0) -> bytes | None:
        frame = ota_frame(cmd, content)
        if self.verbose or self.dry_run:
            print(f"  {'would send' if self.dry_run else '->'} [{self.h.ctrl:#06x}] {hexs(frame)}",
                  file=sys.stderr)
        if self.dry_run:
            return None
        self.att.write_cmd(self.h.ctrl, frame)
        return self.await_reply(cmd, timeout)

    def write_block(self, block: bytes) -> None:
        for i in range(0, len(block), ATT_PAYLOAD):
            self.att.write_cmd(self.h.data, block[i:i + ATT_PAYLOAD])


def widen_link(address: str) -> None:
    """20 ms interval, 6 s supervision timeout, like work/padd.py.

    The half asks the central for 20 ms / latency 6 / 5 s itself (seen as an L2CAP parameter
    update request in the capture); whether the kernel grants that is not visible from here, so
    ask for it explicitly. The default 420 ms timeout is far too short for a minutes-long transfer.
    """
    try:
        out = subprocess.run(["hcitool", "con"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError) as e:
        print(f"hcitool con failed ({e}); leaving link parameters alone", file=sys.stderr)
        return
    handle = None
    for line in out.splitlines():
        if address.upper() in line.upper() and "handle" in line:
            parts = line.split()
            handle = parts[parts.index("handle") + 1]
    if handle is None:
        print("connection handle not found; leaving link parameters alone", file=sys.stderr)
        return
    cmd = ["hcitool", "lecup", "--handle", handle, "--min", "16", "--max", "16",
           "--latency", "0", "--timeout", "600"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    if r.returncode == 0:
        print("link: 20 ms interval, 6 s supervision timeout", file=sys.stderr)
    else:
        print(f"lecup failed: {r.stderr.strip() or r.stdout.strip()}", file=sys.stderr)


class Device:
    """Everything known about the connected half before any OTA frame goes out."""

    def __init__(self, address: str, wait: float, verbose: bool):
        print(f"connecting to {address} (press the half's button if it is asleep) …", file=sys.stderr)
        self.address = address
        sock = connect(address, wait=wait)
        self.att = Att(sock, verbose=verbose)
        widen_link(address)
        ranges = find_ranges(self.att)
        for uuid in ("ff00", "ff10"):
            if uuid not in ranges:
                raise SystemExit(f"no {uuid.upper()} service; services seen: {sorted(ranges)}")
        self.kr = Handles(ranges["ff00"][0])
        self.ota = OtaHandles(*ranges["ff10"])
        self.att.notify_handle = self.kr.notify
        self.att.write_req(self.kr.cccd, b"\x01\x00")          # the app subscribes to FF02 first
        self.name = ""
        if "1800" in ranges:
            val = self.att.read_optional(ranges["1800"][0] + 2)
            if val:
                self.name = val.decode("utf-8", "replace").strip("\x00")
        from mobapad import Pad
        self.pad = Pad(self.att, self.kr, verbose=verbose)

    def half(self) -> str:
        m = re.search(r"M12-HD-([LR])", self.name)
        return m.group(1) if m else ""

    def handle_info(self) -> str | None:
        """`0x84 [1, 0]`, the query the app sends right after connecting.

        The spec's offsets (PROTOCOL.md: project 8:14, protocol 14:20, fw 20:28, hw 28:34) are
        into the hex of the whole frame, length byte included, and tile it exactly: on the capture
        `12 84 01 01 55 76 33 03 05 02 00 00 00 33 01 50 A0 <sn>` the fw field is `00 00 00 33`
        and became `00 00 00 29` after flashing 0.29.
        """
        f = self.pad.one(0x84, bytes([0x01, 0x00]))
        return f.hex() if f and len(f) >= 18 else None

    def describe(self) -> None:
        print(f"connected. GATT device name: {self.name or '(unreadable)'}")
        print(f"handles: KR cmd {self.kr.cmd:#06x} / OTA ctrl {self.ota.ctrl:#06x} data {self.ota.data:#06x}")
        info = self.handle_info()
        if info:
            print(f"handle info (0x84/1): {info}   project {info[8:14]} protocol {info[14:20]} "
                  f"fw {info[20:28]} hw {info[28:34]}")
        else:
            print("handle info (0x84/1): no reply")
        bat = self.pad.battery()
        print(f"battery: {bat['percent']}%  charging={bat['charging']}" if bat else "battery: (unreadable)")
        self.battery = bat


# ----------------------------------------------------------------------------- commands

def cmd_plan(args) -> None:
    cipher, plain, half = load_image(args.image)
    problems = check_image(plain)
    print(f"image      : {args.image}")
    print(f"half       : M12-HD-{half}")
    print(f"length     : {len(cipher)} bytes")
    print(f"OTA crc16  : {jlfw.crc16(cipher):04X}  (CRC-16/XMODEM over the ciphertext)")
    print()
    jlfw.info(plain)
    print()
    if problems:
        print("PROBLEMS:")
        for p in problems:
            print("  -", p)
        raise SystemExit(1)
    print("all header CRCs verify")
    print()
    n_blocks = (len(cipher) + OBSERVED_BLOCK - 1) // OBSERVED_BLOCK
    print("frames (control on FF11, data on FF12):")
    print(f"  0x50 ready    {hexs(ota_frame(CMD_READY, ready_content(cipher)))}")
    print(f"  0x51 block    {hexs(ota_frame(CMD_BLOCK))}   -> device answers the block size "
          f"({OBSERVED_BLOCK} observed)")
    print(f"  data          {n_blocks} blocks of {OBSERVED_BLOCK} bytes, raw, in 20-byte writes, e.g.")
    print(f"                {hexs(cipher[:ATT_PAYLOAD])}")
    print(f"                each block is acknowledged by a 0x52 notification before the next")
    print(f"  0x53 complete {hexs(ota_frame(CMD_DONE))}")


def cmd_probe(args) -> None:
    dev = Device(args.address, args.wait, args.verbose)
    dev.describe()
    print("no OTA command was sent.")


def cmd_flash(args) -> None:
    cipher, plain, half = load_image(args.image)
    problems = check_image(plain)
    if problems:
        print("image fails its own checks, refusing to send it:")
        for p in problems:
            print("  -", p)
        raise SystemExit(1)

    dry = not args.confirm
    dev = Device(args.address, args.wait, args.verbose)
    dev.describe()
    dev_half = dev.half()
    if dev_half and dev_half != half:
        raise SystemExit(f"image is for the {half} half but the device says it is the {dev_half} half")
    if not dev_half and not args.force_half:
        raise SystemExit("could not read which half this is; pass --force-half once you are sure "
                         f"the connected device is the {half} half")
    bat = dev.battery
    if bat is None:
        if not args.skip_battery:
            raise SystemExit("could not read the battery; pass --skip-battery to flash anyway")
        print("battery unreadable, continuing because --skip-battery was given")
    elif bat["percent"] < MIN_BATTERY and not args.skip_battery:
        raise SystemExit(f"battery {bat['percent']}% is below {MIN_BATTERY}%. Charge it first, "
                         "or pass --skip-battery. Losing power mid-write can brick the half.")

    print(f"image {args.image}: {len(cipher)} bytes, crc {jlfw.crc16(cipher):04X}, half {half}")
    link = OtaLink(dev.att, dev.ota, args.verbose, dry_run=dry)
    if dry:
        print("\nDRY RUN — nothing is written. Re-run with --confirm to flash.\n", file=sys.stderr)
        print(f"  would subscribe: write_req [{dev.ota.ctrl_cccd:#06x}] 01 00", file=sys.stderr)
    else:
        dev.att.write_req(dev.ota.ctrl_cccd, b"\x01\x00")
        # the app leaves ~5 s between this subscription and 0x50 in every capture; keep some of it
        time.sleep(2.0)

    reply = link.control(CMD_READY, ready_content(cipher))
    if not dry:
        if reply is None:
            raise SystemExit(f"no answer to 0x50 (last other notification: {hexs(link.last_other)}). "
                             "Nothing was written.")
        print(f"0x50 reply: {hexs(reply)}")
        if reply[:1] != b"\x00":
            raise SystemExit("the device rejected the OTA-ready frame. Nothing was written.")

    reply = link.control(CMD_BLOCK)
    block = OBSERVED_BLOCK
    if not dry:
        if reply is None or len(reply) < 2:
            raise SystemExit(f"no usable answer to 0x51: {hexs(reply)}. Nothing was written.")
        block = be(reply[:2])
        print(f"0x51 reply: {hexs(reply)} -> block size {block}")
        if not ATT_PAYLOAD <= block <= 4096 or block % ATT_PAYLOAD:
            raise SystemExit(f"block size {block} is outside anything seen; refusing to continue.")
        if block != OBSERVED_BLOCK:
            print(f"  (differs from the {OBSERVED_BLOCK} observed on the vendor app; continuing)")

    if dry:
        n_blocks = (len(cipher) + block - 1) // block
        print(f"  would stream {len(cipher)} bytes to [{dev.ota.data:#06x}] in {n_blocks} blocks of "
              f"{block}, waiting for a 0x52 notification after each", file=sys.stderr)
        link.control(CMD_DONE)
        print("dry run finished, nothing was written.")
        return

    t0 = time.time()
    sent = 0
    while sent < len(cipher):
        chunk = cipher[sent:sent + block]
        try:
            link.write_block(chunk)
        except LinkLost as e:
            raise SystemExit(f"\nlink lost after {sent} of {len(cipher)} bytes: {e}. The half holds "
                             "a partial image; run the whole flash again on a fresh connection.") from e
        ack = link.await_reply(CMD_PROGRESS, args.ack_timeout)
        if ack is None:
            raise SystemExit(f"\nno 0x52 progress notification after byte {sent + len(chunk)} of "
                             f"{len(cipher)} (last other notification: {hexs(link.last_other)}). "
                             "Stopping; the half holds a partial image. Run the whole flash again on a "
                             "fresh connection (the app never retries on the same link).")
        sent += len(chunk)
        status, got = ack[0], be(ack[1:5])
        if status != 0 or got != sent:
            raise SystemExit(f"\ndevice reports status {status:#x}, {got} bytes received, after "
                             f"{sent} sent. Stopping; run the whole flash again on a fresh connection.")
        if sent == len(chunk):
            print(f"first 0x52: {hexs(ack)}")
        if (sent // block) % 25 == 0 or sent == len(cipher):
            pct = 100.0 * sent / len(cipher)
            rate = sent / max(0.001, time.time() - t0)
            print(f"\r  {sent}/{len(cipher)} ({pct:.1f}%) {rate:.0f} B/s   ", end="", file=sys.stderr)
    print(file=sys.stderr)

    reply = link.control(CMD_DONE, timeout=15.0)
    if reply is None:
        raise SystemExit("the image was sent but the device did not answer 0x53. Do not power it "
                         "off; wait, then run `probe` to see which version it booted.")
    print(f"0x53 reply: {hexs(reply)}")
    if reply[:1] != b"\x00":
        raise SystemExit("the device answered 0x53 with a non-zero status; it may have rejected "
                         "the image. Run `probe` after it reboots to see which version it runs.")
    print(f"sent {len(cipher)} bytes in {time.time() - t0:.1f}s. Holding the link 5 s like the app, "
          "then closing; the half reboots into the new image. Verify with `probe`.")
    time.sleep(5.0)
    dev.att.sock.close()


def main() -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--address", help="BLE MAC of the half")
    common.add_argument("--wait", type=float, default=40.0, help="seconds to wait for it to advertise")
    common.add_argument("-v", "--verbose", action="store_true", help="dump frames")

    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("plan", help="offline: validate the image and print the frames")
    sp.add_argument("image")
    sp.set_defaults(func=cmd_plan)

    sp = sub.add_parser("probe", parents=[common], help="connect and identify, send nothing")
    sp.set_defaults(func=cmd_probe)

    sp = sub.add_parser("flash", parents=[common], help="write the image (needs --confirm)")
    sp.add_argument("image")
    sp.add_argument("--confirm", action="store_true", help="actually write; irreversible")
    sp.add_argument("--force-half", action="store_true",
                    help="proceed when the device name cannot be read")
    sp.add_argument("--skip-battery", action="store_true",
                    help="flash even on a low or unreadable battery")
    sp.add_argument("--ack-timeout", type=float, default=5.0,
                    help="seconds to wait for each block's 0x52 notification")
    sp.set_defaults(func=cmd_flash)

    args = p.parse_args()
    if getattr(args, "cmd", None) in ("probe", "flash") and not args.address:
        p.error("--address is required (tools/mobapad.py scan finds it)")
    try:
        args.func(args)
    except (AttError, LinkLost) as e:
        raise SystemExit(f"link error: {e}") from e
    return 0


if __name__ == "__main__":
    sys.exit(main())
