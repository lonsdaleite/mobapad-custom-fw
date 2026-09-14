#!/usr/bin/env python3
"""Raw ATT transport for the Mobapad M12 HD.

BlueZ is unusable with this device: its GATT server answers Read By Group Type
(so the service ranges are visible) but returns "Attribute Not Found" for
characteristic and descriptor discovery. BlueZ therefore never learns the FF00
characteristics, and bleak sees an empty device. This module talks ATT over an
L2CAP socket on CID 4 instead, deriving handles from the service ranges.

Two device quirks drive the design:

* Characteristic handles cannot be discovered. They are computed from the
  service range using the standard GATT layout (declaration, value, optional
  CCCD), which was verified on hardware against 180A, whose value handles read
  back correctly.
* Commands must be sent as ATT Write Command (no response). The firmware ACKs a
  Write Request at the protocol level and then silently drops it.
"""
from __future__ import annotations

import ctypes
import errno
import os
import select
import socket
import struct
import time

BTPROTO_L2CAP = 0
ATT_CID = 4
BDADDR_LE_PUBLIC = 1
BDADDR_LE_RANDOM = 2

ATT_ERROR_RSP = 0x01
ATT_READ_REQ = 0x0A
ATT_READ_RSP = 0x0B
ATT_READ_BY_GROUP_REQ = 0x10
ATT_READ_BY_GROUP_RSP = 0x11
ATT_WRITE_REQ = 0x12
ATT_WRITE_RSP = 0x13
ATT_WRITE_CMD = 0x52
ATT_HANDLE_NOTIFY = 0x1B
ATT_HANDLE_INDICATE = 0x1D

ATT_ERRORS = {
    0x01: "Invalid Handle", 0x02: "Read Not Permitted", 0x03: "Write Not Permitted",
    0x05: "Insufficient Authentication", 0x06: "Request Not Supported",
    0x07: "Invalid Offset", 0x08: "Insufficient Authorization",
    0x0A: "Attribute Not Found", 0x0C: "Insufficient Encryption Key Size",
    0x0E: "Unlikely Error", 0x0F: "Insufficient Encryption",
    0x11: "Insufficient Resources",
}

UUID_CMD_SERVICE = "ff00"
UUID_OTA_SERVICE = "ff10"
UUID_DEVICE_INFO = "180a"

libc = ctypes.CDLL("libc.so.6", use_errno=True)


class SockaddrL2(ctypes.Structure):
    _fields_ = [
        ("l2_family", ctypes.c_ushort),
        ("l2_psm", ctypes.c_ushort),
        ("l2_bdaddr", ctypes.c_ubyte * 6),
        ("l2_cid", ctypes.c_ushort),
        ("l2_bdaddr_type", ctypes.c_ubyte),
    ]


def _addr_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in reversed(mac.split(":")))


class AttError(Exception):
    pass


class LinkLost(AttError):
    """The half went away mid-conversation (it sleeps aggressively)."""


def connect(dst: str, wait: float = 40.0, dst_type: int = BDADDR_LE_PUBLIC,
            src: str = "00:00:00:00:00:00") -> socket.socket:
    """Open an ATT channel, waiting for the half to start advertising.

    The connect is issued non-blocking and left pending, so the kernel completes
    it the moment the device shows up -- one button press at any time during the
    wait is enough.
    """
    fd = libc.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
    if fd < 0:
        raise AttError(f"socket: {os.strerror(ctypes.get_errno())}")
    os.set_blocking(fd, False)

    local = SockaddrL2(socket.AF_BLUETOOTH, 0, (ctypes.c_ubyte * 6)(*_addr_bytes(src)),
                       ATT_CID, BDADDR_LE_PUBLIC)
    if libc.bind(fd, ctypes.byref(local), ctypes.sizeof(local)) < 0:
        e = ctypes.get_errno()
        os.close(fd)
        raise AttError(f"bind: {os.strerror(e)}")

    remote = SockaddrL2(socket.AF_BLUETOOTH, 0, (ctypes.c_ubyte * 6)(*_addr_bytes(dst)),
                        ATT_CID, dst_type)
    if libc.connect(fd, ctypes.byref(remote), ctypes.sizeof(remote)) < 0:
        e = ctypes.get_errno()
        if e != errno.EINPROGRESS:
            os.close(fd)
            raise AttError(f"connect: {os.strerror(e)}")
        _, w, _ = select.select([], [fd], [], wait)
        if not w:
            os.close(fd)
            raise AttError("timed out waiting for the half to advertise "
                           "(press its pairing button and retry)")
        err = socket.socket(fileno=os.dup(fd)).getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err:
            os.close(fd)
            raise AttError(f"connect failed: {os.strerror(err)}")

    os.set_blocking(fd, True)
    sock = socket.socket(fileno=fd)
    sock.settimeout(5.0)
    return sock


class Att:
    """Minimal ATT client: the requests this firmware actually answers."""

    def __init__(self, sock: socket.socket, verbose: bool = False):
        self.sock = sock
        self.verbose = verbose
        self.notify_handle: int | None = None
        self._pending: list[bytes] = []   # notifications seen while awaiting a response

    # -- plumbing -----------------------------------------------------------

    @staticmethod
    def _err(rsp: bytes) -> str | None:
        if rsp and rsp[0] == ATT_ERROR_RSP and len(rsp) >= 5:
            code = rsp[4]
            handle = rsp[2] | rsp[3] << 8
            return f"{ATT_ERRORS.get(code, 'Unknown')} (0x{code:02X}) at handle 0x{handle:04X}"
        return None

    def _recv(self, timeout: float) -> bytes | None:
        r, _, _ = select.select([self.sock], [], [], timeout)
        if not r:
            return None
        try:
            return self.sock.recv(1024)
        except OSError:
            return None

    def _request(self, pdu: bytes, timeout: float = 5.0) -> bytes:
        """Send a request and return its response, stashing notifications."""
        self.sock.send(pdu)
        deadline = time.time() + timeout
        while True:
            rsp = self._recv(max(0.05, deadline - time.time()))
            if rsp is None:
                raise AttError("timed out waiting for an ATT response")
            if rsp[0] in (ATT_HANDLE_NOTIFY, ATT_HANDLE_INDICATE):
                self._pending.append(rsp)
                continue
            return rsp

    # -- operations ---------------------------------------------------------

    def read(self, handle: int) -> bytes:
        rsp = self._request(struct.pack("<BH", ATT_READ_REQ, handle))
        err = self._err(rsp)
        if err:
            raise AttError(err)
        if rsp[0] != ATT_READ_RSP:
            raise AttError(f"unexpected opcode 0x{rsp[0]:02X}")
        return rsp[1:]

    def read_optional(self, handle: int) -> bytes | None:
        try:
            return self.read(handle)
        except AttError:
            return None

    def write_req(self, handle: int, data: bytes) -> None:
        rsp = self._request(struct.pack("<BH", ATT_WRITE_REQ, handle) + data)
        err = self._err(rsp)
        if err:
            raise AttError(err)

    def write_cmd(self, handle: int, data: bytes) -> None:
        """Write Command -- the only form this firmware acts on."""
        try:
            self.sock.send(struct.pack("<BH", ATT_WRITE_CMD, handle) + data)
        except OSError as e:
            raise LinkLost(f"link dropped while writing: {e}") from e

    def services(self) -> list[tuple[int, int, str]]:
        """[(start, end, uuid)] via Read By Group Type, the one discovery that works."""
        out: list[tuple[int, int, str]] = []
        start = 1
        while start <= 0xFFFF:
            rsp = self._request(struct.pack("<BHHH", ATT_READ_BY_GROUP_REQ, start, 0xFFFF, 0x2800))
            if self._err(rsp):
                break
            if rsp[0] != ATT_READ_BY_GROUP_RSP:
                break
            step, body = rsp[1], rsp[2:]
            for i in range(0, len(body) - step + 1, step):
                e = body[i:i + step]
                out.append((e[0] | e[1] << 8, e[2] | e[3] << 8, e[4:][::-1].hex()))
            start = out[-1][1] + 1
        return out

    # -- notifications ------------------------------------------------------

    def collect(self, seconds: float) -> list[bytes]:
        """Gather notification payloads from the command characteristic."""
        out = [p for p in self._drain_pending()]
        deadline = time.time() + seconds
        while True:
            left = deadline - time.time()
            if left <= 0:
                return out
            pdu = self._recv(left)
            if pdu is None:
                return out
            if pdu[0] in (ATT_HANDLE_NOTIFY, ATT_HANDLE_INDICATE) and len(pdu) >= 3:
                handle = pdu[1] | pdu[2] << 8
                if self.notify_handle is None or handle == self.notify_handle:
                    out.append(pdu[3:])

    def _drain_pending(self) -> list[bytes]:
        out = []
        for pdu in self._pending:
            handle = pdu[1] | pdu[2] << 8
            if self.notify_handle is None or handle == self.notify_handle:
                out.append(pdu[3:])
        self._pending.clear()
        return out


class Handles:
    """Handles derived from a service range, since discovery is unavailable.

    A characteristic occupies a declaration handle plus a value handle, and one
    more for the CCCD when it can notify. The FF00 range is six handles, which
    only decomposes as service + (write char) + (notify char with CCCD).
    """

    def __init__(self, cmd_start: int):
        self.cmd = cmd_start + 2       # FF01 value  -- commands are written here
        self.notify = cmd_start + 4    # FF02 value  -- responses arrive here
        self.cccd = cmd_start + 5      # FF02 CCCD   -- write 0x0001 to subscribe

    def __repr__(self) -> str:
        return (f"Handles(cmd=0x{self.cmd:04X}, notify=0x{self.notify:04X}, "
                f"cccd=0x{self.cccd:04X})")


def find_ranges(att: Att) -> dict[str, tuple[int, int]]:
    return {uuid: (s, e) for s, e, uuid in att.services()}
