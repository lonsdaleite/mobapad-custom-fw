#!/usr/bin/env python3
"""CoreBluetooth transport for the M12 HD, with the same interface as `att.Att`.

macOS has no raw ATT socket, but CoreBluetooth discovers per service, so bleak sees the whole
table there (it cannot on BlueZ, see att.py). Callers keep using numeric handles: the map below is
built from the characteristics the OS discovered, so a handle that is not a real characteristic
raises instead of being written.

bleak reports a characteristic's declaration handle; the value is one above it and the CCCD, on a
notifying characteristic, one above that. CoreBluetooth owns CCCDs, so writing one is a subscribe.

Write-without-response has no flow control in bleak, and CoreBluetooth silently discards writes
when its queue is full. `write_cmd` therefore waits for `canSendWriteWithoutResponse` first.
"""
from __future__ import annotations

import asyncio
import queue
import re
import sys
import threading
import time

from att import AttError, LinkLost

BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"
CCCD_ENABLE = b"\x01\x00"
QUEUE_POLL_S = 0.001
QUEUE_STALL_S = 5.0
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.I)


def short_uuid(uuid: str) -> str:
    uuid = uuid.lower()
    if uuid.startswith("0000") and uuid.endswith(BASE_UUID_SUFFIX):
        return uuid[4:8]
    return uuid


class BleakAtt:
    """The subset of `att.Att` the tools use, synchronous over bleak's event loop."""

    def __init__(self, client, peripheral, loop: asyncio.AbstractEventLoop,
                 name: str = "", verbose: bool = False):
        self.client, self.peripheral, self.loop = client, peripheral, loop
        self.advertised_name = name
        self.verbose = verbose
        self.notify_handle: int | None = None
        self.values: dict[int, object] = {}
        self.cccds: dict[int, object] = {}
        self.subscribed: set[int] = set()
        self.ranges: list[tuple[int, int, str]] = []
        self.events: queue.Queue = queue.Queue()
        self.link_down = threading.Event()
        self._build_map()

    def _build_map(self) -> None:
        for service in self.client.services:
            last = first = None
            for char in sorted(service.characteristics, key=lambda c: c.handle):
                value = char.handle + 1
                self.values[value] = char
                first = char.handle if first is None else first
                last = value
                if {"notify", "indicate"} & set(char.properties):
                    self.cccds[value + 1] = char
                    last = value + 1
            if first is not None:
                self.ranges.append((first - 1, last, short_uuid(service.uuid)))
        self.ranges.sort()

    def on_disconnect(self, _client=None) -> None:
        self.link_down.set()
        self.events.put(None)  # queued after any notification that arrived first

    def _run(self, coro, timeout: float):
        try:
            return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)
        except TimeoutError as e:
            raise AttError("timed out waiting for CoreBluetooth") from e
        except Exception as e:
            if self.link_down.is_set():
                raise LinkLost(f"link dropped: {e}") from e
            raise AttError(str(e)) from e

    def _char(self, handle: int):
        try:
            return self.values[handle]
        except KeyError:
            raise AttError(f"handle {handle:#06x} is not a discovered characteristic value") from None

    def services(self) -> list[tuple[int, int, str]]:
        return list(self.ranges)

    def read(self, handle: int) -> bytes:
        return bytes(self._run(self.client.read_gatt_char(self._char(handle)), 5.0))

    def read_optional(self, handle: int) -> bytes | None:
        try:
            return self.read(handle)
        except AttError:
            return None

    def write_req(self, handle: int, data: bytes) -> None:
        """Only CCCD subscriptions are needed from the tools; refuse anything else."""
        char = self.cccds.get(handle)
        if char is None or data != CCCD_ENABLE:
            raise AttError(f"write request to {handle:#06x} is not a CCCD subscribe")
        if handle in self.subscribed:
            return
        value = handle - 1

        def deliver(_char, payload: bytearray) -> None:
            self.events.put((value, bytes(payload)))

        self._run(self.client.start_notify(char, deliver), 10.0)
        self.subscribed.add(handle)

    def write_cmd(self, handle: int, data: bytes) -> None:
        char = self._char(handle)
        deadline = time.monotonic() + QUEUE_STALL_S
        while not self.peripheral.canSendWriteWithoutResponse():
            if self.link_down.is_set():
                raise LinkLost("link dropped while writing")
            if time.monotonic() >= deadline:
                raise LinkLost(f"CoreBluetooth write queue stalled for {QUEUE_STALL_S:.0f} s")
            time.sleep(QUEUE_POLL_S)
        if self.link_down.is_set():
            raise LinkLost("link dropped while writing")
        self._run(self.client.write_gatt_char(char, data, response=False), 5.0)

    def next_notification(self, timeout: float) -> tuple[int, bytes] | None:
        """Return (value handle, payload), None on timeout; LinkLost once the link is gone."""
        try:
            event = self.events.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None
        if event is None:
            self.events.put(None)
            raise LinkLost("link closed by the device")
        return event

    def collect(self, seconds: float) -> list[bytes]:
        out: list[bytes] = []
        deadline = time.monotonic() + seconds
        while (left := deadline - time.monotonic()) > 0:
            try:
                event = self.next_notification(left)
            except LinkLost:
                return out
            if event is None:
                return out
            if self.notify_handle is None or event[0] == self.notify_handle:
                out.append(event[1])
        return out

    def close(self) -> None:
        try:
            self._run(self.client.disconnect(), 5.0)
        except AttError as e:
            print(f"disconnect: {e}", file=sys.stderr)


def matches(address: str, identifier: str, name: str) -> bool:
    if UUID_RE.match(address):
        return identifier.lower() == address.lower()
    return address.lower() in name.lower()


async def _find(address: str, wait: float):
    from bleak import BleakScanner

    found = asyncio.get_running_loop().create_future()

    def seen(device, adv) -> None:
        name = adv.local_name or device.name or ""
        if not found.done() and matches(address, device.address, name):
            found.set_result((device, name))

    async with BleakScanner(seen):
        try:
            return await asyncio.wait_for(found, wait)
        except asyncio.TimeoutError:
            raise AttError(f"no advertiser matching {address!r} within {wait:.0f} s "
                           "(press the half's button and retry)") from None


async def _open(address: str, wait: float, verbose: bool, loop) -> BleakAtt:
    from bleak import BleakClient

    device, name = await _find(address, wait)
    print(f"found {name or '(unnamed)'} [{device.address}]", file=sys.stderr)
    link: list[BleakAtt] = []
    client = BleakClient(device, timeout=20.0,
                         disconnected_callback=lambda c: link and link[0].on_disconnect(c))
    await client.connect()
    # Private bleak attribute: without it writes would be unpaced, so fail here if it moves.
    peripheral = client._backend._peripheral
    if not hasattr(peripheral, "canSendWriteWithoutResponse"):
        await client.disconnect()
        raise AttError("CoreBluetooth flow-control state is unavailable; refusing to continue")
    link.append(BleakAtt(client, peripheral, loop, name, verbose))
    return link[0]


def open_link(address: str, wait: float = 40.0, verbose: bool = False) -> BleakAtt:
    """Connect by advertised-name substring (`M12-HD-L`) or CoreBluetooth UUID."""
    if MAC_RE.match(address):
        raise AttError("macOS does not expose MAC addresses; pass the advertised name "
                       "(M12-HD-L or M12-HD-R) or the CoreBluetooth UUID")
    try:
        import bleak  # noqa: F401
    except ImportError:
        raise AttError("bleak is missing: python3 -m venv .venv && .venv/bin/pip install bleak") from None
    print("if this aborts right here, macOS refused this terminal Bluetooth access: "
          "use Terminal.app", file=sys.stderr, flush=True)
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, name="bleak", daemon=True).start()
    try:
        return asyncio.run_coroutine_threadsafe(_open(address, wait, verbose, loop), loop).result()
    except AttError:
        raise
    except Exception as e:
        raise AttError(f"connect failed: {e}") from e
