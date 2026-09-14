# Mobapad M12 HD custom firmware

Custom firmware for the **Mobapad M12 HD** Joy-Con style controller (both halves), plus the tool
that flashes it over Bluetooth LE from Linux.

# ⚠️ USE AT YOUR OWN RISK ⚠️

**THIS IS NOT VENDOR SOFTWARE. FLASHING FIRMWARE CAN PERMANENTLY BRICK YOUR CONTROLLER.
THERE IS NO WARRANTY, NO SUPPORT AND NO GUARANTEE OF ANY KIND. IF IT BREAKS, YOU KEEP BOTH
HALVES. BY USING ANYTHING IN THIS REPOSITORY YOU ACCEPT FULL RESPONSIBILITY FOR THE OUTCOME.**

Do not flash on a low battery. Do not power off, undock or walk away from the controller while a
flash is running. Do not flash a file that did not come from this repository.

## What the custom firmware changes

Base: stock firmware **0.33** for each half, with one change.

**The gyro axis swap follows the connection.** Stock firmware applies the axis swap whenever the
app's "axis swap" switch is on, regardless of how the controller is connected. The custom
firmware swaps the axes **only while the half is docked on the Switch rails (USB)** and leaves
them alone **over Bluetooth**.

The app's "axis swap" switch is still there and now sets the polarity:

| App switch | Docked (USB) | Wireless (Bluetooth) |
|---|---|---|
| off (default) | swapped | not swapped |
| on | not swapped | swapped |

Nothing else is touched: stored settings, remaps, macros, turbo, lighting and the update path all
work as before. The reported version stays 0.33, so the vendor app treats the half as up to date.

Both halves have been flashed with these images and verified on a Switch.

### Known limitations

The firmware decides "docked" by whether **USB power** is present, not by whether the half is
actually on the console. Two situations therefore behave like the opposite connection:

* **On the rails with the rear charging switch off.** No USB power, so the half acts as
  wireless: axes not swapped even though it is docked.
* **Wireless, but sitting on the magnetic charging adapter** (the bundled one with the USB-C
  cable) while you play. USB power present, so the half acts as docked: axes swapped.

In both cases flipping the app's "axis swap" switch for the session gives the right result.

## Files

| Path | What |
|---|---|
| `firmware/custom/M12-HD-L-0.33-axisusb.bin` | custom image, **left** half |
| `firmware/custom/M12-HD-R-0.33-axisusb.bin` | custom image, **right** half |
| `otaflash.py` | the flasher |
| `att.py`, `jlfw.py`, `mobapad.py` | modules the flasher needs, keep them next to it |

Left images only go on the left half and right images only on the right half. The flasher checks
this and refuses a mismatch.

## Requirements

* Linux with a Bluetooth LE adapter, BlueZ installed (`hcitool` is used), Python 3.10+.
* Root: the flasher talks raw L2CAP/ATT, which is not available to a normal user.
* A real host or a VM with the adapter passed through. **It does not work inside an LXC/Docker
  container** — Bluetooth sockets only exist in the root network namespace.
* The half must be within a metre or two of the adapter and charged (the flasher refuses below
  50 %).
* The half must not be connected to the vendor app or to any other BLE host at the same time.
  Being docked on a Switch is fine; both halves were flashed while docked.

No Python packages are needed for flashing. Only `mobapad.py scan` needs `bleak`, and
`bluetoothctl` does the same job without it.

## How to flash

1. Find the Bluetooth address of each half (see below).

2. Dry run. This connects, identifies the half, reads the battery and prints exactly what it would
   send. Nothing is written without `--confirm`.

   ```
   sudo python3 otaflash.py flash firmware/custom/M12-HD-L-0.33-axisusb.bin --address AA:BB:CC:DD:EE:FF
   ```

   Check that the reported name matches the image (`M12-HD-L` for the left image) and the battery
   is fine.

3. Flash for real:

   ```
   sudo python3 otaflash.py flash firmware/custom/M12-HD-L-0.33-axisusb.bin --address AA:BB:CC:DD:EE:FF --confirm
   ```

   Takes four to six minutes. Progress is printed every 10 KB. At the end you should see
   `0x53 reply: 00`; the half then reboots on its own into the new firmware.

4. Verify it came back:

   ```
   sudo python3 otaflash.py probe --address AA:BB:CC:DD:EE:FF
   ```

   It should report the name, `fw 00000033` and the battery. The first connection attempt right
   after a flash sometimes fails with `Function not implemented`; wait a few seconds and retry.

5. Repeat for the other half with the other image.

If a flash aborts partway (lost link, missing acknowledgement), the half keeps running its old
firmware — the new image is only committed at the end. Wait for it to drop the connection, then
run the whole flash again from the start. Do not power it off in the middle.

## Finding the addresses

Each half has its own Bluetooth address; you need both. The left half advertises as
`Mobapad M12-HD-L`, the right as `Mobapad M12-HD-R`. A half only advertises for about ten
seconds after it wakes, so press any button on it while scanning, or keep it docked on the
console (it stays reachable there).

Any of these works on the Linux box you will flash from:

* With BlueZ's own tool, no extra packages:

  ```
  bluetoothctl
  [bluetooth]# scan on
  ```

  Wait for lines like `[NEW] Device A0:58:5F:B0:58:11 Mobapad M12-HD-L`, then `scan off` and
  `exit`. Do **not** `pair` or `connect` from here.

* Or with the included client, which needs `pip install bleak` first:

  ```
  sudo python3 mobapad.py scan
  ```

The addresses do not change, so note them once. If you see the name but no address (some
tools show the name only in a second line), `sudo hcitool lescan` prints both side by side.

## macOS

**The flasher does not run on macOS.** It talks to the controller through a raw Linux Bluetooth
socket, which macOS does not have, and it relies on BlueZ's `hcitool`. The reason it is done that
way is that the controller's command characteristics are not discoverable by a normal BLE stack,
so a CoreBluetooth port is not a matter of swapping a library; it has not been attempted.

What does work from a Mac:

* A Linux VM with a **USB Bluetooth dongle passed through** to it. The Mac's built-in adapter
  cannot be handed to a VM, so a cheap external dongle is needed.
* Any small Linux box on the network: a Raspberry Pi with its onboard Bluetooth, or a PC. Copy
  this repository there and flash from it over SSH.

## Rolling back

Stock images are not distributed here. Roll back with the **official Mobapad Android app**, which
reflashes any stock version over the custom one and does not know the firmware was changed:

1. Connect the half in the app and open the firmware update screen.
2. Pick **0.29** and flash it. The app refuses to flash the version the half already reports, and
   the custom build reports 0.33, so a different version has to go on first.
3. When the half is back, pick **0.33** and flash it again.

Do this for each half. Both halves have been through exactly this cycle.

## Other commands

`otaflash.py plan IMAGE` validates an image offline and prints the frames. `mobapad.py` is a
general read-only client for the controller's configuration (`all`, `info`, `remaps`, `config`,
`macros`, …); it is included because the flasher uses it, and it is handy to check that settings
survived a flash.
