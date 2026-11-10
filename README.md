# Mobapad M12 HD custom firmware

Custom firmware for the **Mobapad M12 HD** Joy-Con style controller (both halves), plus a tool
that flashes it over Bluetooth LE from **macOS or Linux**.

**New: `switch2-native-v2` fixes waking the console with Home. If you flashed the first release,
[update](#version-2-update-if-you-flashed-the-first-release).**

# ⚠️ USE AT YOUR OWN RISK ⚠️

**THIS IS NOT VENDOR SOFTWARE. FLASHING FIRMWARE CAN PERMANENTLY BRICK YOUR CONTROLLER.
THERE IS NO WARRANTY, NO SUPPORT AND NO GUARANTEE OF ANY KIND. IF IT BREAKS, YOU KEEP BOTH
HALVES. BY USING ANYTHING IN THIS REPOSITORY YOU ACCEPT FULL RESPONSIBILITY FOR THE OUTCOME.**

Do not flash on a low battery. Do not power off or walk away from the controller while a flash is
running. Do not flash a file that did not come from this repository.

## Choose a firmware

Both are based on stock firmware **0.33** for each half and report version 0.33. Stored settings
and the update path are kept. Pick one and put the same kind on both halves.

| Firmware | On the Switch 2 rails (USB) | Choose it if |
|---|---|---|
| `axisusb` | stock protocol, gyro axes fixed | you only want the gyro fix |
| `axisusb-autoconnect` | stock protocol (wired Pro Controller), connects by itself, gyro axes fixed | you want stock behaviour with the two fixes and no protocol change |
| `switch2-native` | native Switch 2 controller protocol | you want the half to act like an original Joy-Con 2 on the rails, including NFC |

## `switch2-native`

**On the rails (USB) each half speaks the native Switch 2 controller protocol**, like an original
Joy-Con 2:

* buttons and sticks;
* gyro;
* rumble, as strong as over Bluetooth;
* amiibo/NFC reading and writing in games, on the right half;
* no controller-update prompt and no repeated pairing notifications (tested on console firmware
  23.0.1).

**Detached (Bluetooth), the halves work as Switch 1 style Joy-Cons**, as on stock firmware, and
stay paired after the console restarts. The Switch 2 protocol is not implemented over Bluetooth.

**Home on the right half wakes the console over Bluetooth**, on or off the rails, as on stock
firmware.

Known limitation: charging while the console is fully powered off has not been checked.

### Version 2: update if you flashed the first release

The current files are `switch2-native-v2`. The first release (`switch2-native`, without `-v2`)
could stop waking the console with Home once the console had been asleep for about a minute.
Version 2 fixes that.

To update, flash both halves with the `-v2` files, then attach them to the console. It shows
"Paired" once for each half; that is expected and does not come back.

## `axisusb-autoconnect` and `axisusb`

The `axisusb-autoconnect` images carry both changes below; the `axisusb` images carry the axis
swap only.

**A docked half connects by itself on the Switch 2.** Docked on a Switch 2, the half turns
into a wired Pro Controller, and the console makes a wired Pro Controller a player only after
a button press on it — every time it is docked and every time the console wakes from sleep —
and swallows that press. The custom firmware supplies the press itself: for the first moments
after docking it reports a stick click (L3 on the left half, R3 on the right) every quarter
second until the console has taken the half as a player. At most one stray stick click can
reach a game right after docking or waking. Docking to "connected" still takes about two
seconds; that is the console's own handshake.

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
work as before. Both halves have been flashed with the `axisusb-autoconnect` images and verified
on a Switch 2.

### Known limitations

The firmware decides "docked" by whether **USB power** is present, not by whether the half is
actually on the console. Two situations therefore behave like the opposite connection:

* **On the rails with the rear charging switch off.** No USB power, so the half acts as
  wireless: axes not swapped even though it is docked.
* **Wireless, but sitting on the magnetic charging adapter** (the bundled one with the USB-C
  cable) while you play. USB power present, so the half acts as docked: axes swapped.

In both cases flipping the app's "axis swap" switch for the session gives the right result.

## How to flash

You flash each half separately. The whole thing takes about three minutes per half on a Mac.
Before you start:

* charge the half: the flasher refuses below 50 %;
* keep it within a metre or two of the computer;
* close the vendor app, so nothing else is connected to the half over BLE.

The flasher checks the image and refuses to put a left image on a right half or the other way round.

The commands below use `switch2-native`. For another firmware, change the file name, for example
`M12-HD-L-0.33-axisusb-autoconnect.bin`.

### macOS

Python 3.10 or newer is required (`python3 --version`; `brew install python` if it is older).

Use the built-in **Terminal.app**. Some other terminals, Warp for one, cannot get Bluetooth access
and the flasher dies with `Abort trap: 6`. Allow Bluetooth when macOS asks.

1. Set up, once:

   ```
   git clone https://github.com/lonsdaleite/mobapad-custom-fw
   cd mobapad-custom-fw
   python3 -m venv .venv
   .venv/bin/pip install bleak
   ```

2. Flash the left half. Run this, then press any button on the half so that it shows up:

   ```
   .venv/bin/python otaflash.py flash firmware/custom/M12-HD-L-0.33-switch2-native-v2.bin --address M12-HD-L --wait 60 --confirm
   ```

3. Flash the right half the same way:

   ```
   .venv/bin/python otaflash.py flash firmware/custom/M12-HD-R-0.33-switch2-native-v2.bin --address M12-HD-R --wait 60 --confirm
   ```

Without `--confirm` the same command is a dry run that connects, runs every check and writes
nothing.

### Linux

You need a Bluetooth LE adapter, BlueZ (`hcitool`), Python 3.10+ and root. It does not work inside
an LXC or Docker container. No Python packages are needed.

1. Find the address of each half. Run `bluetoothctl`, type `scan on`, press a button on the half
   and note the address next to `Mobapad M12-HD-L` or `Mobapad M12-HD-R`. Do not pair or connect
   from there. Type `exit` when done.

2. Flash, using the address you noted:

   ```
   sudo python3 otaflash.py flash firmware/custom/M12-HD-L-0.33-switch2-native-v2.bin --address AA:BB:CC:DD:EE:FF --confirm
   sudo python3 otaflash.py flash firmware/custom/M12-HD-R-0.33-switch2-native-v2.bin --address 11:22:33:44:55:66 --confirm
   ```

### Windows

There is no Windows flasher so far. Windows' own Bluetooth stack drops the connection to the
controller right after connecting, and I have not found a simple way around that yet. For now,
flash from a Mac or from Linux, for example a live USB or a Raspberry Pi.

### When it finishes

You should see `0x53 reply: 00`, then the half reboots by itself. Put both halves on the console.
If a half does not reconnect wirelessly afterwards, pair it again from the console's controller
menu.

### If it stops partway

This happens from time to time. Just run the same command again and the flash will start over;
that has always been enough to finish it.

## Files

| Path | What |
|---|---|
| `firmware/custom/M12-HD-{L,R}-0.33-axisusb.bin` | gyro axis swap on USB only |
| `firmware/custom/M12-HD-{L,R}-0.33-axisusb-autoconnect.bin` | automatic connection on the rails and gyro axis swap on USB |
| `firmware/custom/M12-HD-{L,R}-0.33-switch2-native-v2.bin` | native Switch 2 protocol on USB |
| `otaflash.py` | the flasher |
| `att.py`, `att_bleak.py`, `jlfw.py`, `mobapad.py` | modules the flasher needs, keep them next to it |

## Rolling back

Stock images are not distributed here. To go back, use the **official Mobapad Android or iOS app** on
each half. It refuses to flash the version the half already reports, so flash **0.29** first and
then **0.33**.

To switch to another firmware from this repository, flash it with the same commands as above.
