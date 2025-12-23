# Unisoc stuff

- `kernel-module`: kernel module to bypass signature verification in the kernel and boot arbitrary baseband firmware.
- `ldpreload_dump`: contains code to ldpreload for all binaries and do strace + debugging in one go
- `c-based`: Shellscripting given a dump from the `/dev/ubi0_nr_modem`. 
    Allows to inject code to modify the behavior of the baseband.
    Also includes some scripts for parsing log output from the baseband.
- `modem_control`: contains a gdb script to modify the behavior of the baseband by overwriting the path for baseband firmware and booting our version.


## From zero to hero

Assuming a fresh device from factory, you need to do as follows:

1. Enable ADB:

```bash
# Connect to /dev/ttyUSB2 (AT command console)
sudo minicom -o -D /dev/ttyUSB2

# In the shell (separated by Newline):
# Enable AT echo:
ATE1
# Get ADB Key
AT+QGETADBKEY?
# Returns e.g. XXXXXX_7_13_27 (depending on S/N)

# Compute the key for Access
/usr/bin/openssl passwd -1 -salt "QUE_V002" "XXXXXX_7_13_27"
# Assume returns: AAAAA
AT+QADBKEY="AAAAA"

# Enable ADB USB 
AT+QCFG="usbcfg",0x2C7C,0x0800,1,1,1,1,1,1,0

# Connect via ADB (you are root now)
adb shell
```

2. Get ARMLogs

```bash

# In the console /dev/ttyUSB2
AT+ARMLOG=1
# Expose them to /dev/ttyUSB4
AT+QTEST="debug",4

```

3. Reboot
```bash
AT+CFUN=1,1
```


### Useful things

```bash
# Switch UE to minimum (or back to full) functionality.
- AT+CFUN=0
- AT+CFUN=1
# Attach to or detach from network
- AT+CGATT=0   # detach
- AT+CGATT=1   # re-attach, or force attach

# see which networks are available
- AT+COPS=?
# Enable network registration unsolicited result code
- AT+CREG=2
- set the RAT mode to 5G NR only
- AT+QNWPREFCFG= "mode_pref",NR5G
- query/set bands
- AT+QNWPREFCFG= "nr5g_band"
- AT+QNWPREFCFG= "nr5g_band",78
```

## Remote debugging

1. Get a GDB that is aarch64

```bash
wget https://github.com/hugsy/gdb-static/blob/master/gdbserver-8.1.1-aarch64-le
```

2. Copy over to the device

```bash
#remount root fs RW
mount -o rw,remount /
adb push gdbserver-8.1.1-aarch64-le /usr/bin/gdbserver
```

3. Run inside adb shell

```bash
gdbserver --attach PID
adb forward tcp:8000 tcp:8080

#on host need gdb-multiarch
sudo apt install gdb-multiarch
#connect to the remote gdbserver
#target remote localhost:8000
```

## Goodies for pcap collection and analysis

```
# convert pcap to json
tshark -r your.pcap -l -n -T json
```

### Getting baseband logs

```bash
mount -o remount,rw /
add to /mnt/data/modem.ini
ro.debuggable                  = 1

# Kill loggers
kill slogmodem
kill engpc

# Get it at the source
# dd if=/dev/slog_lte of=/var/volatile/bb.log
# Use the logparser (wip)





