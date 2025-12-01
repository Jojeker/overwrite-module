# Unisoc stuff

- `kernel-module`: kernel module to bypass signature verification in the kernel and boot arbitrary baseband firmware.
- `ldpreload_dump`: contains code to ldpreload for all binaries and do strace + debugging in one go
- `c-based`: Shellscripting given a dump from the `/dev/ubi0_nr_modem`. 
    Allows to inject code to modify the behavior of the baseband.
    Also includes some scripts for parsing log output from the baseband.
- `modem_control`: contains a gdb script to modify the behavior of the baseband by overwriting the path for baseband firmware and booting our version.
