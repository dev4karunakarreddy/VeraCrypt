# SOS password and Linux slot regression checks

Build the GUI application using the repository's Linux build instructions, then run:

```sh
src/Main/veracrypt --text --test
python3 Tests/test_linux_volume_slots.py
python3 Tests/test_safeguard_wipe.py
python3 Tests/test_backup_header_retry.py
```

The SOS test requires a Linux build, Python 3, and a C++11 compiler. It links the
production volume and platform libraries and creates disposable file containers
in a temporary directory. It does not mount volumes or access real devices.
It checks primary and backup SOS headers, read-only reopening, failed writes,
credential/cache/key erasure, exception serialization, ordinary passwords, and
rejection of invalid creation settings without changing an existing host.
The slot test compiles production selection methods with scripted discovery.

## Behavior and compatibility

SOS creation is available for new normal volumes in the Unix application GUI
and CLI (`--sos-password` or `--safeguard-password`). Hidden volumes and their
outer-volume creation workflow do not support SOS: the SOS headers occupy the
reserved hidden-header locations. Creating a hidden volume later replaces these
headers and disables SOS. Changing the ordinary password does not change SOS.

To trigger SOS, use the SOS password as the mount password, PIM 0, and no
keyfiles. The SOS header uses the hash selected at creation; automatic hash
detection also works. An ordinary wrong password or wrong keyfile does not
trigger erasure. SOS detection is implemented in the common Unix volume-open
path, so any operation opening the host with those SOS credentials can trigger
it, including operations besides mounting. Windows' separate mount/driver path
does not implement this behavior. Do not expect an unmodified VeraCrypt build
to honor SOS headers.

Detection clears the current process's password cache and reachable password,
header, cipher and XTS key objects and resets the local and mount-option PIMs,
then overwrites and flushes the host and checks that reads return zeroes. A regular container is truncated and deleted
only after that check. A failure reports possible remaining data rather than
claiming success. Read-only access attempts a writable reopen, which can fail.

This does not guarantee physical erasure on SSDs, remapped sectors, snapshots,
backups, swap, hibernation files, memory dumps or other processes. Read-back can
be served by the operating system's cache. GUI string copies and credentials in
other processes are not guaranteed to be erased. Live devices, mounted hosts,
Windows, macOS and the WolfCrypt backend require separate validation; the Linux
file tests do not establish safety for those configurations.
