# Citrix NetScaler Triage

This repository contains a Dissect triage script for Citrix NetScaler devices.

You can use `iocitrix.py` to check for known Indicators of Compromise on a NetScaler Dissect target. It checks for the following things:

* Known strings used in webshells
* Timestomped files
* Suspicious cronjobs
* Unknown SUID binaries

Note that this script is meant to run on acquired disk images of Citrix NetScaler devices and not on the device itself.
Also see the "Acquiring Citrix NetScaler RAM disk" section about how to create a disk image of the Citrix NetScaler RAM disk.

Ensure that you have the latest version of Dissect, support for Citrix NetScaler was added in this PR: https://github.com/fox-it/dissect.target/pull/357

Disclaimer: While this tool strives for accuracy, it is possible for it to produce false posives or false negatives. Users are advised to cross-check results and use their own judgement before making any decisions based on this tool's output.

## iocitrix.py

Within the `citrix-netscaler-triage` folder, first run `pip install -r requirements.txt` to install the dependencies of this script. You can then run `iocitrix.py <<targets>>` to run an IOC check against one or more forensic images. The script accepts any input that `dissect` can read as a `Target`, such as a `.VMDK`, or a raw disk image. 

```shell
python3 iocitrix.py image.vmx
```

If you have also acquired a RAM disk, you can utilize the `MultiRawLoader` of Dissect like such:

```shell
python3 iocitrix.py md0.img+image.vmdk
```

Example output:
```
(venv) user@dissect:/data/netscaler/image$ python3 iocitrix.py md0.img+da0.img
<Target md0.img+da0.img>

Disks
- <RawContainer size=555745286 vs=None>
- <RawContainer size=21474836486 vs=<DissectVolumeSystem serial=None>>

Volumes
- <Volume name=None size=555745286 fs=<FfsFilesystem>>
- <Volume name='part_00000000' size=1717567488 fs=<FfsFilesystem>>
- <Volume name='part_66600000' size=4401922048 fs=<FfsFilesystem>>
- <Volume name='part_16cc00000' size=2097152 fs=<FfsFilesystem>>
- <Volume name='part_16ce00000' size=15353200128 fs=<FfsFilesystem>>

Hostname      : None
Domain        : None
IPs           : 10.164.0.39, 10.164.0.10
OS family     : citrix-netscaler (CitrixBsdPlugin)
OS version    : NetScaler 13.1 build 30 (ns-13.1-30.52)
Architecture  : x86_64-citrix-netscaler
Language(s)   :
Timezone      : None
Install date  : 2023-08-08 13:59:38.228043+00:00
Last activity : 2023-08-11 08:51:13.979536+00:00


*** Checking for webshells ***

<ioc/hit type='php-file-permission' alert='Suspicious php permission 0o644' confidence='high' path='/var/netscaler/logon/LogonPoint/uiareas/linux/adminupevents.php'>
<ioc/hit type='php-file-contents' alert="Suspicious PHP code 'b'array_filter(''" confidence='high' path='/var/netscaler/logon/LogonPoint/uiareas/linux/adminupevents.php'>
<ioc/hit type='php-file-permission' alert='Suspicious php permission 0o644' confidence='high' path='/var/vpn/config.php'>
<ioc/hit type='php-file-contents' alert="Suspicious PHP code 'b'array_filter(''" confidence='high' path='/var/vpn/config.php'>
<ioc/hit type='php-file-permission' alert='Suspicious php permission 0o644' confidence='high' path='/var/vpn/themes/config.php'>

*** Checking for timestomped files ***


*** Checking for suspicious cronjobs ***


*** Checking for SUID Binaries (this takes a while) ***

<ioc/hit type='binary/suid' alert='Binary with SUID bit set Observed' confidence='medium' path='/tmp/python/bash'>

********************************************************************************
***                                                                          ***
*** There were findings for Indicators of Compromise.                        ***
*** Please consider performing further forensic investigation of the system. ***
***                                                                          ***
********************************************************************************

Confidence    Type                 Alert                                       Artefact Location
------------  -------------------  ------------------------------------------  ---------------------------------------------------------------
high          php-file-permission  Suspicious php permission 0o644             /var/netscaler/logon/LogonPoint/uiareas/linux/adminupevents.php
high          php-file-contents    Suspicious PHP code 'b'array_filter(''      /var/netscaler/logon/LogonPoint/uiareas/linux/adminupevents.php
high          php-file-permission  Suspicious php permission 0o644             /var/vpn/config.php
high          php-file-contents    Suspicious PHP code 'b'array_filter(''      /var/vpn/config.php
high          php-file-permission  Suspicious php permission 0o644             /var/vpn/themes/config.php
medium        binary/suid          Binary with SUID bit set Observed           /tmp/python/bash

All targets analyzed.
```

## Acquiring Citrix NetScaler RAM disk

Note that the root directory of Citrix NetScaler is a RAM disk, meaning that this is volatile and gone if you shutdown the NetScaler.
Some volatile configuration changes can be stored on the root disk, such as `crontab`.

When investigating offline on disk images of Citrix NetScalers we recommend to also create a disk image of the RAM disk so that information is not lost.
You can use the following steps to create a disk image of the RAM disk:

1. Login to Citrix NetScaler over SSH
2. type in `shell` to start a shell session.
3. Use the `dd` command to create an image of the RAM disk `/dev/md0`:

```shell
dd if=/dev/md0 bs=10M of=/var/tmp/md0.img
```
4. This takes several seconds as the RAM disk is fairly small, after it is done the disk image is available in `/var/tmp`.
5. Use `scp` to copy this file over.

Example session:

```
local $ ssh nsroot@<NETSCALER-IP>
###############################################################################
#                                                                             #
#        WARNING: Access to this system is for authorized users only          #
#         Disconnect IMMEDIATELY if you are not an authorized user!           #
#                                                                             #
###############################################################################

(nsroot@<NETSCALER-IP>) Password: 
 Done
> shell
root@ns# mount
/dev/md0 on / (ufs, local)
devfs on /dev (devfs, local, multilabel)
procfs on /proc (procfs, local)
/dev/da0s1a on /flash (ufs, local, soft-updates)
/dev/da0s1e on /var (ufs, local, soft-updates)

root@ns# dd if=/dev/md0 bs=10M of=/var/tmp/md0.img
53+0 records in
53+0 records out
555745280 bytes transferred in 4.753627 secs (116909732 bytes/sec)

root@ns# exit
logout
 Done
> exit
Bye!

local $ scp -C nsroot@<NETSCALER-IP>:/var/tmp/md0.img md0.img
md0.img                        100%  530MB   6.6MB/s   01:20     
```

## Acquiring Citrix NetScaler disks over SSH

If you prefer not to write the disk image to `/var/tmp`, you can also stream the disk image directly over SSH to your own machine without touching the disk of the NetScaler device:

```shell
local $ ssh nsroot@<NETSCALER-IP> shell dd if=/dev/md0 bs=10M > md0.img
```

Do note that the builtin shell of NetScaler outputs a ` Done\n` message before and after your command to stdout, so this needs to be stripped from the file.

This can be done using the following oneliner:

```shell
local $ cat md0.img | tail -c +7 | head -c -6 > md0.img.fixed
```

- `tail -c +7` skips the first 6 bytes (yes this needs to be +7)
- `head -c -6` skips the last 6 bytes
- `> md0.img.fixed` is the new fixed output file

You can also chain this directly in the original SSH command:

```shell
local $ ssh nsroot@<NETSCALER-IP> shell dd if=/dev/md0 bs=10M | tail -c +7 | head -c -6 > md0.img
```

This method can also be used to acquire an image of the `/flash` and `/var` disk, which usually resides on `/dev/da0`:

```
local $ ssh nsroot@<NETSCALER-IP> shell dd if=/dev/da0 bs=10M | tail -c +7 | head -c -6 > da0.img
```
