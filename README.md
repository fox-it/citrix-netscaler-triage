# Citrix NetScaler Triage

This repository contains a Dissect triage script for Citrix NetScaler devices.

You can use `iocitrix.py` to check for known Indicators of Compromise on a NetScaler Dissect target. It checks for the following things:

* Known strings used in webshells
* Timestomped files
* Suspicious cronjobs
* Unknown SUID binaries

Note that this script is meant to run on forensic disk images of Citrix NetScaler devices and not on the device itself.
Also see the [Creating Citrix NetScaler disk images](#creating-citrix-netscaler-disk-images) section on how to create forensic disk images of your Citrix NetScaler.

Ensure that you have the latest version of Dissect, support for Citrix NetScaler was added in this PR: https://github.com/fox-it/dissect.target/pull/357

**Disclaimer**: While this tool strives for accuracy, it is possible for it to produce false positives or false negatives. Users are advised to cross-check results and use their own judgement before making any decisions based on this tool's output.

## Installing `iocitrix.py`

Use the following steps:

1. git clone https://github.com/fox-it/citrix-netscaler-triage.git
2. cd citrix-netscaler-triage
3. pip install -r requirements.txt
4. pip install --upgrade --pre dissect.volume dissect.target
 
Note that step 4 will print the following error, but you can ignore it:

```
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts.
```

You can then run `iocitrix.py <TARGETS>` to start an IOC check against one or more forensic images. The script accepts any input that [dissect](https://github.com/fox-it/dissect.target) can read as a `Target`, such as a `.VMDK`, or a raw disk image. Some examples are provided below.

```shell
python3 iocitrix.py image.vmx
python3 iocitrix.py image.vmdk
```

If you have also created a forensic image of the [RAM disk](#create-a-disk-image-of-the-devmd0-disk-to-your-local-machine), you can utilize `iocitrix.py` to incorporate volatile data in its triage as such:

```shell
python3 iocitrix.py md0.img+image.vmx
python3 iocitrix.py md0.img+image.vmdk
python3 iocitrix.py md0.img+da0.img
```

The `+` (plus) sign will load the two disk images as a single Dissect Target.

## Creating Citrix NetScaler disk images

A Citrix NetScaler exposes two important block devices which can imaged for offline forensic analysis. These block device files can be found at the following paths:
* `/dev/md0`: The disk that holds the root (`/`) directory. This is a RAM disk
* `/dev/da0`: The disk that holds the `/var` and `/flash` directories. This is a persistent disk.

The root directory (`/`) of Citrix NetScaler is a RAM disk, meaning that this is a volatile disk. This disk can be found at `/dev/md0` when the NetScaler is powered-on and running, and will be unavailable when the NetScaler is powered-off. The `/var` and `/flash` directories reside on the `/dev/da0` disk as two separate partitions and is persistent.

The following commands can be used on a local linux machine to create disk of your NetScaler over SSH:

#### Create a disk image of the `/dev/da0` disk to your local machine

```shell 
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> shell dd if=/dev/da0 bs=10M | tail -c +7 | head -c -6 > da0.img
```

Do note, that this can take some time to complete. No progess is shown when using `dd`. 
It is adviced to wait until you gain control back over the prompt. This is an indication that `dd` finished.

Also if you don't have `/dev/da0` it's most likely `/dev/ada0`, you can verify using the `mount` or `gpart show` command.

#### Create a disk image of the `/dev/md0` disk to your local machine
```shell
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> shell dd if=/dev/md0 bs=10M | tail -c +7 | head -c -6 > md0.img
```

**NOTE**: While it is recommended to create disk images of both `/dev/md0` and `/dev/da0`. Creating a disk image of `/dev/md0` is optional. This step could be skipped, though this can cause `iocitrix.py` to miss certains incicators of compromise.

### Running `iocitrix.py` on your images

After executing the previous commands on your local machine, the `da0.img` and `md0.img` files will be present. You can point `iocitrix` to these files to start triaging your images. Use the following command to do so:

```shell
local ~ $ python3 iocitrix.py md0.img+da0.img
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