#!/usr/bin/env python3
#
# file:   iocitrix.py
#
#  $ python3 iocitrix.py netscaler-image.vmx
#
# author: Fox-IT Security Research Team <srt@fox-it.com>
#
import argparse
import re
from typing import Iterator

try:
    from tabulate import tabulate
except ImportError:
    raise ImportError("tabulate missing, please use `pip install tabulate`")

try:
    from dissect.target import Target
    from dissect.target.tools.info import print_target_info
    from dissect.util.ts import from_unix
    from flow.record import RecordDescriptor
except ImportError:
    raise ImportError("dissect missing, please use `pip install dissect`")

EXPECTED_PHP_FILE_PERMISSION = 0o444

SUSPICIOUS_PHP_CONTENTS = {"eval($_", "base64_decode(", "http_status_code(", "http_status_code(", "array_filter("}

MAXIMUM_BYTE_SIZE_PHP_TO_CHECK_CONTENTS = 2048

# Difference of two weeks between modification time and changed time
TIMESTOMP_THRESHOLD_SECONDS = (60 * 60) * 24 * 7 * 2

WEBSHELL_PATHS = [
    "/var/netscaler/logon/",
    "/var/vpn/",
    "/var/netscaler/ns_gui/",
]


TIMESTOMP_DIRS = WEBSHELL_PATHS + ["/var/tmp"]

KNOWN_SUID_BINARIES = [
    "/netscaler/ping",
    "/netscaler/ping6",
    "/netscaler/traceroute",
    "/netscaler/traceroute6",
    "/sbin/mksnap_ffs",
    "/sbin/shutdown",
    "/sbin/poweroff",
    "/usr/bin/crontab",
    "/usr/bin/lock",
    "/usr/bin/login",
    "/usr/bin/passwd",
    "/usr/bin/yppasswd",
    "/usr/bin/su",
    "/usr/libexec/ssh-keysign",
    "/bin/umount",
    "/bin/ping",
    "/bin/mount",
    "/bin/su",
    "/bin/ping6",
    "/lib64/dbus-1/dbus-daemon-launch-helper",
    "/usr/bin/atq",
    "/usr/bin/at",
    "/usr/bin/sudo",
    "/usr/bin/newgrp",
    "/usr/bin/chsh",
    "/usr/bin/sg",
    "/usr/bin/gpasswd",
    "/usr/bin/chfn",
    "/usr/bin/sudoedit",
    "/usr/bin/staprun",
    "/usr/bin/atrm",
    "/usr/bin/chage",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/sbin/userhelper",
    "/usr/sbin/usernetctl",
    "/usr/sbin/ping6",
    "/opt/likewise/bin/ksu",
    "/sbin/umount.nfs",
    "/sbin/pam_timestamp_check",
    "/sbin/unix_chkpwd",
    "/sbin/mount.nfs",
    "/sbin/mount.nfs4",
    "/sbin/umount.nfs4",
]


EVIL_CRONTAB_CONTENTS = [
    ("ip address ", re.compile(r"([0-9]{1,3}\.){3}[0-9]{1,3}")),
    ("/var/tmp", re.compile("/var/tmp")),
    ("nobody user", re.compile("nobody")),
]

FindingRecord = RecordDescriptor(
    "ioc/hit",
    [
        ("string", "type"),
        ("string", "alert"),
        ("string", "confidence"),
        ("string", "path"),
    ],
)


def check_suspicious_php_files(target: Target, start_path) -> Iterator[FindingRecord]:
    if not target.fs.exists(start_path):
        return
    for path in target.fs.path(start_path).rglob("*.php"):
        stat = path.stat()
        mode = stat.st_mode & 0o777
        if mode != EXPECTED_PHP_FILE_PERMISSION:
            permission_printable = oct(mode)
            yield FindingRecord(
                alert=f"Suspicious php permission {permission_printable}",
                confidence="high",
                path=path,
                type="php-file-permission",
            )

        if stat.st_size > MAXIMUM_BYTE_SIZE_PHP_TO_CHECK_CONTENTS:
            continue

        with path.open("rt") as php_file:
            for line in php_file:
                for evil in SUSPICIOUS_PHP_CONTENTS:
                    if evil.lower() in line.lower():
                        yield FindingRecord(
                            type="php-file-contents",
                            path=path,
                            confidence="high",
                            alert=f"Suspicious PHP code '{evil}'",
                        )


def check_suid_binaries(target: Target) -> Iterator[tuple[str, str]]:
    for suid_binary_record in target.suid_binaries():
        if suid_binary_record.path in KNOWN_SUID_BINARIES:
            continue
        yield FindingRecord(
            type="binary/suid",
            alert="Binary with SUID bit set Observed",
            confidence="medium",
            path=suid_binary_record.path,
        )


def check_crontabs(target: Target):
    for cronjob_record in target.cronjobs():
        if cronjob_record._desc.name == "linux/environmentvariable":
            continue
        if cronjob_record.user in ["nobody"]:
            yield FindingRecord(
                type="cronjob/user",
                alert="Crontab by nobody user observed",
                confidence="high",
                path=cronjob_record.path,
            )
        for evil_check in EVIL_CRONTAB_CONTENTS:
            name, pattern = evil_check
            if match := pattern.match(cronjob_record.command):
                yield FindingRecord(
                    type="cronjob/command",
                    alert=f"{name} find in crontab comand ({match.group(0)})",
                    confidence="medium",
                    path=cronjob_record.path,
                )


def check_timestomps(target: Target):
    for timestomp_dir in TIMESTOMP_DIRS:
        for entry in target.fs.path(timestomp_dir).rglob("*"):
            if not entry.exists():
                continue
            stat = entry.lstat()
            modification_time = from_unix(stat.st_mtime)
            changed_time = from_unix(stat.st_ctime)

            difference = changed_time - modification_time

            if difference.seconds > TIMESTOMP_THRESHOLD_SECONDS:
                yield FindingRecord(
                    type="file/timestomp",
                    alert=f"Possibly Timestomped File Observed ({difference.seconds} seconds)",
                    confidence="medium",
                    path=entry.path,
                )


def ioc_check_target(target: Target) -> list[FindingRecord]:
    findings = []

    print("\n*** Checking for webshells ***\n")
    for path in WEBSHELL_PATHS:
        for finding in check_suspicious_php_files(target, path):
            print(finding)
            findings.append(finding)

    print("\n*** Checking for timestomped files ***\n")
    for finding in check_timestomps(target):
        print(finding)
        findings.append(finding)

    print("\n*** Checking for suspicious cronjobs ***\n")
    for finding in check_crontabs(target):
        print(finding)
        findings.append(finding)

    print("\n*** Checking for SUID Binaries (this takes a while) ***\n")
    for finding in check_suid_binaries(target):
        print(finding)
        findings.append(finding)

    return findings


def check_targets(target_paths: list[str]) -> None:
    for path in target_paths:
        target = Target.open(path)
        if target.os != "citrix-netscaler":
            raise ValueError(f"Target not recognized as a citrix-netscaler: {target.path}: {target.os}")
        print_target_info(target)
        print("")
        target_findings = ioc_check_target(target)
        if len(target_findings) == 0:
            print("[*] No hits found for IOC checks.")
        else:
            print("")
            print("********************************************************************************")
            print("***                                                                          ***")
            print("*** There were findings for Indicators of Compromise.                        ***")
            print("*** Please consider performing further forensic investigation of the system. ***")
            print("***                                                                          ***")
            print("********************************************************************************")
            print("")
            # Display in table format
            table_entries = []
            for finding in target_findings:
                table_entries.append(
                    {
                        "Confidence": finding.confidence,
                        "Type": finding.type,
                        "Alert": finding.alert,
                        "Artefact Location": finding.path,
                    }
                )
            print(tabulate(table_entries, headers="keys"))

    print("\n\n")
    print("All targets analyzed.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze forensic images of Citrix Netscalers for IOCs")
    parser.add_argument("targets", metavar="TARGETS", nargs="+", help="Target(s) to load")
    args = parser.parse_args()
    check_targets(args.targets)


if __name__ == "__main__":
    main()
