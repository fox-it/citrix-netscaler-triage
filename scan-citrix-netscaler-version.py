#!/usr/bin/env python3
#
# file:     scan-citrix-netscaler-version.py
# author:   Fox-IT Security Research Team <srt@fox-it.com>
#
# This script scans a remote Citrix NetScaler device to determine the version based on a GZIP timestamp in a resource file.
# The version hash is not always present anymore since our blog, so we need to rely on this timestamp metadata.
#
# Blog on how to fingerprint Citrix NetScaler devices using timestamp metadata of a GZIP file or hash:
#  - https://blog.fox-it.com/2022/12/28/cve-2022-27510-cve-2022-27518-measuring-citrix-adc-gateway-version-adoption-on-the-internet/
#
# GZIP file used for extracting the timestamp metadata:
#  - /vpn/js/rdx/core/lang/rdx_en.json.gz
#
from __future__ import annotations

import argparse
import csv
import json
import logging
import ssl
from datetime import datetime, timezone
from typing import NamedTuple

import httpx

# Original Citrix NetScaler version CSV file (updated in this Python script):
#  - https://gist.github.com/fox-srt/c7eb3cbc6b4bf9bb5a874fa208277e86
CITRIX_NETSCALER_VERSION_CSV = """
rdx_en_date,rdx_en_stamp,vhash,version
2018-08-25 03:29:12+00:00,1535167752,,12.1-49.23
2018-10-16 17:54:20+00:00,1539712460,,12.1-49.37
2018-11-28 08:56:26+00:00,1543395386,26df0e65fba681faaeb333058a8b28bf,12.1-50.28
2019-01-18 17:41:34+00:00,1547833294,d3b5c691a4cfcc6769da8dc4e40f511d,12.1-50.31
2019-02-13 06:11:52+00:00,1550038312,1ffe249eccc42133689c145dc37d6372,
2019-02-27 09:30:02+00:00,1551259802,995a76005c128f4e89474af12ac0de66,12.1-51.16
2019-03-25 22:37:08+00:00,1553553428,d2bd166fed66cdf035a0778a09fd688c,12.1-51.19
2019-04-19 11:04:22+00:00,1555671862,489cadbd8055b1198c9c7fa9d34921b9,
2019-05-13 17:41:47+00:00,1557769307,86b4b2567b05dff896aae46d6e0765bc,13.0-36.27
2019-06-03 08:17:03+00:00,1559549823,73217f4753a74300c0a2ad762c6f1e65,
2019-07-15 16:42:47+00:00,1563208967,dc8897f429a694d44934954b47118908,
2019-09-10 07:54:45+00:00,1568102085,43a8abf580ea09a5fa8aa1bd579280b9,13.0-41.20
2019-09-16 22:22:54+00:00,1568672574,0705e646dc7f84d77e8e48561253be12,
2019-10-07 10:37:28+00:00,1570444648,09a78a600b4fc5b9f581347604f70c0e,
2019-10-11 13:24:36+00:00,1570800276,7116ed70ec000da9267a019728ed951e,13.0-41.28
2019-11-05 05:18:47+00:00,1572931127,8c62b39f7068ea2f3d3f7d40860c0cd4,12.1-55.13
2019-11-28 19:06:22+00:00,1574967982,fedb4ba86b5edcbc86081f2893dc9fdf,13.0-47.22
2020-01-20 12:46:27+00:00,1579524387,02d30141fd053d5c3448bf04fbedb8d6,12.1-55.18
2020-01-20 13:09:05+00:00,1579525745,fd96bc8977256003de05ed84270b90bb,13.0-47.24
2020-02-28 14:27:56+00:00,1582900076,f787f9a8c05a502cd33f363e1e9934aa,12.1-55.24
2020-03-18 17:41:16+00:00,1584553276,b5fae8db23061679923e4b2a9b6c7a82,
2020-03-19 17:40:43+00:00,1584639643,e79f3bbf822c1fede6b5a1a4b6035a41,13.0-52.24
2020-03-29 09:10:32+00:00,1585473032,f2db014a3eb9790a19dfd71331e7f5d0,12.1-56.22
2020-06-01 06:48:41+00:00,1590994121,fdf2235967556bad892fbf29ca69eefd,13.0-58.30
2020-06-09 19:06:55+00:00,1591729615,4ecb5abf6e4b1655c07386a2c958597c,12.1-57.18
2020-07-02 16:38:13+00:00,1593707893,dcb06155d51a0234e9d127658ef9f21f,13.0-58.32
2020-07-22 19:49:27+00:00,1595447367,12c4901ecc3677aad06f678be49cb837,13.0-61.48
2020-08-14 14:54:04+00:00,1597416844,a1494e2e09cb96e424c6c66512224941,
2020-09-01 11:47:01+00:00,1598960821,b1b38debf0e55c285c72465da3715034,12.1-58.15
2020-09-01 16:14:56+00:00,1598976896,06fbfcf525e47b5538f856965154e28c,13.0-64.35
2020-09-22 01:21:45+00:00,1600737705,7a0c8874e93395c5e4f1ef3e5e600a25,12.1-59.16
2020-10-07 16:07:09+00:00,1602086829,a8e0eb4a1b3e157e0d3a5e57dc46fd35,13.0-67.39
2020-10-08 09:03:02+00:00,1602147782,0aef7f8e9ea2b528aa2073f2875a28b8,12.1-55.190
2020-11-04 10:14:41+00:00,1604484881,f1eb8548a4f1d4e565248d4db456fffe,
2020-11-13 12:56:30+00:00,1605272190,e2444db11d0fa5ed738aa568c2630704,13.0-67.43
2020-11-22 13:29:18+00:00,1606051758,62eba0931b126b1558fea39fb466e588,
2020-12-03 05:13:26+00:00,1606972406,9b545e2e4d153348bce08e3923cdfdc1,13.0-71.40
2020-12-26 19:04:08+00:00,1609009448,25ad60e92a33cbb5dbd7cd8c8380360d,13.0-71.44
2020-12-26 19:39:25+00:00,1609011565,0b516b768edfa45775c4be130c4b96b5,12.1-60.19
2021-01-04 03:07:45+00:00,1609729665,b3deb35b8a990a71acca052fd1e6e6e1,12.1-55.210
2021-01-06 09:43:42+00:00,1609926222,f0cc58ce7ec931656d9fcbfe50d37c4b,
2021-02-02 13:36:06+00:00,1612272966,83e486e7ee7eb07ab88328a51466ac28,12.1-61.18
2021-02-18 18:37:49+00:00,1613673469,454d4ccdefa1d802a3f0ca474a2edd73,13.0-76.29
2021-03-08 17:23:41+00:00,1615224221,08ff522057b9422863dbabb104c7cf4b,12.1-61.19
2021-03-09 09:20:39+00:00,1615281639,648767678188e1567b7d15eee5714220,13.0-76.31
2021-03-11 15:46:10+00:00,1615477570,ce5da251414abbb1b6aed6d6141ed205,12.1-61.19
2021-04-05 14:13:22+00:00,1617632002,5e55889d93ff0f13c39bbebb4929a68e,13.0-79.64
2021-05-10 14:38:02+00:00,1620657482,35389d54edd8a7ef46dadbd00c1bc5ac,12.1-62.21
2021-05-12 11:36:11+00:00,1620819371,9f4514cd7d7559fa1fb28960b9a4c22d,
2021-05-17 15:56:11+00:00,1621266971,8e4425455b9da15bdcd9d574af653244,12.1-62.23
2021-05-31 14:05:18+00:00,1622469918,73952bdeead9629442cd391d64c74d93,13.0-82.41
2021-06-10 19:21:20+00:00,1623352880,25169dea48ef0f939d834468f3c626d2,13.0-82.42
2021-06-10 23:39:05+00:00,1623368345,efb9d8994f9656e476e80f9b278c5dae,12.1-62.25
2021-07-06 17:02:58+00:00,1625590978,affa5cd9f00480f144eda6334e03ec27,
2021-07-07 01:45:38+00:00,1625622338,e1ebdcea7585d24e9f380a1c52a77f5d,12.1-62.27
2021-07-16 16:45:56+00:00,1626453956,eb3f8a7e3fd3f44b70c121101618b80d,13.0-82.45
2021-09-10 07:31:30+00:00,1631259090,98a21b87cc25d486eb4189ab52cbc870,13.1-4.43
2021-09-27 14:01:20+00:00,1632751280,c9e95a96410b8f8d4bde6fa31278900f,13.0-83.27
2021-10-12 11:53:46+00:00,1634039626,435b27d8f59f4b64a6beccb39ce06237,
2021-10-13 08:24:09+00:00,1634113449,f3d4041188d723fec4547b1942ffea93,12.1-63.22
2021-11-11 14:42:53+00:00,1636641773,158c7182df4973f1f5346e21e9d97a01,13.1-4.44
2021-11-11 17:02:35+00:00,1636650155,a66c02f4d04a1bd32bfdcc1655c73466,13.0-83.29
2021-11-11 20:06:47+00:00,1636661207,5cd6bd7d0aec5dd13a1afb603111733a,12.1-63.23
2021-11-17 15:43:23+00:00,1637163803,645bded68068748e3314ad3e3ec8eb8f,13.1-9.60
2021-12-10 16:17:15+00:00,1639153035,5112d5394de0cb5f6d474e032a708907,13.1-12.50
2021-12-10 18:48:29+00:00,1639162109,3a316d2de5362e9f76280b3157f48d08,13.0-84.10
2021-12-22 09:54:58+00:00,1640166898,ee44bd3bc047aead57bc000097e3d8aa,12.1-63.24
2021-12-22 10:57:32+00:00,1640170652,13693866faf642734f0498eb45f73672,
2021-12-22 15:18:49+00:00,1640186329,2b46554c087d2d5516559e9b8bc1875d,13.0-84.11
2021-12-23 08:28:43+00:00,1640248123,cf9d354b261231f6c6121058ba143af7,13.1-12.51
2022-01-20 02:36:41+00:00,1642646201,c6bcd2f119d83d1de762c8c09b482546,12.1-64.16
2022-01-28 06:22:15+00:00,1643350935,b3fb0319d5d2dad8c977b9986cc26bd8,12.1-55.265
2022-02-21 12:49:29+00:00,1645447769,0f3a063431972186f453e07954f34eb8,13.1-17.42
2022-02-23 07:02:10+00:00,1645599730,7364f85dc30b3d570015e04f90605854,
2022-03-10 15:17:42+00:00,1646925462,e42d7b3cf4a6938aecebdae491ba140c,13.0-85.15
2022-04-01 19:41:31+00:00,1648842091,310ffb5a44db3a14ed623394a4049ff9,
2022-04-03 05:18:28+00:00,1648963108,2edf0f445b69b2e322e80dbc3f6f711c,12.1-55.276
2022-04-07 06:11:44+00:00,1649311904,b4ac9c8852a04234f38d73d1d8238d37,13.1-21.50
2022-04-21 07:34:34+00:00,1650526474,9f73637db0e0f987bf7825486bfb5efe,12.1-55.278
2022-04-21 10:38:48+00:00,1650537528,c212a67672ef2da5a74ecd4e18c25835,12.1-64.17
2022-04-22 19:18:31+00:00,1650655111,fbdc5fbaed59f858aad0a870ac4a779c,12.1-65.15
2022-05-19 08:10:13+00:00,1652947813,1884e7877a13a991b6d3fac01efbaf79,13.0-85.19
2022-05-26 12:51:09+00:00,1653569469,853edb55246c138c530839e638089036,13.1-24.38
2022-06-14 17:03:48+00:00,1655226228,7a45138b938a54ab056e0c35cf0ae56c,13.0-86.17
2022-06-29 13:46:08+00:00,1656510368,4434db1ec24dd90750ea176f8eab213c,12.1-65.17
2022-07-06 08:54:42+00:00,1657097682,469591a5ef8c69899320a319d5259922,12.1-55.282
2022-07-06 10:41:43+00:00,1657104103,adc1f7c850ca3016b21776467691a767,13.1-27.59
2022-07-29 17:39:52+00:00,1659116392,1f63988aa4d3f6d835704be50c56788a,13.0-87.9
2022-08-24 14:57:01+00:00,1661353021,57d9f58db7576d6a194d7dd10888e354,13.1-30.52
2022-09-23 18:53:35+00:00,1663959215,7afe87a42140b566a2115d1e232fdc07,13.1-33.47
2022-10-04 16:11:03+00:00,1664899863,c1b64cea1b80e973580a73b787828daf,12.1-65.21
2022-10-12 07:25:44+00:00,1665559544,4d817946cef53571bc303373fd6b406b,12.1-55.289
2022-10-12 17:01:28+00:00,1665594088,aff0ad8c8a961d7b838109a7ee532bcb,13.1-33.49
2022-10-14 17:10:45+00:00,1665767445,37c10ac513599cf39997d52168432c0e,13.0-88.12
2022-10-31 15:54:59+00:00,1667231699,27292ddd74e24a311e4269de9ecaa6e7,13.0-88.13
2022-10-31 16:31:43+00:00,1667233903,5e939302a9d7db7e35e63a39af1c7bec,13.1-33.51
2022-11-03 05:22:05+00:00,1667452925,6e7b2de88609868eeda0b1baf1d34a7e,13.0-88.14
2022-11-03 05:38:29+00:00,1667453909,56672635f81a1ce1f34f828fef41d2fa,13.1-33.52
2022-11-11 04:16:21+00:00,1668140181,8ecc8331379bc60f49712c9b25f276ea,
2022-11-11 06:00:31+00:00,1668146431,86c7421a034063574799dcd841ee88f0,
2022-11-17 09:55:40+00:00,1668678940,9bf6d5d3131495969deba0f850447947,13.1-33.54
2022-11-17 10:37:18+00:00,1668681438,3bd7940b6425d9d4dba7e8b656d4ba65,13.0-88.16
2022-11-23 11:42:31+00:00,1669203751,0d656200c32bb47c300b81e599260c42,13.1-37.38
2022-11-28 11:55:05+00:00,1669636505,953fae977d4baedf39e83c9d1e134ef1,12.1-55.291
2022-11-30 11:42:25+00:00,1669808545,f063b04477adc652c6dd502ac0c39a75,12.1-65.25
2022-12-14 15:54:39+00:00,1671033279,14c6a775edda324764a940cfd3da48cb,13.0-89.7
2023-01-24 17:44:35+00:00,1674582275,c2b8537eb733844f1e0cc4f63210d016,13.0-90.7
2023-02-22 13:31:29+00:00,1677072689,b4c220db03ea18bc2eebb40e9ad3f4f8,13.1-42.47
2023-04-05 06:57:33+00:00,1680677853,0b2a3cb74b5c6adbe28827e8b76a9f64,12.1-55.296
2023-04-12 08:05:14+00:00,1681286714,6925fba74320b9bfb960299f7c3e7cce,13.1-45.61
2023-04-17 18:09:24+00:00,1681754964,cdb72bd7677da8af9942897256782c9b,13.1-37.150
2023-04-19 15:34:38+00:00,1681918478,281b46a105662de06fb259293aa79f2a,13.0-90.11
2023-04-26 11:42:55+00:00,1682509375,1487b55f253ea54b1d3603cc1212f164,13.1-45.62
2023-04-28 20:39:00+00:00,1682714340,a6a783263968040a97e44d7cac55eda6,12.1-65.35
2023-04-30 08:54:31+00:00,1682844871,d72c9f2af7ccded704862da7486cfef2,13.1-45.63
2023-05-12 04:49:56+00:00,1683866996,,13.0-91.12
2023-05-12 07:33:58+00:00,1683876838,14195083e08df261613408eb5cf3b212,13.1-45.64
2023-05-15 10:23:44+00:00,1684146224,4d63b52cc99fe712f9be5e4795c854e9,13.0-90.12
2023-06-03 07:35:50+00:00,1685777750,,13.1-48.47
2023-07-07 15:32:56+00:00,1688743976,,13.0-91.13
2023-07-07 16:15:10+00:00,1688746510,e72b4f05a103118667208783b57eee3b,
2023-07-07 16:17:07+00:00,1688746627,46d83b1a2981c1cfefe8d3063adf78f4,13.1-37.159
2023-07-07 16:29:27+00:00,1688747367,28e592a607e8919cc6ca7dec63590e04,12.1-55.297
2023-07-10 18:36:31+00:00,1689014191,,13.1-49.13
2023-07-28 00:25:01+00:00,1690503901,,14.1-4.42
2023-08-30 07:03:54+00:00,1693379034,,13.0-92.18
2023-09-15 06:40:36+00:00,1694760036,,14.1-8.50
2023-09-21 05:25:24+00:00,1695273924,,13.0-92.19
2023-09-21 06:17:01+00:00,1695277021,,13.1-49.15
2023-09-21 17:12:48+00:00,1695316368,155a75fb7efac3347e7362fd23083aa5,12.1-55.300
2023-09-27 12:27:52+00:00,1695817672,,13.1-37.164
2023-10-18 07:27:04+00:00,1697614024,,13.1-50.23
2023-11-22 18:19:39+00:00,1700677179,,14.1-12.30
2023-12-08 19:10:40+00:00,1702062640,,13.1-51.14
2023-12-14 10:12:36+00:00,1702548756,,13.0-92.21
2023-12-15 07:26:58+00:00,1702625218,,13.1-51.15
2023-12-15 09:18:34+00:00,1702631914,,14.1-12.35
2023-12-18 07:59:52+00:00,1702886392,f6beac6ccd073f5f7c1a64c4c7e24c7e,12.1-55.302
2024-01-05 04:15:53+00:00,1704428153,,13.1-37.176
2024-02-08 05:34:51+00:00,1707370491,,14.1-17.38
2024-02-29 17:31:08+00:00,1709227868,,13.1-52.19
2024-04-18 21:13:30+00:00,1713474810,,14.1-21.57
2024-05-01 05:48:44+00:00,1714542524,fe1071e2b14a5b5016d3eb57ddcfc86d,12.1-55.304
2024-05-13 16:45:28+00:00,1715618728,,13.1-53.17
2024-05-14 12:55:51+00:00,1715691351,,13.1-37.183
2024-06-08 07:28:50+00:00,1717831730,,14.1-25.53
"""


def load_version_hashes() -> tuple[dict[str, str], dict[int, str]]:
    """Return a tuple of two dictionaries: vhash_to_version, vstamp_to_version.

    Returns:
        vhash_to_version: dict[str, str] - mapping of version hash to version string
        vstamp_to_version: dict[int, str] - mapping of rdx_en timestamp to version string
    """
    vhash_to_version = {}
    vstamp_to_version = {}
    for row in csv.DictReader(CITRIX_NETSCALER_VERSION_CSV.strip().splitlines()):
        vhash = row["vhash"]
        version = row["version"]
        rdx_en_date = row["rdx_en_date"]
        rdx_en_stamp = int(row["rdx_en_stamp"])
        dt = datetime.fromisoformat(rdx_en_date)
        assert int(dt.timestamp()) == rdx_en_stamp, (rdx_en_date, rdx_en_stamp, version)
        vstamp_to_version[rdx_en_stamp] = version
        if vhash:
            vhash_to_version[vhash] = version
    stamps = list(vstamp_to_version.keys())
    assert stamps == sorted(stamps), "not sorted"
    return vhash_to_version, vstamp_to_version


vhash_to_version, vstamp_to_version = load_version_hashes()


class NetScalerVersion(NamedTuple):
    target: str
    rdx_en_stamp: int | None
    rdx_en_dt: datetime | None
    version: str | None
    error: str | None = None


def scan_netscaler_version(target: str, client: httpx.Client) -> NetScalerVersion:
    url = target
    if not target.startswith(("http://", "https://")):
        url = f"https://{target}"
    url = f"{url}/vpn/js/rdx/core/lang/rdx_en.json.gz"
    logging.info("Scanning %r", url)
    stamp = None
    dt = None
    version = None
    error = None
    with client.stream("GET", url) as response:
        stream = response.iter_raw(100)
        data = next(stream)
        if data.startswith(b"\x1f\x8b\x08\x08") and b"rdx_en.json" in data:
            stamp = int.from_bytes(data[4:8], "little")
            dt = datetime.fromtimestamp(stamp, timezone.utc)
            version = vstamp_to_version.get(stamp, "unknown")
            logging.info(
                "Extracted timestamp: stamp=%s, dt=%s, version=%s", stamp, dt, version
            )
        else:
            error = "No valid data found, probably not a Citrix NetScaler"
            logging.info("No valid data found, probably not a Citrix NetScaler")
    return NetScalerVersion(target, stamp, dt, version, error)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan Citrix NetScaler to determine version"
    )
    parser.add_argument(
        "targets",
        metavar="TARGET",
        nargs="*",
        help="Citrix NetScaler IP or domain (eg: 192.168.1.1:443, https://192.168.1.1)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        metavar="SECONDS",
        type=float,
        default=5.0,
        help="http timeout in seconds",
    )
    parser.add_argument(
        "-i",
        "--input",
        metavar="FILE",
        type=argparse.FileType("r"),
        help="input file with targets",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="increase verbosity"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        default=False,
        help="enable TLS certificate verification",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", default=False, help="output scan results as JSON"
    )
    args = parser.parse_args()

    if not args.targets and not args.input:
        parser.error("at least one target is required")

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(
        level=levels[min(args.verbose, 2)],
        format="%(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S%z",
    )

    # Enable legacy TLS support for old NetScaler devices
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
    ctx.check_hostname = args.verify
    ctx.verify_mode = ssl.CERT_REQUIRED if args.verify else ssl.CERT_NONE

    client = httpx.Client(verify=args.verify, timeout=args.timeout)
    targets = args.input or args.targets

    for target in targets:
        target = target.strip()
        try:
            version = scan_netscaler_version(target, client)
        except httpx.HTTPError as e:
            logging.warning(f"Failed to scan {target}: {e}")
            version = NetScalerVersion(target, None, None, None, str(e))

        if args.json:
            jdict = {"scanned_at": datetime.now(timezone.utc).isoformat()}
            version = version._replace(
                rdx_en_dt=version.rdx_en_dt.isoformat() if version.rdx_en_dt else None
            )
            jdict.update(version._asdict())
            print(json.dumps(jdict))
            continue

        if version.error:
            print(f"{target}: {version.error}")
        elif version.version == "unknown":
            print(
                f"{target} is running an unknown version (stamp={version.stamp}, dt={version.dt})"
            )
        else:
            print(f"{target} is running Citrix NetScaler version {version.version}")


if __name__ == "__main__":
    main()
