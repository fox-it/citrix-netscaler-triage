#!/usr/bin/env python3
#
# file:     scan-citrix-netscaler-version.py
# author:   Fox-IT Security Research Team <srt@fox-it.com>
#
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "httpx",
# ]
# ///
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
import doctest
import json
import logging
import os
import ssl
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import NamedTuple

import httpx

# ============================================================================
# NetScaler version fingerprints
# ============================================================================

# Original Citrix NetScaler version CSV file (updated in this Python script):
#  - https://gist.github.com/fox-srt/c7eb3cbc6b4bf9bb5a874fa208277e86
CITRIX_NETSCALER_VERSION_CSV = """
rdx_en_date,rdx_en_stamp,vhash,version
2018-08-25 03:29:12+00:00,1535167752,,12.1-49.23
2018-10-16 17:54:20+00:00,1539712460,,12.1-49.37
2018-11-28 08:56:26+00:00,1543395386,26df0e65fba681faaeb333058a8b28bf,12.1-50.28
2019-01-18 17:41:34+00:00,1547833294,d3b5c691a4cfcc6769da8dc4e40f511d,12.1-50.31
2019-02-13 06:11:52+00:00,1550038312,1ffe249eccc42133689c145dc37d6372,unknown
2019-02-27 09:30:02+00:00,1551259802,995a76005c128f4e89474af12ac0de66,12.1-51.16
2019-03-25 22:37:08+00:00,1553553428,d2bd166fed66cdf035a0778a09fd688c,12.1-51.19
2019-04-19 11:04:22+00:00,1555671862,489cadbd8055b1198c9c7fa9d34921b9,unknown
2019-05-13 17:41:47+00:00,1557769307,86b4b2567b05dff896aae46d6e0765bc,13.0-36.27
2019-06-03 08:17:03+00:00,1559549823,73217f4753a74300c0a2ad762c6f1e65,unknown
2019-07-15 16:42:47+00:00,1563208967,dc8897f429a694d44934954b47118908,unknown
2019-09-10 07:54:45+00:00,1568102085,43a8abf580ea09a5fa8aa1bd579280b9,13.0-41.20
2019-09-16 22:22:54+00:00,1568672574,0705e646dc7f84d77e8e48561253be12,unknown
2019-10-07 10:37:28+00:00,1570444648,09a78a600b4fc5b9f581347604f70c0e,unknown
2019-10-11 13:24:36+00:00,1570800276,7116ed70ec000da9267a019728ed951e,13.0-41.28
2019-11-05 05:18:47+00:00,1572931127,8c62b39f7068ea2f3d3f7d40860c0cd4,12.1-55.13
2019-11-28 19:06:22+00:00,1574967982,fedb4ba86b5edcbc86081f2893dc9fdf,13.0-47.22
2020-01-16 13:36:04+00:00,1579181764,,11.1-63.15
2020-01-20 12:46:27+00:00,1579524387,02d30141fd053d5c3448bf04fbedb8d6,12.1-55.18
2020-01-20 13:09:05+00:00,1579525745,fd96bc8977256003de05ed84270b90bb,13.0-47.24
2020-02-28 14:27:56+00:00,1582900076,f787f9a8c05a502cd33f363e1e9934aa,12.1-55.24
2020-03-18 17:41:16+00:00,1584553276,b5fae8db23061679923e4b2a9b6c7a82,unknown
2020-03-19 17:40:43+00:00,1584639643,e79f3bbf822c1fede6b5a1a4b6035a41,13.0-52.24
2020-03-29 09:10:32+00:00,1585473032,f2db014a3eb9790a19dfd71331e7f5d0,12.1-56.22
2020-06-01 06:48:41+00:00,1590994121,fdf2235967556bad892fbf29ca69eefd,13.0-58.30
2020-06-01 15:16:27+00:00,1591024587,,12.0-63.21
2020-06-02 02:27:33+00:00,1591064853,,11.1-64.14
2020-06-09 19:06:55+00:00,1591729615,4ecb5abf6e4b1655c07386a2c958597c,12.1-57.18
2020-07-02 16:38:13+00:00,1593707893,dcb06155d51a0234e9d127658ef9f21f,13.0-58.32
2020-07-22 19:49:27+00:00,1595447367,12c4901ecc3677aad06f678be49cb837,13.0-61.48
2020-07-30 09:05:04+00:00,1596099904,bf898768ad1e1d477fa649711c72c6df,13.0-61.48
2020-08-14 14:54:04+00:00,1597416844,a1494e2e09cb96e424c6c66512224941,12.1-58.14
2020-09-01 11:47:01+00:00,1598960821,b1b38debf0e55c285c72465da3715034,12.1-58.15
2020-09-01 16:14:56+00:00,1598976896,06fbfcf525e47b5538f856965154e28c,13.0-64.35
2020-09-10 10:26:58+00:00,1599733618,,11.1-65.12
2020-09-22 01:21:45+00:00,1600737705,7a0c8874e93395c5e4f1ef3e5e600a25,12.1-59.16
2020-10-07 16:07:09+00:00,1602086829,a8e0eb4a1b3e157e0d3a5e57dc46fd35,13.0-67.39
2020-10-08 09:03:02+00:00,1602147782,0aef7f8e9ea2b528aa2073f2875a28b8,12.1-55.190
2020-11-04 10:14:41+00:00,1604484881,f1eb8548a4f1d4e565248d4db456fffe,12.1-60.16
2020-11-13 12:56:30+00:00,1605272190,e2444db11d0fa5ed738aa568c2630704,13.0-67.43
2020-11-22 13:29:18+00:00,1606051758,62eba0931b126b1558fea39fb466e588,unknown
2020-11-24 13:26:53+00:00,1606224413,3a65afd164db6f39aa41f5729001d257,13.0-67.43
2020-12-03 05:13:26+00:00,1606972406,9b545e2e4d153348bce08e3923cdfdc1,13.0-71.40
2020-12-26 19:04:08+00:00,1609009448,25ad60e92a33cbb5dbd7cd8c8380360d,13.0-71.44
2020-12-26 19:39:25+00:00,1609011565,0b516b768edfa45775c4be130c4b96b5,12.1-60.19
2021-01-04 03:07:45+00:00,1609729665,b3deb35b8a990a71acca052fd1e6e6e1,12.1-55.210
2021-01-06 09:43:42+00:00,1609926222,f0cc58ce7ec931656d9fcbfe50d37c4b,unknown
2021-02-02 13:36:06+00:00,1612272966,83e486e7ee7eb07ab88328a51466ac28,12.1-61.18
2021-02-18 18:37:49+00:00,1613673469,454d4ccdefa1d802a3f0ca474a2edd73,13.0-76.29
2021-03-08 17:23:41+00:00,1615224221,08ff522057b9422863dbabb104c7cf4b,12.1-61.19
2021-03-09 09:20:39+00:00,1615281639,648767678188e1567b7d15eee5714220,13.0-76.31
2021-03-11 15:46:10+00:00,1615477570,ce5da251414abbb1b6aed6d6141ed205,12.1-61.19
2021-04-05 14:13:22+00:00,1617632002,5e55889d93ff0f13c39bbebb4929a68e,13.0-79.64
2021-05-10 14:38:02+00:00,1620657482,35389d54edd8a7ef46dadbd00c1bc5ac,12.1-62.21
2021-05-12 11:36:11+00:00,1620819371,9f4514cd7d7559fa1fb28960b9a4c22d,unknown
2021-05-17 15:56:11+00:00,1621266971,8e4425455b9da15bdcd9d574af653244,12.1-62.23
2021-05-29 18:33:31+00:00,1622313211,,11.1-65.20
2021-05-31 14:05:18+00:00,1622469918,73952bdeead9629442cd391d64c74d93,13.0-82.41
2021-06-10 19:21:20+00:00,1623352880,25169dea48ef0f939d834468f3c626d2,13.0-82.42
2021-06-10 23:39:05+00:00,1623368345,efb9d8994f9656e476e80f9b278c5dae,12.1-62.25
2021-07-06 17:02:58+00:00,1625590978,affa5cd9f00480f144eda6334e03ec27,unknown
2021-07-07 01:45:38+00:00,1625622338,e1ebdcea7585d24e9f380a1c52a77f5d,12.1-62.27
2021-07-07 06:20:31+00:00,1625638831,,11.1-65.22
2021-07-16 16:45:56+00:00,1626453956,eb3f8a7e3fd3f44b70c121101618b80d,13.0-82.45
2021-09-10 07:31:30+00:00,1631259090,98a21b87cc25d486eb4189ab52cbc870,13.1-4.43
2021-09-27 14:01:20+00:00,1632751280,c9e95a96410b8f8d4bde6fa31278900f,13.0-83.27
2021-10-06 13:25:54+00:00,1633526754,394e3fa5ffce140c9dd4bedc38ddefa7,13.1-9.52
2021-10-12 11:53:46+00:00,1634039626,435b27d8f59f4b64a6beccb39ce06237,unknown
2021-10-12 18:49:09+00:00,1634064549,,11.1-65.23
2021-10-13 08:24:09+00:00,1634113449,f3d4041188d723fec4547b1942ffea93,12.1-63.22
2021-11-11 14:42:53+00:00,1636641773,158c7182df4973f1f5346e21e9d97a01,13.1-4.44
2021-11-11 17:02:35+00:00,1636650155,a66c02f4d04a1bd32bfdcc1655c73466,13.0-83.29
2021-11-11 20:06:47+00:00,1636661207,5cd6bd7d0aec5dd13a1afb603111733a,12.1-63.23
2021-11-17 15:43:23+00:00,1637163803,645bded68068748e3314ad3e3ec8eb8f,13.1-9.60
2021-11-26 05:41:16+00:00,1637905276,7277ec67fd822b7dae3399aa71786a0a,13.1-9.107
2021-12-08 13:14:05+00:00,1638969245,e8ff095e03a3efcff7ed851bfb9141e5,13.1-9.112
2021-12-10 16:17:15+00:00,1639153035,5112d5394de0cb5f6d474e032a708907,13.1-12.50
2021-12-10 18:48:29+00:00,1639162109,3a316d2de5362e9f76280b3157f48d08,13.0-84.10
2021-12-17 08:48:15+00:00,1639730895,bb71c656f6b4e0e1573c77c6536397c3,13.1-12.103
2021-12-22 09:54:58+00:00,1640166898,ee44bd3bc047aead57bc000097e3d8aa,12.1-63.24
2021-12-22 10:57:32+00:00,1640170652,13693866faf642734f0498eb45f73672,unknown
2021-12-22 15:18:49+00:00,1640186329,2b46554c087d2d5516559e9b8bc1875d,13.0-84.11
2021-12-23 08:28:43+00:00,1640248123,cf9d354b261231f6c6121058ba143af7,13.1-12.51
2022-01-20 02:36:41+00:00,1642646201,c6bcd2f119d83d1de762c8c09b482546,12.1-64.16
2022-01-28 06:22:15+00:00,1643350935,b3fb0319d5d2dad8c977b9986cc26bd8,12.1-55.265
2022-02-21 12:49:29+00:00,1645447769,0f3a063431972186f453e07954f34eb8,13.1-17.42
2022-02-23 07:02:10+00:00,1645599730,7364f85dc30b3d570015e04f90605854,unknown
2022-03-10 15:17:42+00:00,1646925462,e42d7b3cf4a6938aecebdae491ba140c,13.0-85.15
2022-03-25 20:49:02+00:00,1648241342,71ad6c771d99d846195b67c30bfb0433,13.1-12.117
2022-04-01 19:41:31+00:00,1648842091,310ffb5a44db3a14ed623394a4049ff9,unknown
2022-04-03 05:18:28+00:00,1648963108,2edf0f445b69b2e322e80dbc3f6f711c,12.1-55.276
2022-04-07 06:11:44+00:00,1649311904,b4ac9c8852a04234f38d73d1d8238d37,13.1-21.50
2022-04-21 07:34:34+00:00,1650526474,9f73637db0e0f987bf7825486bfb5efe,12.1-55.278
2022-04-21 10:38:48+00:00,1650537528,c212a67672ef2da5a74ecd4e18c25835,12.1-64.17
2022-04-22 19:18:31+00:00,1650655111,fbdc5fbaed59f858aad0a870ac4a779c,12.1-65.15
2022-05-09 12:54:41+00:00,1652100881,e24224ce907593aaadd243831b51dbd7,13.1-12.130
2022-05-19 08:10:13+00:00,1652947813,1884e7877a13a991b6d3fac01efbaf79,13.0-85.19
2022-05-26 12:51:09+00:00,1653569469,853edb55246c138c530839e638089036,13.1-24.38
2022-06-14 17:03:48+00:00,1655226228,7a45138b938a54ab056e0c35cf0ae56c,13.0-86.17
2022-06-29 13:46:08+00:00,1656510368,4434db1ec24dd90750ea176f8eab213c,12.1-65.17
2022-07-06 08:54:42+00:00,1657097682,469591a5ef8c69899320a319d5259922,12.1-55.282
2022-07-06 10:41:43+00:00,1657104103,adc1f7c850ca3016b21776467691a767,13.1-27.59
2022-07-12 19:52:59+00:00,1657655579,8f1767a6961f7b797d318d884dbb3a9c,13.1-12.131
2022-07-29 17:39:52+00:00,1659116392,1f63988aa4d3f6d835704be50c56788a,13.0-87.9
2022-08-24 14:57:01+00:00,1661353021,57d9f58db7576d6a194d7dd10888e354,13.1-30.52
2022-09-05 09:57:52+00:00,1662371872,8c6bef3b4f16d6c9bfc2913aae2535d1,13.1-30.103
2022-09-07 12:17:13+00:00,1662553033,f214d9aa6ff8f43fdb17ce81caac723f,13.1-30.105
2022-09-23 18:53:35+00:00,1663959215,7afe87a42140b566a2115d1e232fdc07,13.1-33.47
2022-09-27 12:31:22+00:00,1664281882,8cbccac1a96eee108ae3c85bf9ff845a,13.1-30.108
2022-09-30 04:47:01+00:00,1664513221,212fa0e7b3a5ca540f156caceba507fe,13.1-30.109
2022-10-04 12:03:35+00:00,1664885015,29adf2b509250b780bac083577c92b45,13.1-30.111
2022-10-04 16:11:03+00:00,1664899863,c1b64cea1b80e973580a73b787828daf,12.1-65.21
2022-10-12 07:25:44+00:00,1665559544,4d817946cef53571bc303373fd6b406b,12.1-55.289
2022-10-12 17:01:28+00:00,1665594088,aff0ad8c8a961d7b838109a7ee532bcb,13.1-33.49
2022-10-14 17:10:45+00:00,1665767445,37c10ac513599cf39997d52168432c0e,13.0-88.12
2022-10-31 15:54:59+00:00,1667231699,27292ddd74e24a311e4269de9ecaa6e7,13.0-88.13
2022-10-31 16:31:43+00:00,1667233903,5e939302a9d7db7e35e63a39af1c7bec,13.1-33.51
2022-11-03 05:22:05+00:00,1667452925,6e7b2de88609868eeda0b1baf1d34a7e,13.0-88.14
2022-11-03 05:38:29+00:00,1667453909,56672635f81a1ce1f34f828fef41d2fa,13.1-33.52
2022-11-11 04:16:21+00:00,1668140181,8ecc8331379bc60f49712c9b25f276ea,unknown
2022-11-11 06:00:31+00:00,1668146431,86c7421a034063574799dcd841ee88f0,unknown
2022-11-17 09:55:40+00:00,1668678940,9bf6d5d3131495969deba0f850447947,13.1-33.54
2022-11-17 10:37:18+00:00,1668681438,3bd7940b6425d9d4dba7e8b656d4ba65,13.0-88.16
2022-11-23 11:42:31+00:00,1669203751,0d656200c32bb47c300b81e599260c42,13.1-37.38
2022-11-28 11:55:05+00:00,1669636505,953fae977d4baedf39e83c9d1e134ef1,12.1-55.291
2022-11-30 11:42:25+00:00,1669808545,f063b04477adc652c6dd502ac0c39a75,12.1-65.25
2022-12-01 10:48:25+00:00,1669891705,c0c00b7caed367b1569574e4982294c5,13.1-30.114
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
2023-07-07 16:15:10+00:00,1688746510,e72b4f05a103118667208783b57eee3b,unknown
2023-07-07 16:17:07+00:00,1688746627,46d83b1a2981c1cfefe8d3063adf78f4,13.1-37.159
2023-07-07 16:29:27+00:00,1688747367,28e592a607e8919cc6ca7dec63590e04,12.1-55.297
2023-07-10 01:57:59+00:00,1688954279,,13.1-49.101
2023-07-10 18:36:31+00:00,1689014191,,13.1-49.13
2023-07-11 07:14:37+00:00,1689059677,,13.1-49.102
2023-07-20 04:36:25+00:00,1689827785,,13.1-49.106
2023-07-28 00:25:01+00:00,1690503901,,14.1-4.42
2023-08-30 07:03:54+00:00,1693379034,,13.0-92.18
2023-09-15 06:40:36+00:00,1694760036,,14.1-8.50
2023-09-21 05:25:24+00:00,1695273924,,13.0-92.19
2023-09-21 06:17:01+00:00,1695277021,,13.1-49.15
2023-09-21 08:15:02+00:00,1695284102,e1aa8ba6d7e558d43f0369d9b81cbb1c,12.1-65.37
2023-09-21 17:12:48+00:00,1695316368,155a75fb7efac3347e7362fd23083aa5,12.1-55.300
2023-09-27 12:27:52+00:00,1695817672,,13.1-37.164
2023-10-18 07:27:04+00:00,1697614024,,13.1-50.23
2023-11-22 18:19:39+00:00,1700677179,,14.1-12.30
2023-12-06 18:15:43+00:00,1701886543,,14.1-8.120
2023-12-08 11:31:08+00:00,1702035068,,14.1-12.34
2023-12-08 19:10:40+00:00,1702062640,,13.1-51.14
2023-12-14 10:12:36+00:00,1702548756,,13.0-92.21
2023-12-15 07:26:58+00:00,1702625218,,13.1-51.15
2023-12-15 09:18:34+00:00,1702631914,,14.1-12.35
2023-12-18 07:59:52+00:00,1702886392,f6beac6ccd073f5f7c1a64c4c7e24c7e,12.1-55.302
2023-12-18 14:16:04+00:00,1702908964,9debca402a9fae56a0d5e0979f685cf2,12.1-65.39
2024-01-02 11:24:56+00:00,1704194696,,14.1-8.122
2024-01-05 04:15:53+00:00,1704428153,,13.1-37.176
2024-02-08 05:34:51+00:00,1707370491,,14.1-17.38
2024-02-29 17:31:08+00:00,1709227868,,13.1-52.19
2024-04-18 21:13:30+00:00,1713474810,,14.1-21.57
2024-04-26 11:56:34+00:00,1714132594,08604a97f08f6973502adb8ebf78e0b0,12.1-55.304
2024-05-01 05:48:44+00:00,1714542524,fe1071e2b14a5b5016d3eb57ddcfc86d,12.1-55.304
2024-05-13 16:45:28+00:00,1715618728,,13.1-53.17
2024-05-14 12:55:51+00:00,1715691351,,13.1-37.183
2024-06-08 07:28:50+00:00,1717831730,,14.1-25.53
2024-06-24 12:44:20+00:00,1719233060,,14.1-25.107
2024-07-04 10:41:15+00:00,1720089675,,13.0-92.31
2024-07-04 14:32:40+00:00,1720103560,,13.1-53.24
2024-07-04 16:31:28+00:00,1720110688,,14.1-25.56
2024-07-04 16:49:33+00:00,1720111773,,13.1-37.190
2024-07-05 06:07:38+00:00,1720159658,,14.1-25.108
2024-07-08 18:53:11+00:00,1720464791,,13.0-92.31
2024-07-17 17:53:35+00:00,1721238815,,13.1-54.29
2024-08-13 11:43:40+00:00,1723549420,,13.1-37.199
2024-10-07 20:11:28+00:00,1728331888,,13.1-37.207
2024-10-07 20:55:33+00:00,1728334533,a7c411815373059b33b4d83bed6145a2,12.1-55.321
2024-10-11 10:23:04+00:00,1728642184,,14.1-29.72
2024-10-21 20:52:15+00:00,1729543935,0dd3f401dd33679f07e06961db10a298,12.1-55.321
2024-10-22 01:37:14+00:00,1729561034,,14.1-34.42
2024-10-24 13:43:49+00:00,1729777429,,13.1-55.34
2024-10-29 06:55:25+00:00,1730184925,,14.1-34.101
2024-11-07 16:17:10+00:00,1730996230,,13.1-56.18
2024-11-29 10:21:03+00:00,1732875663,,13.1-37.219
2024-12-16 17:20:08+00:00,1734369608,,14.1-38.53
2025-01-25 10:12:49+00:00,1737799969,,13.1-57.26
2025-02-11 01:19:25+00:00,1739236765,c624dcce8d3355d555021d2aac5f9715,12.1-55.325
2025-02-21 16:41:24+00:00,1740156084,,14.1-43.50
2025-03-06 13:19:10+00:00,1741267150,,14.1-34.105
2025-03-14 09:32:59+00:00,1741944779,,14.1-34.107
2025-04-01 08:43:29+00:00,1743497009,,13.1-37.232
2025-04-08 14:08:19+00:00,1744121299,,13.1-58.21
2025-04-09 07:52:44+00:00,1744185164,,14.1-43.109
2025-05-13 17:58:16+00:00,1747159096,,14.1-47.40
2025-05-20 07:48:42+00:00,1747727322,,14.1-47.43
2025-05-21 08:05:34+00:00,1747814734,,14.1-47.44
2025-06-07 13:53:15+00:00,1749304395,,14.1-47.46
2025-06-10 10:53:47+00:00,1749552827,,14.1-43.56
2025-06-10 14:02:25+00:00,1749564145,89929af92ff35a042d78e9010b7ec534,12.1-55.328
2025-06-10 16:26:42+00:00,1749572802,,13.1-37.235
2025-06-10 20:52:27+00:00,1749588747,,13.1-58.32
2025-06-17 04:21:23+00:00,1750134083,f069136a9297a52b6d86a5de987d9323,12.1-55.328
2025-06-18 13:04:11+00:00,1750251851,,13.1-59.19
2025-08-20 12:21:05+00:00,1755692465,765c645f7af4a1ef5c11d464fafc6244,12.1-55.330
2025-08-20 12:23:35+00:00,1755692615,,14.1-47.48
2025-08-20 12:35:34+00:00,1755693334,,13.1-37.241
2025-08-20 12:44:46+00:00,1755693886,,13.1-59.22
2025-08-26 02:22:30+00:00,1756174950,a53b1af56a97019171ec39665fedc54a,12.1-55.330
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
        assert version, f"version not defined for: {row}"
        assert int(dt.timestamp()) == rdx_en_stamp, (rdx_en_date, rdx_en_stamp, version)
        vstamp_to_version[rdx_en_stamp] = version
        if vhash:
            vhash_to_version[vhash] = version
    stamps = list(vstamp_to_version.keys())
    assert stamps == sorted(stamps), "not sorted"
    return vhash_to_version, vstamp_to_version


vhash_to_version, vstamp_to_version = load_version_hashes()


# ============================================================================
# Color functions
# ============================================================================

KBOLD = "\033[1m"
KRED = "\x1b[31m"
KCYAN = "\x1b[36m"
KGREEN = "\x1b[32m"
KYELLOW = "\x1b[33m"
KNORM = "\033[0m"


def bold(text):
    return KBOLD + text + KNORM


def cyan(text):
    return KCYAN + text + KNORM


def green(text):
    return KGREEN + text + KNORM


def red(text):
    return KRED + text + KNORM


def yellow(text):
    return KYELLOW + text + KNORM


def nocolor(text):
    return text


# ============================================================================
# Helper functions
# ============================================================================


@contextmanager
def temporary_ssl_verify_mode(ssl_ctx: ssl.SSLContext, new_mode: ssl.VerifyMode):
    """Temporarily change the SSL verification mode."""
    old_mode = ssl_ctx.verify_mode
    ssl_ctx.verify_mode = new_mode
    yield
    ssl_ctx.verify_mode = old_mode


# ============================================================================
# Vulnerability check functions
# ============================================================================
class VersionTuple(NamedTuple):
    major: int
    minor: int
    build: int
    patch: int


def parse_version(version: str) -> VersionTuple:
    """Convert a version string to a VersionTuple.

    Raises ValueError if the version string cannot be parsed.

    Example:
    >>> parse_version("12.1-55.328")
    VersionTuple(major=12, minor=1, build=55, patch=328)
    >>> parse_version("unknown")
    Traceback (most recent call last):
      ...
    ValueError: Invalid version: unknown
    """
    if version and version != "unknown":
        version = version.replace(".", "-")
        major, minor, build, patch = map(int, version.split("-"))
        return VersionTuple(major, minor, build, patch)
    raise ValueError(f"Invalid version: {version}")


def is_fips_13_1(vtuple: VersionTuple) -> bool:
    """Return True if the version is FIPS 13.1.

    >>> is_fips_13_1(parse_version("13.1-37-241"))
    True
    >>> is_fips_13_1(parse_version("13.1-9.60"))
    False
    """
    return (vtuple.major, vtuple.minor, vtuple.build) == (13, 1, 37)  # fips, ndcpp


def is_fips_12_1(vtuple: VersionTuple) -> bool:
    """Return True if the version is FIPS 12.1.

    >>> is_fips_12_1(parse_version("12.1-55-12345"))
    True
    >>> is_fips_12_1(parse_version("12.1-62.27"))
    False
    """
    return (vtuple.major, vtuple.minor, vtuple.build) == (12, 1, 55)  # fips, ndcpp


def is_eol(vtuple: VersionTuple) -> bool:
    """Return True if the version is considered End Of Life (EOL).

    NetScaler ADC and NetScaler Gateway versions 12.1 and 13.0 are now End Of Life (EOL)

    >>> is_eol(parse_version("12.1-55.328"))    # fips is not EOL
    False
    >>> is_eol(parse_version("13.1-37.241"))    # fips is not EOL
    False
    >>> is_eol(parse_version("13.0-0.0"))
    True
    >>> is_eol(parse_version("13.1-37.241"))
    False
    >>> is_eol(parse_version("11.1-65.20"))
    True
    >>> is_eol(parse_version("12.1-50.28"))
    True
    """
    if is_fips_13_1(vtuple) or is_fips_12_1(vtuple):
        return False
    elif vtuple.major == 13 and vtuple.minor == 0:
        return True
    elif vtuple.major <= 12:
        return True
    return False


def is_vuln_ctx693420(vtuple: VersionTuple) -> bool:
    """Check if the version is vulnerable to CVE-2025-5349 or CVE-2025-5777 (citrixbleed 2).

    Affected versions:
    - NetScaler ADC and NetScaler Gateway 14.1 BEFORE 14.1-43.56
    - NetScaler ADC and NetScaler Gateway 13.1 BEFORE 13.1-58.32
    - NetScaler ADC 13.1-FIPS and NDcPP BEFORE 13.1-37.235-FIPS and NDcPP
    - NetScaler ADC 12.1-FIPS BEFORE 12.1-55.328-FIPS

    NetScaler ADC and NetScaler Gateway versions 12.1 and 13.0 are now End Of Life (EOL) and are vulnerable.

    References:
    - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420
    - https://www.akamai.com/blog/security-research/mitigating-citrixbleed-memory-vulnerability-ase
    - https://www.netscaler.com/blog/news/netscaler-critical-security-updates-for-cve-2025-6543-and-cve-2025-5777/
    - https://docs.netscaler.com/en-us/netscaler-console-service/instance-advisory/upgrade-advisory.html

    >>> is_vuln_ctx693420(parse_version("13.1-37-234"))
    True
    >>> is_vuln_ctx693420(parse_version("13.1-37-235"))
    False
    >>> is_vuln_ctx693420(parse_version("14.1-43.56"))
    False
    >>> is_vuln_ctx693420(parse_version("14.1-43.55"))
    True
    >>> is_vuln_ctx693420(parse_version("13.1-58.32"))
    False
    >>> is_vuln_ctx693420(parse_version("13.1-58.31"))
    True
    >>> is_vuln_ctx693420(parse_version("12.1-55.328"))
    False
    >>> is_vuln_ctx693420(parse_version("12.1-55.320"))
    True
    >>> is_vuln_ctx693420(parse_version("12.1-50.28"))
    True
    """

    if is_fips_13_1(vtuple):
        return vtuple < VersionTuple(13, 1, 37, 235)
    elif is_fips_12_1(vtuple):
        return vtuple < VersionTuple(12, 1, 55, 328)
    elif vtuple.major == 14:
        return vtuple < VersionTuple(14, 1, 43, 56)
    elif vtuple.major == 13:
        return vtuple < VersionTuple(13, 1, 58, 32)
    return is_eol(vtuple)


def is_vuln_ctx694788(vtuple: VersionTuple) -> bool:
    """Check if the version is vulnerable to CVE-2025-6543 (memory overflow exploited ITW)

    Affected versions:
    - NetScaler ADC and NetScaler Gateway 14.1 BEFORE 14.1-47.46
    - NetScaler ADC and NetScaler Gateway 13.1 BEFORE 13.1-59.19
    - NetScaler ADC 13.1-FIPS and NDcPP  BEFORE 13.1-37.236-FIPS and NDcPP

    NetScaler ADC 12.1-FIPS is not affected by this vulnerability.
    NetScaler ADC and NetScaler Gateway versions 12.1 and 13.0 are now End Of Life (EOL) and are vulnerable.

    References:
    - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX694788
    - https://support.citrix.com/external/article/694788/netscaler-adc-and-netscaler-gateway-secu.html
    - https://www.ncsc.nl/actueel/nieuws/2025/07/21/informatie-over-kwetsbaarheden-in-citrix-netscaler-adc-en-netscaler-gateway

    >>> is_vuln_ctx694788(parse_version("14.1-47.46"))
    False
    >>> is_vuln_ctx694788(parse_version("14.1-47.45"))
    True
    >>> is_vuln_ctx694788(parse_version("13.1-59.19"))
    False
    >>> is_vuln_ctx694788(parse_version("13.1-59.18"))
    True
    >>> is_vuln_ctx694788(parse_version("13.1-37.236")) # fips
    False
    >>> is_vuln_ctx694788(parse_version("13.1-37.235")) # fips
    True
    >>> is_vuln_ctx694788(parse_version("12.1-55.132")) # fips 12.1 not affected
    False
    >>> is_vuln_ctx694788(parse_version("12.1-55.328")) # fips 12.1 not affected
    False
    >>> is_vuln_ctx694788(parse_version("12.1-55.327")) # fips 12.1 not affected
    False
    """
    if is_fips_13_1(vtuple):
        return vtuple < VersionTuple(13, 1, 37, 236)
    elif is_fips_12_1(vtuple):
        return False
    elif vtuple.major == 14:
        return vtuple < VersionTuple(14, 1, 47, 46)
    elif vtuple.major == 13:
        return vtuple < VersionTuple(13, 1, 59, 19)
    return is_eol(vtuple)


def is_vuln_ctx694938(vtuple: VersionTuple) -> bool:
    """Check if the version is vulnerable to CVE-2025-7775, CVE-2025-7776 and CVE-2025-8424

    Affected versions:
    - NetScaler ADC and NetScaler Gateway 14.1 BEFORE 14.1-47.48
    - NetScaler ADC and NetScaler Gateway 13.1 BEFORE 13.1-59.22
    - NetScaler ADC 13.1-FIPS and NDcPP BEFORE 13.1-37.241-FIPS and NDcPP
    - NetScaler ADC 12.1-FIPS and NDcPP BEFORE 12.1-55.330-FIPS and NDcPP

    References:
    - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX694938

    >>> is_vuln_ctx694938(parse_version("14.1-47.48"))
    False
    >>> is_vuln_ctx694938(parse_version("14.1-47.47"))
    True
    >>> is_vuln_ctx694938(parse_version("13.1-59.22"))
    False
    >>> is_vuln_ctx694938(parse_version("13.1-59.21"))
    True
    >>> is_vuln_ctx694938(parse_version("13.1-37.241")) # fips
    False
    >>> is_vuln_ctx694938(parse_version("13.1-37.240")) # fips
    True
    >>> is_vuln_ctx694938(parse_version("12.1-55.330")) # fips
    False
    >>> is_vuln_ctx694938(parse_version("12.1-55.329")) # fips
    True
    """
    if is_fips_13_1(vtuple):
        return vtuple < VersionTuple(13, 1, 37, 241)
    elif is_fips_12_1(vtuple):
        return vtuple < VersionTuple(12, 1, 55, 330)
    elif vtuple.major == 14:
        return vtuple < VersionTuple(14, 1, 47, 48)
    elif vtuple.major == 13:
        return vtuple < VersionTuple(13, 1, 59, 22)
    return is_eol(vtuple)


CVE_CHECKS = {
    # added 2025-06-17
    "CVE-2025-5349": is_vuln_ctx693420,
    "CVE-2025-5777": is_vuln_ctx693420,
    # added 2025-06-25
    "CVE-2025-6543": is_vuln_ctx694788,
    # added 2025-08-26
    "CVE-2025-7775": is_vuln_ctx694938,
    "CVE-2025-7776": is_vuln_ctx694938,
    "CVE-2025-8424": is_vuln_ctx694938,
}

# ============================================================================
# Main scanning logic
# ============================================================================


class NetScalerScanResult(NamedTuple):
    target: str
    tls_names: str
    rdx_en_stamp: int | None
    rdx_en_dt: datetime | None
    version: str | None
    error: str | None = None


# Enable legacy TLS support for old NetScaler devices
ssl_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
ssl_ctx.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE
ssl_ctx.set_ciphers("ALL:@SECLEVEL=0")


def scan_netscaler_target(target: str, client: httpx.Client) -> NetScalerScanResult:
    url = target
    if not target.startswith(("http://", "https://")):
        url = f"https://{target}"
    url = f"{url}/vpn/js/rdx/core/lang/rdx_en.json.gz"
    logging.info("Scanning %r", url)
    stamp = None
    dt = None
    version = None
    error = None
    subject_alt_names = None
    with client.stream("GET", url) as response:
        network_stream = response.extensions["network_stream"]
        ssl_object = network_stream.get_extra_info("ssl_object")

        # Temporarily enable certificate verification to extract some information that is not available otherwise
        with temporary_ssl_verify_mode(ssl_ctx, ssl.CERT_OPTIONAL):
            try:
                cert = ssl_object.getpeercert()
            except AttributeError:
                pass
            else:
                if cert and "subjectAltName" in cert:
                    subject_alt_names = ", ".join(s[1] for s in cert["subjectAltName"])

        stream = response.iter_raw(100)
        data = next(stream, b"")
        if data.startswith(b"\x1f\x8b\x08\x08") and b"rdx_en.json" in data:
            stamp = int.from_bytes(data[4:8], "little")
            dt = datetime.fromtimestamp(stamp, timezone.utc)
            version = vstamp_to_version.get(stamp, "unknown")
            logging.info(
                "Extracted timestamp: stamp=%s, dt=%s, version=%s", stamp, dt, version
            )
        else:
            error = "No valid data found, probably not a Citrix NetScaler"

    return NetScalerScanResult(
        target=target,
        tls_names=subject_alt_names,
        rdx_en_stamp=stamp,
        rdx_en_dt=dt,
        version=version,
        error=error,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan Citrix NetScaler to determine version and vulnerabilities",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
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
        "--json",
        "-j",
        action="store_true",
        default=False,
        help="output scan results as JSON",
    )
    parser.add_argument(
        "--csv",
        "-C",
        action="store_true",
        default=False,
        help="output scan results as CSV",
    )
    parser.add_argument(
        "--cve",
        "-c",
        help="limit CVEs to check instead of all, e.g. CVE-2025-6543,CVE-2025-7775",
    )
    args = parser.parse_args()

    if not args.targets and not args.input:
        parser.error("at least one target is required")

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(
        level=levels[min(args.verbose, 2)],
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S%z",
    )

    # Respect NO_COLOR
    if os.getenv("NO_COLOR"):
        global bold, cyan, green, red, yellow
        bold = cyan = green = red = yellow = nocolor

    available_cves = list(CVE_CHECKS.keys())
    cves_to_check = (
        [cve.strip() for cve in args.cve.split(",")] if args.cve else available_cves
    )
    for cve in cves_to_check:
        if cve not in available_cves:
            parser.error(
                f"Unknown CVE: {cve!r}, available CVEs are:\n - {"\n - ".join(available_cves)}"
            )

    client = httpx.Client(verify=ssl_ctx, timeout=args.timeout)
    targets = args.input or args.targets
    csv_writer = None

    for target in targets:
        target = target.strip()
        try:
            version = scan_netscaler_target(target, client)
        except Exception as exc:
            if args.verbose >= 2:
                logging.exception(f"Exception while scanning {target}")
            version = NetScalerScanResult(
                target=target,
                tls_names=None,
                rdx_en_stamp=None,
                rdx_en_dt=None,
                version=None,
                error=str(exc),
            )

        # Check version for vulnerabilities
        vulnerable_map: dict[str, bool] = {}
        try:
            vtuple = parse_version(version.version)
        except ValueError:
            pass
        else:
            for cve in cves_to_check:
                vuln_check = CVE_CHECKS[cve]
                logging.info(f"Checking {cve} on {target}")
                vulnerable_map[cve] = vuln_check(vtuple)
                if vulnerable_map[cve]:
                    logging.debug(f"VULNERABLE: {cve} on {target}")

        # Determine if the target is vulnerable
        is_vulnerable = any(vulnerable_map.values()) if vulnerable_map else False

        # Output as JSON or CSV
        if args.json or args.csv:
            jdict = {"scanned_at": datetime.now(timezone.utc).isoformat()}
            version = version._replace(
                rdx_en_dt=version.rdx_en_dt.isoformat() if version.rdx_en_dt else None
            )
            jdict.update(version._asdict())
            jdict.update({"vulnerable": vulnerable_map})
            jdict.update({"is_vulnerable": is_vulnerable})

            if args.csv:
                # convert vulnerable dict to columns
                for cve, value in jdict["vulnerable"].items():
                    jdict[f"vuln_{cve}"] = int(value)
                jdict.pop("vulnerable", None)
                # ensure is_vulnerable column is last for consistency
                jdict["is_vulnerable"] = int(jdict.pop("is_vulnerable"))
                if not csv_writer:
                    csv_writer = csv.DictWriter(sys.stdout, fieldnames=jdict.keys())
                    csv_writer.writeheader()
                csv_writer.writerow(jdict)
            elif args.json:
                print(json.dumps(jdict))
            continue

        # Plain text output
        if version.error:
            print(f"{target} ({version.tls_names}): ERROR: {version.error}")
        elif version.version == "unknown":
            print(
                f"{target} ({version.tls_names}) is running an unknown version (stamp={version.rdx_en_stamp}, dt={version.rdx_en_dt})"
            )
        else:
            vulnerable_str = (
                red("VULNERABLE") if is_vulnerable else green("NOT VULNERABLE")
            )
            print(
                f"{target} ({version.tls_names}) is running Citrix NetScaler version {version.version} ({vulnerable_str})"
            )


if __name__ == "__main__":
    # Run self-test (doctests)
    results = doctest.testmod()
    if results.failed:
        print(f"Self test failed: {results}")
        raise SystemExit(1)
    main()
