"""
should match benches/aead_benches.hpp
"""

from enum import Enum

from dataclasses import dataclass

AEAD_REPEAT = 4

kTLSADLen = 13


@dataclass
class MeasurementTarget:
    hostname: str
    has_areion: bool
    measure_cycles: bool
    texdesc: str
    texarch: str


hitch = MeasurementTarget(
    "hitch", True, True, "an Intel Raptor Lake processor", "desktop x86-64"
)
pancake = MeasurementTarget(
    "pancake", True, True, "an ARM Cortex-A76 processor", "lightweight arm64"
)
offside = MeasurementTarget(
    "offside", True, False, "an Apple M2 Pro processor", "laptop arm64"
)


def getTarget(hostname: str) -> MeasurementTarget:
    if hostname == "offside.local":
        hostname = "offside"
    assert hostname in ["hitch", "offside", "pancake"]

    if hostname == hitch.hostname:
        return hitch
    elif hostname == pancake.hostname:
        return pancake
    elif hostname == offside.hostname:
        return offside


@dataclass
class ThroughputMetric:
    name: str
    shortname: str
    texlabel: str
    texinter: str
    texlegendpos: str


mb_per_second = ThroughputMetric(
    "mb_per_second",
    "mbps",
    "millions of bytes-per-second",
    "higher is faster",
    "north west",
)
ops_per_second = ThroughputMetric(
    "ops_per_second",
    "ops",
    "operations-per-second",
    "higher is faster",
    "north west",
)
cycles_per_byte = ThroughputMetric(
    "cycles_per_byte",
    "cpb",
    "CPU cycles-per-byte",
    "lower is faster",
    "north east",
)
cycles_per_op = ThroughputMetric(
    "cycles_per_op",
    "cpo",
    "CPU cycles-per-operation",
    "lower is faster",
    "north east",
)


def getSupportedMetrics(target: MeasurementTarget) -> list[ThroughputMetric]:
    out = [mb_per_second]
    if target.measure_cycles:
        out.extend([cycles_per_byte])
    return out


@dataclass
class AeadOperation:
    name: str
    texdesc: str


hot_seal_rand_nonce = AeadOperation("hot_seal_rand_nonce", "encrypting messages")
cold_seal_rand_nonce = AeadOperation("cold_seal_rand_nonce", "encrypting messages")
hot_seal_seq_nonce = AeadOperation("hot_seal_seq_nonce", "encrypting messages")
hot_open = AeadOperation("hot_open", "decrypting messages")


def getDefaultOperations(target: MeasurementTarget) -> list[AeadOperation]:
    out = [hot_seal_rand_nonce]
    # FIXME: do this properly
    if True or target.hostname == "hitch":
        out.extend([hot_seal_seq_nonce, hot_open, cold_seal_rand_nonce])
    return out


@dataclass
class AeadSchemeClass:
    texlinewidth: str
    texlinestyle: str
    texcolor: str
    texmarkscale: str


InsecureAeads = AeadSchemeClass("thin", "dashed", "graphDarkPurple", 1)
MostlySecureAeads = AeadSchemeClass("semithick", "solid", "graphLightGreen", 1)
SecureAeads = AeadSchemeClass("thick", "solid", "graphDarkGreen", 1)

CtyAeads = AeadSchemeClass("semithick", "solid", "graphLightGreen", 1)
XthAeads = AeadSchemeClass("thick", "solid", "graphDarkGreen", 1)


@dataclass
class AeadScheme:
    # name in cryptography-run library
    libname: str
    # name to display in graph legends
    texname: str
    texmark: str
    aeadclass: AeadSchemeClass


Aead_bssl_aes256_gcm = AeadScheme(
    "BSSL-AES256-GCM", "AES128-GCM", "triangle*", InsecureAeads
)
Aead_bssl_chapoly = AeadScheme(
    "BSSL-ChaCha20/Poly1305", "ChaCha20/Poly1305", "diamond*", InsecureAeads
)

Aead_shake128 = AeadScheme("Aead-SHAKE128", "SHAKE128", "pentagon", MostlySecureAeads)
Aead_turboshake128 = AeadScheme(
    "Aead-TurboSHAKE128", "TurboSHAKE128", "pentagon*", MostlySecureAeads
)

Aead_och_s_areion = AeadScheme("AreionOCH-S", "AreionOCH-S", "o", SecureAeads)
Aead_och_p_areion = AeadScheme("AreionOCH-P", "AreionOCH-P", "*", SecureAeads)

Aead_OCSimple256_512_S_Areion = AeadScheme(
    "AreionOCSimple-S", "AreionOCSimple-S", "o", SecureAeads
)
Aead_OCSimple256_512_P_Areion = AeadScheme(
    "AreionOCSimple-P", "AreionOCSimple-P", "*", SecureAeads
)

Aead_aes256_gcm = AeadScheme(
    "Haberdashery-AES256-GCM", "AES256-GCM", "o", MostlySecureAeads
)
Aead_cty_areion512sponge_aes256_gcm = AeadScheme(
    "CTY-Areion512Sponge-AES256-GCM",
    "CTY-Areion512Sponge-AES256-GCM",
    "o",
    MostlySecureAeads,
)
Aead_xth_areion512sponge_aes256_gcm = AeadScheme(
    "XtH-Areion512Sponge-AES256-GCM",
    "XtH-Areion512Sponge-AES256-GCM",
    "o",
    MostlySecureAeads,
)
Aead_cty_sha256_aes256_gcm = AeadScheme(
    "CTY-SHA256-AES256-GCM", "CTY-SHA256-AES256-GCM", "o", MostlySecureAeads
)
Aead_xth_sha256_aes256_gcm = AeadScheme(
    "XtH-SHA256-AES256-GCM", "XtH-SHA256-AES256-GCM", "o", MostlySecureAeads
)


class XAxis(Enum):
    msg_len = "message length in bytes"
    ad_len = "associated data in bytes"


class XMode(Enum):
    linear = 0
    log = 1


@dataclass
class AeadBench:
    benchname: str
    operations: list[AeadOperation]
    timing_metrics: list[ThroughputMetric]
    xaxis: XAxis
    xmode: XMode
    msg_ad_lens: list[tuple[int, int]]
    xticks: list[int]
    texwidth: int
    texheight: int
    fighead: str
    caption: str
    texlinedesc: str


def getAeadBenches(target: MeasurementTarget) -> list[AeadBench]:
    metrics = getSupportedMetrics(target)
    defaultOperations = getDefaultOperations(target)
    texwidth = "160mm"
    texheight = "80mm"
    fighead = "AEAD Performance"
    caption = " of various sizes (x-axis, in bytes) with 13 bytes of associated data"
    texlinedesc = "Solid lines indicate schemes that achieve 128-bit NAE and 128-bit CMT security, and dashed lines indicate schemes that do not."
    out = [
        AeadBench(
            "log",
            defaultOperations,
            metrics,
            XAxis.msg_len,
            XMode.log,
            [(2**i, kTLSADLen) for i in range(1, 18)],
            [2**i for i in range(1, 18)],
            texwidth,
            texheight,
            fighead,
            caption,
            texlinedesc,
        ),
        AeadBench(
            "linear",
            defaultOperations,
            metrics,
            XAxis.msg_len,
            XMode.log,
            [(i, kTLSADLen) for i in range(64, 1024 + 1, 64)],
            [i for i in range(128, 1024 + 1, 128)],
            texwidth,
            texheight,
            fighead,
            caption,
            texlinedesc,
        ),
    ]
    if target == hitch:
        out.append(
            AeadBench(
                "xth",
                [hot_seal_rand_nonce],
                [cycles_per_op, ops_per_second],
                XAxis.ad_len,
                XMode.linear,
                [(16, i) for i in range(16, 256 + 1, 16)],
                [i for i in range(16, 256 + 1, 16)],
                texwidth,
                texheight,
                fighead,
                caption,
                texlinedesc,
            )
        )
    return out


def getSchemesToBench(
    bench: AeadBench, target: MeasurementTarget, op: AeadOperation
) -> list[AeadScheme]:
    if bench.benchname in ["log", "linear"]:
        out = [
            Aead_bssl_aes256_gcm,
            Aead_bssl_chapoly,
        ]
        if op is not hot_open:
            out.extend(
                [
                    Aead_shake128,
                    Aead_turboshake128,
                ]
            )

        if target.has_areion:
            out.extend(
                [
                    Aead_och_s_areion,
                    Aead_och_p_areion,
                    Aead_OCSimple256_512_S_Areion,
                    Aead_OCSimple256_512_P_Areion,
                ]
            )
        return out

    elif bench.benchname == "xth" and target.hostname == "hitch":
        out = [
            Aead_aes256_gcm,
            Aead_cty_areion512sponge_aes256_gcm,
            Aead_xth_areion512sponge_aes256_gcm,
            Aead_cty_sha256_aes256_gcm,
            Aead_xth_sha256_aes256_gcm,
        ]
        return out

    else:
        raise Exception("unsupported benchname and host")
