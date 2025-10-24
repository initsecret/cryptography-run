import datetime
import json
import sqlite3
import statistics
import platform

import latextemplates


VERSION = "v0.2"
PRECISION = 3  # decimal points in mean and stddev

GRAPHS_FILE = f"./graphs.toml"

DB_FILE = f"./results.sqlite"
RESULT_TEX_FOLDER = f"./data/results-tex/"
RESULT_DICT_FOLDER = f"./data/results-dict/"

# \definecolor{graphDarkPurple}{HTML}{7b3294}
# \definecolor{graphLightPurple}{HTML}{c2a5cf}
# \definecolor{graphLightGreen}{HTML}{a6dba0}
# \definecolor{graphDarkGreen}{HTML}{008837}

# ultra thin: 0.1 pt
# very thin: 0.2 pt
# (default) thin: 0.4 pt
# semithick: 0.6 pt
# thick: 0.8 pt
# very thick: 1.2 pt
# ultra thick: 1.6 pt

class_to_texstyle = {
    "insecure": {
        # <128-bit NAE
        # <128-bit CMT
        # any-size nonces without nonce versatility
        "texlinewidth": "thin",
        "texlinestyle": "dashed",
        "texcolor": "graphDarkPurple",
        "texmarkscale": 1,
    },
    "medium-secure": {
        "texlinewidth": "thin",
        "texlinestyle": "dashed",
        "texcolor": "graphDarkPurple",
        "texmarkscale": 1,
        # # 128-bit NAE
        # # <128-bit CMT
        # # >=192-bit nonces without nonce versatility
        # "texlinewidth": "semithick",
        # "texlinestyle": "dashed",
        # "texcolor": "graphLightPurple",
        # "texmarkscale": 1,
    },
    "mostly-secure": {
        # 128-bit NAE
        # 128-bit CMT
        # >=192-bit nonces without nonce versatility
        "texlinewidth": "semithick",
        "texlinestyle": "solid",
        "texcolor": "graphLightGreen",
        "texmarkscale": 1,
    },
    "secure": {
        # 128-bit NAE
        # 128-bit CMT
        # >=192-bit nonces with nonce versatility
        "texlinewidth": "thick",
        "texlinestyle": "solid",
        "texcolor": "graphDarkGreen",
        "texmarkscale": 1,
    },
    "cty-trans": {
        "texlinewidth": "semithick",
        "texlinestyle": "solid",
        "texcolor": "graphLightGreen",
        "texmarkscale": 1,
    },
    "xth-trans": {
        "texlinewidth": "thick",
        "texlinestyle": "solid",
        "texcolor": "graphDarkGreen",
        "texmarkscale": 1,
    },
    "ocs": {
        "texlinewidth": "semithick",
        "texlinestyle": "solid",
        "texcolor": "graphLightGreen",
        "texmarkscale": 1,
    },
}


scheme_to_texplot = {
    "AreionOCH-S": {
        "texmark": "o",
        "texlegend": "AreionOCH-S",
        "class": "secure",
    },
    "AreionOCH-P": {
        "texmark": "*",
        "texlegend": "AreionOCH-P",
        "class": "secure",
    },
    "AreionOCSimple-S": {
        "texmark": "square",
        "texlegend": "AreionOCSimple-S",
        "class": "ocs",
    },
    "AreionOCSimple-P": {
        "texmark": "square*",
        "texlegend": "AreionOCSimple-P",
        "class": "ocs",
    },
    "BSSL-AES128-GCM": {
        "texmark": "triangle",
        "texlegend": "AES128-GCM",
        "class": "insecure",
    },
    "BSSL-AES256-GCM": {
        "texmark": "triangle*",
        "texlegend": "AES256-GCM",
        "class": "insecure",
    },
    "AES128-OCB3": {
        "texmark": "pentagon",
        "texlegend": "AES128-OCB3",
        "class": "insecure",
    },
    "BSSL-ChaCha20/Poly1305": {
        "texmark": "diamond*",
        "texlegend": "ChaCha20/Poly1305",
        "class": "insecure",
    },
    "Ascon-AEAD128": {
        "texmark": "square",
        "texlegend": "Ascon128",
        "class": "medium-secure",
    },
    "Aead-SHAKE128": {
        "texmark": "pentagon",
        "texlegend": "SHAKE128",
        "class": "mostly-secure",
    },
    "Aead-TurboSHAKE128": {
        "texmark": "pentagon*",
        "texlegend": "TurboSHAKE128",
        "class": "mostly-secure",
    },
    "Aead-Aegis256": {
        "texmark": "diamond",
        "texlegend": "Aegis256",
        "class": "medium-secure",
    },
    "Blake2b-OPP-MEM": {
        "texmark": "square",
        "texlegend": "Blake2b-OPP-MEM",
        "class": "medium-secure",
    },
    "CTY-SHA256-AES256-GCM": {
        "texmark": "diamond",
        "class": "cty-trans",
        "texlegend": "CTY-SHA256",
    },
    "XtH-SHA256-AES256-GCM": {
        "texmark": "diamond*",
        "class": "xth-trans",
        "texlegend": "XtH-SHA256",
    },
    "CTY-Blake2b-AES256-GCM": {
        "texmark": "pentagon",
        "class": "cty-trans",
        "texlegend": "CTY-Blake2b",
    },
    "XtH-Blake2b-AES256-GCM": {
        "texmark": "pentagon*",
        "class": "xth-trans",
        "texlegend": "XtH-Blake2b",
    },
    "CTY-SHA3-256-AES256-GCM": {
        "texmark": "triangle",
        "class": "cty-trans",
        "texlegend": "CTY-SHA3-256",
    },
    "XtH-SHA3-256-AES256-GCM": {
        "texmark": "triangle*",
        "class": "xth-trans",
        "texlegend": "XtH-SHA3-256",
    },
    "CTY-AsconHash256-AES256-GCM": {
        "texmark": "square",
        "class": "cty-trans",
        "texlegend": "CTY-AsconHash256",
    },
    "XtH-AsconHash256-AES256-GCM": {
        "texmark": "square*",
        "class": "xth-trans",
        "texlegend": "XtH-AsconHash256",
    },
}
kTLSADLen = 13


def process_results(results_file):
    with open(results_file, "r") as f:
        f_data = f.read()
    results = json.loads(f_data)

    hostname = results["hostname"]
    if hostname == "offside.local":
        hostname = "offside"

    assert hostname in ["hitch", "offside", "pancake"]

    timestamp = results["timestamp"]
    all_measurements = results["measurements"]

    metrics = ["mb_per_second", "ops_per_second"]
    # we only count cycles on pancake and hitch
    if hostname == "pancake" or hostname == "hitch":
        metrics += ["cycles_per_byte", "cycles_per_op"]

    DROP_QUERY = f"DROP TABLE if exists {hostname}"
    CREATE_QUERY = f"CREATE TABLE if not exists {hostname}(name TEXT, operation TEXT, msg_len INT, ad_len INT, numCalls DOUBLE, microseconds DOUBLE, ops_per_second DOUBLE, mb_per_second DOUBLE, cycles DOUBLE, cycles_per_byte DOUBLE, cycles_per_op DOUBLE)"

    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()

    cur.execute(DROP_QUERY)
    con.commit()
    cur.execute(CREATE_QUERY)
    con.commit()

    for measurement in all_measurements:

        name = measurement["name"]
        operation = measurement["operation"]
        msg_len = measurement["msg_len"]
        ad_len = measurement["ad_len"]
        numCalls = measurement["numCalls"]
        microseconds = measurement["microseconds"]
        ops_per_second = measurement["ops_per_second"]
        mb_per_second = measurement["mb_per_second"]
        # we only count cycles on pancake and hitch
        if hostname == "pancake" or hostname == "hitch":
            cycles = measurement["cycles"]
            cycles_per_byte = measurement["cycles_per_byte"]
            cycles_per_op = measurement["cycles"] / numCalls
        else:
            cycles = -1
            cycles_per_byte = -1
            cycles_per_op = -1

        query = f'INSERT into {hostname} VALUES ("{name}", "{operation}", {msg_len}, {ad_len}, {numCalls}, {microseconds}, {ops_per_second}, {mb_per_second}, {cycles}, {cycles_per_byte}, {cycles_per_op})'
        cur.execute(query)
        con.commit()

    res = cur.execute(f"SELECT name FROM {hostname}")
    schemes = set(res.fetchall())

    for operation in [
        "hot_seal_rand_nonce",
        # "hot seq nonce seal",
        # "cold seal",
        # "hot open",
    ]:
        for metric in metrics:
            assert metric in [
                "mb_per_second",
                "cycles_per_byte",
                "ops_per_second",
                "cycles_per_op",
            ]
            if metric == "mb_per_second":
                shortmetric = "mbps"
                texmetric = "Throughput in millions of bytes-per-second (y-axis, higher is faster)"
                texylabel = "throughput in millions of bytes-per-second"
                # mbps goes south west to north east
                legendpos = "north west"
            elif metric == "cycles_per_byte":
                shortmetric = "cpb"
                texmetric = (
                    "Throughput in CPU cycles-per-byte (y-axis, lower is faster)"
                )
                texylabel = "throughput in cycles-per-byte"
                # cpb goes north west to south east
                legendpos = "north east"
            elif metric == "ops_per_second":
                shortmetric = "ops"
                texmetric = (
                    "Throughput in operations-per-second (y-axis, higher is faster)"
                )
                texylabel = "throughput in operations-per-second"
                legendpos = "north west"
            elif metric == "cycles_per_op":
                shortmetric = "cpo"
                texmetric = (
                    "Throughput in CPU cycles-per-operation (y-axis, lower is faster)"
                )
                texylabel = "throughput in cycles-per-operation"
                legendpos = "north west"

            if hostname == "offside":
                texhost = "an Apple M2 Pro processor"
                texarch = "laptop arm64"
            elif hostname == "hitch":
                texhost = "an Intel Raptor Lake processor"
                texarch = "desktop x86-64"
            elif hostname == "pancake":
                texhost = "an ARM Cortex-A76 processor"
                texarch = "lightweight arm64"

            texlinedesc = "Solid lines indicate schemes that achieve 128-bit NAE and 128-bit CMT security, and dashed lines indicate schemes that do not."

            texgraphs = {}
            if metric in ["mb_per_second", "cycles_per_byte"]:
                texgraphs["aead-log"] = {
                    "schemes": [
                        # "AES128-OCB3",
                        # "BSSL-AES128-GCM",
                        "BSSL-AES256-GCM",
                        "AreionOCH-P",
                        "AreionOCH-S",
                        "BSSL-ChaCha20/Poly1305",
                        # "Ascon-AEAD128",
                        # "Aead-TurboSHAKE128",
                        # "Aead-SHAKE128",
                        # "Aead-Aegis256",
                        # "Blake2b-OPP-MEM",
                    ],
                    "msg_ad_lens": [(2**i, kTLSADLen) for i in range(1, 18)],
                    "xaxis": "msg_len",
                    "xmode": "log",
                    "xticks": [2**i for i in range(1, 18)],
                    "xticklabels": [2**i for i in range(1, 18)],
                    "width": "160mm",
                    "height": "80mm",
                    "fighead": f"AEAD performance on {texarch}.",
                    "caption": f"{texmetric} for encrypting messages of various sizes (x-axis, in bytes) with 13 bytes of associated data on {texhost}. {texlinedesc}",
                }
                LINEAR_MAX_MSGLEN = 1024
                texgraphs["aead-linear"] = {
                    "operation": "hot seal",
                    "schemes": [
                        # "BSSL-AES128-GCM",
                        "BSSL-AES256-GCM",
                        "AreionOCH-P",
                        "AreionOCH-S",
                        "AreionOCSimple-S",
                        "AreionOCSimple-P",
                        # "AES128-OCB3",
                        "BSSL-ChaCha20/Poly1305",
                        # "Aead-TurboSHAKE128",
                        # "Aead-SHAKE128",
                        # "Ascon-AEAD128",
                        # "Aead-Aegis256",
                        # "Blake2b-OPP-MEM",
                    ],
                    "msg_ad_lens": [
                        (i, kTLSADLen) for i in range(0, LINEAR_MAX_MSGLEN + 1, 64)
                    ],
                    "xaxis": "msg_len",
                    "xmode": "linear",
                    "xticks": [i for i in range(0, LINEAR_MAX_MSGLEN + 1, 128)],
                    "xticklabels": [i for i in range(0, LINEAR_MAX_MSGLEN + 1, 128)],
                    "width": "160mm",
                    "height": "80mm",
                    "fighead": f"AEAD performance on {texarch}.",
                    "caption": f"{texmetric} for encrypting messages of various sizes (x-axis, in bytes) with 13 bytes of associated data on {texhost}. {texlinedesc}",
                }

            # we only do the XtH graph on hitch
            if (
                hostname == "hitch"
                and metric == "cycles_per_op"
                and operation == "hot seal"
            ):
                XTH_MAX_ADLEN = 256
                texgraphs["xth-ad-linear-perf"] = {
                    "schemes": [
                        "XtH-SHA256-AES256-GCM",
                        "CTY-SHA256-AES256-GCM",
                        "XtH-Blake2b-AES256-GCM",
                        "CTY-Blake2b-AES256-GCM",
                        "XtH-SHA3-256-AES256-GCM",
                        "CTY-SHA3-256-AES256-GCM",
                        "XtH-AsconHash256-AES256-GCM",
                        "CTY-AsconHash256-AES256-GCM",
                    ],
                    "msg_ad_lens": [(16, i) for i in range(0, XTH_MAX_ADLEN + 1, 16)],
                    "xaxis": "ad_len",
                    "xmode": "linear",
                    "xticks": [i for i in range(0, XTH_MAX_ADLEN + 1, 16)],
                    "xticklabels": [i for i in range(0, XTH_MAX_ADLEN + 1, 16)],
                    "width": "160mm",
                    "height": "80mm",
                    "fighead": f"Committing transform performance on {texarch}.",
                    "caption": f"{texmetric} for encrypting a 16-byte message with varying amounts of associated data (x-axis, in bytes)on {texhost}. {texlinedesc}",
                }

            for graph in texgraphs:
                assert texgraphs[graph]["xaxis"] in ["msg_len", "ad_len"]
                assert texgraphs[graph]["xmode"] in ["linear", "log"]

                plot_list = []
                graphdict = {}
                name_to_datapoints = {}

                schemes_list = texgraphs[graph]["schemes"]
                if metric in ["cycles_per_byte", "cycles_per_op"]:
                    schemes_list = reversed(schemes_list)

                for name in schemes_list:
                    datapoints = {}
                    coords = []

                    for msg_len, ad_len in texgraphs[graph]["msg_ad_lens"]:
                        if metric == "cycles_per_byte" and msg_len == 0:
                            continue
                        query = f'SELECT {metric} FROM {hostname} WHERE name="{name}" AND operation="{operation}" AND msg_len={msg_len} AND ad_len={ad_len}'
                        res = cur.execute(query)
                        fetched = res.fetchall()
                        msg_ad_on_metric_list = [i[0] for i in fetched]
                        if len(msg_ad_on_metric_list) == 0:
                            print(f"NO DATA FOR {name} at {(msg_len, ad_len)}")
                        msg_ad_on_metric_median = round(
                            statistics.median(msg_ad_on_metric_list), ndigits=PRECISION
                        )

                        if texgraphs[graph]["xaxis"] == "msg_len":
                            coords += [f"({msg_len}, {msg_ad_on_metric_median})"]
                            datapoints[msg_len] = msg_ad_on_metric_median
                        elif texgraphs[graph]["xaxis"] == "ad_len":
                            coords += [f"({ad_len}, {msg_ad_on_metric_median})"]
                            datapoints[ad_len] = msg_ad_on_metric_median

                    texname = scheme_to_texplot[name]["texlegend"]
                    name_to_datapoints[texname] = datapoints

                    coords = " ".join(coords)
                    scheme_class = scheme_to_texplot[name]["class"]
                    plot = latextemplates.tikzplot.substitute(
                        texmark=scheme_to_texplot[name]["texmark"],
                        texlegend=scheme_to_texplot[name]["texlegend"],
                        texcolor=class_to_texstyle[scheme_class]["texcolor"],
                        texlinestyle=class_to_texstyle[scheme_class]["texlinestyle"],
                        texlinewidth=class_to_texstyle[scheme_class]["texlinewidth"],
                        texmarkscale=class_to_texstyle[scheme_class]["texmarkscale"],
                        coords=coords,
                    )
                    plot_list += [plot]

                plots = "\n".join(plot_list)

                graphid = f"{graph}-{operation}-{hostname}-{shortmetric}"
                texlabel = f"fig:{graphid}"
                texfilename = f"{graphid}.tex"
                dictfilename = f"{graphid}.json"

                if texgraphs[graph]["xaxis"] == "msg_len":
                    texxlabel = "message length in bytes"
                elif texgraphs[graph]["xaxis"] == "ad_len":
                    texxlabel = "associated data length in bytes"

                graphcode = latextemplates.tikzgraph.substitute(
                    hostname=hostname,
                    benchtimestamp=datetime.datetime.fromtimestamp(
                        timestamp
                    ).isoformat(),
                    gentimestamp=datetime.datetime.now().isoformat(),
                    xmode=texgraphs[graph]["xmode"],
                    xlabel=texxlabel,
                    ylabel=texylabel,
                    xticks=", ".join([str(i) for i in texgraphs[graph]["xticks"]]),
                    xticklabels=", ".join(
                        [str(i) for i in texgraphs[graph]["xticklabels"]]
                    ),
                    width=texgraphs[graph]["width"],
                    height=texgraphs[graph]["height"],
                    plots=plots,
                    fighead=texgraphs[graph]["fighead"],
                    caption=texgraphs[graph]["caption"],
                    texlabel=texlabel,
                    legendpos=legendpos,
                )

                texfile = f"{RESULT_TEX_FOLDER}/{texfilename}"
                with open(texfile, "w") as f:
                    f.write(graphcode)

                print(f"WROTE TEX GRAPH TO {texfile}")

                graphdict["hostname"] = hostname
                graphdict["benchtimestamp"] = datetime.datetime.fromtimestamp(
                    timestamp
                ).isoformat()
                graphdict["gentimestamp"] = datetime.datetime.now().isoformat()
                graphdict["xaxis"] = texgraphs[graph]["xaxis"]
                graphdict["xmode"] = texgraphs[graph]["xmode"]
                graphdict["xlabel"] = texxlabel
                graphdict["yaxis"] = metric
                graphdict["ylabel"] = texylabel
                graphdict["xticks"] = ", ".join(
                    [str(i) for i in texgraphs[graph]["xticks"]]
                )
                graphdict["xticklabels"] = ", ".join(
                    [str(i) for i in texgraphs[graph]["xticklabels"]]
                )
                graphdict["fighead"] = texgraphs[graph]["fighead"]
                graphdict["caption"] = texgraphs[graph]["caption"]

                graphdict["datapoints"] = name_to_datapoints

                dictfile = f"{RESULT_DICT_FOLDER}/{dictfilename}"
                with open(dictfile, "w") as f:
                    json.dump(graphdict, f, indent=2)

                print(f"WROTE JSON GRAPH TO {dictfile}")

    cur.close()
