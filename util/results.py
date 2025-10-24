import datetime
import json
import sqlite3
import statistics
import difflib
import os.path

import latextemplates
import aead_benches


VERSION = "v0.3"
PRECISION = 3  # decimal points in mean and stddev

GRAPHS_FILE = f"./graphs.toml"

DB_FILE = f"./results.sqlite"
RESULT_TEX_FOLDER = f"./data/results-tex/"
RESULT_DICT_FOLDER = f"./data/results-dict/"

RESULTS_JSON = "./data/results-dict/data.json"


def write_tex_file(texfilename, graphcode):
    texfile = f"{RESULT_TEX_FOLDER}/{texfilename}"
    if os.path.isfile(texfile):
        with open(texfile, "r") as f:
            fromlines = f.readlines()
        tolines = graphcode.splitlines(keepends=True)
        diff = difflib.unified_diff(fromlines, tolines)
        difflines = "".join(diff).splitlines()

        # skip trivial updates, ie only updating the generated time
        if (
            (len(difflines) == 11)
            and (difflines[2] == "@@ -1,7 +1,7 @@")
            and (difflines[4] == " %!TEX root = ./main.tex")
            and (difflines[6].startswith("-% tex generated at"))
            and (difflines[7].startswith("+% tex generated at"))
        ):
            print(f"{texfile} is up-to-date")
            return

    with open(texfile, "w") as f:
        f.write(graphcode)
    print(f"WROTE TEX GRAPH TO {texfile}")


def process_results(results_file):
    with open(results_file, "r") as f:
        f_data = f.read()
    results = json.loads(f_data)

    target = aead_benches.getTarget(results["hostname"])

    timestamp = results["timestamp"]
    all_measurements = results["measurements"]

    table_name = target.hostname

    DROP_QUERY = f"DROP TABLE if exists {table_name}"
    CREATE_QUERY = f"CREATE TABLE if not exists {table_name}(name TEXT, operation TEXT, msg_len INT, ad_len INT, numCalls DOUBLE, microseconds DOUBLE, ops_per_second DOUBLE, mb_per_second DOUBLE, cycles DOUBLE, cycles_per_byte DOUBLE, cycles_per_op DOUBLE)"

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
        if target.measure_cycles:
            cycles = measurement["cycles"]
            cycles_per_byte = measurement["cycles_per_byte"]
            cycles_per_op = measurement["cycles"] / numCalls
        else:
            cycles = -1
            cycles_per_byte = -1
            cycles_per_op = -1

        query = f'INSERT into {table_name} VALUES ("{name}", "{operation}", {msg_len}, {ad_len}, {numCalls}, {microseconds}, {ops_per_second}, {mb_per_second}, {cycles}, {cycles_per_byte}, {cycles_per_op})'
        cur.execute(query)
        con.commit()

    with open(RESULTS_JSON, "r") as f:
        f_data = f.read()
    datadict = json.loads(f_data)
    # datadict = {}
    datadict[target.hostname] = {}

    benches = aead_benches.getAeadBenches(target)
    for bench in benches:
        datadict[target.hostname][bench.benchname] = {}
        for operation in bench.operations:
            datadict[target.hostname][bench.benchname][operation.name] = {}
            for metric in bench.timing_metrics:
                plot_list = []
                graphdict = {}
                name_to_datapoints = []

                schemes_list = aead_benches.getSchemesToBench(bench, target, operation)
                if metric.name in ["cycles_per_byte", "cycles_per_op"]:
                    schemes_list = reversed(schemes_list)

                for scheme in schemes_list:
                    datapoint_list = []
                    coords = []

                    for msg_len, ad_len in bench.msg_ad_lens:
                        query = f'SELECT {metric.name} FROM {table_name} WHERE name="{scheme.libname}" AND operation="{operation.name}" AND msg_len={msg_len} AND ad_len={ad_len}'
                        res = cur.execute(query)
                        fetched = res.fetchall()
                        msg_ad_on_metric_list = [i[0] for i in fetched]
                        if len(msg_ad_on_metric_list) < aead_benches.AEAD_REPEAT:
                            print(
                                f"INCORRECT NUMBER OF DATAPOINTS FOR {scheme.libname} {operation.name} {metric.name} AT {(msg_len, ad_len)}: {len(msg_ad_on_metric_list)}"
                            )
                        assert len(msg_ad_on_metric_list) >= aead_benches.AEAD_REPEAT
                        msg_ad_on_metric_median = round(
                            statistics.median(msg_ad_on_metric_list), ndigits=PRECISION
                        )

                        if bench.xaxis == aead_benches.XAxis.msg_len:
                            coords += [f"({msg_len}, {msg_ad_on_metric_median})"]
                            datapoint_list += [(msg_len, msg_ad_on_metric_median)]
                        elif bench.xaxis == aead_benches.XAxis.ad_len:
                            coords += [f"({ad_len}, {msg_ad_on_metric_median})"]
                            datapoint_list += [(ad_len, msg_ad_on_metric_median)]

                    texname = scheme.texname
                    datapoint = {}
                    datapoint["type"] = "line"
                    datapoint["name"] = texname
                    datapoint["data"] = datapoint_list

                    name_to_datapoints += [datapoint]

                    coords = " ".join(coords)
                    plot = latextemplates.tikzplot.substitute(
                        texmark=scheme.texmark,
                        texlegend=texname,
                        texcolor=scheme.aeadclass.texcolor,
                        texlinestyle=scheme.aeadclass.texlinestyle,
                        texlinewidth=scheme.aeadclass.texlinewidth,
                        texmarkscale=scheme.aeadclass.texmarkscale,
                        coords=coords,
                    )
                    plot_list += [plot]

                plots = "\n".join(plot_list)

                graphid = f"{target.hostname}-{bench.benchname}-{operation.name}-{metric.shortname}"
                texlabel = f"fig:{graphid}"
                texfilename = f"{graphid}.tex"

                fighead = bench.fighead + f" on {target.texarch}."
                caption = (
                    f"Throughput in {metric.texlabel} for "
                    + operation.texdesc
                    + bench.caption
                    + f" on {target.texdesc}. {bench.texlinedesc}"
                )

                benchtimestamp = datetime.datetime.fromtimestamp(timestamp).isoformat()
                gentimestamp = datetime.datetime.now().isoformat()

                graphcode = latextemplates.tikzgraph.substitute(
                    hostname=target.hostname,
                    benchtimestamp=benchtimestamp,
                    gentimestamp=gentimestamp,
                    xmode=bench.xmode.name,
                    xlabel=bench.xaxis.value,
                    ylabel=metric.texlabel,
                    xticks=", ".join([str(i) for i in bench.xticks]),
                    xticklabels=", ".join([str(i) for i in bench.xticks]),
                    width=bench.texwidth,
                    height=bench.texheight,
                    plots=plots,
                    fighead=fighead,
                    caption=caption,
                    texlabel=texlabel,
                    legendpos=metric.texlegendpos,
                )

                write_tex_file(texfilename, graphcode)

                graphdict["hostname"] = target.hostname
                graphdict["benchtimestamp"] = benchtimestamp
                graphdict["gentimestamp"] = gentimestamp
                graphdict["xmode"] = bench.xmode.name
                graphdict["xaxis"] = bench.xaxis.name
                graphdict["xlabel"] = bench.xaxis.value
                graphdict["yaxis"] = metric.name
                graphdict["ylabel"] = metric.texlabel
                graphdict["xticks"] = ", ".join([str(i) for i in bench.xticks])
                graphdict["xticklabels"] = ", ".join([str(i) for i in bench.xticks])
                graphdict["fighead"] = fighead
                graphdict["caption"] = caption

                graphdict["datapoints"] = name_to_datapoints

                datadict[target.hostname][bench.benchname][operation.name][
                    metric.shortname
                ] = graphdict

    cur.close()
    with open(RESULTS_JSON, "w") as f:
        json.dump(datadict, f, indent=2)
    print(f"WROTE JSON GRAPH TO {RESULTS_JSON}")
