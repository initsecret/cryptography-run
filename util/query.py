import datetime
import json
import sqlite3
import statistics
import platform

from results import DB_FILE
from aead_benches import kTLSADLen

PRECISION = 1

hostnames = ["hitch"]

msg_ad_lens = [
    # (65536, kTLSADLen),
    #  (131072, kTLSADLen),
            {16, kTLSADLen},
            {32, kTLSADLen},
            {64, kTLSADLen},
            # {128, kTLSADLen},
            # {256, kTLSADLen},
]

metric = "mb_per_second"
# metric = "cycles_per_byte"
assert metric in [
    "mb_per_second",
    "cycles_per_byte",
    "ops_per_second",
    "cycles_per_op",
]

schemes_list = [
    "AreionOCH-S",
    "AreionOCH-P",
    "Haberdashery-AES256-GCM", 
    "CTY-Areion512Sponge-AES256-GCM",
    "XtH-Areion512Sponge-AES256-GCM",
    "CTY-SHA256-AES256-GCM", 
    "XtH-SHA256-AES256-GCM", 
    # "Aead-SHAKE128",
    # "Aead-TurboSHAKE128",
    # "BSSL-AES128-GCM",
    # "BSSL-AES256-GCM",
    # "BSSL-ChaCha20/Poly1305",
    # # "AES128-OCB3",
    # # "Blake2b-OPP-MEM",
    # "Ascon-AEAD128",
]

if __name__ == "__main__":
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()

    dataout = {}
    for hostname in hostnames:
        assert hostname in ["hitch", "offside", "pancake"]
        dataout[hostname] = {}

        for msg_len, ad_len in msg_ad_lens:
            dataout[hostname][msg_len] = {}

            for name in schemes_list:
                if metric == "cycles_per_byte" and msg_len == 0:
                    continue

                query = f'SELECT {metric} FROM {hostname} WHERE name="{name}" AND msg_len={msg_len} AND ad_len={ad_len}'
                res = cur.execute(query)
                fetched = res.fetchall()
                msg_ad_on_metric_list = [i[0] for i in fetched]
                if len(msg_ad_on_metric_list) == 0:
                    print(f"NO DATA FOR {name} at {(msg_len, ad_len)}")
                msg_ad_on_metric_median = round(
                    statistics.median(msg_ad_on_metric_list), ndigits=PRECISION
                )
                name = name.ljust(25)
                dataout[hostname][msg_len][name] = msg_ad_on_metric_median
                
                # if name == "AreionOCH-S".ljust(25):
                #     dataout[hostname][msg_len][name] = msg_ad_on_metric_median
                # else:
                #     comp = (
                #         dataout[hostname][msg_len]["AreionOCH-S".ljust(25)]
                #         / msg_ad_on_metric_median
                #     )
                #     comp = round(comp, ndigits=2)

                #     dataout[hostname][msg_len][name] = comp

    print(json.dumps(dataout, indent=2))
    cur.close()
