#!/usr/bin/env python3
"""Read the benchmark CSV and output a json file for graphing"""
#
#

import argparse
import csv
import json
import sys


def argparser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--file",
        default=sys.stdin,
        type=argparse.FileType("r"),
        help="The csv file to read",
    )

    args = ap.parse_args()

    return args


def main():
    args = argparser()

    db = {}

    reader = csv.DictReader(args.file)
    for row in reader:
        k = row["name"] + "," + row["variant"]

        loops = int(row["ptrace_loops"])
        instr = int(row["ptrace_instr"])
        ipl = int(instr / loops)

        db[k] = ipl

    reporton = [
        "aes_decr,",
        "aes_encr,",
        "pdu2tun,",
        "NOP,",
    ]

    output = []
    for name in reporton:
        item = {
            "name": f"{name}",
            "unit": "Instructions",
            "value": db[name],
        }
        output.append(item)

    print(json.dumps(output))


if __name__ == '__main__':
    main()
