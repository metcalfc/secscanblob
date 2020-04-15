#!/usr/bin/env python

import argparse
import json
from pprint import pprint

from google.protobuf.json_format import MessageToJson

from scan_pb2 import *

parser = argparse.ArgumentParser()
parser.add_argument("--file", help="json file", default="./snyk-debian.json")
args = parser.parse_args()

scan = Scan()
scan.backend = SNYK
scan.created.GetCurrentTime()

# Snyk is a flat scan (ie no layers)
layer = scan.layer_results.add()

with open(args.file) as f:
    data = json.load(f)

for vuln in data["vulnerabilities"]:
    v = layer.vulnerabilities.add()
    v.name = vuln["name"]
    v.summary = vuln["title"]
    v.description = vuln["description"]
    v.version = vuln["version"]
    v.severity = Severity.Value(vuln["severity"].upper())
    for identifier in ["CVE", "CWE"]:
        if vuln["identifiers"][identifier]:
            v.identifiers[identifier] = str(vuln["identifiers"][identifier].pop())
    v.identifiers["cvssScore"] = str(vuln["cvssScore"])
    v.identifiers["CVSSv3"] = str(vuln["CVSSv3"])
    for reference in vuln["references"]:
        ref = v.references.add()
        ref.title = reference["title"]
        ref.url = reference["url"]

pprint(scan)
