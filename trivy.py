#!/usr/bin/env python3

import argparse
import json
from pprint import pprint

from google.protobuf.json_format import MessageToJson

from scan_pb2 import *

parser = argparse.ArgumentParser()
parser.add_argument("--file", help="json file", default="./trivy-debian.json")
args = parser.parse_args()

scan = Scan()
scan.backend = TRIVY
scan.created.GetCurrentTime()

with open(args.file) as f:
    data = json.load(f)

data = data[0]

scan.target = data["Target"]

layers = set()

for vuln in data["Vulnerabilities"]:
    layers.add(vuln["LayerID"])

for layer in layers:
    l = scan.layer_results.add()
    l.sha256 = layer
    for vuln in data["Vulnerabilities"]:
        if layer == vuln["LayerID"]:
            v = l.vulnerabilities.add()
            if "PkgName" in vuln:
                v.name = vuln["PkgName"]
            if "Description" in vuln:
                v.description = vuln["Description"]
            if "Title" in vuln:
                pprint(vuln)
                v.summary = vuln["Title"]
            v.version = vuln["InstalledVersion"]
            v.severity = Severity.Value(vuln["Severity"])
            if "References" in vuln:
                for ref in vuln["References"]:
                    r = v.references.add()
                    r.url = ref
            v.identifiers["CVE"] = vuln["VulnerabilityID"]

# pprint(scan)
