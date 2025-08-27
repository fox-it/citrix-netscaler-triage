#!/usr/bin/env python3
#
# file:   version_check_based_on_csv_lists.py
# author: HiS3
#
# This script can extract the individual IP addresses/domains from a csv table and pass them to scan-citrix-netscaler-version.py. 
# The results are compared directly to determine whether the systems are vulnerable to current CVEs or not. All results are supplemented with the other available information and written to a new CSV.
#
import csv
import subprocess
import json

input_file = 'input.csv'
output_file = 'output.csv'
delimiter = ','

# Name of the column where the IP address or domain is located
tab_target = 'target'

# Names of the columns to be filled
tab_version = 'version'
tab_error = 'error'
tab_vuln = 'vulnerable'

# List of patched Version for CVE
patched_versionen = [
    "14.1-47.48",
    "13.1-37.241",
    "13.1-59.22",
    "12.1-55.330"
]

# Datei öffnen und lesen
with open(input_file, newline='', encoding='utf-8') as csvfile_in, \
     open(output_file, 'w', newline='', encoding='utf-8') as csvfile_out:
    
    reader = csv.DictReader(csvfile_in, delimiter=delimiter)
    fieldnames = reader.fieldnames.copy()
    for col in [tab_version, tab_error, tab_vuln]:
        if col not in fieldnames:
            fieldnames.append(col)

    writer = csv.DictWriter(csvfile_out, fieldnames=fieldnames, delimiter=delimiter)
    writer.writeheader()

    for line in reader:
        wert = line[tab_target]
        
        try:
            # Use can-citrix-netscaler-version.py
            finding_raw = subprocess.check_output(
                ['python3', 'scan-citrix-netscaler-version.py', wert, '--json'],
                universal_newlines=True
            ).strip()

            # parse output JSON
            try:
                data = json.loads(finding_raw)
                version = data.get("version", "")
                error = data.get("error", "")
                
                # vulnerable-check: if version in List of patched_version or not
                if version and version not in patched_versionen:
                    vulnerable = "true"
                elif version in patched_versionen:
                    vulnerable = "false"
                else:
                    vulnerable = "unclear" 
                    
            except json.JSONDecodeError:
                version = ""
                error = ""

        except subprocess.CalledProcessError as e:
            version = ""
            error = f"Error: {e}"
            
        line[tab_version] = version
        line[tab_error] = error
        line[tab_vuln] = vulnerable
        print(line[tab_error], line[tab_version], line[tab_vuln])
        #print(fieldnames)
        writer.writerow(line)
        
print(f'Output in: {output_file}')
