# Script for querying the CISA Known Exploited Vulnerabilities 
# and merge it with the CDB Identifier
# Initial Author : Palash Oswal
# TODO : Some snippets are duplicated across various other scripts (CVE.py/NIST.py)

#
# Invoke this script directly from cdb-database workdir
#

import requests
import json
import os


vuln_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def cve_to_cdb(cve):
    return cve.replace("CVE","CDB")

def get_filename(cdb_id):
    # The filename will look like
    # {self.path} / year / thousand_dir / {self.id}.json
    (year, just_id) = cdb_id.split('-')[1:]
    id_int = int(just_id)
    thousand_dir = "%dxxx" % int(id_int / 1000)
    the_path = os.path.join(os.getcwd(), year, thousand_dir) # Currently thinks cwd is cdb-database. TODO: Update this to take path as input.
    id_file = f"{cdb_id}.json"
    the_filename = os.path.join(the_path, id_file)
    if not os.path.exists(the_filename):
      print("The following CVE Entry does not have a CDB File - " + cdb_id)
      return ""
    return the_filename


def update_cdb_file(filename, json_blob):
    if (filename == ""):
      #Error has been reported, skip
      return
    with open(filename, 'r') as fh:
      json_data = json.load(fh)
    namespace = 'cisa.gov'
    try:
      if (json_data['namespaces'][namespace] != json_blob):
        json_data['namespaces'][namespace] = json_blob
        print(filename + " updated")
    except KeyError:
      #Key Does not Exist
      json_data['namespaces'][namespace] = json_blob
    with open(filename, 'w+') as fh:
      json.dump(json_data, fh, sort_keys=True, indent=2)
    return

def main():
    source_data = requests.get(url=vuln_url).json()
    for vuln in source_data["vulnerabilities"]:
       cdb_identifier = cve_to_cdb(vuln['cveID'])
       filename = get_filename(cdb_identifier)
       update_cdb_file(filename,vuln)

if __name__=="__main__":
    main()
