# https://github.com/octopilami/python/blob/main/get_cvss_from_dsa.py

Get all CVE and score from a debian DSA release using NVD api v2.0. 

HOWTO : Change variable dsa_id. Get an api key from NVD : https://nvd.nist.gov/developers/request-an-api-key

Requirements :
* apt install python3-bs4
* apt install python3-requests

DSA list : https://www.debian.org/security/

CVE list from a DSA : https://lists.debian.org/debian-security-announce/2025/msg00137.html
