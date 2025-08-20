import requests
import re
import csv
import time
from bs4 import BeautifulSoup

# 🔐 Mets ici ta clé API NVD
NVD_API_KEY = "API_KEY" # https://nvd.nist.gov/developers/request-an-api-key

# 1. Extraire les CVEs depuis la page Debian DSA
def get_cves_from_dsa_html(dsa_id):
    year = dsa_id.split("-")[1]
    url = f"https://www.debian.org/security/{year}/{dsa_id.lower()}"
    print(f"🔎 Lecture des CVE depuis {url}")
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Erreur HTTP {response.status_code} pour l'URL {url}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    text = soup.get_text()
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text)
    return sorted(set(cves))

# 2. Appeler l'API NVD v2.0 pour un CVE donné
def get_cvss_from_nvd_v2(cve_id, api_key):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        "apiKey": api_key,
        "User-Agent": "cvss-cve-fetcher/1.0"
    }
    params = {"cveId": cve_id}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
        items = data.get("vulnerabilities", [])
        if not items:
            return None
        metrics = items[0].get("cve", {}).get("metrics", {})
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Erreur pour {cve_id} : {e}")
        return None

# 3. Sauvegarde CSV
def save_to_csv(dsa_id, cve_scores, filename="cvss_scores_nvd.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["DSA", "CVE", "CVSS Score"])
        for cve, score in cve_scores.items():
            writer.writerow([dsa_id, cve, score])
    print(f"✅ CSV généré : {filename}")

# === Point d’entrée ===
if __name__ == "__main__":
    dsa_id = "DSA-5973-1"  # Remplace avec ton DSA
    cves = get_cves_from_dsa_html(dsa_id)
    print(f"🔍 {len(cves)} CVE(s) trouvée(s) pour {dsa_id} : {cves}")

    cve_scores = {}
    for cve in cves:
        score = get_cvss_from_nvd_v2(cve, NVD_API_KEY)
        print(f"→ {cve}: CVSS = {score}")
        cve_scores[cve] = score
        time.sleep(1.2)  # Respect du quota NVD (50 req / 30s)

    save_to_csv(dsa_id, cve_scores)
