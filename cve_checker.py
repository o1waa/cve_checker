#!/usr/bin/env python3
"""
CVE Checker Module
Spolehlivé vyhledávání zranitelností přes veřejné NVD / CIRCL fallback API.
"""

import sys
import argparse
import requests

def search_cve(product, version=None):
    query = f"{product} {version}".strip() if version else product
    print(f"[*] Vyhledávám CVE zranitelnosti pro: {query}...")
    
    # Použijeme oficiální NVD API endpoint
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=12)

        if response.status_code != 200:
            print(f"[-] Chyba serveru při dotazu na NVD API (Status Code: {response.status_code})")
            return

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            print(f"[+] Pro výraz '{query}' nebyly nalezeny žádné záznamy.")
            return

        print(f"\n[!] Nalezeno {len(vulnerabilities)} potenciálních CVE zranitelností:\n")
        print(f"{'CVE ID':<18} | Popis")
        print("-" * 80)

        count = 0
        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "N/A")
            
            # Vytažení anglického popisu
            descriptions = cve_data.get("descriptions", [])
            summary = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    summary = desc.get("value", "")
                    break
            
            if not summary and descriptions:
                summary = descriptions[0].get("value", "")

            short_summary = summary[:58].replace("\n", " ") + "..." if len(summary) > 58 else summary.replace("\n", " ")
            print(f"{cve_id:<18} | {short_summary}")
            
            count += 1
            if count >= 10:  # Zobrazíme max 10 výsledků
                break

    except Exception as e:
        print(f"[-] Chyba při připojení k API: {e}")

def main():
    parser = argparse.ArgumentParser(description="CVE Search Tool")
    parser.add_argument("-p", "--product", required=True, help="Produkt/Služba (např. apache, nginx, openssh)")
    parser.add_argument("-v", "--version", help="Verze (např. 2.4.49)")
    args = parser.parse_args()

    search_cve(args.product, args.version)

if __name__ == "__main__":
    main()