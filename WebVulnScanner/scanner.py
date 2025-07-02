from datetime import datetime
import requests
from bs4 import BeautifulSoup
from fpdf import FPDF
import random 
import time

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
]

def scan_url(url):
    findings = []
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    payloads = {
        "XSS": "<script>alert('XSS')</script>",
        "SQLi": "' OR '1'='1 -- ",
        "CSRF": "<form action='{}' method='POST'></form>".format(url),
        "RCE": "test; ping -c 1 kali.org"
    }

    for vuln_type, payload in payloads.items():
        test_url = url + "?input=" + payload
        try:
            r = requests.get(test_url, headers=headers, timeout=10)
            content = r.text.lower()
            if vuln_type == "XSS" and "script" in content:
                findings.append(f"[!] Potential XSS vulnerability at {test_url}")
            elif vuln_type == "SQLi" and ("sql" in content or "syntax" in content):
                findings.append(f"[!] Possible SQL Injection at {test_url}")
            elif vuln_type == "CSRF":
                findings.append(f"[*] Tested CSRF form injection on {url}")
            elif vuln_type == "RCE" and ("ping" in content or "command" in content):
                findings.append(f"[!] RCE test reflected in output: {test_url}")
            else:
                findings.append(f"[+] {vuln_type} tested at {test_url}, no issues observed.")
        except Exception as e:
            findings.append(f"[x] Error testing {vuln_type} at {test_url}: {str(e)}")

    return findings

def generate_report(findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # HTML Report
    with open("report.html", "w") as f:
        f.write(f"<html><body><h1>Web Vulnerability Scan Report</h1><p><b>Scan Time:</b> {timestamp}</p><ul>")
        for finding in findings:
            f.write(f"<li>{finding}</li>")
        f.write("</ul></body></html>")

    # PDF Report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Web Vulnerability Scan Report", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Scan Time: {timestamp}", ln=True, align='L')
    pdf.ln(5)
    for finding in findings:
        pdf.multi_cell(0, 10, txt=finding)
    pdf.output("report.pdf")

if __name__ == "__main__":
    url = input("Enter URL to scan: ")
    findings = scan_url(url)
    generate_report(findings)
    print("Scan complete. Reports saved as report.html and report.pdf")
