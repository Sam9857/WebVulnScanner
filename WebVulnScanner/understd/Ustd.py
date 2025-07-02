# Import required libraries
from datetime import datetime  # For adding timestamps to reports
import requests                # For sending HTTP requests
from bs4 import BeautifulSoup  # (Not used currently, can be removed)
from fpdf import FPDF          # For generating PDF reports
import random                  # For random selection of User-Agent
import time                    # (Not used, can be removed)

# List of common User-Agent headers to simulate different browsers
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
]

# Function to scan a given URL for basic vulnerabilities
def scan_url(url):
    findings = []  # Store detected issues
    headers = {'User-Agent': random.choice(USER_AGENTS)}  # Pick a random browser user-agent

    # Define common vulnerability payloads
    payloads = {
        "XSS": "<script>alert('XSS')</script>",  # For Cross-site Scripting
        "SQLi": "' OR '1'='1 -- ",              # For SQL Injection
        "CSRF": "<form action='{}' method='POST'></form>".format(url),  # CSRF Form Injection
        "RCE": "test; ping -c 1 kali.org"       # For Remote Code Execution
    }

    # Loop through each payload and test the URL
    for vuln_type, payload in payloads.items():
        test_url = url + "?input=" + payload  # Append payload as a query parameter
        try:
            r = requests.get(test_url, headers=headers, timeout=10)  # Send request
            content = r.text.lower()  # Convert response to lowercase for easier matching

            # Check if certain keywords exist in the response to detect possible vulnerabilities
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

    return findings  # Return the results

# Function to generate HTML and PDF reports
def generate_report(findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current time

    # Create HTML report
    with open("report.html", "w") as f:
        f.write(f"<html><body><h1>Web Vulnerability Scan Report</h1><p><b>Scan Time:</b> {timestamp}</p><ul>")
        for finding in findings:
            f.write(f"<li>{finding}</li>")
        f.write("</ul></body></html>")

    # Create PDF report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Web Vulnerability Scan Report", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Scan Time: {timestamp}", ln=True, align='L')
    pdf.ln(5)  # Add some space

    # Add each finding as a line in the PDF
    for finding in findings:
        pdf.multi_cell(0, 10, txt=finding)

    pdf.output("report.pdf")  # Save the PDF file

# Main execution
if __name__ == "__main__":
    url = input("Enter URL to scan: ")          # Ask user for URL
    findings = scan_url(url)                    # Perform scan
    generate_report(findings)                   # Generate reports
    print("Scan complete. Reports saved as report.html and report.pdf")
