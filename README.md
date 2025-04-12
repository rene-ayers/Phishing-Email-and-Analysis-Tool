# OSINT Threat Indicator Analyzer

This Python tool performs OSINT lookups on IP addresses, domains, or hashes using the **AbuseIPDB** and **AlienVault OTX** APIs. It reads indicators from a text file, checks each one, and produces a structured threat report in both the terminal and a JSON file.

---

## Features

- Checks IP reputation using AbuseIPDB
- Checks domain/hash threat intelligence using AlienVault OTX
- Logs all API activity to a log file
- Saves a threat report to a JSON file
- Prints results to the console with timestamps

---

## File Descriptions

| File Name                | Purpose                                |
|--------------------------|----------------------------------------|
| `osint_threat_checker.py`| Main Python script                     |
| `threat_indicators.txt`  | Input list of IPs, domains, or hashes  |
| `threat_report.json`     | Output report saved as JSON            |
| `script.log`             | Activity and error log file            |

---

## How to Use

- Python 3 must be installed
- Install required libraries by running: `pip install requests`
- Open your code editor (like VS Code) and create a file named `osint_threat_checker.py`
- Paste the full script into this file and save it
- Create a text file named `threat_indicators.txt` in the same folder
- Add one IP, domain, or hash per line
- Inside the Python script, replace the placeholder API keys with your actual keys from AbuseIPDB and AlienVault OTX
- In your terminal or command prompt, navigate to the folder where the script is saved and run:
  `python osint_threat_checker.py`

## Requirements

- Python 3  
- `requests` library (install with `pip install requests`)  
- Free API keys from:
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [AlienVault OTX](https://otx.alienvault.com/)
