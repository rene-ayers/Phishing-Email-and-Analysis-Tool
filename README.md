# Phishing Email Analysis Tool

This Python tool scans emails for suspicious URLs each one using the VirusTotal API, and creates a report showing the links that might be dangerous.

---

## Features

- Extracts all URL's from an email text file
- Checks each URL against VirTotal's database
- Shows how many security vendors marked the URL as malicious
- Saves results to a clean JSON report
- Logs activity to a file for easy troubleshooting

---

## File Descriptions

| File Name                     | Purpose                                   |
| ------------------------------| ----------------------------------------- |
| 'phishing_email_analysis.py'  | Main Python script                        |
| "emails.txt                   | Input file that contains the raw email    |
| 'script.log'                  | Log file of what the script did           |

## How to Use

1. Put your email content into a file called 'emails.txt'
2. Open the Python script and **add your VirusTota API key** at the top
3. Run the script like this:

```bash
python phishing_email_analysis.py
