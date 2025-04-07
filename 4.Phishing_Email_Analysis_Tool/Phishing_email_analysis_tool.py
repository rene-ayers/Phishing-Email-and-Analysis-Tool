import re
import json
import datetime
import logging
import requests

# Configuration
EMAIL_FILE = "emails.txt"  # Input file containing email content
OUTPUT_JSON = "phishing_report.json"  # Report file
LOG_FILE = "script.log"  # Log file
VIRUSTOTAL_API_KEY = "05dd036dcadb76fa5feb4034bc82e7aeeadfb1af6b86f28aff51a8a5c0209210"  # Replace with your API key

# Set up logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Function to extract URLs from email content
def extract_urls_from_email():
    try:
        with open(EMAIL_FILE, "r") as file:
            email_content = file.read()
        
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)
        logging.info(f"Extracted {len(urls)} URLs from email.")
        return urls

    except FileNotFoundError:
        logging.error(f"Error: {EMAIL_FILE} not found.")
        return {"error": "Email file not found"}
    except Exception as e:
        logging.error(f"Unexpected error in extract_urls_from_email: {e}")
        return {"error": "Unexpected error occurred"}

# Function to check URL reputation via VirusTotal API
def check_url_with_virustotal(url):
    try:
        api_url = f"https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        data = {"url": url}
        
        response = requests.post(api_url, headers=headers, data=data)
        if response.status_code != 200:
            logging.warning(f"VirusTotal API error: {response.status_code}")
            return {"error": "VirusTotal API error"}

        # Extract analysis ID
        analysis_id = response.json().get("data", {}).get("id", "")
        if not analysis_id:
            logging.warning(f"Failed to get analysis ID for {url}")
            return {"error": "Failed to retrieve analysis ID"}

        # Fetch report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_response = requests.get(report_url, headers=headers)

        if report_response.status_code != 200:
            logging.warning(f"VirusTotal report fetch failed for {url}")
            return {"error": "VirusTotal report fetch error"}

        analysis = report_response.json()
        results = analysis.get("data", {}).get("attributes", {}).get("results", {})
        
        detections = sum(1 for engine in results.values() if engine["category"] == "malicious")
        logging.info(f"URL {url} classified: {detections} security vendors flagged it as malicious.")

        return {"url": url, "malicious_detections": detections}

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error for {url}: {e}")
        return {"error": "API request failed"}
    except Exception as e:
        logging.error(f"Unexpected error in check_url_with_virustotal: {e}")
        return {"error": "Unexpected error occurred"}

# Function to generate phishing analysis report
def generate_phishing_report():
    print("\nAnalyzing email for phishing URLs...\n")
    logging.info("Started phishing analysis.")

    urls = extract_urls_from_email()
    if isinstance(urls, dict):  # Error handling if URLs are not extracted
        print("Error:", urls["error"])
        return

    results = []
    for url in urls:
        result = check_url_with_virustotal(url)
        results.append(result)

    # Get current timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Structuring the report
    report = {
        "Scanned URLs": results,
        "Timestamp": timestamp
    }

    # Print report to console
    print("--- Phishing Analysis Report ---\n")
    print(json.dumps(report, indent=4))

    # Save report to JSON file
    try:
        with open(OUTPUT_JSON, "w") as json_file:
            json.dump(report, json_file, indent=4)
        logging.info(f"Report successfully saved to {OUTPUT_JSON}")
    except Exception as e:
        logging.error(f"Failed to save JSON report: {e}")

    print(f"\nReport saved to {OUTPUT_JSON}")
    logging.info("Script execution completed.\n")

# Execute the script
if __name__ == "__main__":
    generate_phishing_report()
