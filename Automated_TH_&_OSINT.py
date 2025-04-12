import json
import datetime
import logging
import requests

# API Configuration
ABUSEIPDB_API_KEY = ""
OTX_API_KEY = ""

# Input & Output Files
INPUT_FILE = "threat_indicators.txt"  # Contains IPs, domains, or hashes
OUTPUT_JSON = "threat_report.json"
LOG_FILE = "script.log"

# Set up logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Function to check IP reputation using AbuseIPDB
def check_ip_abuseipdb(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            logging.warning(f"AbuseIPDB API error: {response.status_code}")
            return {"error": "AbuseIPDB API error"}

        result = response.json()
        abuse_score = result.get("data", {}).get("abuseConfidenceScore", 0)

        logging.info(f"Checked IP {ip}: Abuse Score {abuse_score}")
        return {"ip": ip, "abuse_score": abuse_score}

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error for AbuseIPDB: {e}")
        return {"error": "API request failed"}
    except Exception as e:
        logging.error(f"Unexpected error in check_ip_abuseipdb: {e}")
        return {"error": "Unexpected error occurred"}

# Function to check domain/hash reputation using AlienVault OTX
def check_otx_reputation(indicator):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            logging.warning(f"AlienVault OTX API error for {indicator}: {response.status_code}")
            return {"error": "AlienVault OTX API error"}

        result = response.json()
        threat_info = result.get("pulse_info", {}).get("count", 0)

        logging.info(f"Checked {indicator}: Found in {threat_info} threat pulses.")
        return {"indicator": indicator, "threat_pulses": threat_info}

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error for AlienVault OTX: {e}")
        return {"error": "API request failed"}
    except Exception as e:
        logging.error(f"Unexpected error in check_otx_reputation: {e}")
        return {"error": "Unexpected error occurred"}

# Function to analyze indicators from file
def analyze_indicators():
    print("\nStarting OSINT-based threat hunting...\n")
    logging.info("Started OSINT-based threat analysis.")

    try:
        with open(INPUT_FILE, "r") as file:
            indicators = [line.strip() for line in file if line.strip()]

        results = []
        for indicator in indicators:
            if indicator.count(".") >= 2:  # Basic check for IPs/domains
                result = check_ip_abuseipdb(indicator)
            else:
                result = check_otx_reputation(indicator)

            results.append(result)

        # Get current timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Structuring the report
        report = {
            "Threat Indicators": results,
            "Timestamp": timestamp
        }

        # Print report to console
        print("--- OSINT Threat Report ---\n")
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

    except FileNotFoundError:
        logging.error(f"Error: {INPUT_FILE} not found.")
        print("Error: Input file not found.")
    except Exception as e:
        logging.error(f"Unexpected error in analyze_indicators: {e}")
        print("Error: Unexpected issue occurred.")

# Execute the script
if __name__ == "__main__":
    analyze_indicators()
