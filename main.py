import requests
from datetime import datetime
import whois
import tldextract
import re
from bs4 import BeautifulSoup
import requests
from requests.auth import HTTPBasicAuth


def is_url_safe(url, api_key):
    safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + api_key
    payload = {
        "client": {
            "clientId": "your_client_name",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(safe_browsing_url, json=payload)
    result = response.json()

    return "matches" not in result

def is_url_safe_virustotal(url, api_key):
    headers = {
        "x-apikey": api_key
    }
    vt_url = f"https://www.virustotal.com/api/v3/urls"
    response = requests.post(vt_url, headers=headers, data={"url": url})
    json_response = response.json()

    if response.status_code == 200:
        id = json_response['data']['id']
    else:
        print(f"Error submitting URL to VirusTotal: {json_response}")
        return False

    vt_url = f"https://www.virustotal.com/api/v3/urls/{id}"
    response = requests.get(vt_url, headers=headers)
    json_response = response.json()

    if response.status_code == 200:
        malicious_engines = 0
        for scan_result in json_response['data']['attributes']['last_analysis_results'].values():
            if scan_result['result']:
                malicious_engines += 1

        if malicious_engines > 0:
            return False
    else:
        print(f"Error fetching URL analysis from VirusTotal: {json_response}")
        return False

    return True



def is_url_safe_ibm_xforce(url, api_key, api_password):
    headers = {
        "Accept": "application/json"
    }
    xforce_url = f"https://api.xforce.ibmcloud.com/url/{url}"
    response = requests.get(xforce_url, headers=headers, auth=HTTPBasicAuth(api_key, api_password))
    json_response = response.json()

    if response.status_code == 200:
        if 'result' in json_response:
            score = json_response['result']['score']
            if score >= 4.0:  # The threshold can be adjusted according to your requirements
                return False
    else:
        print(f"Error fetching URL analysis from IBM X-Force Exchange: {json_response}")
        return False

    return True




def is_domain_new(url):
    domain = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
    try:
        domain_info = whois.whois(domain)
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date

        if creation_date is None:
            return False

        domain_age = (datetime.now() - creation_date).days
        return domain_age < 30
    except Exception as e:
        print(f"Error: {e}")
        return False



def contains_suspicious_keywords(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Request failed with status code {response.status_code}")
            return False

        soup = BeautifulSoup(response.content, "html.parser")
        text = soup.get_text().lower()

        suspicious_keywords = ["make money", "earn money", "get rich", "lottery", "winner", "jackpot"]
        for keyword in suspicious_keywords:
            if re.search(r'\b{}\b'.format(keyword), text):
                return True
        print("No suspicious keywords found")
        return False
       
    except Exception as e:
        print(f"Error: {e}")
        return False


def main():
    
    url = input("Enter Url you want to check")
    google_safe_browsing_api_key = "<YOUR_API_KEY_HERE>"
    virustotal_api_key = "<YOUR_API_KEY_HERE>"
    ibm_xforce_api_key = "<YOUR_API_KEY_HERE>"
    ibm_xforce_api_password = "<YOUR_API_PASSWORD_HERE>"
              
    if not is_url_safe(url, google_safe_browsing_api_key):
        print(f"The URL {url} is flagged by Google Safe Browsing.")
    elif not is_url_safe_virustotal(url, virustotal_api_key):
        print(f"The URL {url} is flagged by VirusTotal.")
    elif not is_url_safe_ibm_xforce(url, ibm_xforce_api_key, ibm_xforce_api_password):
        print(f"The URL {url} is flagged by IBM X-Force Exchange")
    elif is_domain_new(url):
        print(f"The URL {url} has a new domain, which might indicate a phishing attempt or scam.")
    else:
        if contains_suspicious_keywords(url):
            print(f"The URL {url} contains suspicious keywords, which might indicate a scam.")
        else:
            print(f"The URL {url} appears to be safe.")


if __name__ == "__main__":
    main()
