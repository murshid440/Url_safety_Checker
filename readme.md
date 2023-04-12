# Web Threat Intelligence Analyzer

The Web Threat Intelligence Analyzer is an all-in-one solution designed to detect potential scams and malicious websites. Developed using Python, this project highlights the ability to employ a range of techniques and tools to ensure safe browsing experiences. The analyzer integrates various security APIs, including Google Safe Browsing, VirusTotal, and IBM X-Force Exchange, to perform in-depth assessments of the URLs. In addition to these comprehensive checks, it also examines whether the domain is recently registered and scrutinizes the website content for any suspicious keywords. The primary goal of this project is to create a reliable tool that helps users steer clear of prevalent scams and phishing threats, thereby demonstrating the technical aptitude and cybersecurity expertise required for effective threat detection and mitigation.Key accomplishments and technical skills showcased in this project include:

1. Implemented multiple API integrations, including Google Safe Browsing, VirusTotal, and IBM X-Force Exchange, to assess the safety of a given URL.

2. Utilized Python libraries such as Requests, BeautifulSoup, and Whois to extract and analyze website data for potential threats.

3. Developed a custom function to identify suspicious keywords in website content, which may indicate a scam or phishing attempt.

4. Analyzed domain registration data to detect newly registered domains, a potential indicator of phishing attempts or scams.

5. Explored various methods for enhancing the project's capabilities, including machine learning-based phishing detection, SSL certificate verification,      domain reputation assessment, and natural language processing for content analysis.

6. Demonstrated strong proficiency in Python, web scraping, and API integration, as well as an understanding of common cybersecurity threats and detection    methods.

## Prerequisites

Python 3.8

## Installation

1. Clone this repository to your local machine:

```
git clone https://github.com/murshid440/Web-Threat-Intelligence-Analyzer.git
```

2. Navigate to the project directory:


```
cd Web-Threat-Intelligence-Analyzer
```


3. Install the necessary Python packages:

```
pip install -r requirements.txt
```


4. Obtain API Keys

To utilize this script, you'll need API keys for the following services:

Google Safe Browsing
VirusTotal
IBM X-Force Exchange

Create an account for this services and obtain API keys.
Replace the placeholders in the main() function with your corresponding API keys:

```
google_safe_browsing_api_key = "<YOUR_API_KEY_HERE>"
virustotal_api_key = "<YOUR_API_KEY_HERE>"
ibm_xforce_api_key = "<YOUR_API_KEY_HERE>"
ibm_xforce_api_password = "<YOUR_API_PASSWORD_HERE>"
```

5. Usage

Execute the script with the following command:

```
python main.py
```

When prompted, input the URL you wish to analyze. The script will  assess the URL using various security APIs, determine if the domain is new, and examine the web page for suspicious keywords. Based on these evaluations, the script will provide a verdict on the safety of the URL.

## Future scope

The URL Safety Checker has the potential for further development and improvements. The following ideas are potential avenues for enhancing the project and increasing its capabilities:

1. Machine Learning-based Phishing Detection: Implement a machine learning model trained to recognize phishing websites using features like URL structure, page content, or hosting information. This would add a layer of intelligence to the detection process and potentially increase accuracy.

2. SSL Certificate Verification: Integrate SSL certificate checks to ensure that a website uses HTTPS and has a valid SSL certificate. This can help identify suspicious websites that lack proper security measures.

3. Blacklist/Whitelist Comparison: Incorporate comparisons with known blacklists or whitelists of malicious or safe websites. Sources like PhishTank, OpenPhish, or Spamhaus can provide valuable information for this purpose.

4. Domain Reputation Assessment: Evaluate the reputation of a domain using services like Web of Trust (WOT), which offers a safety score based on user ratings and reviews. This can help identify websites with poor reputations that might be scams.

5. URL Shortener and Redirection Detection: Detect if a given URL is a shortened URL or redirects to another page, and analyze the destination URL for safety. This can help uncover scams that use URL shorteners or redirection services to hide their true destination.

6. Natural Language Processing for Content Analysis: Employ NLP techniques to analyze website content for potential scam indicators. Extracting features such as sentiment, keyword frequency, or other textual patterns can help identify scams that rely on specific language or content.

7. Image-based Analysis: Utilize computer vision techniques to analyze images on a website, searching for specific patterns or content indicative of scams. This can help identify scams that use images to convey their message, bypassing text-based analysis.

By exploring and implementing these potential improvements, the URL Safety Checker can become an even more robust and comprehensive tool for identifying online scams and ensuring a safer browsing experience.
