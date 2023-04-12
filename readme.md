# URL Safety Checker

The URL Safety Checker is a Python script designed to evaluate the safety of a given URL. It incorporates multiple security APIs, such as Google Safe Browsing, VirusTotal, and IBM X-Force Exchange, to assess the URL thoroughly. In addition to these security checks, the script verifies whether the domain is recently registered and scans the web page for any suspicious keywords. Main aim of this project is to build a project to protect from usual scams and phishing attempts. 

## Prerequisites

Python 3.8

## Installation

1. Clone this repository to your local machine:

<pre>
```
git clone https://github.com/murshid440/Url_safety_Checker.git

```
</pre>

2. Navigate to the project directory:

<pre>
```
cd Url_safety_Checker

```
</pre>

3. Install the necessary Python packages:

<pre>
```
pip install -r requirements.txt

```
</pre>


4. Obtain API Keys

To utilize this script, you'll need API keys for the following services:

Google Safe Browsing
VirusTotal
IBM X-Force Exchange

Create an account for this services and obtain API keys.
Replace the placeholders in the main() function with your corresponding API keys:

<pre>
```
google_safe_browsing_api_key = "<YOUR_API_KEY_HERE>"
virustotal_api_key = "<YOUR_API_KEY_HERE>"
ibm_xforce_api_key = "<YOUR_API_KEY_HERE>"
ibm_xforce_api_password = "<YOUR_API_PASSWORD_HERE>"

```
</pre>

5. Usage

Execute the script with the following command:

<pre>
```
python main.py

```
</pre>

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
