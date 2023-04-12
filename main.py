import requests
import re
from bs4 import BeautifulSoup

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

def test_contains_suspicious_keywords():
    test_url = input("Enter the URL you want to check: ")
    if contains_suspicious_keywords(test_url):
        print(f"The URL {test_url} contains suspicious keywords.")
    else:
        print(f"The URL {test_url} does not contain suspicious keywords.")

if __name__ == "__main__":
    test_contains_suspicious_keywords()
