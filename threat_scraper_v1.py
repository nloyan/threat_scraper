# imports IOCs from Threatfox, URLScan.io, and PhishStats.info for processing in xxxxxx, by Nur Loyan

import requests
import sys

# API URLs
ps_url = "https://phishstats.info:2096/api/phishing?_where=(score,gt,5)&_size=100&page_4&_sort=-date"
tf_url = "https://threatfox.abuse.ch/export/json/urls/recent/"
us_url = "https://urlscan.io/api/v1/search/?q=(task.source:certstream-suspicious)(domain)"
ph_url = "https://api.phishunt.io/suspicious/today/feed_json"
pd_url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-TODAY.txt"

# API key
api_key_headers_us = {'API-Key': ''}
api_key_headers_ph = {'x-api-key': '[]'}

# PhishStats json
ps_response = requests.get(ps_url)
ps_list = ps_response.json()

# Threatfox json
tf_response = requests.get(tf_url)
tf_data = tf_response.json()

# URLScan.io json
us_response = requests.get(us_url, headers=api_key_headers_us)
us_data = us_response.json()


# Extracts URLs from Phishstats
def ps_cleaner():
    for data in ps_list:
        ps_final = data['host']
        ps_final_clean = ps_final.replace("www.", "")
        print(ps_final_clean)


# Extracts URLs from Threatfox
def tf_cleaner():
    for lst in tf_data.values():
        for data in lst:
            tf_final = data['ioc_value']
            tf_final1 = tf_final.replace("https://", "")
            tf_final2 = tf_final1.replace("http://", "")
            tf_final3 = tf_final2.replace("www.", "")
            print(tf_final3)


# Extracts URLs from UrlScan.IO

def us_cleaner():
    for url_data in us_data.values():
        for i in url_data:
            us_final = i["task"]
            print(us_final['apexDomain'])


# Extract IOCs from opensource phish database
def pd_cleaner():
    pd_response = requests.get(pd_url)
    pd_urls = pd_response.text
    pd_urls1 = pd_urls.replace("www.", "")
    pd_urls2 = pd_urls1.replace("http://", "")
    pd_urls3 = pd_urls2.replace("https://", "")
    print(pd_urls3)


# Combines all scraper functions together
def threat_scraper():
    pd_cleaner()
    ps_cleaner()
    tf_cleaner()
    us_cleaner()


# Run the Scraper!

threat_scraper()
