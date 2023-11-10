import requests
from bs4 import BeautifulSoup
import time

def check_for_phishing(cwe_id):
    """
    Check if the word 'phishing' is present on the page for a given CWE-ID.
    """
    # Base URL
    base_url = "https://cwe.mitre.org/data/definitions/{}.html"
    
    # Send GET request to the CWE URL
    response = requests.get(base_url.format(cwe_id))

    # Check if the request was successful
    if response.status_code != 200:
        print(f"CWE-{cwe_id}: Failed to fetch the page.")
        return False

    # Parse the page using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Check for the word 'phishing'
    return 'phishing' in soup.get_text().lower()

def main():
    # List of CWE-IDs
    cwe_ids = [
        116, 1188, 119, 120, 121, 122, 125, 1284, 129, 131, 134,
        16, 178, 189, 19, 190, 191, 193, 20, 200, 22, 23, 252, 254,
        255, 264, 269, 270, 275, 281, 284, 285, 287, 288, 290, 294,
        295, 306, 310, 312, 326, 330, 345, 347, 352, 36, 361, 362,
        388, 399, 400, 401, 404, 406, 415, 416, 425, 426, 427, 434,
        436, 444, 494, 502, 521, 522, 532, 552, 59, 610, 611, 640,
        664, 665, 667, 668, 669, 681, 693, 697, 703, 704, 706, 73,
        732, 74, 749, 754, 755, 77, 770, 772, 78, 782, 787, 79,
        798, 80, 824, 829, 843, 862, 863, 88, 89, 91, 912, 917, 918,
        94
    ]

    for cwe_id in cwe_ids:
        time.sleep(2)
        if check_for_phishing(cwe_id):
            print(f"CWE-{cwe_id}: 'phishing' found!")
        else:
            print(f"CWE-{cwe_id}: 'phishing' not found.")

if __name__ == "__main__":
    main()

