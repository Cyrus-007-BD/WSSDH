import os
import sys
import platform
import threading
import dns.resolver # type: ignore
import requests
from bs4 import BeautifulSoup # type: ignore
import re
from queue import Queue
from colorama import init, Fore

# Initialize colorama for colored output
init(autoreset=True)

# Global set to store unique subdomains
subdomains = set()

# Mutex lock for thread safety
lock = threading.Lock()

# User-Agent for HTTP requests
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
}

def fetch_crtsh(domain):
    """Fetch subdomains from crt.sh"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    if sub.endswith(domain):
                        with lock:
                            subdomains.add(sub.strip())
            print(Fore.GREEN + "[+] Fetched from crt.sh")
        else:
            print(Fore.RED + f"[-] crt.sh request failed with status code {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[-] Error fetching crt.sh: {e}")

def fetch_bing(domain):
    """Fetch subdomains from Bing search results"""
    url = f"https://www.bing.com/search?q=site%3A*.{domain}"
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                match = re.search(r"https?://([a-zA-Z0-9.-]+\." + re.escape(domain) + ")", href)
                if match:
                    with lock:
                        subdomains.add(match.group(1))
            print(Fore.GREEN + "[+] Fetched from Bing")
        else:
            print(Fore.RED + f"[-] Bing request failed with status code {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[-] Error fetching Bing: {e}")

def fetch_duckduckgo(domain):
    """Fetch subdomains from DuckDuckGo search results"""
    url = f"https://duckduckgo.com/html/?q=site%3A*.{domain}"
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            for result in soup.find_all("a", href=True):
                href = result["href"]
                match = re.search(r"https?://([a-zA-Z0-9.-]+\." + re.escape(domain) + ")", href)
                if match:
                    with lock:
                        subdomains.add(match.group(1))
            print(Fore.GREEN + "[+] Fetched from DuckDuckGo")
        else:
            print(Fore.RED + f"[-] DuckDuckGo request failed with status code {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[-] Error fetching DuckDuckGo: {e}")

def fetch_wordlist_subdomains(domain, wordlist_file="subdomains.txt"):
    """Fetch subdomains from a local wordlist using DNS resolution"""
    if not os.path.isfile(wordlist_file):
        print(Fore.RED + f"[!] Wordlist file '{wordlist_file}' not found.")
        return

    try:
        with open(wordlist_file, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error reading the wordlist file: {e}")
        return

    print(Fore.CYAN + "[INFO] Enumerating subdomains using DNS resolution...")

    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            for answer in answers:
                with lock:
                    subdomains.add(subdomain)
                print(Fore.GREEN + f"[+] Found: {subdomain} -> {answer}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.resolver.LifetimeTimeout:
            print(Fore.RED + f"[!] Timeout querying {subdomain}")
        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")
            sys.exit(0)

def enumerate_subdomains(domain):
    """Main function to enumerate subdomains using multiple sources"""
    print(Fore.CYAN + f"[INFO] Enumerating subdomains for: {domain}")

    # List of enumeration functions
    sources = [fetch_crtsh, fetch_bing, fetch_duckduckgo]

    # Create threads for each source
    threads = []
    for source in sources:
        thread = threading.Thread(target=source, args=(domain,))
        threads.append(thread)
        thread.start()

    # Start DNS-based subdomain enumeration
    fetch_wordlist_subdomains(domain)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Display unique subdomains
    if subdomains:
        print(Fore.YELLOW + "\n[RESULT] Found subdomains:")
        for sub in sorted(subdomains):
            print(Fore.RED + sub)
    else:
        print(Fore.RED + "[!] No subdomains found.")

def print_banner():
    banner = ("""
               _____        _____          _         _       
\ \      / /      |   \ /\   / ____|        | |       | |      
 \ \ /\ / /  ___| |  | /  \ | |      _ _ | |_ ___  | |    
  \ V  V / _ \/ _ \ |  | | /\ \| |    / _` | '| / _ \ | '_ \   
   \ /\ /  /  / || |/  \ | |___| (_| | |  | ||  / | | | |  
    \/  \/ \___|\___|_____//_/ \_\\_____\,_|_|   \__\___| |_| |_|  
                                                                     
     WSSDH - Web Subdomain Search and Discovery Helper
     Discover subdomains quickly and efficiently!
     Author: Cyrus_007
""")
    print(Fore.RED + banner)

def clear_terminal():
    # Clear the terminal based on the platform
    system = platform.system().lower()
    if system == "windows":
        os.system('cls')
    else:
        os.system('clear')

if __name__ == "__main__":
    import argparse

    clear_terminal()
    print_banner()

    parser = argparse.ArgumentParser(
        description="Author - Cyrus_007\nA subdomain enumeration tool without API keys.",
        epilog="Example usage:\n  python3 WSSDH.py example.com",
        usage="python3 WSSDH.py [domain]",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "domain",
        help="The target domain to enumerate subdomains for (e.g., example.com)."
    )

    args = parser.parse_args()
    enumerate_subdomains(args.domain)
