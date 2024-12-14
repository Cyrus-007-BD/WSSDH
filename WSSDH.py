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

#List of admin paths to chack
common_admin_paths = [
    "/private.php",
    "/robots.txt",
    "/photoalbum/upload/",
    "/_vti_pvt/",
    ":5800/",
    "/phpMyAdmin/",
    "/config.html/",
    "/private/",
    "/admin1.php",
    "/admin1.html",
    "/admin2.php",
    "/admin2.html",
    "/yonetim.php",
    "/yonetim.html",
    "/yonetici.php",
    "/yonetici.html",
    "/adm/",
    "/admin/",
    "/admin/account.php",
    "/admin/account.html",
    "/admin/index.php",
    "/admin/index.html",
    "/admin/login.php",
    "/admin/login.html",
    "/admin/home.php",
    "/admin/controlpanel.html",
    "/admin/controlpanel.php",
    "/admin.php",
    "/admin.html",
    "/admin/cp.php",
    "/admin/cp.html",
    "/cp.php",
    "/cp.html",
    "/administrator/",
    "/administrator/index.html",
    "/administrator/index.php",
    "/administrator/login.html",
    "/administrator/login.php",
    "/administrator/account.html",
    "/administrator/account.php",
    "/administrator.php",
    "/administrator.html",
    "/login.php",
    "/login.html",
    "/modelsearch/login.php",
    "/moderator.php",
    "/moderator.html",
    "/moderator/login.php",
    "/moderator/login.html",
    "/moderator/admin.php",
    "/moderator/admin.html",
    "/account.php",
    "/account.html",
    "/controlpanel/",
    "/controlpanel.php",
    "/controlpanel.html",
    "/admincontrol.php",
    "/admincontrol.html",
    "/adminpanel.php",
    "/adminpanel.html",
    "/admin1.asp",
    "/admin2.asp",
    "/yonetim.asp",
    "/yonetici.asp",
    "/admin/account.asp",
    "/admin/index.asp",
    "/admin/login.asp",
    "/admin/home.asp",
    "/admin/controlpanel.asp",
    "/admin.asp",
    "/admin/cp.asp",
    "/cp.asp",
    "/administrator/index.asp",
    "/administrator/login.asp",
    "/administrator/account.asp",
    "/administrator.asp",
    "/login.asp",
    "/modelsearch/login.asp",
    "/moderator.asp",
    "/moderator/login.asp",
    "/moderator/admin.asp",
    "/account.asp",
    "/controlpanel.asp",
    "/admincontrol.asp",
    "/adminpanel.asp",
    "/fileadmin/",
    "/fileadmin.php",
    "/fileadmin.asp",
    "/fileadmin.html",
    "/administration/",
    "/administration.php",
    "/administration.html",
    "/sysadmin.php",
    "/sysadmin.html",
    "/phpmyadmin/",
    "/myadmin/",
    "/sysadmin.asp",
    "/sysadmin/",
    "/ur-admin.asp",
    "/ur-admin.php",
    "/ur-admin.html",
    "/ur-admin/",
    "/Server.php",
    "/Server.html",
    "/Server.asp",
    "/Server/",
    "/wp-admin/",
    "/administr8.php",
    "/administr8.html",
    "/administr8/",
    "/administr8.asp",
    "/webadmin/",
    "/webadmin.php",
    "/webadmin.asp",
    "/webadmin.html",
    "/administratie/",
    "/admins/",
    "/admins.php",
    "/admins.asp",
    "/admins.html",
    "/administrivia/",
    "/Database_Administration/",
    "/WebAdmin/",
    "/useradmin/",
    "/sysadmins/",
    "/admin1/",
    "/system-administration/",
    "/administrators/",
    "/pgadmin/",
    "/directadmin/",
    "/staradmin/",
    "/ServerAdministrator/",
    "/SysAdmin/",
    "/administer/",
    "/LiveUser_Admin/",
    "/sys-admin/",
    "/typo3/",
    "/panel/",
    "/cpanel/",
    "/cPanel/",
    "/cpanel_file/",
    "/platz_login/",
    "/rcLogin/",
    "/blogindex/",
    "/formslogin/",
    "/autologin/",
    "/support_login/",
    "/meta_login/",
    "/manuallogin/",
    "/simpleLogin/",
    "/loginflat/",
    "/utility_login/",
    "/showlogin/",
    "/memlogin/",
    "/members/",
    "/login-redirect/",
    "/sub-login/",
    "/wp-login/",
    "/login1/",
    "/dir-login/",
    "/login_db/",
    "/xlogin/",
    "/smblogin/",
    "/customer_login/",
    "/UserLogin/",
    "/login-us/",
    "/acct_login/",
    "/admin_area/",
    "/bigadmin/",
    "/project-admins/",
    "/phppgadmin/",
    "/pureadmin/",
    "/sql-admin/",
    "/radmind/",
    "/openvpnadmin/",
    "/wizmysqladmin/",
    "/vadmind/",
    "/ezsqliteadmin/",
    "/hpwebjetadmin/",
    "/newsadmin/",
    "/adminpro/",
    "/Lotus_Domino_Admin/",
    "/bbadmin/",
    "/vmailadmin/",
    "/Indy_admin/",
    "/ccp14admin/",
    "/irc-macadmin/",
    "/banneradmin/",
    "/sshadmin/",
    "/phpldapadmin/",
    "/macadmin/",
    "/administratoraccounts/",
    "/admin4_account/",
    "/admin4_colon/",
    "/radmind-1/",
    "/Super-Admin/",
    "/AdminTools/",
    "/cmsadmin/",
    "/SysAdmin2/",
    "/globes_admin/",
    "/cadmins/",
    "/phpSQLiteAdmin/",
    "/navSiteAdmin/",
    "/server_admin_small/",
    "/logo_sysadmin/",
    "/server/",
    "/database_administration/",
    "/power_user/",
    "/system_administration/",
    "/ss_vms_admin_sm/",
    "/bb-admin/",
    "/panel-administracion/",
    "/instadmin/",
    "/memberadmin/",
    "/administratorlogin/",
    "/adm.%EXT%",
    "/admin_login.%EXT%",
    "/panel-administracion/login.%EXT%",
    "/pages/admin/admin-login.%EXT%",
    "/pages/admin/",
    "/acceso.%EXT%",
    "/admincp/login.%EXT%",
    "/admincp/",
    "/adminarea/",
    "/admincontrol/",
    "/affiliate.%EXT%",
    "/adm_auth.%EXT%",
    "/memberadmin.%EXT%",
    "/administratorlogin.%EXT%",
    "/modules/admin/",
    "/administrators.%EXT%",
    "/siteadmin/",
    "/siteadmin.%EXT%",
    "/adminsite/",
    "/kpanel/",
    "/vorod/",
    "/vorod.%EXT%",
    "/vorud/",
    "/vorud.%EXT%",
    "/adminpanel/",
    "/PSUser/",
    "/secure/",
    "/webmaster/",
    "/webmaster.%EXT%",
    "/autologin.%EXT%",
    "/userlogin.%EXT%",
    "/admin_area.%EXT%",
    "/cmsadmin.%EXT%",
    "/security/",
    "/usr/",
    "/root/",
    "/secret/",
    "/admin/login.%EXT%",
    "/admin/adminLogin.%EXT%",
    "/moderator.php",
    "/moderator.html",
    "/moderator/login.%EXT%",
    "/moderator/admin.%EXT%",
    "/yonetici.%EXT%",
    "/0admin/",
    "/0manager/",
    "/aadmin/",
    "/cgi-bin/login%EXT%",
    "/login1%EXT%",
    "/login_admin/",
    "/login_admin%EXT%",
    "/login_out/",
    "/login_out%EXT%",
    "/login_user%EXT%",
    "/loginerror/",
    "/loginok/",
    "/loginsave/",
    "/loginsuper/",
    "/loginsuper%EXT%",
    "/login%EXT%",
    "/logout/",
    "/logout%EXT%",
    "/secrets/",
    "/super1/",
    "/super1%EXT%",
    "/super_index%EXT%",
    "/super_login%EXT%",
    "/supermanager%EXT%",
    "/superman%EXT%",
    "/superuser%EXT%",
    "/supervise/",
    "/supervise/Login%EXT%",
    "/super%EXT%",
    "/admin1.php",
    "/admin1.html",
    "/admin2.php",
    "/admin2.html",
    "/yonetim.php",
    "/yonetim.html",
    "/yonetici.php",
    "/yonetici.html",
    "/adm/",
    "/admin/",
    "/admin/account.php",
    "/admin/account.html",
    "/admin/index.php",
    "/admin/index.html",
    "/admin/login.php",
    "/admin/login.html",
    "/admin/home.php",
    "/admin/controlpanel.html",
    "/admin/controlpanel.php",
    "/admin.php",
    "/admin.html",
    "/admin/cp.php",
    "/admin/cp.html",
    "/cp.php",
    "/cp.html",
    "/administrator/",
    "/administrator/index.html",
    "/administrator/index.php",
    "/administrator/login.html",
    "/administrator/login.php",
    "/administrator/account.html",
    "/administrator/account.php",
    "/administrator.php",
    "/administrator.html",
    "/login.php",
    "/login.html",
    "/modelsearch/login.php",
    "/moderator.php",
    "/moderator.html",
    "/moderator/login.php",
    "/moderator/login.html",
    "/moderator/admin.php",
    "/moderator/admin.html"
]

# GitHub repository details for the update feature
GITHUB_REPO_URL = "https://raw.githubusercontent.com/Cyrus-007-BD/WSSDH/blob/main/WSSDH.py"
CURRENT_VERSION = "1.0"

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
                print(Fore.YELLOW + f"[+] Found: " + Fore.RED + f"{subdomain} -> {answer}")
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
            print(Fore.YELLOW + "[+] Found: " + Fore.RED + sub)
    else:
        print(Fore.RED + "[!] No subdomains found.")

# Function to check if admin page exists
def check_admin_page(url, path):
    admin_url = url + path
    try:
        response = requests.get(admin_url, timeout=5)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] Found admin page: {admin_url}")
        elif response.status_code == 403:
            print(Fore.YELLOW + f"[+] Admin page found but access denied: {admin_url}")
        elif response.status_code == 301 or response.status_code == 302:
            print(Fore.CYAN + f"[+] Redirected to admin page: {admin_url}")
        else:
            print(Fore.RED + f"[-] No admin page found at: {admin_url}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[-] Error checking {admin_url}: {e}")

def check_admins_on_domain(domain):
    print(Fore.CYAN + f"\n\n[INFO] Starting admin page search on {domain}")
    # Loop through each common admin path and check if it exists
    for path in common_admin_paths:
        check_admin_page(domain, path)

# Function to ensure the domain starts with http:// or https://
def add_https_www(url):
    # Check if the URL starts with http:// or https://, if not, add https://www
    if not re.match(r'^https?://', url):
        url = 'https://www.' + url
    elif url.startswith('http://') or url.startswith('https://'):
        # If the URL already starts with http or https, ensure 'www' is included
        if 'www.' not in url:
            url = url.replace('http://', 'http://www.').replace('https://', 'https://www.')
    return url

def print_banner():
    banner = ("""
               _____        _____          _         _       
\ \      / /      |   \ /\   / ____|        | |       | |      
 \ \ /\ / /  ___| |  | /  \ | |      _ _ | |_ ___  | |    
  \ V  V / _ \/ _ \ |  | | /\ \| |    / _` | '| / _ \ | '_ \   
   \ /\ /  /  / || |/  \ | |___| (_| | |  | ||  / | | | |  
    \/  \/ \___|\___|_____//_/ \_\\_____\,_|_|   \__\___| |_| |_|  
                                                                     
     WSASDH - Web Subdomain Admin Search and Discovery Helper
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

def check_for_update():
    """Check for updates from the GitHub repository"""
    try:
        print(Fore.CYAN + "[INFO] Checking for updates...")
        response = requests.get(GITHUB_REPO_URL, headers=HEADERS)
        if response.status_code == 200:
            with open(__file__, 'r') as current_file:
                current_content = current_file.read()
            latest_content = response.text
            if latest_content != current_content:
                print(Fore.YELLOW + "[INFO] New update found! Updating...")
                with open(__file__, 'w') as current_file:
                    current_file.write(latest_content)
                print(Fore.GREEN + "[+] Update successful! Please restart the script.")
                sys.exit(0)
            else:
                print(Fore.GREEN + "[INFO] You are using the latest version.")
        else:
            print(Fore.RED + f"[-] Failed to check for updates (status code: {response.status_code})")
    except Exception as e:
        print(Fore.RED + f"[-] Error checking for updates: {e}")

if __name__ == "__main__":
    import argparse

    clear_terminal()
    print_banner()
    check_for_update()

    import argparse

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

    # Ensure the domain starts with http:// or https://
    domain = add_https_www(args.domain)
    
    check_admins_on_domain(domain)
