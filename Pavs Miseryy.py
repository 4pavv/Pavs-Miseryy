import socket
import requests
import hashlib
import os
import sys
import time
import dns.resolver
from ipwhois import IPWhois

BANNER = r'''
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄               ▄  ▄▄▄▄▄▄▄▄▄▄▄       ▄▄       ▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄         ▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌             ▐░▌▐░░░░░░░░░░░▌     ▐░░▌     ▐░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░▌       ▐░▌
▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌ ▐░▌           ▐░▌ ▐░█▀▀▀▀▀▀▀▀▀      ▐░▌░▌   ▐░▐░▌ ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░▌       ▐░▌
▐░▌       ▐░▌▐░▌       ▐░▌  ▐░▌         ▐░▌  ▐░▌               ▐░▌▐░▌ ▐░▌▐░▌     ▐░▌     ▐░▌          ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌   ▐░▌       ▐░▌   ▐░█▄▄▄▄▄▄▄▄▄      ▐░▌ ▐░▐░▌ ▐░▌     ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌    ▐░▌     ▐░▌    ▐░░░░░░░░░░░▌     ▐░▌  ▐░▌  ▐░▌     ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌     ▐░▌   ▐░▌      ▀▀▀▀▀▀▀▀▀█░▌     ▐░▌   ▀   ▐░▌     ▐░▌      ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀  ▀▀▀▀█░█▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ 
▐░▌          ▐░▌       ▐░▌      ▐░▌ ▐░▌                ▐░▌     ▐░▌       ▐░▌     ▐░▌               ▐░▌▐░▌          ▐░▌     ▐░▌       ▐░▌          ▐░▌     
▐░▌          ▐░▌       ▐░▌       ▐░▐░▌        ▄▄▄▄▄▄▄▄▄█░▌     ▐░▌       ▐░▌ ▄▄▄▄█░█▄▄▄▄  ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌      ▐░▌      ▐░▌          ▐░▌     
▐░▌          ▐░▌       ▐░▌        ▐░▌        ▐░░░░░░░░░░░▌     ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌     ▐░▌          ▐░▌     
 ▀            ▀         ▀          ▀          ▀▀▀▀▀▀▀▀▀▀▀       ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀       ▀            ▀  

                    Pav's Miseryy - by @4pav
'''

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def port_scanner():
    target = input("Enter IP or Hostname: ")
    try:
        ip = socket.gethostbyname(target)
        print(f"Scanning {ip}...")
        for port in range(1, 1025):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Port {port} is open")
            s.close()
    except Exception as e:
        print(f"Error: {e}")

def whois_lookup():
    target = input("Enter IP: ")
    try:
        obj = IPWhois(target)
        res = obj.lookup_rdap()
        for k, v in res.items():
            print(f"{k}: {v}")
    except Exception as e:
        print(f"Error: {e}")

def dns_lookup():
    domain = input("Enter domain: ")
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            print('IP:', ipval.to_text())
    except Exception as e:
        print(f"Error: {e}")

def geo_ip():
    ip = input("Enter IP: ")
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        for key, val in res.items():
            print(f"{key}: {val}")
    except Exception as e:
        print(f"Error: {e}")

def hash_cracker():
    hash_input = input("Enter the hash: ")
    algo = input("Enter hash algorithm (md5/sha1/sha256): ").lower()
    wordlist_path = input("Enter path to wordlist: ")

    try:
        with open(wordlist_path, "r", errors="ignore") as file:
            for word in file:
                word = word.strip()
                if algo == "md5":
                    result = hashlib.md5(word.encode()).hexdigest()
                elif algo == "sha1":
                    result = hashlib.sha1(word.encode()).hexdigest()
                elif algo == "sha256":
                    result = hashlib.sha256(word.encode()).hexdigest()
                else:
                    print("Unsupported algorithm.")
                    return

                if result == hash_input:
                    print(f"[+] Hash cracked: {word}")
                    return
        print("[-] No match found.")
    except FileNotFoundError:
        print("Wordlist file not found.")

def admin_panel_finder():
    target = input("Enter target URL (e.g., https://example.com): ")
    paths = ["admin", "admin/login", "adminpanel", "login", "administrator"]
    for path in paths:
        url = f"{target.rstrip('/')}/{path}"
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print(f"[+] Found: {url}")
        except:
            continue

def http_brute_force():
    url = input("Enter URL (Basic Auth protected): ")
    username = input("Enter username: ")
    wordlist = input("Enter path to password wordlist: ")

    try:
        with open(wordlist, 'r', errors="ignore") as f:
            for line in f:
                password = line.strip()
                r = requests.get(url, auth=(username, password))
                if r.status_code == 200:
                    print(f"[+] Password found: {password}")
                    return
        print("[-] Password not found.")
    except FileNotFoundError:
        print("Wordlist not found.")

def osint_user_lookup():
    username = input("Enter username: ")
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
    }

    for platform, url in platforms.items():
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print(f"[+] Found on {platform}: {url}")
            else:
                print(f"[-] Not found on {platform}")
        except:
            print(f"[-] Error checking {platform}")

def main_menu():
    while True:
        clear()
        print(BANNER)
        print("""
1. Port Scanner
2. Whois Lookup
3. DNS Lookup
4. IP Geolocation
5. Hash Cracker
6. Admin Panel Finder
7. HTTP Brute Forcer
8. OSINT Username Lookup
9. Exit
""")
        choice = input("Select an option: ")
        if choice == '1':
            port_scanner()
        elif choice == '2':
            whois_lookup()
        elif choice == '3':
            dns_lookup()
        elif choice == '4':
            geo_ip()
        elif choice == '5':
            hash_cracker()
        elif choice == '6':
            admin_panel_finder()
        elif choice == '7':
            http_brute_force()
        elif choice == '8':
            osint_user_lookup()
        elif choice == '9':
            print("Exiting Pav's Miseryy. Built by @4pav.")
            time.sleep(1)
            sys.exit()
        else:
            print("Invalid option.")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main_menu()
