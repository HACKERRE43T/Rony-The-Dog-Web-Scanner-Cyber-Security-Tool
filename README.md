Rony The Dog - Educational Cybersecurity Tool
Developed by Arjun P A
 
⚠️ IMPORTANT: Ethical Use Only
Rony The Dog is designed exclusively for educational purposes. It must only be used on systems or networks where you have explicit written permission to test. Unauthorized use of this tool is illegal and unethical, potentially violating laws such as the U.S. Computer Fraud and Abuse Act (CFAA) or EU GDPR. Always obtain consent and test in controlled environments (e.g., Metasploitable, DVWA). If vulnerabilities are discovered during authorized testing, follow responsible disclosure practices.
Overview
Rony The Dog is a powerful Python-based cybersecurity tool for Kali Linux, crafted to help students, educators, and cybersecurity enthusiasts learn ethical hacking and penetration testing. It offers a suite of features for analyzing network and web security, including advanced website scanning, multi-threaded IP scanning, remote SSH connections, and brute-forcing login pages. The tool emphasizes usability, detailed reporting, and ethical conduct, with comprehensive logging and HTML reports for educational analysis.
Key Features

Advanced Website Scanning: Crawls websites, analyzes headers, detects outdated software, and identifies potential vulnerabilities (e.g., XSS-prone inputs).
Multi-Threaded IP Scanning: Performs high-speed port scanning with service version and OS detection using nmap.
Remote SSH Connection: Supports command execution and file uploads via SSH/SFTP with robust error handling.
Multi-Threaded Brute-Forcing: Conducts parallelized login attacks with proxy support and adaptive rate-limiting.
Comprehensive Reporting: Generates styled HTML reports and detailed logs for all operations.

Installation
Prerequisites

Operating System: Kali Linux (latest version recommended).
Internet Connection: Required for downloading packages and dependencies.
Root Privileges: Installation requires sudo access.

Dependencies

System Packages: nmap, python3, python3-pip.
Python Libraries: python-nmap, requests, paramiko, beautifulsoup4, fake-useragent.

Installation Steps

Clone the Repository:
git clone https://github.com/<your-username>/rony-the-dog.git
cd rony-the-dog


Run the Installation Script:

The provided install_rony_the_dog.sh script automates dependency installation and setup.
Set execute permissions and run the script:chmod +x install_rony_the_dog.sh
sudo ./install_rony_the_dog.sh


The script will:
Update package lists.
Install nmap, python3, and python3-pip.
Install Python dependencies.
Create the /opt/rony_the_dog directory.
Copy the rony_the_dog.py script and a sample passwords.txt file.
Set up a symbolic link for the command rony_the_dog.




Verify Installation:

Ensure the tool is accessible by running:rony_the_dog --help


Check for the sample password file at /opt/rony_the_dog/passwords.txt.



Manual Installation (Alternative)
If you prefer manual setup:

Install system dependencies:sudo apt-get update
sudo apt-get install -y nmap python3 python3-pip


Install Python dependencies:pip3 install python-nmap requests paramiko beautifulsoup4 fake-useragent


Copy rony_the_dog.py to a directory (e.g., /opt/rony_the_dog):sudo mkdir -p /opt/rony_the_dog
sudo cp rony_the_dog.py /opt/rony_the_dog/
sudo chmod +x /opt/rony_the_dog/rony_the_dog.py


Create a sample password file:echo -e "admin\npassword123\ntest123\n123456\nqwerty" | sudo tee /opt/rony_the_dog/passwords.txt


Create a symbolic link:sudo ln -sf /opt/rony_the_dog/rony_the_dog.py /usr/local/bin/rony_the_dog



User Manual
Running the Tool
Run Rony The Dog using either command:
rony_the_dog

or
python3 /opt/rony_the_dog/rony_the_dog.py

Menu Options
Upon launching, the tool presents a command-line menu:

Scan Website (Advanced): Scans a website for vulnerabilities, crawls linked pages, and checks headers/software.
Scan IP Address (Multi-threaded): Scans an IP/hostname for open ports, services, and OS details.
Remote SSH Connection (Command/File Upload): Connects to a remote host via SSH, executes commands, or uploads files.
Brute-Force Login (Multi-threaded): Attempts to brute-force a login page with a password list.
Exit: Terminates the program.

Usage Examples
Scenario: Testing a Metasploitable VM (IP: 192.168.1.100) with a vulnerable web app and SSH service.

Website Scan:

Select option 1.
Enter URL: http://192.168.1.100.
Set crawl depth: 1.
Output: HTML report (/opt/rony_the_dog/rony_the_dog_report.html) with headers, forms, and vulnerability details.


IP Scan:

Select option 2.
Enter IP: 192.168.1.100.
Set port range: 1-1024.
Output: Report listing open ports (e.g., 22/SSH, 80/HTTP), services, and OS (Linux).


SSH Connection:

Select option 3.
Enter host: 192.168.1.100, username: msfadmin, password: msfadmin, port: 22.
Enter command: whoami (optional).
Enter file: /opt/rony_the_dog/test.txt (optional).
Output: Report confirming connection, command output, and file upload.


Brute-Force Login:

Select option 4.
Enter URL: http://192.168.1.100/dvwa/login.php.
Enter username: admin.
Enter password file: /opt/rony_the_dog/passwords.txt.
Set threads: 5.
Enter proxy: (leave blank or e.g., http://proxy:8080).
Output: Report with brute-force results (success or failure).



Output Files

Logs: Stored in /opt/rony_the_dog/rony_the_dog.log for detailed operation records.
Reports: HTML reports at /opt/rony_the_dog/rony_the_dog_report.html. Open in a browser (e.g., firefox /opt/rony_the_dog/rony_the_dog_report.html) for styled results.
Password File: Sample at /opt/rony_the_dog/passwords.txt. Edit or replace with custom passwords.

Customizing the Password File
The sample passwords.txt contains basic entries:
admin
password123
test123
123456
qwerty

To use a custom password list:

Edit /opt/rony_the_dog/passwords.txt or create a new file.
Ensure one password per line.
Specify the file path during brute-force operations.

Ethical Guidelines

Permission is Critical: Only test systems you own or have explicit written permission to scan. Unauthorized use is illegal and can lead to severe legal consequences.
Controlled Environments: Use lab setups like Metasploitable, Damn Vulnerable Web Application (DVWA), or other authorized testbeds.
Responsible Disclosure: If vulnerabilities are found during authorized testing, report them to system owners following ethical disclosure practices.
Data Privacy: Do not collect or store sensitive data during testing without consent.

Troubleshooting

Installation Fails: Ensure internet connectivity and re-run install_rony_the_dog.sh. Check error messages for missing packages.
Permission Errors: Run commands with sudo if access is denied.
Dependency Issues: Verify Python packages with pip3 list. Re-install missing ones using pip3 install <package>.
Tool Fails to Run: Check /opt/rony_the_dog/rony_the_dog.log for errors. Ensure rony_the_dog.py is executable (chmod +x).
Brute-Force Issues: Verify the login page URL and password file path. Ensure the target form is compatible (e.g., no CAPTCHA).

Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a feature branch (git checkout -b feature/YourFeature).
Commit changes (git commit -m 'Add YourFeature').
Push to the branch (git push origin feature/YourFeature).
Open a Pull Request.

Please ensure contributions align with the tool’s educational purpose and ethical guidelines.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Contact
For questions, suggestions, or issues, please open an issue on GitHub or contact the developer at <your-email> (replace with your actual email).
Acknowledgments

Built with Python and libraries: python-nmap, requests, paramiko, beautifulsoup4, fake-useragent.
Inspired by educational tools for ethical hacking and penetration testing.
Thanks to the Kali Linux community for providing a robust platform for cybersecurity learning.


Stay Ethical, Learn Responsibly, and Have Fun with Rony The Dog!
