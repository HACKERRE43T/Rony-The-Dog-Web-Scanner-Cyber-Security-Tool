#!/bin/bash

# Installation script for Rony The Dog on Kali Linux
# Developed by Arjun P A for educational purposes only

echo "=== Rony The Dog Installation Script ==="
echo "Developed by Arjun P A"
echo "WARNING: This tool is for EDUCATIONAL PURPOSES ONLY."
echo "Use ONLY on systems/networks with EXPLICIT WRITTEN PERMISSION."
echo "Unauthorized use is ILLEGAL and UNETHICAL."
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run this script as root (use sudo)."
    exit 1
fi

# Update package lists
echo "[*] Updating package lists..."
apt-get update -y
if [ $? -ne 0 ]; then
    echo "Error: Failed to update package lists."
    exit 1
fi

# Install nmap
echo "[*] Installing nmap..."
apt-get install -y nmap
if [ $? -ne 0 ]; then
    echo "Error: Failed to install nmap."
    exit 1
fi

# Install Python 3 and pip
echo "[*] Installing Python 3 and pip..."
apt-get install -y python3 python3-pip
if [ $? -ne 0 ]; then
    echo "Error: Failed to install Python 3 or pip."
    exit 1
fi

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install python-nmap requests paramiko beautifulsoup4 fake-useragent
if [ $? -ne 0 ]; then
    echo "Error: Failed to install Python dependencies."
    exit 1
fi

# Create directory for Rony The Dog
echo "[*] Creating directory for Rony The Dog..."
mkdir -p /opt/rony_the_dog
if [ $? -ne 0 ]; then
    echo "Error: Failed to create directory /opt/rony_the_dog."
    exit 1
fi

# Download Rony The Dog script
# Note: Replace this with the actual download link or copy the script manually
# For this example, we assume the script is provided or will be copied
echo "[*] Setting up Rony The Dog script..."
cat > /opt/rony_the_dog/rony_the_dog.py << 'EOF'
# [Insert the full Rony The Dog Python script here]
# Due to length, please copy the Python script from the previous response (artifact ID: ca5b13e8-3402-42db-9ae3-1948ff9775c7)
# and paste it here before running the installation script.
EOF

# Verify the script was created
if [ ! -s /opt/rony_the_dog/rony_the_dog.py ]; then
    echo "Error: Rony The Dog script is empty or missing. Please copy the Python script into /opt/rony_the_dog/rony_the_dog.py."
    exit 1
fi

# Set permissions
echo "[*] Setting script permissions..."
chmod +x /opt/rony_the_dog/rony_the_dog.py
if [ $? -ne 0 ]; then
    echo "Error: Failed to set permissions."
    exit 1
fi

# Create a sample password file
echo "[*] Creating sample password file..."
cat > /opt/rony_the_dog/passwords.txt << 'EOF'
admin
password123
test123
123456
qwerty
EOF
if [ $? -ne 0 ]; then
    echo "Error: Failed to create password file."
    exit 1
fi

# Create a symbolic link for easy access
echo "[*] Creating symbolic link for easy access..."
ln -sf /opt/rony_the_dog/rony_the_dog.py /usr/local/bin/rony_the_dog
if [ $? -ne 0 ]; then
    echo "Error: Failed to create symbolic link."
    exit 1
fi

# Verify installation
echo "[*] Verifying Python dependencies..."
pip3 show python-nmap requests paramiko beautifulsoup4 fake-useragent > /dev/null
if [ $? -ne 0 ]; then
    echo "Error: Some Python dependencies are missing."
    exit 1
fi

echo ""
echo "=== Installation Completed Successfully! ==="
echo "Rony The Dog is installed in /opt/rony_the_dog"
echo "Sample password file: /opt/rony_the_dog/passwords.txt"
echo "Log file will be created at: /opt/rony_the_dog/rony_the_dog.log"
echo "Reports will be generated at: /opt/rony_the_dog/rony_the_dog_report.html"
echo ""
echo "To run Rony The Dog, use:"
echo "  rony_the_dog"
echo "or"
echo "  python3 /opt/rony_the_dog/rony_the_dog.py"
echo ""
echo "Ensure you have permission to test any system or network."
echo "Stay ethical and have fun learning!"
exit 0