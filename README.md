# Web Subdomain Admin Search and Discovery Helper

Web Attack is a powerful tool designed for web penetration testing and security analysis. It allows users to conduct subdomain and Admin page discovery to help improve the security posture of websites and web applications.

## Features

- Subdomain Discovery: Discover subdomains of a given domain to map out potential attack vectors.
- Admin Path Discovery: Scans for common admin paths and reports any accessible ones.
- Clean Terminal Output: Clear the terminal screen automatically on startup for better readability.
- Cross-platform: Works on Windows, Linux, and macOS.

## Installation

### Requirements
- Python 3.x
- Pip (Python package installer)

### Steps

1. Install the necessary libraries:
   ```bash
   $ pip install requests beautifulsoup4 colorama
   ```
2. Clone the repository:
   ```bash
   $ git clone https://github.com/Cyrus-007-BD/WSSDH.git
   ```
3. Go to WSSDH directory:
   ```bash
   $ cd WSSDH
   ```
4. Run the program:
   ```bash
   $ python3 WSSDH.py [Domain]
   ```
