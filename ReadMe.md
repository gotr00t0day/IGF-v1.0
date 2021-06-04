# IGF (Information Gathering Framework)

## IGF Gathers information about a target and its environment.

- DNS LOOKUP<br/>
- Subdomai Bruteforcing<br/>
- Bruteforce Directories and Filenames<br/>
- Scan for Ports and Services<br/>
- HTTP requests<br/>
- Whois information<br/>
- Domain to IP converter<br/>
- ReversE DNS lookup<br/>
- Cloudflare bypass<br/>
- Admin Panel Finder<br/>
- Find Wordpress directories<br/>
- Find Shells<br/>
- Find upload location<br/>
- Find Backup files<br/>
- Shodan IP Information<br/>
- IP Geolocation<br/>
- Spider: Extract links<br/>
- Web Technology Discovery<br/>
- Google Dork Search<br/>
- Retrieve Session Cookies<br/>
- DNS, SMB, SMTP & FTP user Enumeration<br/>
- Vulnerability Scanning<br/>
- Windows Exploitation<br/>



<b>More to come in the next release.</b>

# v1.8

![alt text](https://github.com/gotr00t0day/IGF/blob/master/igf3.png)

___________________________________________________________________________________________________________


# INSTALLATION

requires Python 3

git clone https://github.com/gotr00t0day/IGF.git

cd IGF

chmod +x igf.py<br/>
chmod +x main.py

pip3 install -r requirements.txt


# USAGE

./main.py

(Change Domains: config domain.com)

# UPDATES

## IGF V1.8

1. Added: A Config File
   - Now you will be able to change to the domain that you want to pentest.
   - This will work across the entire framework, meaning that all tools will use that specific domain.
2. Added: TorGh0st
3. Added: Dirb
4. Added: FFUF
5. Added: DirSearch
6. Added: Sub0ver
7. Added: RappidDNS
8. Added: Httprobe
9. Added: Nikto

## IGF V1.7

1. Added: Windows Exploitation
   - Exploit Suggester
   - Evil-WinRM
2. Added: Subdomain Playground
   - Subrute
   - CertSpotter
   - CertSh
   - Amass
   - Sublist3r
   - Knockpy
   - Subfinder
3. Added: Vulnerability Scan
   - ShellShock
   - HeartBleed
   - Drupageddon
   - Drupageddon2
   - Apache Struts RCE
   - XSStrike

## IGF V1.6

1. Added: A New Enumeration Section
2. Added: SMB Enumeration 
3. Added: FTP User Enumeration
4. Added: DNS Enumeration
5. Bug Fixes

## IGF v1.5

1. Added: Google Dork Search
2. Added: Phone Number Validation
3. Added: Retrieve Session Cookies
4. Added: Bug Fixes

## IGF v1.4

1. Added: A new theme
2. Added: Web Technology Discovery
3. Added: Extract Links
4. Added: Find backup files
5. Bug Fixes

## IGF V1.3

1. Added: Find Shells (c99, r57 and etc..)
2. Added: Find upload locations
3. Added: Shodan IP Information
4. Added: IP Geolocation
5. Bug Fixes

## IGF V1.2

1. Added: Bypass Cloudflare
2. Added: Find Admin panels
3. Added: Find Wordpress Directories
4. Added: Reverse DNS lookup
5. Bug Fixes

## IGF V1.1

1. Added SSL/TLS support to some scripts
2. Added a file downloader 
3. Added a SMTP Enumeration script
4. Fixed a few bugs.
