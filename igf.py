#!/usr/bin/python3

from colorama import Fore, Back, Style
from urllib.request import urlopen
from fake_useragent import UserAgent
import socket, time, os, dns.resolver, sys, urllib, urllib.request
import requests, io, sys
import ipaddress
import whois
import http.client
import ftplib
import ssl
import re
import json

#####################################################################
#                                                                   #
# IGF - Information Gathering Framework v1.2 by c0deninja           #
#                                                                   #
# pip3 install -r requirements.txt                                  #
#                                                                   # 
#####################################################################

banner = """


 ██▓     ▄████      █████▒
▓██▒    ██▒ ▀█▒   ▓██   ▒ 
▒██▒   ▒██░▄▄▄░   ▒████ ░ 
░██░   ░▓█  ██▓   ░▓█▒  ░ 
░██░   ░▒▓███▀▒   ░▒█░    
░▓      ░▒   ▒     ▒ ░    
 ▒ ░     ░   ░     ░      
 ▒ ░   ░ ░   ░     ░ ░   v1.2
 ░           ░                                        

"""

def geolocation():
    # IP Geolocation by Sir809 (gotr00t? member)
    ip = input("IP:> ")
    print('\n')
    url = ("https://ipinfo.io/{}/json".format(ip))
    v =  urllib.request.urlopen(url)
    j = json.loads(v.read())

    for dato in j:
        print(dato + ": " +j[dato])

def reversednslookup():
	ip = input("Enter IP: ")
	print("\n")
	try:
		reversedns = socket.gethostbyaddr(str(ip))
		print(reversedns[0])
	except socket.error:
		print (Fore.RED + "Error")

def wordpresscheck():
	wp = ['wordpress', 'wp-content', 'wp-login', 'wp-login.php', 'wp-admin', 'wp', 'wp-config',
	'wp-config.php', 'wp-mail.php', 'wp-load.php', 'wp-settings.php', 'wp-includes', 'wp-activate.php',
	'wp-cron.php', 'wp-signup.php', 'wp-config-sample.php']

	site = input("Enter website: ")
	print ("\n")
	
	for wpress in wp:
		wpress = wpress.strip()
		wplinks = site + "/" + wpress
		response = requests.get(wplinks)
		if response.status_code == 200:
			print (Fore.GREEN + "Wordpress directory has been found! {}".format(wplinks))
		elif response.status_code == 429:
			print (Fore.RED + "Too many requests")
			webinfo()
		elif response.status_code == 400:
			print (Fore.RED + "Bad Request")
			webinfo()
		elif response.status_code == 403:
			print (Fore.RED + "Forbidden")
			webinfo()
		elif response.status_code == 500:
			print (Fore.RED + "Internal server error")	
			webinfo()

def cloudflarebypass():
	domains = ['mail', 'ftp', 'mail', 'cpanel']
	try:
		site = input("Enter Website: ")
		print ("\n")
		try:
			ip = socket.gethostbyname(str(site))
		except socket.error:
			pass
		for subdomain in domains:
			subdomains = subdomain.strip()
			subsite = subdomains + site
			try:
				subip = socket.gethostbyname(subsite)
				if subip is not ip:
					print (Fore.GREEN + "Cloudflare has been bypassed!")
					print (Fore.GREEN + "The real IP is {}".format(subip))
					time.sleep(1)
					webinfo()
				else:
					print ("Could not retrieve the real IP.")
			except socket.error:
				pass
	except requests.exceptions.MissingSchema:
		print ("Please use: caca.com")

def adminpanelfind():
	adminlist = ['admin', 'cpanel', 'phpmyadmin', 'login', 'login.php', 'wp-admin', 'cp', 'master', 'adm', 'member', 'control', 'webmaster', 
'myadmin', 'admin_cp', 'admin_site', 'administratorlogin/', 'adm/', 'admin/account.php', 'admin/index.php', 'admin/login.php', 'admin/admin.php',
'admin/account.php', 'admin_area/admin.php', 'admin_area/login.php', 'siteadmin/login.php', 'siteadmin/index.php', 'siteadmin/login.html',
'admin/account.html', 'admin/index.html', 'admin/login.html', 'admin/admin.html']
	try:
		site = input("Enter Website: ")
		print ("\n")
		ua = UserAgent()
		header = {'User-Agent':str(ua.chrome)}
		for admin in adminlist:
			admin = admin.strip()
			link = site + "/" + admin
			response = requests.get(link, headers=header)
			if response.status_code == 200:
				print ("Found {}".format(link))
			elif response.status_code == 400:
				print("{} Not Found".format(link))
			elif response.status_code == 429:
				print ("Too many requests")
			elif response.status_code == 400:
				print ("Bad Request")
			elif response.status_code == 403:
				print ("Forbidden")
			elif response.status_code == 500:
				print ("Internal server error")	
	except requests.exceptions.MissingSchema:
		print (Fore.RED + "Please use http:// or https://")

def smtpenum():
	wordlist = input("Wordlist: ")
	host = input("Host: ")
	port = input("Port: ")
	
	f = open(wordlist, 'rb')
	smtplist = f.readlines()
	
	print ("********************")
	print ("Host: " + host)
	print ("Port: " + port)
	print ("Wordlist: " + wordlist)
	print ("Size: " + str(len(wordlist)))
	print ("********************")
	print ("\n")
		
	print ("Verifying Users, Please wait..." + "\n")
		
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, int(port)))	
	except socket.error:
		print ("Could not connect to host")
	except TimeoutError:
		print ("Connection timed out")
		
	try:
		for users in smtplist:
			userlist = users.strip()
			s.sendall(b"VRFY " + userlist + b"\r\n")
			response = s.recv(1024)
			
			if re.match(b"250", response):
				print ("Found User: " + str(userlist))
			elif re.match(b"550", response):
				print ("{} NOT found".format(str(userlist)))
	except ConnectionResetError:
		print ("Connection reset by peer")
	f.close()		
	s.close()

def filedownload():
	site = input("URL of the file: ")
	filename = input("Save file as: ")

	headers={'User-Agent': 'Mozilla/5.0'}
	req = requests.get(site, headers)

	with open(filename, 'wb') as download:
		download.write(req.content)
	
	print ("File {} has been downloaded".format(filename))

def serviceban():
	host = input("IP: ")
	port = input("Port: ")
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, int(port)))
		data = s.recv(1024)
		print (data.strip())
		s.close()
	except socket.error:
		print ("Could not connect to host")

def anonftp():
	host = input("FTP server: ")
	print ("\n")
	try:
		ftp = ftplib.FTP(host)
		ftp.login('anonymous', 'anonymous')
		print (str(host) + "\033[0;0m Anonymous FTP logon successful")
		time.sleep(2)
		ftp.quit()
	except Exception as e:
		print (str(host) + Fore.RED + " Anonymous FTP logon failed.")


def subrute():
	host = input("Enter Website: ")
	wordlist = input("Enter Sub Domain list: ")
	ua = UserAgent()
	header = {'User-Agent':str(ua.chrome)}
	try:
		with open(wordlist, 'r') as f:
			sublist = f.readlines()
			sublist = list(map(lambda s: s.rstrip("\n"),sublist))
	except IOError:
		print (Fore.RED + "File not found")
	try:
		for lines in sublist:
			time.sleep(1.5)
			check = requests.get("https://" + lines + "." + host, headers=header).status_code
			if check == 200:
				print (Fore.GREEN + "Found: " + lines + "." + host)
	except requests.exceptions.ConnectionError:
		print (Fore.RED + "Connection Refused by Host")
	except UnboundLocalError:
		pass


def getoptions():
	try:
		host = input("Enter website: ")
		print ("\n")
		conn = http.client.HTTPConnection(host)
		conn.connect()
		conn.request('OPTIONS', '/')
		response = conn.getresponse()
		check = response.getheader('allow')
		print (Fore.GREEN + "[OPTIONS]")
		print (response.getheader('allow'))
		if check is None:
			print ("OPTIONS is not available for listing.")
			conn.close()
	except socket.gaierror:
		print (Fore.RED + "Name or service not known")
		time.sleep(2)
	except http.client.InvalidURL:
		print (Fore.RED + "Please use: site.com or www.site.com")

def gethead():
	try:
		host = input("Enter Website: ")
		print ("\n")
		resp = requests.head(host)
		print (resp.headers)
		time.sleep(2)
	except socket.gaierror:
		print (Fore.RED + "Name or service not known")
	except requests.exceptions.MissingSchema:
		print (Fore.RED + "Please use http or https://site.com")

def whoistool():
	try:
		host = input("Enter website: ")
		w = whois.whois(host)
		print (w)
		time.sleep(2)
	except socket.gaierror:
		print (Fore.RED + "Name or service not known")

def getrobot():
	try:
		site = input("Enter Website: ")
		print ("\n")
		getreq = urlopen(site + "/" + "robots.txt", data=None)
		data = io.TextIOWrapper(getreq, encoding='utf-8')
		print (Fore.GREEN + data.read())
		time.sleep(2)
	except socket.gaierror:
		print (Fore.RED + "Name or service not known")
	except urllib.error.URLError:
		print (Fore.RED + "Name or service not known")
	except ValueError:
		print(Fore.RED + "Unknown URL type, please use: http://site.com")


def ipaddressresolv():
	try:
		print ("EX: site.com")
		host = input("Website: ") #Ex: use site.com format
		print ("\n")
		print (Fore.GREEN + "IPv4 Address: " + socket.gethostbyname(host))
	except socket.gaierror:
		print (Fore.RED + "Name or service not known")
	time.sleep(2)

def ipv4tov6():
	try:
		ip = input("Enter IP Address: ")
		print ("\n")
		print (Fore.GREEN + ipaddress.IPv6Address('2002::' + ip).compressed)
		time.sleep(2)
	except ipaddress.AddressValueError:
		print (Fore.RED + "IP address not permitted sorry")


def grabthebanner():
	try:
		host = input("Enter Host: ")
		port = int(input("Enter Port: "))
		sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sck.connect((host, port))
		print ("STATUS: " + "host is up!" + "\n")
		print ("Grabbing the banner please wait!" + "\n")
		time.sleep(3)
		sck.send(b"HEAD / HTTP/1.0\r\n\r\n")
		data = sck.recv(1024)
		sck.close()
		print (data.strip())
		time.sleep(2)
	except socket.error:
		print (Fore.RED + "Host is not reachable")
	except ValueError:
		pass

def grabthebannerssl():
	host = input("Enter Host: ")
	port = int(input("Enter Port: "))
	try:
		sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		ssock = ssl.wrap_socket(sck)
		ssock.connect((host, port))
		print ("STATUS: " + "host is up!" + "\n")
		print ("Grabbing the banner please wait!" + "\n")
		time.sleep(3)
		ssock.send(b"HEAD / HTTP/1.0\r\n\r\n")
		data = ssock.recv(1024)
		ssock.close()
		print (data.strip())
		time.sleep(2)
	except socket.error:
		print (Fore.RED + "Host is not reachable")

def dirbrute():
	host = input("Enter Website: ")
	wordlist = input("Enter Wordlist: ")
	try:
		file = open(wordlist, 'r')
		print (Fore.GREEN + "Found: " + wordlist)
		file.close()
	except IOError:
		print (Fore.RED + "Couldn't find " + wordlist)
		pass
	
	ua = UserAgent()
	header = {'User-Agent':str(ua.chrome)}

	with open(wordlist, 'r') as f:
		dirblist = f.readlines()
	try:
		for lines in dirblist:
			dirlines = lines.strip()
			links = host + dirlines
			response = requests.get(links, headers=header)
			if response.status_code == 200:
				print ("Found: {}".format(links))
			elif response.status_code == 429:
				print (Fore.RED + "Too many requests")
				webinfo()
			elif response.status_code == 400:
				print (Fore.RED + "Bad Request")
				webinfo()
			elif response.status_code == 403:
				print (Fore.RED + "Forbidden")
				webinfo()
			elif response.status_code == 500:
				print (Fore.RED + "Internal server error")	
				webinfo()
			else: 
				print ("Not Found: {}".format(links))

	except requests.exceptions.MissingSchema:
		print (Fore.RED + "Please use: http or https://www.site.com/")
	except socket.gaierror:
		print (Fore.RED + "Name or service not known")

def dnslookup():
	try:
		host = input("Enter Host: ")
		print ("\n")
		info = dns.resolver.query(host, 'MX')
		for rdata in info:
			print (Fore.GREEN + "Host ", rdata.exchange, 'has preference', rdata.preference)
			time.sleep(2)
	except dns.resolver.NoAnswer:
		print (Fore.RED + "Please use: site.com")
	except dns.resolver.NXDOMAIN:
		print (Fore.RED + "Please use: site.com")

def portscanner():
	ip = input("Enter IP to scan: ")
	print ("\n")
	print ("Scanning IP: " + ip + " please wait..." + "\n")
	try:
		for port in range(1, 6000):
			sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			data = sck.connect_ex((ip, port))
			if data == 0:
				print (Fore.GREEN + "Port: " + str(port) + " " + "open")
			sck.close()
	except socket.error:
		print (Fore.RED + "Could not connect to host")
	except KeyboardInterrupt:
		print ("You pressed CTRL+C")
	except ipaddress.AddressValueError:
		print ("IP address not allowed")


def webinfo():
	while True:
		print (Fore.RED + banner)
		print ("\033[0;0m[+] Web Information" + "\n")

		print (Fore.WHITE + "[1]  Banner Grabber" +       "[A] Find Admin Panel".rjust(35))
		print (Fore.WHITE + "[2]  Directory brute" +      "[B] Cloudflare bypass".rjust(35))
		print (Fore.WHITE + "[3]  Sub domain brute" +     "[C] Wordpress Dir Finder".rjust(37))
		print (Fore.WHITE + "[4]  Convert domain to IP" + "[D] Reverse DNS lookup".rjust(31))
		print (Fore.WHITE + "[5]  Get robots.txt")
		print (Fore.WHITE + "[6]  Whois lookup tool")
		print (Fore.WHITE + "[7]  HTTP HEAD request")
		print (Fore.WHITE + "[8]  HTTP OPTIONS")
		print (Fore.WHITE + "[9]  DNS lookup")
		print (    "\033[0;0m<--  Back")


		print ("\n")

		prompt = input(Fore.WHITE + "IGF~# ")
		if "1" in prompt:
			ask = input("HTTP or HTTPS? ")
			if "HTTPS" in ask:
				grabthebannerssl()
			else:
				grabthebanner()
		if "2" in prompt:
			dirbrute()
		if "3" in prompt:
			subrute()
		if "4" in prompt:
			ipaddressresolv()
		if "5" in prompt:
			getrobot()
		if "6" in prompt:
			whoistool()
		if "7" in prompt:
			gethead()
		if "8" in prompt:
			getoptions()
		if "9" in prompt:
			dnslookup()
		if "A" in prompt:
			adminpanelfind()
		if "B" in prompt:
			cloudflarebypass()
		if "C" in prompt:
			wordpresscheck()
		if "D" in prompt:
			reversednslookup()
		if "back" in prompt:
			start()
		if "exit" in prompt:
			exit()

def start():
	while True:
		print (Fore.RED + banner)
		print (Fore.RED + "\033[0;0mCoded by :  c0deninja".rjust(30, "="))
		print (Fore.RED + "\033[0;0mDiscord  :  gotr00t?".rjust(29, "=") + "\n\n")

		print (Fore.WHITE + "[1]  Website Information")
		print (Fore.WHITE + "[2]  Port Scanner")
		print (Fore.WHITE + "[3]  SMTP Enumeration")
		print (Fore.WHITE + "[4]  Anon FTP")
		print (Fore.WHITE + "[5]  Service Banner")
		print (Fore.WHITE + "[6]  Download a file")
		print (Fore.WHITE + "[7]  IPv4 to IPv6")
		print (Fore.WHITE + "[8]  IP Geolocation")
		print (Fore.RED +   "[X]  Exit")

		print ("\n")
		prompt = input(Fore.WHITE + "IGF~#: ")
		if "1" in prompt:
			webinfo()
		if "2" in prompt:
			portscanner()
		if "3" in prompt:
			smtpenum()
		if "4" in prompt:
			anonftp()
		if "5" in prompt:
			serviceban()
		if "6" in prompt:
			filedownload()
		if "7" in prompt:
			ipv4tov6()
		if "8" in prompt:
			geolocation()
		if "exit" in prompt:
			sys.exit(0)

if __name__ == "__main__":
	start()
