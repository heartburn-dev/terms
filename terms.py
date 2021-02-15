import sys
import time
import socket
import os
import subprocess
import time
import re
from art import *
from colorama import Fore, Back, Style
from colorama import init
from urllib3.exceptions import InsecureRequestWarning
from signal import signal, SIGINT
from datetime import datetime



class Terms():

	def __init__(self):

		self.ip = ""
		self.file_storage = ""
		self.working_folder = ""
		self.command_history = "command_history.txt"
		self.host = ""
		self.switches = ""
		self.border = "=" * 50
		self.perms = False

	def title(self):
		title = "T E R M S"
		print("\n")
		header = text2art(title, font='alligator2')
		print(blue + header + white + f"\n[*] {yellow}[T]{white}arget {yellow}[E]{white}numeration, {yellow}[R]{white}econnaissance and {yellow}[M]{white}ethodology {yellow}[S]{white}uggester - by {yellow}inspired v0.0.1")
		print("\n")
		print(red + "[!] You should only use this tool against targets that you have the permission to do so. The creator is not liable for any illegal or immoral usage of this tool.\n")
		self.info()

	def info(self):
		print(yellow + "*" * 35 + "Welcome to TERMS" + "*" * 35)
		print(blue + "[?] Why did I create TERMS?")
		print(white + "[*] So your first nmap scan output doesn't seem so daunting\n")
		print(blue + "[?] Who is TERMS aimed at?")
		print(white + "[*] Any beginner in the cyber security field who wants to improve their methodology and enumeration!\n")
		print(blue + "[?] How do I use TERMS?") 
		print(white + "[*] TERMS is interactive. Just follow the prompts in your terminal!\n")
		print(blue + "[?] What exactly is TERMS going to do?") 
		print(white + "[*] Help you to discover your target IP if you haven't already")
		print(white + "[*] Scan the target for open ports and services")
		print(white + "[*] Create a structured enumeration plan for the target")
		print(white + "[*] Provide resources and links on how to attack found services\n")
		print(blue + "[?] What's the goal of TERMS? Surely I won't learn if it does it all for me?")
		print(white + "[*] Well, I guess the earnest is on you. I can take you to the water, but not force you to drink it.")
		print(white + "[*] TERMS will list all commands used, and the outputs, so you can practice yourself afterward.")
		print(white + "[*] Over time, it would be hoped that you use it as a reference point for work you've done, rather than a starting point.")
		print(yellow + "*" * 36 + "Happy Hacking" + "*" * 36 + "\n")
		while True:
			start = input(yellow + "[?] Shall we get started? Y or N: ")
			if start.lower() == "n":
				print(red + "[!] Oh.. what a shame. Exiting...")
				sys.exit()
			elif start.lower() == "y":
				print(green + "[*] Here we go!")
				print(white + self.border)
				self.setup_env()
				self.target()
				break
			else:
				print(red + "[!] I didn't understand that response..")
		

	def setup_env(self):
		#When starting the script, I will create a directory called TERMS to store all data related to this program.
		#The issue arises when they run it twice, the data will be overwritten. Therefore, I will be creating a directory called terms_<datetime> to 
		#help users distinguish between folders.
		current_time = datetime.now()
		current_time = current_time.strftime("%d-%m-%Y_%H:%M:%S")
		file_storage = "/TERMS_{}/".format(current_time)
		current_folder = os.getcwd()
		#self.file_storage = file_storage
		self.working_folder = current_folder + file_storage
		os.system("mkdir {}".format(self.working_folder))
		self.create_dir("initial_scan")


	def create_dir(self, name):
		name = self.working_folder + name
		if os.path.isdir(name) == True:
			os.system("rm -r {}".format(name))
			os.system("mkdir {}".format(name))
		else:
			os.system("mkdir {}".format(name))


	def target(self):
		while True:
			check = input(yellow + "[?] Do you know the IP address of your target? Y/N: ")
			if check.lower() == "y":
				self.ip = input(yellow + "[*] Please enter a target IP: ")
				try:
					socket.inet_aton(self.ip)
					self.scan_options()
					break
				except socket.error:
					print(red + "Invalid IP entered. IPv4 Only.")
			elif check.lower() == "n":
				print(red + "[!] Please note: Target discovery will not be possible when using TryHackMe's network. The target IP is on the deployment page! This feature works when the target is on your local network.")
				cont = input(yellow + "[?] Would you like to continue? Y/N: ")
				cont = cont.lower()
				while True:
					if cont == 'no' or cont == 'n':
						print(red + "[!] Sorry about that. Grab the target IP and run the tool again.")
						sys.exit()
					break
				print(white + self.border)
				print(green + "[*] Okay - I am going to need to know some details before I can begin target discovery.")
				print(white + self.border)
				while True:
					check_ifconfig = input(yellow + "[*] The command " + white + "ifconfig" + yellow + " brings up your own IP address. Type it in now and it'll run: ")
					if check_ifconfig == 'ifconfig':
						break
					if check_ifconfig != 'ifconfig':
						print(red + "[!] That doesn't look right...")
				ifconfig = subprocess.check_output(['ifconfig'])
				ifconfig = ifconfig.decode("utf8")
				# Take the nmap host discovery output and identify anything that looks like an IP with regex
				identified_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
				hosts = []
				for line in ifconfig.splitlines():
					line = line.split(" ")
					for word in line:
						valid_ip = identified_ip.match(word)
						if valid_ip:
							# Create a list of all the hosts found to use to replace the scan output
							hosts.append(word)

				# Highlight the IPs discovered to help the user identify them
				for address in hosts:
					highlighted = blue + address + reset
					ifconfig = ifconfig.replace(address, highlighted)

				print(reset + ifconfig)
				with open(self.working_folder + self.command_history, "w") as f:
					f.write("Find your IP Address\n - ifconfig\n")
				print(green + "[*] IP Addresses detected! I've highlighted them for you.")		
				self.host = input(yellow + "[*] Locate your IP in the output and enter it here: ")
				print(white + self.border)
				try:
					socket.inet_aton(self.host)
					self.discover_target(self.host)
					
				except socket.error:
					print(socket.error)
					print(red + "[!] Invalid IP entered. IPv4 Only.")
					sys.exit()
			else: 
				print(red + "[!] Invalid response.")

	def discover_target(self, host):
	
		# Nmap -sn switch means a ping scan - just to identify hosts that respond
		find_hosts = "nmap -sn {}/24".format(self.host)
		print(green + "[*] In order to find all the hosts on your network, you would run the command " + white + find_hosts)
		while True:
			run = input(yellow + "[?] Try running it now: ")
			if run == find_hosts:
				break
			else:
				print(red + "[!] Not quite - check the command again!")

		print(white + self.border)
		# Add the network scan command to the command history file
		with open(self.working_folder + self.command_history, "a") as f:
				f.write("\nScan your network for targets:\n - {}\n".format(find_hosts))
		# Subprocess check_output takes arguments as a list, so we need to convert our find_hosts command to a list with .split()
		find_hosts = find_hosts.split(" ")
		host_discovery = subprocess.check_output(find_hosts)
		host_discovery = host_discovery.decode("utf8")
		# Add the host discovery to a file 
		with open("{}initial_scan/host_discovery.txt".format(self.working_folder), "w") as file:
			file.write(host_discovery)
			file.close()
		
		# Take the nmap host discovery output and identify anything that looks like an IP with regex
		identified_host = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
		hosts = []
		for line in host_discovery.splitlines():
			line = line.split(" ")
			for word in line:
				valid = identified_host.match(word)
				if valid:
					# Create a list of all the hosts found to use to replace the scan output
					hosts.append(word)

		# Highlight the IPs discovered to help the user identify them
		for address in hosts:
			highlighted = blue + address + reset
			host_discovery = host_discovery.replace(address, highlighted)

		print(reset + host_discovery)
		

		#time.sleep(5)
		print(white + "[*] You need to identify the target from this list of IP addresses.")
		print(red + "[!] Remember, .1, .2, .254 and .255 are likely to be default gateways and network devices, so it's probably one of the other addresses.")
		#time.sleep(5)
		print(white + self.border)
		while True:
			self.ip = input(yellow + "[?] What is the IP address of the target: ")
			try:
				socket.inet_aton(self.ip)
				self.scan_options()
				break
			except socket.error:
				print(red + "Invalid IP entered. IPv4 Only.")
		
		


	def scan_options(self):
		print(white + self.border)
		print(green + "[*] OK. We're performing an nmap on {}{}{}. Let's take some settings and workout the best type of scan for your target.".format(white, self.ip, green))
		print(white + self.border)
		while True:
			faster = input(yellow + "[?] Would you like to only show open ports? Y/N: ")
			if faster.lower() == 'y':
				print(green + "[*] OK. We will only display open ports!")
				self.switches += '--open '
				break
			elif faster.lower() == 'n':
				print(green + "[*] OK. Some filtered or closed ports may be listed!")
				break
			else:
				print(red + "[!] I didn't quite understand that!")
		print(white + self.border)		
		while True:
			quiet = input(yellow + "[?] Do you need to limit the noise of the scan? This means not being able to grab detailed OS information. Y/N: ")
			if quiet.lower() == 'y':
				print(green + "[*] OK. We will use a stealth scan and turn off OS and service detection!")
				break
			elif quiet.lower() == 'n':
				print(green + "[*] OK. We will be using the aggressive option to fingerprint the target!")
				self.switches += '-A '
				break
			else:
				print(red + "[!] I didn't quite understand that!")
		print(white + self.border)
		while True:
			scan_type = input(yellow + "[?] Do you want to perform a TCP (default) or UDP scan? Choice: ")
			scan_type = scan_type.lower()		
			if scan_type == 'tcp':
				print(green + "[*] Ok, we will be performing a TCP scan!")
				break
			elif scan_type == 'udp':
				print(green + "[*] Ok, we will be performing a UDP scan! This must be run as the root user.")
				self.switches += '-sU '
				self.perms = True
				print(self.perms)
				break
			else:
				print(red + "[!] Sorry, I didn't quite understand that response. TCP or UDP are the only valid answers.")
		print(white + self.border)
		while True:
			print(white + "[*] Nmap scans the top 1000 most common ports by default, but we can customize this to specific ports or instead, all ports.")
			port_range = input(yellow + "[?] 'A' for all ports (May take a while). 'D' for default 1000. 'C' for custom ports. Selection: ")
			if port_range.lower() == 'a':
				print(green + "[*] OK. We will be scanning all ports!")
				self.switches += '-p- '
				break
			elif port_range.lower() == 'c':
				check = re.compile("((\d*,)\d+)|\d{1,5}$")
				port_range = input(yellow + "[?] Enter your target ports, split by a comma (1,2,3,4,5): ")
				regex = check.match(port_range)
				if regex:
					if port_range[-1].isnumeric() and port_range[0].isnumeric():
						print(green + "[*] OK. We will be using the port range: {}".format(port_range))
						self.switches += '-p ' + port_range + ' '
						break
					else:
						print(red + "[!] Those ports seem invalid. Ports must be split by commas and no spaces!")	
				else:
					print(red + "[!] Those ports seem invalid. Ports must be split by commas and no spaces!")
			elif port_range.lower() == 'd':
				print(green + "[*] OK. We will be searching the top 1000 open ports!")
				break
			else:
				print(red + "[!] I didn't quite understand that!")
		print(white + self.border)
		self.scan_target()


	def scan_target(self):
		#If we're doing a udp scan, must be run as root
		if self.perms == True:
			scan_syntax = "sudo nmap {}{}".format(self.switches, self.ip)
		else:
			scan_syntax = "nmap {}{}".format(self.switches, self.ip)
		# Force them to actually type their commands out to improve retention levels
		print(green + "[*] Based on the information you've given, we're going to be performing an nmap scan with the following syntax: {}{}".format(white, scan_syntax))
		while True:
			# Give the user the impression that their command is what is triggering it the scan
			force_understanding = input(yellow + "[*] Let's run it. Type it out yourself: {}".format(white))
			if force_understanding == scan_syntax:
				break
			else:
				print(red + "[!] That's not the command listed above. Check again?")
		print(green + "[*] Running scan, please wait...")
		print(white + self.border)

		# Convert the nmap scan to a list so subprocess.check_output can use it
		scan = scan_syntax.split(" ")
		# Actually run the scan
		nmap = subprocess.check_output(scan)
		nmap = nmap.decode("utf8")
		#Check to see if host is down, if it is, add -Pn and re-scan
		if "Host seems down" in nmap:
			print(red + "[!] It appears the host is either down or blocking ping probes with a firewall. I'm going to add -Pn to try and bypass it...")
			scan.append('-Pn')
			nmap = subprocess.check_output(scan)
			nmap = nmap.decode("utf8")
			print(white + self.border)
			#If it now works it means there was a firewall blocking the pings
			if "open" not in nmap:
				scan_syntax += " -Pn"
				print(green + "[*] The scan has now run. It seems the target was blocking our ping probes. I've amended the command used to {}{}".format(white, scan_syntax))
				print(white + self.border)
			else:
				#If not, it's a damp squib. No connection can be made
				print(white + self.border)
				print(red + "[!] The host does not appear to be contactable! Please check your IP and try again.")
				sys.exit()
		# Creating a record of the scan we run in the command history file but need to 
		# ensure we don't overwrite the target discovery commands if they were run
		if os.path.isfile(self.working_folder + self.command_history):
			with open(self.working_folder + self.command_history, "a") as f:
				f.write("\nInitial Scan Syntax\n - {}\n".format(scan_syntax))
		else:
			with open(self.working_folder + self.command_history, "w") as f:
				f.write("Initial Scan Syntax\n - {}\n".format(scan_syntax))
		with open("{}initial_scan/nmap_scan.txt".format(self.working_folder), "w") as f:
			f.write(nmap)
			f.close()
		#Check to see if there is the message to say all scanned ports are closed
		if "scanned ports on {} are closed".format(self.ip) in nmap:
			print(red + "[!] We didn't detect any open ports! The target may not have any of the specified ports open or may actually just be uncontactable!")
			sys.exit()
		#Regex to highlight anything that looks like (int)/tcp or (int)/udp
		highlight_port = re.compile("\d+\/tcp|\d+\/udp")
		detected_open_ports = []
		for line in nmap.splitlines():
			line = line.split(" ")

			if "open" in line:
				for word in line:
					open_port = highlight_port.match(word)
					if open_port:
						# Create a list of all the ports found to use to replace the scan output
						detected_open_ports.append(word) 
		detected_open_ports.reverse()
		for port in detected_open_ports:
				# green is simply colouring that word green. 
				# reset changes it back to normal after the string in the list finishes
				highlighted = green + port + reset
				nmap = nmap.replace(port, highlighted)
		print(nmap)

		print(white + "[*] I've written a copy of this nmap scan to a new directory called 'initial_scan' so you can have a look after.")
		print(white + f"{yellow}[*] I've also {green}highlighted discovered ports!")
		print(white + self.border)
		print(white + f"{red}[!] Don't get overwhelmed by the output!")
		print(yellow + f"[*] The typical format of a scan is simply {blue}port number,{white} open/closed,{green} service name. {white}\n[*] All other information is just extras that nmap managed to identify which MAY be useful. The key is understanding what's running on the target.")
		print(white + self.border)
		input(yellow + "[?] When you've had a good look and identified the key information, hit enter and we can examinine the ports that were found one by one.")
		print(white + self.border)
		# To stop 80/tcp triggering twice when it seens 8080/tcp
		checked_ports = []
		with open("{}/initial_scan/nmap_scan.txt".format(self.working_folder), "r") as f:
			ports = f.readlines()
			for line in ports:
				line = line.strip()
				for port in detected_open_ports:
					if port in line:
						if port not in checked_ports:
							print(green + "[*] {} is showing as open!".format(line))
							p.port_detect(line)
							print(white + self.border)
							checked_ports.append(port)
		print(red + "[!] Ports showing as open without learning materials suggested? This tool has been developed as a prototype and therefore is currently only offering enumeration resources on the most common/vulnerable ports!")
		print(white + self.border)
		a.analyse_results()


class Ports():
	def __init__(self):
		#Create a list of ports we found
		self.open_ports = []
		#Create a base dictionary for storing the "rating" of each open service
		self.score = {}

	#The ports that will be explained have been decided based on the literature review
	def port_detect(self, port_name):
		port_name = port_name.lower()
		#Go through each port found (as long as it's in our list)
		if "ssh" in port_name and "22" in port_name:
			while True:
				learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in ssh/ssh_attack.txt. Y/N: ")
				learn = learn.lower()
				if learn == 'y' or learn == 'yes':
					print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/ssh.html")
					input(yellow + "[?] Hit enter when you're ready to move on.")
					break
				elif learn == 'n' or learn == 'no':
					break
				else:
					print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.ssh()
		if "http" in port_name and "80/tcp" in port_name and "8080/tcp" not in port_name: 
			while True:
				learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in web_server/http_attack.txt. Y/N: ")
				learn = learn.lower()
				if learn == 'y' or learn == 'yes':
					print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/web_server.html")
					input(yellow + "[?] Hit enter when you're ready to move on.")
					break
				elif learn == 'n' or learn == 'no':
					break
				else:
					print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.http()
		if "https" in port_name and "443" in port_name: 
			while True:
				learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in tls_web_server/https_attack.txt. Y/N: ")
				learn = learn.lower()
				if learn == 'y' or learn == 'yes':
					print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/web_server.html")
					input(yellow + "[?] Hit enter when you're ready to move on.")
					break
				elif learn == 'n' or learn == 'no':
					break
				else:
					print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.http()
		if "ftp" in port_name and "21" in port_name:
			while True:
				learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in ftp/ftp_attack.txt. Y/N: ")
				learn = learn.lower()
				if learn == 'y' or learn == 'yes':
					print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/ftp.html")
					input(yellow + "[?] Hit enter when you're ready to move on.")
					break
				elif learn == 'n' or learn == 'no':
					break
				else:
					print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.ftp()
		if "telnet" in port_name and "23" in port_name:
			while True:
				learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in telnet/telnet_attack.txt. Y/N: ")
				learn = learn.lower()
				if learn == 'y' or learn == 'yes':
					print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/telnet.html")
					input(yellow + "[?] Hit enter when you're ready to move on.")
					break
				elif learn == 'n' or learn == 'no':
					break
				else:
					print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.telnet()
		if "smtp" in port_name and "25" in port_name:
			while True:
				learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in smtp/smtp_attack.txt. Y/N: ")
				learn = learn.lower()
				if learn == 'y' or learn == 'yes':
					print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/smtp.html")
					input(yellow + "[?] Hit enter when you're ready to move on.")
					break
				elif learn == 'n' or learn == 'no':
					break
				else:
					print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.smtp()
		if "pop3" in port_name:
			if "110" in port_name:
				self.open_ports.append(110)
				while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in pop/pop_attack. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/pop3.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			if "995" in port_name:
				self.open_ports.append(995)
				while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in pop/pop_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/pop3.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.pop3()
		if "rpc" in port_name and "111" in port_name:
			while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in rpcbind/rpcbind_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/rpc.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.rpcbind()
		if "msrpc" in port_name and "135" in port_name:
			while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in dcom_rpc/dcom_rpc_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/msrpc.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.dcom()
		if "netbios" in port_name:
			if "137" in port_name:
				self.open_ports.append(137)	
				while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in netbios/netbios_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/netbios.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			if "138" in port_name:
				self.open_ports.append(138)
				while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in netbios/netbios_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/netbios.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			if "139" in port_name:
				self.open_ports.append(139)
				while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in netbios/netbios_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/netbios.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.netbios()
		if "445/tcp" in port_name:
			while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in smb/smb_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/smb.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.smb()
		if "imap" in port_name:
			if "143" in port_name:
				self.open_ports.append(143)
				while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in imap/imap_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/imap.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			if "993" in port_name:
				self.open_ports.append(993)
				while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in imap/imap_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/imap.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.imap()
		if "pptp" in port_name and "1723" in port_name:
			while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in pptp/pptp_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/pptp.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.pptp()
		if "mysql" in port_name and "3306" in port_name:
			while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in mysql/mysql_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/mysql.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.mysql()
		if "ms-wbt-server" in port_name and "3389" in port_name:
			while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in rdp/rdp_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/rdp.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.rdp()
		if "vnc" in port_name:
			if "5800" in port_name:
				self.open_ports.append(5800)
				while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in vnc/vnc_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/vnc.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			# Correcting a slight bug here. Prints duplicates sometimes if 5900 is also listed in the line for the 5800 port, happens on an aggressive scan. Fix works for the most part.
			if "5900" in port_name and "5800" not in port_name:
				self.open_ports.append(5900)
				while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in vnc/vnc_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/vnc.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.vnc()
		if "8080/tcp" in port_name:
			while True:
				learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in alternative_http/alternative_http_attack.txt. Y/N: ")
				learn = learn.lower()
				if learn == 'y' or learn == 'yes':
					print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/web_server.html")
					input(yellow + "[?] Hit enter when you're ready to move on.")
					break
				elif learn == 'n' or learn == 'no':
					break
				else:
					print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.alternative()
		if "snmp" in port_name and "161" in port_name:
			while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in snmp/snmp_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/snmp.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.snmp()
		if "domain" in port_name and "53" in port_name:
			while True:
					learn = input(yellow + "[?] Would you like to learn more about enumerating this service? I will also write some useful information to a file in dns/dns_attack.txt. Y/N: ")
					learn = learn.lower()
					if learn == 'y' or learn == 'yes':
						print(green + f"[*] I've curated some learning materials here: {white}https://learn2enumerate.co.uk/services/dns.html")
						input(yellow + "[?] Hit enter when you're ready to move on.")
						break
					elif learn == 'n' or learn == 'no':
						break
					else:
						print(red + "[!] Sorry, I didn't understand that. Yes or no only.")
			self.dns()


	def ssh(self):
		terms.create_dir("ssh")
		#Add to a record of open ports
		self.open_ports.append(22)
		#Add the score for dictionary
		self.score["SSH"] = 6
		#https://www.hackingloops.com/ssh-for-penetration-testing/
		with open(terms.working_folder + "ssh/ssh_attack.txt", "w") as f:
			f.write("SSH // [S]ecure [SH]ell\n")
			f.write("==================================================\n")
			f.write("SSH provides a secure, encrypted way to login to a remote computer. Due to this, it is commonly targeted for weak credential attacks. Below is a list of commands that can be used to enumerate the SSH service.\n\n")
			f.write("Logging In via SSH\n")
			f.write("==================================================\n")
			f.write("At the most basic level, SSH logins can be performed by using the syntax below and entering the user's password.\n")
			f.write("ssh <USERNAME>@<IP_ADDRESS>\n\n")
			f.write("Versions\n")
			f.write("==================================================\n")
			f.write("Always check if the SSH version is up to date. Old versions may have vulnerabilities. This can be accomplished, in general, with Google, by searching for SSH <version> vulnerabilites. Some outdated versions of SSH, for example, are susceptible to a username enumeration attack. This can be performed with the metasploit module 'ssh_enumusers'.\n\n")
			f.write("Brute Force Attacks and Examples\n")
			f.write("==================================================\n")
			f.write("A common attack against SSH, as mentioned before, is to brute force the login. This can be done in a variety of ways, but Hydra is a common choice due to it's speed and flexibility. Plus, it's built-in to Kali Linux.\n")
			f.write("\nExample 1: Hydra with username and password list\nhydra -L <USERNAME_LIST> -P <PASSWORD_LIST> <IP_ADDRESS> ssh -V\n\n")
			f.write("Example 2: Hydra with a single username and password\nhydra -l <USERNAME> -p <PASSWORD> <IP_ADDRESS> ssh -V\n\n")
			f.write("Key Logins\n")
			f.write("==================================================\n")
			f.write("Aside from this, one may find that the SSH does not allow password logins but instead only key based logins.\n")
			f.write("If you have a private key of a user, the syntax to login is slightly different, using the -i switch to specify the key file instead of a password.\n")
			f.write("ssh -i <PRIVATE_KEY_FILE> <USERNAME>@<IP_ADDRESS>\n\n")
			f.write("Notable Files\n")
			f.write("==================================================\n")
			f.write("ssh_config // sshd_config - The configuration files.\n")
			f.write("authorized_keys - Where the public half of an SSH key is kept. Usually in the users personal .ssh directory.\n")
			f.write("id_rsa - The private key. This would be used to remotely login to a target that had the matching public key in their authorized_key file.\n")
			f.close()

	def http(self):
		terms.create_dir("web_server")
		self.open_ports.append(80)
		self.score["HTTP"] = 8
		#https://book.hacktricks.xyz/pentesting/pentesting-web
		with open(terms.working_folder + "web_server/http_attack.txt", "w") as f:
			f.write("HTTP // Web Servers\n")
			f.write("==================================================\n")
			f.write("Web servers are all around you. Every website that is visited is inevitably hosted somewhere on a server. These sites are typically found on ports 80, for standard, unencrypted sites, and port 443 for encrypted, https sites.\n")
			f.write("Enumerating a web application is no small task. They can vary greatly in size and be extremely complex. The points below are a general beginner level 'what to keep an eye out for', and are by no means a complete list.\n\n")
			f.write("Identifying Software\n")
			f.write("==================================================\n")
			f.write("Often your nmap scan will be able to provide some information on the web technology in use, such as Apache, Nginx. If it gives a version, the first port of call should be to Google for any vulnerabilities with this version, especially if it's outdated.\n")
			f.write("Unless a website is custom built, it will often be running on top of some sort of existing software or content management system. For example, a website might be running on top of wordpress. This can then shape your enumeration of that site. Checking the source code of the webpages (Ctrl + U) for any clues regarding any software in use can lead to a rewarding exploitation experience.\n")
			f.write("If a site has links in the source code to /wp-login.php or /wp-admin.php, you could assume that it's generally running Wordpress. From there, dedicated vulnerability scanners are available to try and identify any flaws in the version, or plugins, that are in use. These can be found with a simple Google search. For Wordpres, you may consider 'wpscan', for example.\n")
			f.write("So always check the source for interesting pieces of information!\n\n")
			f.write("Directory Busting\n")
			f.write("==================================================\n")
			f.write("Web directories are simply locations on the server where information is categorized. So for example, an administrator panel might be located at 'http://website.com/admin'. A login page might be located at 'http://website.com/login.php'.\n")
			f.write("Brute forcing these directory names might leave one with access to a page that wasn't publicly advertised, or a back up file left on the server.\n")
			f.write("So how can it be done? Dirb provides a really simple, command-line tool to scan for directories and is built into Kali Linux. An example has been given below.\n")
			f.write("\nExample 1: Running a directory brute force with dirb\n")
			f.write("dirb http://<WEBSITE_IP>\n\n")
			f.write("It's really as simple as that. It uses a pre-built wordlist to identify common directories or files. However, sometimes you may want more control. For this you can use alternative command-line tools, such as gobuster.\n\n")
			f.write("Example 2: Running a directory brute force with gobuster\n")
			f.write("gobuster dir -u http://<WEBSITE_IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt\n\n")
			f.write("In this example, we set the website with the -u switch, then specify a wordlist that is pre-built into Kali. You can also specify extensions, depending on what the website seems to be using. This is something you should try to manually work out by exploring it yourself. For example, if you go to the page and it's 'http://website.com/index.php', then php is likely to be in use and you should specify this as an extension! Directory brute forcing can give access to hidden areas or files that might contain useful information for attacking the target. Keep an eye out for /robots.txt!\n\n")
			f.write("Nikto\n")
			f.write("==================================================\n")
			f.write("Nikto is a tool that takes some heavy lifting out of a web application scan. It can be set off and attempts to find useful information and vulnerabilities for you automatically. The downside is that the information presented can often be false positives, so should always be confirmed through manual attempts.\n\n")
			f.write("Example: Running Nikto against a target: nikto -h http://<WEBSITE_IP>\n\n")
			f.write("User Input Points\n")
			f.write("==================================================\n")
			f.write("Identifying areas where a user can input information can often lead to finding vulnerabilities. This can include login forms, contact forms and URL parameters.\n")
			f.write("There are many vulneabilities that could be present, such as SQL Injections, command injections, Cross-Site Scripting (XSS). Generally, they stem from the website not properly sanitizing input from a user, therefore letting malicious things get entered and interpreted by the site.\nUse Google to find guides on testing for these vulnerabilities as it is a topic in itself.\n")
			f.write("If you have Burpsuite set up (If you don't, get it set up ASAP!) then try to enter a piece of information and intercept the request as it gets sent to the server by turning intercept on. That way you can see exactly what is happening when you send your login details, or enter your e-mail address, and this sort of information can help you build a bigger picture of how the site is functioning.\n\n")
			f.write("Cookies\n")
			f.write("==================================================\n")
			f.write("If there are custom cookie values in place then maybe they can be modified to change your privileges, or your user ID, for example, to the Administrator ID (Generally this will be 1 as they were the first user created).\n")
			f.write("Press F12 to bring up the developer console and then go to Application/Storage, depending on whether Chrome or Firefox is in use. If the values look like they are custom set rather than randomly generated, maybe they can be edited!\n\n")
			f.write("Weak Authentication\n")
			f.write("==================================================\n")
			f.write("If you find access to a login panel, or administrator panel. Try to see if there are different messages when entering invalid credentials. If you enter a valid username but invalid password, does it tell you that the username is valid? If so, then it might be possible to brute force the login page by trying common passwords since you know a correct username.\n")
			f.write("Maybe there is some default credentials, if it is an existing piece of software, no harm in trying to login with the likes of 'admin:admin'!\n\n")
			f.write("Subdomain Fuzzing\n")
			f.write("==================================================\n")
			f.write("Exploring whether a website has subdomains can be useful. For example, www.google.com is a subdomain of google.com. There might be dev.google.com which could be a development environment that shouldn't be publicly accessible. Being inquisitive and exploring these areas might bear some fruit. It can be performed with fuzzing tools such as ffuf.\n\n")
			f.write("Example: Fuzzing for Subdomains with ffuf (Coloured Output)\n")
			f.write("ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://FUZZ.website.com -mc 200\n\n")
			f.write("In the above example, a wordlist is used that comes pre-instlled with Kali and the word FUZZ replicates where the words will be replaced. The -mc 200 switch means to only match pages where a 200 OK response is returned, meaning a successful connection was made and the page probably exists!\n")
			f.close()

	def https(self):
		terms.create_dir("tls_web_server")
		self.open_ports.append(443)
		self.score["HTTPS"] = 8
		#https://book.hacktricks.xyz/pentesting/pentesting-web
		with open(terms.working_folder + "tls_web_server/https_attack.txt", "w") as f:
			f.write("HTTPs // Web Servers\n")
			f.write("==================================================\n")
			f.write("Web servers are all around you. Every website that is visited is inevitably hosted somewhere on a server. These sites are typically found on ports 80, for standard, unencrypted sites, and port 443 for encrypted, https sites.\n")
			f.write("Enumerating a web application is no small task. They can vary greatly in size and be extremely complex. The points below are a general beginner level 'what to keep an eye out for', and are by no means a complete list.\n\n")
			f.write("Note: The process is similar to the non-https web server on port 80, with just a few extra points.\n\n")
			f.write("Identifying Software\n")
			f.write("==================================================\n")
			f.write("Often your nmap scan will be able to provide some information on the web technology in use, such as Apache, Nginx. If it gives a version, the first port of call should be to Google for any vulnerabilities with this version, especially if it's outdated.\n")
			f.write("Unless a website is custom built, it will often be running on top of some sort of existing software or content management system. For example, a website might be running on top of wordpress. This can then shape your enumeration of that site. Checking the source code of the webpages (Ctrl + U) for any clues regarding any software in use can lead to a rewarding exploitation experience.\n")
			f.write("If a site has links in the source code to /wp-login.php or /wp-admin.php, you could assume that it's generally running Wordpress. From there, dedicated vulnerability scanners are available to try and identify any flaws in the version, or plugins, that are in use. These can be found with a simple Google search. For Wordpres, you may consider 'wpscan', for example.\n")
			f.write("So always check the source for interesting pieces of information!\n\n")
			f.write("Directory Busting\n")
			f.write("==================================================\n")
			f.write("Web directories are simply locations on the server where information is categorized. So for example, an administrator panel might be located at 'http://website.com/admin'. A login page might be located at 'http://website.com/login.php'.\n")
			f.write("Brute forcing these directory names might leave one with access to a page that wasn't publicly advertised, or a back up file left on the server.\n")
			f.write("So how can it be done? Dirb provides a really simple, command-line tool to scan for directories and is built into Kali Linux. An example has been given below.\n")
			f.write("\nExample 1: Running a directory brute force with dirb\n")
			f.write("dirb http://<WEBSITE_IP>\n\n")
			f.write("It's really as simple as that. It uses a pre-built wordlist to identify common directories or files. However, sometimes you may want more control. For this you can use alternative command-line tools, such as gobuster.\n\n")
			f.write("Example 2: Running a directory brute force with gobuster\n")
			f.write("gobuster dir -u http://<WEBSITE_IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt\n\n")
			f.write("In this example, we set the website with the -u switch, then specify a wordlist that is pre-built into Kali. You can also specify extensions, depending on what the website seems to be using. This is something you should try to manually work out by exploring it yourself. For example, if you go to the page and it's 'http://website.com/index.php', then php is likely to be in use and you should specify this as an extension! Directory brute forcing can give access to hidden areas or files that might contain useful information for attacking the target. Keep an eye out for /robots.txt!\n\n")
			f.write("Nikto\n")
			f.write("==================================================\n")
			f.write("Nikto is a tool that takes some heavy lifting out of a web application scan. It can be set off and attempts to find useful information and vulnerabilities for you automatically. The downside is that the information presented can often be false positives, so should always be confirmed through manual attempts.\n\n")
			f.write("Example: Running Nikto against a target: nikto -h http://<WEBSITE_IP>\n\n")
			f.write("User Input Points\n")
			f.write("==================================================\n")
			f.write("Identifying areas where a user can input information can often lead to finding vulnerabilities. This can include login forms, contact forms and URL parameters.\n")
			f.write("There are many vulneabilities that could be present, such as SQL Injections, command injections, Cross-Site Scripting (XSS). Generally, they stem from the website not properly sanitizing input from a user, therefore letting malicious things get entered and interpreted by the site.\nUse Google to find guides on testing for these vulnerabilities as it is a topic in itself.\n")
			f.write("If you have Burpsuite set up (If you don't, get it set up ASAP!) then try to enter a piece of information and intercept the request as it gets sent to the server by turning intercept on. That way you can see exactly what is happening when you send your login details, or enter your e-mail address, and this sort of information can help you build a bigger picture of how the site is functioning.\n\n")
			f.write("Cookies\n")
			f.write("==================================================\n")
			f.write("If there are custom cookie values in place then maybe they can be modified to change your privileges, or your user ID, for example, to the Administrator ID (Generally this will be 1 as they were the first user created).\n")
			f.write("Press F12 to bring up the developer console and then go to Application/Storage, depending on whether Chrome or Firefox is in use. If the values look like they are custom set rather than randomly generated, maybe they can be edited!\n\n")
			f.write("Weak Authentication\n")
			f.write("==================================================\n")
			f.write("If you find access to a login panel, or administrator panel. Try to see if there are different messages when entering invalid credentials. If you enter a valid username but invalid password, does it tell you that the username is valid? If so, then it might be possible to brute force the login page by trying common passwords since you know a correct username.\n")
			f.write("Maybe there is some default credentials, if it is an existing piece of software, no harm in trying to login with the likes of 'admin:admin'!\n\n")
			f.write("Subdomain Fuzzing\n")
			f.write("==================================================\n")
			f.write("Exploring whether a website has subdomains can be useful. For example, www.google.com is a subdomain of google.com. There might be dev.google.com which could be a development environment that shouldn't be publicly accessible. Being inquisitive and exploring these areas might bear some fruit. It can be performed with fuzzing tools such as ffuf.\n\n")
			f.write("Example: Fuzzing for Subdomains with ffuf (Coloured Output)\n")
			f.write("ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://FUZZ.website.com -mc 200\n\n")
			f.write("In the above example, a wordlist is used that comes pre-instlled with Kali and the word FUZZ replicates where the words will be replaced. The -mc 200 switch means to only match pages where a 200 OK response is returned, meaning a successful connection was made and the page probably exists!\n\n")
			f.write("TLS Scanning\n")
			f.write("==================================================\n")
			f.write("Scanning for TLS misconfigurations or vulnerabilities can be done with sslscan.\n\n")
			f.write("Example: Scanning a Site with sslscan\n")
			f.write("sslscan <WEBSITE_IP>\n\n")
			f.write("One of the most famous vulnerabilities, Heartbleed, can be identified using this tool!\n")
			f.close()
			
	def ftp(self):
		terms.create_dir("ftp")
		self.open_ports.append(21)
		self.score["FTP"] = 9
		#https://www.briskinfosec.com/blogs/blogsdetail/FTP-Penetration-Testing
		with open(terms.working_folder + "ftp/ftp_attack.txt", "w") as f:
			f.write("FTP // File Transfer Protocol\n")
			f.write("==================================================\n")
			f.write("FTP provides a means of serving and storing files on a network between a client and the file server.\n\n")
			f.write("Anonymous Authentication\n")
			f.write("==================================================\n")
			f.write("If there is an FTP server open, it can be connected to by using the command below.\n\n")
			f.write("Example: Connecting to an FTP server\n")
			f.write("ftp <IP_ADDRESS>\n\n")
			f.write("Generally, it will ask for credentials. If you do not posess credentials, some servers are misconfigured to allow what is known as 'anonymous' login. This gives a user access without having the correct details.\n")
			f.write("To check for anonymous login, just enter 'anonymous' into the username and password fields.\n")
			f.write("This can be used to gain access to useful information that was not originally intended to be viewed.\n\n")
			f.write("Versions\n")
			f.write("==================================================\n")
			f.write("As with all open services, they can sometimes be outdated. Googling the version number displayed in your initial nmap scan and searching for exploits might reveal there is a publicly known vulnerability with that specific FTP version.\n\n")
			f.write("Alternatively, it is possible to just use searchsploit to enumerate for existing vulnerabilities in ExploitDB.\n\n")
			f.write("Example: Searching for a freeFTP Exploit in Searchsploit\n")
			f.write("searchsploit freeftp 1.0\n\n")
			f.write("Commands\n")
			f.write("==================================================\n")
			f.write("If lucky enough to get inside an FTP server, commands are similar to bash commands. Running 'help' lists the available commands. You can't 'open' a file on the server, it must be transferred back to the host first.\n")
			f.write("The key commands have been listed below.\n\n")
			f.write("List Contents: ls -la\n")
			f.write("Transfer a file to your host: GET <filename>\n")
			f.write("Check if you can upload files: PUT <filename>\n\n")
			f.write("Brute Force Attack\n")
			f.write("==================================================\n")
			f.write("FTP can also be attacked via brute force using hydra and specifying either wordlists or single username and password combinations!\n\n")
			f.write("Example: Hydra brute force with username and password list\nhydra -L <USERNAME_LIST> -P <PASSWORD_LIST> <IP_ADDRESS> ftp -V\n\n")
			f.write("Example 2: Hydra brute force with a single username and password\nhydra -l <USERNAME> -p <PASSWORD> <IP_ADDRESS> ftp -V\n\n")
			f.write("Note the alteration between upper and lower case l's and p's to denote whether a list is used, or singular user/pass.\n")
			f.close()

	def telnet(self):
		terms.create_dir("telnet")
		self.open_ports.append(23)
		self.score["Telnet"] = 5
		with open(terms.working_folder + "telnet/telnet_attack.txt", "w") as f:
			#https://book.hacktricks.xyz/pentesting/pentesting-telnet
			f.write("Telnet // A Remote Login Protocol\n")
			f.write("==================================================\n")
			f.write("Telnet provides a way to remotely login to a client computer over an unencrypted network connection. It was for this reason that SSH was implemented in it's place.\n\n")
			f.write("Basic Login\n")
			f.write("==================================================\n")
			f.write("Telnet typically runs on port 23 and the syntax to login can be seen below.\n\n")
			f.write("Example: Logging in over Telnet\n")
			f.write("telnet <IP_ADDRESS> 23\n\n")
			f.write("Brute Forcing Telnet\n")
			f.write("==================================================\n")
			f.write("Much like other remote login services, telnet can be brute forced with Hydra.\n\n")
			f.write("Example 1: Hydra brute force with username and password list\nhydra -L <USERNAME_LIST> -P <PASSWORD_LIST> <IP_ADDRESS> telnet -V\n\n")
			f.write("Example 2: Hydra brute force with a single username and password\nhydra -l <USERNAME> -p <PASSWORD> <IP_ADDRESS> telnet -V\n\n")
			f.write("Banner Grabbing\n")
			f.write("==================================================\n")
			f.write("Telnet can also be used to grab banners of running services to better understand the versions that they are running. This can be done against many services. An example has been given below of how it could be done against SSH, if the SSH port was open. To adapt to other services, just change the port.\n\n")
			f.write("Example: Using Telnet to grab SSH banners\n")
			f.write("telnet <IP_ADDRESS> 22\n\n")
			f.write("It can also be used to communicate with specific services, which is covered in the documentation when respective services are identified.\n")
			f.close()

	def smtp(self):
		terms.create_dir("smtp")
		self.open_ports.append(25)
		self.score["SMTP"] = 3
		#https://shahmeeramir.com/penetration-testing-an-smtp-server-cf91e4846101
		with open(terms.working_folder + "smtp/smtp_attack.txt", "w") as f:
			f.write("SMTP // Simple Mail Transfer Protocol\n")
			f.write("==================================================\n")
			f.write("SMTP is generally used as a protocol that other applications use to send e-mails. It has limitations with receiving mail, so these are generally left to the POP3 or IMAP services.\n\n")
			f.write("Connecting to SMTP Servers\n")
			f.write("==================================================\n")			
			f.write("Connecting to an SNMP server can be done via the telnet protocol.\n\n")
			f.write("Example: Connecting to SNMP Server\n")
			f.write("telnet <TARGET_IP> 25\n\n")
			f.write("Enumerating Usernames with SMTP\n")
			f.write("==================================================\n")
			f.write("This is an interesting feature that is sometimes enabled on SMTP servers that responds with different error messages if you query an existing user or a non-existing user. This allows for the enumeration of valid usernames on the server!\n\n")
			f.write("Example: Testing for if the user 'root' exists\n")
			f.write("VRFY root\n\n")
			f.write("Example 2: Testing for a random username to see the invalid response\n")
			f.write("VRFY euhtuwrhtuaweyhirjhyirh\n\n")
			f.write("Example 3: Using an alternative method to test if the root user exists\n")
			f.write("EXPN root\n\n")
			f.write("Error codes will be able to discern a valid user from an invalid user. Try to check for a user that definitely won't exist and compare the results.\n\n")
			f.write("Automating User Enumeration\n")
			f.write("==================================================\n")
			f.write("The process above can be automated using one of nmap's built in scripts!\n\n")
			f.write("Example: SMTP Username Enumeration with nmap\n")
			f.write("nmap --script smtp-enum-users.nse -p 25 <TARGET_IP>\n")
			f.close()

	def pop3(self):
		terms.create_dir("pop")
		self.score["POP3"] = 2
		#Information collated from https://www.techopedia.com/definition/5383/post-office-protocol-pop and https://book.hacktricks.xyz/pentesting/pentesting-pop
		with open(terms.working_folder + "pop/pop_attack.txt", "w") as f:
			f.write("pop3 // Post Office Protocol\n")
			f.write("==================================================\n")
			f.write("The Post Office Protocol allows users to fetch emails from a remote email server and makes them accessible on their machine.\n\n")
			f.write("Connecting to POP3 Server\n")
			f.write("==================================================\n")			
			f.write("Connecting to a POP3 server can be done via the telnet protocol.\n\n")
			f.write("Example: Connecting to POP3 Server\n")
			f.write("telnet <TARGET_IP> <PORT 110 or 995>\n\n")
			f.write("Basic POP3 Commands\n") 
			f.write("==================================================\n")	
			f.write("Logging in step 1 - USER <username> \n")
			f.write("Logging in step 2 - PASS <password>\n")
			f.write("List e-mails - LIST\n")
			f.write("View e-mail number X -  RETR X\n")
			f.write("Delete e-mail number X - DELE X\n")
			f.write("Logout of Application - QUIT\n")
			f.close()


	def rpcbind(self):
		terms.create_dir("rpcbind")
		self.open_ports.append(111)
		self.score["Rpcbind"] = 3
		with open(terms.working_folder + "rpcbind/rpcbind_attack.txt", "w") as f:
			f.write("RPC // Remote Procedure Calls\n")
			f.write("==================================================\n")	
			f.write("The RPC protocol is a Unix based protocol which provides access to run procedures on remote machines. It is often used in tangent with services such as NFS, Network File Sharing. It is sometimes referred to as the Portmapper service.\n\n")
			f.write("Enumerating RPC\n")
			f.write("==================================================\n")	
			f.write("There are a few commands that can be used to enumerate the RPC protocol.\n\n")
			f.write("Example 1: Enumerating RPC with rpcinfo\n")
			f.write("rpcinfo -p <TARGET_IP>\n\n")
			f.write("Example 2: Enumerating RPC with rpcclient and a null sessions\n")
			f.write("rpcclient -U '' <TARGET_IP>\n\n")
			f.write("Using rpcclient\n")
			f.write("==================================================\n")	
			f.write("If you manage to get in with rpcclient and a null session, or if you have credentials, the following commands are commonly used for further enumeration.\n\n")
			f.write("Example 1: Enumerating domain users\n")
			f.write("enumdomusers\n\n")
			f.write("Example 2: Getting server information\n")
			f.write("srvinfo\n\n")
			f.write("Example 3: Query domain information\n")
			f.write("querydominfo\n\n")
			f.write("Example 4: List connected shares\n")
			f.write("netshareenumall\n")
			f.close()

	def dcom(self):
		terms.create_dir("dcom_rpc")
		self.open_ports.append(135)
		self.score["DCOM"] = 2
		with open(terms.working_folder + "dcom_rpc/dcom_rpc_attack.txt", "w") as f:
			#Thanks to Carlos Poplos https://book.hacktricks.xyz/pentesting/135-pentesting-msrpc
			f.write("DCOM // Distributed Service Control Manager\n")
			f.write("==================================================\n")	
			f.write("This is Microsoft's version of RPC which is used to allow a program to request services from a program on another computer without knowledge of the computers network.\n\n")
			f.write("Enumeration via Metasploit\n")
			f.write("==================================================\n")	
			f.write("This service is complex to analyse at a beginner level, using metasploit takes some of the heavy lifting out.\n\n")
			f.write("Example 1: Start Metasploit\n")
			f.write("sudo msfconsole\n\n")
			f.write("Example 2: Set the module\n")
			f.write("use auxiliary/scanner/dcerpc/endpoint_mapper\n\n")
			f.write("Example 3: Set the target\n")
			f.write("set RHOSTS <TARGET_IP>\n\n")
			f.write("Example 4: Start the scan\n")
			f.write("run\n")
			f.close()

	def netbios(self):
		terms.create_dir("netbios")
		self.score["Netbios"] = 3
		with open(terms.working_folder + "netbios/netbios_attack.txt", "w") as f:
			f.write("Netbios // Network Basic Input/Output System\n")
			f.write("==================================================\n")
			f.write("Netbios runs on port 137/udp where it provides a name service, 138/udp where it provides a datagram service and 139/tcp where it provides a session service. Certain tools can be used to enumerate these running services.\n\n")
			f.write("Example 1: Enumerating with nbtscan\n")
			f.write("nbtscan <TARGET_IP> -v\n\n")
			f.write("Example 2: Enumerating with nmblookup\n")
			f.write("nmblookup -A <TARGET_IP>\n")
			f.close()

	def smb(self):
		terms.create_dir("smb")
		# Info adapted from https://www.hackingarticles.in/smb-penetration-testing-port-445/
		self.open_ports.append(445)
		self.score["SMB"] = 10
		with open(terms.working_folder + "smb/smb_attack.txt", "w") as f:
			f.write("SMB // Server Message Block\n")
			f.write("==================================================\n")
			f.write("SMB offers cross compatibility between operating systems with what is known as a Common Internet File System.\n")
			f.write("It has been in the spotlight many times since it's inception due to exploits such as Eternal Blue, used in the 2017 Wannacry attack, targetting it.\n")
			f.write("There could be a whole tool on smb enumeration itself, but the commands and tools below should help to cover the basics that will be necessary when you find it on a test.\n\n")
			f.write("Versions\n")
			f.write("==================================================\n")
			f.write("Nmap will usually be able to identify what version of SMB/Samba is in use. You can then use Google or searchsploit to find out whether these have any vulnerabilities. Alternatively, nmap's scripting engine comes with a preset filter to attempt to identify SMB related vulnerabilities, such as the aforementioned Eternal Blue.\n\n")
			f.write("Example 1: Searching for exploits on searchsploit\n")
			f.write("searchsploit samba 2.0\n\n")
			f.write("Example 2: Searching for vulnerabilities with nmap\n")
			f.write("nmap --script smb-vuln* -p 139,445 <TARGET_IP>\n\n")
			f.write("Enumeration Tools\n")
			f.write("==================================================\n")
			f.write("Certain tools take the heavy lifting out of enumerating SMB by trying common commands for you and attempting to enumerate shares, users, and items like password policies, RID and SID's. There is usually lots of output from this, so make sure you take note of things you find as you scroll through.\n\n")
			f.write("Example 1: using enum4linux to enumerate SMB\n")
			f.write("enum4linux <TARGET_IP>\n\n")
			f.write("Example 2: Running enum4linux with credentials\n")
			f.write("enum4linux -u <USERNAME> -p <PASSWORD> <TARGET_IP>\n\n")
			f.write("Brute Force SMB Credentials\n")
			f.write("==================================================\n")
			f.write("Since it's based on authentication of usernames and passwords, it's possible to brute force login credentials. However, accounts may have a lockout period so this should be done with caution.\n\n")
			f.write("Example 1: Brute Forcing SMB with username and password list\n")
			f.write("hydra -L <USERNAME_LIST> -P <PASSWORD_LIST> <TARGET_IP> smb -V\n\n")
			f.write("Example 2: Brute Forcing SMB with a single username and password\n")
			f.write("hydra -l <USERNAME> -p <PASSWORD> <TARGET_IP> smb -V\n\n")
			f.write("Accessing an SMB Share\n")
			f.write("==================================================\n")
			f.write("Sometimes it is possible, even without credentials, to list and access SMB shares that are hosted on the target.\n\n")
			f.write("Example 1: Listing shares with smbclient\n")
			f.write("smbclient -L \\\\\\\\<TARGET_IP>\\\\\n\n")
			f.write("When prompted for a username or password, just hit enter and if anonymous sessions are allowed, the shares will be listed. You can then try to connect to these specific shares with smbclient.\n\n")
			f.write("Example 2: Connecting to a share called BACKUPS with smbclient\n")
			f.write("smbclient \\\\\\\\<TARGET_IP>\\\\BACKUPS\n\n")
			f.write("This will drop into a prompt, if successful, where it is possible to run 'help' to view available commands. These are similar to FTP, being able to list the directory with 'ls' and transfer files back to your host with GET <filename>.\n\n")
			f.write("rpcclient\n")
			f.write("==================================================\n")
			f.write("It is possible to use rpcclient to enumerate information about the target, sometimes without credentials.\n\n")
			f.write("Example 1: Enumerating SMB with rpcclient and a null session\n")
			f.write("rpcclient -U '' -N <TARGET_IP>\n\n")
			f.write("Using rpcclient\n")
			f.write("==================================================\n")	
			f.write("If you manage to get in with rpcclient and a null session, or if you have credentials, the following commands are commonly used for further enumeration.\n\n")
			f.write("Example 1: Enumerating domain users\n")
			f.write("enumdomusers\n\n")
			f.write("Example 2: Getting server information\n")
			f.write("srvinfo\n\n")
			f.write("Example 3: Query domain information\n")
			f.write("querydominfo\n\n")
			f.write("Example 4: List connected shares\n")
			f.write("netshareenumall\n\n")
			f.write("Example 5: Enumerate groups\n")
			f.write("enumdomgroups\n\n")
			f.write("Exploiting with impacket\n")
			f.write("==================================================\n")
			f.write("If you manage to get credentials, you can then try to get a shell on the target using impacket's psexec tool. This can be downloaded from their github, the repository contains many offensive tools written in python: https://github.com/SecureAuthCorp/impacket\n")		
			f.close()

	def imap(self):
		terms.create_dir("imap")
		self.score["IMAP"] = 2
		with open(terms.working_folder + "imap/imap_attack.txt", "w") as f:
			f.write("IMAP // Internet Message Access Protocol\n")
			f.write("==================================================\n")
			f.write("The Internet Message Access Protocol allows a user to read e-mails directly off an email server without actually ever downloading them with the goal of greater accessibility to the information.\n\n")
			f.write("Connecting to IMAP\n")
			f.write("==================================================\n")	
			f.write("Telnet is actually used to create the connection to IMAP, using either port 143 or 993, depending on what is open.\n\n")
			f.write("Example: Communicating with IMAP\n")
			f.write("telnet <TARGET_IP> <143/993>\n\n")
			f.write("Basic IMAP Commands\n") #List derived from https://donsutherland.org/crib/imap 
			f.write("==================================================\n")	
			f.write("Logging in - A1 LOGIN username password\n")
			f.write("List available mailboxes - A1 LIST INBOX *\n")
			f.write("Selecting your inbox - A1 SELECT INBOX\n")
			f.write("List messages -  A1 FETCH 1:* <FLAGS>\n")
			f.write("Viewing a message's content - A1 FETCH 2 all\n")
			f.write("Logging out - A1 LOGOUT\n")
			f.close()

	def pptp(self):
		terms.create_dir("PPTP")
		self.open_ports.append(1723)
		self.score["pptp"] = 1
		with open(terms.working_folder + "pptp/pptp_attack.txt", "w") as f:
			f.write("PPTP // Point to Point Tunneling Protocol\n")
			f.write("==================================================\n")			
			f.write("PPTP is an older vpn based protocol. It is widely regarded as insecure and can be bruteforced with a tool called thc-pptp-bruter.\n\n")
			f.write("Example: Brute Forcing PPTP Protocol\n")
			f.write("thc-pptp-bruter -v -u <USERNAME> -w <PASSWORD_LIST> <TARGET_IP>\n")
			f.close()

	def dns(self):
		terms.create_dir("dns")
		self.open_ports.append(53)
		self.score["DNS"] = 5
		#https://medium.com/@klockw3rk/back-to-basics-dns-enumeration-446017957aa3
		with open(terms.working_folder + "dns/dns_attack.txt", "w") as f:
			f.write("DNS // Domain Name Server\n")
			f.write("==================================================\n")
			f.write("The Domain Name Server can be likened to the phonebook of the internet. It maps a name to an IP address. Whenever google.com is visited, this is realistically just an IP address that the web server is hosted on. People would struggle to remember specific IP addresses, and thus a domain name server links that IP to a name, much like a person links a name to a number.\n")
			f.write("Tools such as dig can attempt to reveal information about a target based on their domain name.\n\n")
			f.write("Installing dig\n")
			f.write("==================================================\n")
			f.write("sudo apt-get install dnsutils -y\n\n")
			f.write("Using dig\n")
			f.write("==================================================\n")
			f.write("DNS Lookup - dig <DOMAIN_NAME>\n")
			f.write("Search for all DNS record types - dig <DOMAIN_NAME> ANY\n")
			f.write("Search for DNS mail exchanges - dig <DOMAIN_NAME> MX\n")
			f.write("Reverse lookup from an IP address - dig +answer -x <IP_ADDRESS>\n")
			f.write("Query common names - dig <DOMAIN_NAME> CNAME\n")
			f.write("Query a records - dig <DOMAIN_NAME> A\n")
			f.write("Query nameservers - dig <DOMAIN_NAME> NS\n\n")
			f.write("Using Metasploit\n")
			f.write("==================================================\n")
			f.write("Metasploit has a fantastic DNS enumeration module called enum_dns.\n")
			f.write("Start metasploit - msfconsole\n")
			f.write("Set the module up - use auxiliary/gather/enum_dns\n")
			f.write("Set the domain name target - set domain <DOMAIN_NAME>\n")
			f.write("Start the script - run\n")
			f.close()

	def mysql(self):
		terms.create_dir("mysql")
		self.open_ports.append(3306)
		self.score["MYSQL"] = 6
		#https://book.hacktricks.xyz/pentesting/pentesting-mysql
		with open(terms.working_folder + "mysql/mysql_attack.txt", "w") as f:
			f.write("MySQL // Structured Query Language\n")
			f.write("MySQL is a popular database management service which makes use of a Structured Query Language. There are many DBMS backends, such as Oracle or MSSQL, but MySQL is one of the most popular ports found open according to nmap's top port list.\n\n")
			f.write("Connecting to a MySQL Server\n")
			f.write("==================================================\n")
			f.write("To connect to a server that is running MySQL and is accessible remotely you would use the syntax below. To connect to a local one (on your device) just omit the -h switch. Typical usernames to try are mysql and root. By default, there is no password set on the root account, so this might be an entry point.\n\n")
			f.write("Example: Connecting to Remote MySQL Server\n")
			f.write("mysql -h <TARGET_IP> -u <USERNAME> -p\n\n")
			f.write("The -p is optional, depending if the user has a password set!\n\n")
			f.write("Keep it in your pocket!\n")
			f.write("==================================================\n")
			f.write("Seeing a MySQL server open is often indicative that the backend database in use on a website is MySQL. You can use this information when trying SQL Injections. Enumeration is all about making mental notes of these services as you go, as it might become useful later.\n\n")
			f.write("MySQL Commands\n")
			f.write("==================================================\n")
			f.write("If you are lucky enough to get inside the MySQL client on a target, you can enumerate specific pieces of information using basic MySQL queries. Notice they all end in ';' which is how a query is ended.\n\n")
			f.write("Show a list of available databases - show databases;\n")
			f.write("Use the chosen database - use <DATABASE_NAME>;\n")
			f.write("Show tables in that database - show tables;\n")
			f.write("Show current user - select user();\n")
			f.write("List usernames and passwords from the MySQL database - select user,password from mysql.users;\n")
			f.write("If MySQL is running as root, attempt to execute code and get a root shell - ! /bin/sh\n\n")
			f.write("There are hundreds of SQL commands that could be included here, but the primary idea is to be able to SELECT data which could provide credentials or useful information.\n\n")
			f.write("Brute Forcing MySQL Logins\n")
			f.write("==================================================\n")
			f.write("Since it is authentication based, it can be brute forced.\n\n")
			f.write("Example: Brute Forcing MySQL with Hydra\n")
			f.write("hydra -l root -P <PASSWORD_LIST> <TARGET_IP> mysql -V\n\n")
			f.write("Useful Files\n")
			f.write("==================================================\n")
			f.write("Find a MySQL Configuration file in Windows - dir my.ini /B /S\n")
			f.write("Linux Configuration files - /etc/my.cnf | /etc/mysql/my.cnf\n")
			f.close()

	def rdp(self):
		terms.create_dir("rdp")
		self.open_ports.append(3389)
		self.score["RDP"] = 5
		with open(terms.working_folder + "rdp/rdp_attack.txt", "w") as f:
			f.write("RDP // Remote Desktop Protocol\n")
			f.write("==================================================\n")
			f.write("The remote desktop protocol allows a user to login to a device remotely and utilize a GUI rather than just a command prompt or terminal.\n\n")
			f.write("Connecting to an RDP Server\n")
			f.write("==================================================\n")
			f.write("The simplest way to connect with an RDP server when the credentials are known is to use the rdesktop command.\n\n")
			f.write("Example: Connecting to a device via RDP\n")
			f.write("rdesktop -u <USERNAME> <IP_ADDRESS>\n\n")
			f.write("Brute Forcing RDP Logins\n")
			f.write("==================================================\n")
			f.write("Whilst Hydra can be used to brute force logins for RDP enabled accounts, a more specialised brute force tool can be used to more effect - crowbar.\n\n")
			f.write("Example 1: Downloading crowbar\n")
			f.write("sudo apt-get install crowbar\n\n")
			f.write("Example 2: Launching the brute force attack on a single user/pass\n")
			f.write("crowbar -b rdp -s <IP_ADDRESS/32> -u <USERNAME> -c <PASSWORD>\n\n")
			f.write("Example 3: Launching the brute force attack on a single user with password list\n")
			f.write("crowbar -b rdp -s <IP_ADDRESS/32> -U <USERNAME_LIST> -C <PASSWORD_LIST>\n\n")
			f.write("Remember to denote the /32 at the end of the IP!\n")
			f.close()

	def vnc(self):
		terms.create_dir("vnc")
		self.score["VNC"] = 7
		with open(terms.working_folder + "vnc/vnc_attack.txt", "w") as f:
			f.write("VNC // Virtual Network Computing\n")
			f.write("==================================================\n")
			f.write("VNC provides a way to remotely control the GUI of a desktop while it runs. Unlike logging in, the user is simple viewing the logged in user's screen but can still interact as normal with keyboard and mouse stokes.\n\n")
			f.write("Connecting to VNC\n")
			f.write("==================================================\n")
			f.write("To connect to a computer that has vnc running, the command below can be used from within Kali Linux.\n\n")
			f.write("Example: Connecting to a VNC session\n")
			f.write("vncviewer <IP_ADDRESS>::<PORT>\n\n")
			# Thanks to https://www.raymond.cc/blog/crack-or-decrypt-vnc-server-encrypted-password/ for the information in the following part
			f.write("Exploiting Weak Encryption\n")
			f.write("==================================================\n")
			f.write("VNC passwords are often stored on the target and can be decrypted due to the fact the encryption algorithm was cracked years ago. Depending on the version and OS, they might be in different places.\n\n")
			f.write("Linux - ~/.vnc/passwd\n")
			f.write("Windows (RealVNC) - HKEY_LOCAL_MACHINE\\SOFTWARE\\RealVNC\\vncserver (In the registry editor!)\n")
			f.write("Windows (TightVNC) - HKEY_CURRENT_USER\\Software\\TightVNC\\Server (In the registry editor!)\n")
			f.write("Windows (TigerVNC) - HKEY_LOCAL_USER\\Software\\TigerVNC\\WinVNC4 (In the registry editor!)\n")
			f.write("Windows (UltraVNC) - C:\\Program Files\\UltraVNC\\ultravnc.ini\n\n")
			f.write("If a password is obtained, it can then be cracked using vncpwd which can be downloaded from github at https://github.com/jeroennijhof/vncpwd.\n\n")
			f.write("Brute Forcing VNC Logins\n")
			f.write("==================================================\n")
			f.write("It is also possible to brute force VNC logins! Similar to other protocols, although a login username is not required!\n\n")
			f.write("Example: Brute forcing a VNC login with Hydra\n")
			f.write("hydra -s <PORT> -P <PASSWORD_LIST> <TARGET_IP> vnc -t 16 -V\n")
			f.close()

	def alternative(self):
		terms.create_dir("alternative_http")
		#https://book.hacktricks.xyz/pentesting/pentesting-web
		self.open_ports.append(8080)
		self.score["ALTERNATIVE_WEBSERVER"] = 8
		with open(terms.working_folder + "alternative_http/alternative_http_attack.txt", "w") as f:
			f.write("HTTP // Alternative Web Server\n")
			f.write("==================================================\n")
			f.write("Note: The steps for enumerating port 8080 are similar to those of 80 and 443 but tips have been added for potential services that are typically hosted on this port.\n\n")
			f.write("Web servers are all around you. Every website that is visited is inevitably hosted somewhere on a server. These sites are typically found on ports 80, for standard, unencrypted sites, and port 443 for encrypted, https sites.\n")
			f.write("Enumerating a web application is no small task. They can vary greatly in size and be extremely complex. The points below are a general beginner level 'what to keep an eye out for', and are by no means a complete list.\n\n")
			f.write("Note: The process is similar to the non-https web server on port 80, with just a few extra points.\n\n")
			f.write("Identifying Software\n")
			f.write("==================================================\n")
			f.write("Often your nmap scan will be able to provide some information on the web technology in use, such as Apache, Nginx. If it gives a version, the first port of call should be to Google for any vulnerabilities with this version, especially if it's outdated.\n")
			f.write("Unless a website is custom built, it will often be running on top of some sort of existing software or content management system. For example, a website might be running on top of wordpress. This can then shape your enumeration of that site. Checking the source code of the webpages (Ctrl + U) for any clues regarding any software in use can lead to a rewarding exploitation experience.\n")
			f.write("If a site has links in the source code to /wp-login.php or /wp-admin.php, you could assume that it's generally running Wordpress. From there, dedicated vulnerability scanners are available to try and identify any flaws in the version, or plugins, that are in use. These can be found with a simple Google search. For Wordpres, you may consider 'wpscan', for example.\n")
			f.write("So always check the source for interesting pieces of information!\n\n")
			f.write("Directory Busting\n")
			f.write("==================================================\n")
			f.write("Web directories are simply locations on the server where information is categorized. So for example, an administrator panel might be located at 'http://website.com/admin'. A login page might be located at 'http://website.com/login.php'.\n")
			f.write("Brute forcing these directory names might leave one with access to a page that wasn't publicly advertised, or a back up file left on the server.\n")
			f.write("So how can it be done? Dirb provides a really simple, command-line tool to scan for directories and is built into Kali Linux. An example has been given below.\n")
			f.write("\nExample 1: Running a directory brute force with dirb\n")
			f.write("dirb http://<WEBSITE_IP>\n\n")
			f.write("It's really as simple as that. It uses a pre-built wordlist to identify common directories or files. However, sometimes you may want more control. For this you can use alternative command-line tools, such as gobuster.\n\n")
			f.write("Example 2: Running a directory brute force with gobuster\n")
			f.write("gobuster dir -u http://<WEBSITE_IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt\n\n")
			f.write("In this example, we set the website with the -u switch, then specify a wordlist that is pre-built into Kali. You can also specify extensions, depending on what the website seems to be using. This is something you should try to manually work out by exploring it yourself. For example, if you go to the page and it's 'http://website.com/index.php', then php is likely to be in use and you should specify this as an extension! Directory brute forcing can give access to hidden areas or files that might contain useful information for attacking the target. Keep an eye out for /robots.txt!\n\n")
			f.write("Nikto\n")
			f.write("==================================================\n")
			f.write("Nikto is a tool that takes some heavy lifting out of a web application scan. It can be set off and attempts to find useful information and vulnerabilities for you automatically. The downside is that the information presented can often be false positives, so should always be confirmed through manual attempts.\n\n")
			f.write("Example: Running Nikto against a target: nikto -h http://<WEBSITE_IP>\n\n")
			f.write("User Input Points\n")
			f.write("==================================================\n")
			f.write("Identifying areas where a user can input information can often lead to finding vulnerabilities. This can include login forms, contact forms and URL parameters.\n")
			f.write("There are many vulneabilities that could be present, such as SQL Injections, command injections, Cross-Site Scripting (XSS). Generally, they stem from the website not properly sanitizing input from a user, therefore letting malicious things get entered and interpreted by the site.\nUse Google to find guides on testing for these vulnerabilities as it is a topic in itself.\n")
			f.write("If you have Burpsuite set up (If you don't, get it set up ASAP!) then try to enter a piece of information and intercept the request as it gets sent to the server by turning intercept on. That way you can see exactly what is happening when you send your login details, or enter your e-mail address, and this sort of information can help you build a bigger picture of how the site is functioning.\n\n")
			f.write("Cookies\n")
			f.write("==================================================\n")
			f.write("If there are custom cookie values in place then maybe they can be modified to change your privileges, or your user ID, for example, to the Administrator ID (Generally this will be 1 as they were the first user created).\n")
			f.write("Press F12 to bring up the developer console and then go to Application/Storage, depending on whether Chrome or Firefox is in use. If the values look like they are custom set rather than randomly generated, maybe they can be edited!\n\n")
			f.write("Weak Authentication\n")
			f.write("==================================================\n")
			f.write("If you find access to a login panel, or administrator panel. Try to see if there are different messages when entering invalid credentials. If you enter a valid username but invalid password, does it tell you that the username is valid? If so, then it might be possible to brute force the login page by trying common passwords since you know a correct username.\n")
			f.write("Maybe there is some default credentials, if it is an existing piece of software, no harm in trying to login with the likes of 'admin:admin'!\n\n")
			f.write("Subdomain Fuzzing\n")
			f.write("==================================================\n")
			f.write("Exploring whether a website has subdomains can be useful. For example, www.google.com is a subdomain of google.com. There might be dev.google.com which could be a development environment that shouldn't be publicly accessible. Being inquisitive and exploring these areas might bear some fruit. It can be performed with fuzzing tools such as ffuf.\n\n")
			f.write("Example: Fuzzing for Subdomains with ffuf (Coloured Output)\n")
			f.write("ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://FUZZ.website.com -mc 200\n\n")
			f.write("In the above example, a wordlist is used that comes pre-instlled with Kali and the word FUZZ replicates where the words will be replaced. The -mc 200 switch means to only match pages where a 200 OK response is returned, meaning a successful connection was made and the page probably exists!\n\n")
			f.write("TLS Scanning\n")
			f.write("==================================================\n")
			f.write("Scanning for TLS misconfigurations or vulnerabilities can be done with sslscan.\n\n")
			f.write("Example: Scanning a Site with sslscan\n")
			f.write("sslscan <WEBSITE_IP>\n\n")
			f.write("One of the most famous vulnerabilities, Heartbleed, can be identified using this tool!\n\n")
			f.write("Potential Software\n")
			f.write("==================================================\n")
			f.write("Often port 8080 will have some sort of web software running on it, such as Tomcat. It is important to identify if there is outdated software running, or whether there is default credentials in use. Tomcat, for example, is susceptible to a file upload exploit.\n")
			f.write("When the software has been identified, use searchsploit or Google to see if there are any specific exploits!\n")
			f.write("Tomcat, for example, is vulnerable to a .WAR file upload vulnerability.. You just need to get into the management panel. Remember, it's always a good idea to try default credentials for web applications!\n")
			f.close()

	def snmp(self):
		terms.create_dir("snmp")
		self.open_ports.append(161)
		#https://resources.infosecinstitute.com/topic/snmp-pentesting/
		self.score["SNMP"] = 6
		with open(terms.working_folder + "snmp/snmp_attack.txt", "w") as f:
			f.write("SNMP // Simple Network Management Protocol\n")
			f.write("==================================================\n")
			f.write("As suggested by the name, SNMP provides a way to manage devices on a network and monitor them for issues. These can include IoT devices, computers, routers etc.\n")
			f.write("3 versions are currently available. Version 1 is still the most widely used, but is fraught with security issues due to its lack of authentication. These are improved in later versions.\n\n")
			f.write("SNMP Structure\n")
			f.write("==================================================\n")
			f.write("Much like the Linux file system, the SNMP structure is based on hierarchy. MIBs, or Management Information Bases hold the overall structure of the objects on the network. Within these, OIDs, or Object Identifirs, represent specific objects within that management information base.\n\n")
			f.write("Enumerating SNMP\n")
			f.write("==================================================\n")
			f.write("SNMP can be enumerated by using a tool called snmpwalk. Examples of usage can be seen below. The output from SNMP data can be intimidating, but services, user accounts and patches could all be identified if the service is misconfigured.\n\n")
			f.write("Example 1: Enumerating with standard community strings\n")
			f.write("snmpwalk -c public -t 10 -v1 <IP_ADDRESS>\n\n")
			f.write("Example 2: Using a discovered OID string to enumerate that specific identifier\n")
			f.write("snmpwalk -c public -v1 <IP_ADDRESS> 1.3.6.1.2.1.25.4.2.1.2\n\n")
			f.write("The examples above give the basic syntax, the string identifier will be uniquely changed to whatever the initial snmpwalk command finds so rememember to edit accordingly!\n")
			f.close()

# Here we will take the open ports and somehow work out some analysis of the most likely path to success 
class AttackPath():
	def __init__(self):
		self.path = ""

	def analyse_results(self):
		print(yellow + "[*] Now we've seen all the open ports, where should you start?!")
		print(green + "[*] I've been sorting the discovered ports into a list based on how likely you are to get information from them, the time they take to enumerate, and the overall severity of successfully exploiting the service!")
		input(yellow + "[?] Hit enter to view the order that I'd recommend! I'll write all this to a file too.")
		sorted_scores = dict(sorted(p.score.items(), key=lambda item: item[1], reverse=True)) #Sort the scores in descending order
		print(white + terms.border)
		print(green + "[*] -- Highest Rated Services -- [*]")
		with open(terms.working_folder + "enumeration_path.txt", "w") as f:
				f.write("[*] -- Highest Rated Services -- [*]\n")
				f.close()
		for key, value in sorted_scores.items():
			#Add description of why!
			print(yellow + "Service: " + blue + key)
			if key == "SMB":
				print(white + "The SMB service is rated high due to the fact so many vulnerabilties have stemmed from it, such as Eternal Blue, and the fact it is often configured to allow anonymous sessions which can provide lucrative information.\n")
			if key == "SNMP":
				print(white + "The SNMP service rated medium as it is often capable of providing in depth information about the target if it's not been properly configured.\n")
			if key == "ALTERNATIVE_WEBSERVER" or key == "HTTP" or key == "HTTPS":
				print(white + "Web servers are rated high due to the fact there is a broad attack surface and multiple attack vectors that rely on the websites developer ensuring that it is secure.\n")
			if key == "PPTP":
				print(white + "PPTP is rated low, despite it being traditionall insecure, as it's relatively uncommon to see and the primary attack vector is just a brute force.\n")
			if key == "IMAP":
				print(white + "IMAP is rated low due to the shortage of enumeration available on the service.\n")
			if key == "DNS":
				print(white + "DNS is rated medium due to the fact it can reveal large amounts of information about a target which can be used to paint a bigger picture about a targets overall infrastructure, but isn't quite as damaging as protocols such as SMB due to the fact DNS is all, for the most part, public information.\n")
			if key == "SSH":
				print(white + "SSH is rated medium due to the fact it's generally considered an extremely secure protocol. The weakness comes from the fact users can potentially use weak passwords. Due to it's nature, a compromised SSH service can lead to serious consequences.\n")
			if key == "RDP":
				print(white + "Similarly to SSH, RDP is rated medium due to the fact successful compromise of an RDP login will have serious consequences and it relies on the users settings strong passwords.\n")
			if key == "VNC":
				print(white + "VNC protocols offer an interesting attack base and they've been rated medium. There are multiple versions with vulnerabilities, and all old servers provide little to no defence against brute force attempts.\n")
			if key == "MYSQL":
				print(white + "With MySQL being a database, it makes sense to rate it relatively high due to the severity of consequences if it gets compromised. This could lead to consequences such as customer details being breached. Even worse, if the user re-uses passwords, the MySQL login could lead to even further damages.\n")
			if key == "SMTP":
				print(white + "SMTP is rated medium purely based on the fact it allows for potential username information, which and the information used can then be fed into other attack vectors such as brute forcing login protocols.\n")
			if key == "Telnet":
				print(white + "Telnet is rated medium because it can provide the functionality of banner grabbing against other services but the primary compromise is once again, a brute force, which is intermittent when using standard tools due to the way it handles lots of requests.\n")
			if key == "POP3":
				print(white + "Pop3 is rated low due to the lack of sensitive or device compromising information that can be gained from it.\n")
			if key == "FTP":
				print(white + "FTP is rated high because it is by definition, a file server, which might lead to exposure of sensitive information. Furthermore, it is commonly configured to allow anonymous access.\n")
			if key == "Netbios":
				print(white + "Netbios is considered low on the enumeration scale due to the fact an outfacing netbios port is not likely to contribute to system compromise, but it might provide information that can be used when attacking alternative services.\n")
			if key == "Rpcbind":
				print(white + "The portmapper (Rpcbind) is considered to be low on the enumeration scale because it does not, itself, post a security risk but can be more vulnerable when used in conjunction with something such as NFS, or Network File Service.\n")
			if key == "DCOM":
				print(white + "The msrpc protocol is considered low on the enumeration scale because of the technical knowledge needed to act upon enumeration results and the fact the information gathered may not be beneficial at all.\n")

			with open(terms.working_folder + "enumeration_path.txt", "a") as f:
				f.write("Service: " + key + "\n")
				f.close()
		print(red + "[!] -- Lowest Rated Services -- [!]")
		with open(terms.working_folder + "enumeration_path.txt", "a") as f:
				f.write("[!] -- Lowest Rated Services -- [!]\n")
				f.close()
		print(white + terms.border)
		au_revoir()

# End the program
def au_revoir():
	print(green + f"[*] That comes to the end of the TERMS functionality.\n{yellow}[*] I hope it helped in some sort of way, and remember, enumeration is a skill that you will develop over time. Understanding what to look for and where to look for it won't happen overnight, so keep at it and don't give up. Thanks! - Toby :)\n")
	sys.exit()


#Handle Ctrl-C gracefully
def handler(signal_received, frame):
	# Catch user exit
	print('\n' + red + '[!] CTRL-C detected. Exiting.')
	exit(0)


if __name__ in '__main__':

	#Catch user exit gracefully
	signal(SIGINT, handler)

	while True:

		#Set some pretty colours
		red = Fore.RED + Style.BRIGHT
		green = Fore.GREEN + Style.BRIGHT
		blue = Fore.CYAN + Style.BRIGHT
		yellow = Fore.YELLOW + Style.BRIGHT
		white = Fore.WHITE + Style.BRIGHT
		reset = Style.RESET_ALL
		init(autoreset=True)

		terms = Terms()
		p = Ports()
		a = AttackPath()
		terms.title()
		sys.exit()
		
		


