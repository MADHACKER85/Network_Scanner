

import scapy.all as scapy
import optparse

def header():
	print('''
===========[ N e t w o r k  s c a n n e r ]===========
Written by Substing, assignmnet 1 from a course by ZSecurity.
		''')

def get_argument():
	parser = optparse.OptionParser()

	parser.add_option("-t", "--target", dest ="target", help = "Target adress or adress range to scan")
	(option, argument) = parser.parse_args()
	if not option.target:
		parser.error("[-] Please specify a target address to scan --help for more info.")

	return option.target


def scan(ip):
	arp_request = scapy.ARP(pdst = ip)
	broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
	clients_list = []

	for element in answered_list:
		client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
		clients_list.append(client_dict)
	return(clients_list)

def print_result(results_list):
	print("IP\t\t\tMAC Address\n-----------------------------------------------")
	for client in results_list:
		print(client["ip"] + "\t\t" + client["mac"])


header()
ip = get_argument()
scan_result = scan(ip)
print_result(scan_result)