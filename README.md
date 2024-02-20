# Monitoring of DHCP Communication

### author: Tomas Husar, xhusar11
### date: 17.11.2023

## Description
The program obtains statistics of the network prefixes based on the number of allocated IP addresses from interface or pcap file. 
When the prefix allocation exceeds 50, 75, 90 and 95% the program informs the administrator by logging through the syslog server.
After reading from a file, the program waits for a character input (or CTRL+C) to terminate itself. 
When obtaining packets from an interface, terminate the program with CTRL+C.

## Files

 - dhcp-stats.c
 - Makefile
 - dhcp-stats.1
 - manual.pdf
 - README (this file)

## Dependencies (Ununtu/Debian)

Program uses standard C, pcap, networking, packet handling and ncurses user interface libraries.

Make sure to install necessary libraries with:

	sudo apt-get install build-essential
		
	sudo apt-get install libpcap-dev

	sudo apt-get install libncurses5-dev libncursesw5-dev

## Setup

Make the project before running the program with:

	make

Clean program with:

	make clean

## Usage Examples

Run the program with following command:

	./dhcp-stats [-r <filename> | -i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]

	-r <filename> - statistics will be created from pcap file
	-i <interface> - interface on which the program will listen

	<ip-prefix> - network range, for which the statistics will be generated

Generating statistics from file:

	./dhcp-stats -r dhcp.pcapng 192.168.1.0/26 172.16.32.0/24 192.168.0.0/22

Generating statistics from interface:
	
	sudo ./dhcp-stats -i wlp13s0 192.168.1.0/26 172.16.32.0/24 192.168.0.0/22

## Output example:

	IP-Prefix Max-hosts Allocated addresses Utilization
	192.168.1.0/26 62 50 80.65%
	172.16.32.0/24 254 0 0.00%
	192.168.0.0/22 1022 50 4.89%

## Restrictions

 - Program generates statistics either from interface, or from file (it can not generate statistics when both are provided).
 - Valid prefix is in range from 1 to 30 (0 is default gateway, 31 and 32 have no ip addresses to allocate in subnet).


## Acknowledgements
https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-top
https://datatracker.ietf.org/doc/html/rfc2131
https://www.tcpdump.org/pcap.html
https://tldp.org/HOWTO/NCURSES-Programming-HOWTO/
https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#libpcap-installation
https://itecnote.com/tecnote/sockets-standard-safe-way-to-check-if-ip-address-is-in-range-subnet/
