# DNS_Sniff
This program was designed to sniff DNS response packet on a Linux machine and print the domain and IP of each entry

To compile the program, run the following command:

gcc -o dns_sniffer dns_sniffer.c -lpcap

Then, execute the program using:

sudo ./dns_sniffer
