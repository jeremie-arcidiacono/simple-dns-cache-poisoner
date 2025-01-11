# basic script that listen on port 53 (UDP) but never sends a response

import socket

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 53))

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            print(f"Received {data} from {addr}")
    except KeyboardInterrupt:
        print()
        print("[INFO] Exiting the program...")
        sock.close()
