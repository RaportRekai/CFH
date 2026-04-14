import socket

CLIENT_IP  = '192.168.0.11'
CLIENT_PORT = 4791
HOST_IP = '192.168.0.16'
HOST_PORT = 10000

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST_IP, HOST_PORT))
    print(f"UDP listener bound on {(HOST_IP, HOST_PORT)}")

    while True:
        data, addr = s.recvfrom(1024)
        print(f"Received from {addr}: {data}")
        if not data:
            continue
        s.sendto(data, addr)