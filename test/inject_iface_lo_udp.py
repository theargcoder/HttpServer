import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s.sendto(
    b"HELLO_FROM_AF_XDP",
    ("127.0.0.1", 443),
)
