# protocol.py

import struct

HEADER_SIZE = 4

def send_frame(sock, data: bytes):
    length = len(data)
    header = struct.pack("!I", length)
    sock.sendall(header + data)

def recv_exact(sock, num_bytes: int) -> bytes:
    chunks = []

    bytes_received = 0

    while bytes_received < num_bytes:
        chunk = sock.recv(num_bytes - bytes_received)

        if chunk == b"":
            raise ConnectionError("Socket connection closed")

        chunks.append(chunk)
        bytes_received += len(chunk)

    return b"".join(chunks)

def recv_frame(sock) -> bytes:
    header = recv_exact(sock, HEADER_SIZE)
    length = struct.unpack("!I", header)[0]

    if length == 0:
        return b""

    return recv_exact(sock, length)