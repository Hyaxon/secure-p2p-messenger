# protocol.py

import struct
import json


HEADER_SIZE = 4


def send_frame(sock, data: bytes):
    """
    Send a length prefixed byte frame over a socket.
    """
    length = len(data)
    header = struct.pack("!I", length)
    sock.sendall(header + data)


def recv_exact(sock, num_bytes: int) -> bytes:
    """
    Receive exactly num_bytes from a socket.
    """
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
    """
    Receive a length prefixed byte frame from a socket.
    """
    header = recv_exact(sock, HEADER_SIZE)
    length = struct.unpack("!I", header)[0]

    if length == 0:
        return b""

    return recv_exact(sock, length)


def send_packet(sock, packet: dict):
    """
    Serialize a dictionary as JSON and send it as a framed packet.
    """
    data = json.dumps(packet).encode("utf-8")
    send_frame(sock, data)


def recv_packet(sock) -> dict:
    """
    Receive a framed JSON packet and deserialize it into a dictionary.
    """
    data = recv_frame(sock)
    return json.loads(data.decode("utf-8"))