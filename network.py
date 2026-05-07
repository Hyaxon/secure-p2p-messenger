import socket
import threading
import base64

from protocol import send_packet, recv_packet

from crypto_utils import (
    generate_salt,
    generate_session_id,
    derive_master_key,
    derive_session_key,
    encrypt_message,
    decrypt_message,
)

class PeerToPeerConnection:
    def __init__(self, on_status=None, on_message=None):
        self.socket = None
        self.server_socket = None 
        self.on_status = on_status 
        self.on_message = on_message
        self.running = False 

        self.password = None
        self.salt = None
        self.session_id = None
        self.master_key = None
        self.rekey_counter = 0
        self.session_key = None
        self.verified = False
        self.sent_message_count = 0
        self.rekey_every = 24

    def _status(self, message):
        if self.on_status:
            self.on_status(message)
    def _message(self, message):
        if self.on_message:
            self.on_message(message)

    def start_host(self, port, password):
        self.password = password 

        thread = threading.Thread(
            target=self._host_thread,
            args=(port,),
            daemon=True
        )

        thread.start()

    def _host_thread(self, port):

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", port))
            self.server_socket.listen(1)

            self._status(f"Hosting on port {port}. Waiting for connection...")

            client_socket, address = self.server_socket.accept()
            self.socket = client_socket
            self.running = True

            self._status(f"Connected to {address[0]}:{address[1]}")

            self.salt = generate_salt()
            self.session_id = generate_session_id()
            self.rekey_counter = 0
            self._derive_keys()

            setup_packet = {
                "type": "setup",
                "salt": base64.b64encode(self.salt).decode("ascii"),
                "session_id": base64.b64encode(self.session_id).decode("ascii"),
            }

            send_packet(self.socket, setup_packet)
            self._status("Sent setup packet. Waiting for encrypted client hello...")

            client_hello_packet = recv_packet(self.socket)

            if client_hello_packet.get("type") != "client_hello":
                raise ValueError("Expected client hello packet.")

            plaintext = decrypt_message(
                self.session_key,
                client_hello_packet["payload"],
                aad=b"client_hello"
            )

            if plaintext != "CLIENT_HELLO":
                raise ValueError("Invalid client hello.")

            server_hello_payload = encrypt_message(
                self.session_key,
                "SERVER_HELLO",
                aad=b"server_hello"
            )

            send_packet(self.socket, {
                "type": "server_hello",
                "payload": server_hello_payload,
            })

            self.verified = True
            self._status("Secure session verified.")
            self._start_receive_loop()

        except Exception as e:
            self.close()
            self._status(f"Host error: {e}")

    def connect_to_host(self, host_ip, port, password):
        self.password = password 

        thread = threading.Thread(
            target=self._connect_thread,
            args=(host_ip, port),
            daemon=True
        )

        thread.start()
    
    def _connect_thread(self, ip, port):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((ip, port))
            self.running = True

            self._status(f"Connected to {ip}:{port}")

            setup_packet = recv_packet(self.socket)

            if setup_packet.get("type") != "setup":
                raise ValueError("Expected setup packet.")

            self.salt = base64.b64decode(setup_packet["salt"])
            self.session_id = base64.b64decode(setup_packet["session_id"])
            self.rekey_counter = 0
            self._derive_keys()

            client_hello_payload = encrypt_message(
                self.session_key,
                "CLIENT_HELLO",
                aad=b"client_hello"
            )

            send_packet(self.socket, {
                "type": "client_hello",
                "payload": client_hello_payload,
            })

            server_hello_packet = recv_packet(self.socket)

            if server_hello_packet.get("type") != "server_hello":
                raise ValueError("Expected server hello packet.")

            plaintext = decrypt_message(
                self.session_key,
                server_hello_packet["payload"],
                aad=b"server_hello"
            )

            if plaintext != "SERVER_HELLO":
                raise ValueError("Invalid server hello.")

            self.verified = True
            self._status("Secure session verified.")

            self._start_receive_loop()
        except Exception as e:
            self.close()
            self._status(f"Connection error: {e}")

    def _start_receive_loop(self):
        thread = threading.Thread(
            target=self._receive_loop,
            daemon=True
        )
        thread.start()

    def _receive_loop(self):
        while self.running:
            try:
                packet = recv_packet(self.socket)

                packet_type = packet.get("type")

                if packet_type == "message":
                    packet_rekey_counter = packet["rekey_counter"]

                    if packet_rekey_counter < self.rekey_counter:
                        self._status(
                            f"Rejected message using old session key #{packet_rekey_counter}; "
                            f"current key is #{self.rekey_counter}"
                        )
                        continue

                    if packet_rekey_counter > self.rekey_counter:
                        self._update_session_key(packet_rekey_counter)
                        self._status(f"Updated to session key #{self.rekey_counter}")

                    aad = f"message:{packet_rekey_counter}".encode("utf-8")

                    plaintext = decrypt_message(
                        self.session_key,
                        packet["payload"],
                        aad=aad
                    )

                    self._message({
                        "plaintext": plaintext,
                        "ciphertext": packet["payload"]["ciphertext"],
                        "nonce": packet["payload"]["nonce"],
                        "rekey_counter": packet_rekey_counter,
                    })

                else:
                    self._status(f"Unknown packet type received: {packet_type}")
            except Exception as e:
                self.close()
                self._status(f"Disconnected: {e}")
                break

    def send_text(self, message: str):
        if not self.socket or not self.running:
            raise ConnectionError("Not connected")

        if not self.verified:
            raise ConnectionError("Secure session has not been verified.")

        if self.sent_message_count > 0 and self.sent_message_count % self.rekey_every == 0:
            self._update_session_key(self.rekey_counter + 1)
            self._status(f"Rekeyed to session key #{self.rekey_counter}")

        aad = f"message:{self.rekey_counter}".encode("utf-8")

        encrypted_payload = encrypt_message(
            self.session_key,
            message,
            aad=aad
        )

        packet = {
            "type": "message",
            "rekey_counter": self.rekey_counter,
            "payload": encrypted_payload,
        }

        send_packet(self.socket, packet)

        self.sent_message_count += 1

        return encrypted_payload

    def is_connected(self):
        return self.socket is not None and self.running and self.verified
    
    def _derive_keys(self):
        self.master_key = derive_master_key(self.password, self.salt)
        self.session_key = derive_session_key(
            self.master_key,
            self.session_id,
            self.rekey_counter
        )

    def _update_session_key(self, rekey_counter):
        self.rekey_counter = rekey_counter
        self.session_key = derive_session_key(
            self.master_key,
            self.session_id,
            self.rekey_counter
        )

    def close(self):
        self.running = False
        self.verified = False

        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None

        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
            self.server_socket = None