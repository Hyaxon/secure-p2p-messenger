import socket
import threading

from protocol import send_frame, recv_frame

class PeerToPeerConnection:
    def __init__(self, on_status=None, on_message=None):
        self.socket = None
        self.server_socket = None 
        self.on_status = on_status 
        self.on_message = on_message
        self.running = False 
    
    def _status(self, message):
        if self.on_status:
            self.on_status(message)
    def _message(self, message):
        if self.on_message:
            self.on_message(message)

    def start_host(self, port):
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
            self._start_receive_loop()

        except Exception as e:
            self._status(f"Host error: {e}")

    def connect_to_host(self, host_ip, port):
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
            self._start_receive_loop()
        except Exception as e:
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
                data = recv_frame(self.socket)
                message = data.decode("utf-8")
                self._message(message)
            except Exception as e:
                self.running = False
                self._status(f"Disconnected: {e}")
                break
            
    def send_text(self, message: str):
        if not self.socket:
            raise ConnectionError("Not connected")
        data = message.encode("utf-8")
        send_frame(self.socket, data) 

    def is_connected(self):
        return self.socket is not None
    
    def send_msg(self, data: bytes):
        pass
    def recieve_msg(self):
        pass
    