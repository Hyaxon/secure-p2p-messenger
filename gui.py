# gui.py

import sys
from network import PeerToPeerConnection

from PySide6.QtCore import Signal

from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
)


class SecureMessengerGUI(QWidget):
    status_signal = Signal(str)
    message_signal = Signal(str)

    def __init__(self):
        super().__init__()

        self.connection = PeerToPeerConnection(
            on_status=self.handle_network_status,
            on_message=self.handle_network_message
        )

        self.status_signal.connect(self.update_status_from_thread)
        self.message_signal.connect(self.display_received_message)

        self.setWindowTitle("Secure P2P Messenger")
        self.resize(800, 600)

        self.build_widgets()

    def build_widgets(self):
        main_layout = QVBoxLayout()

        connection_layout = QHBoxLayout()

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP Address")
        self.ip_input.setText("127.0.0.1")

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port")
        self.port_input.setText("5000")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.host_button = QPushButton("Host")
        self.connect_button = QPushButton("Connect")

        self.host_button.clicked.connect(self.on_host_clicked)
        self.connect_button.clicked.connect(self.on_connect_clicked)

        connection_layout.addWidget(QLabel("IP:"))
        connection_layout.addWidget(self.ip_input)
        connection_layout.addWidget(QLabel("Port:"))
        connection_layout.addWidget(self.port_input)
        connection_layout.addWidget(QLabel("Password:"))
        connection_layout.addWidget(self.password_input)
        connection_layout.addWidget(self.host_button)
        connection_layout.addWidget(self.connect_button)

        self.status_label = QLabel("Status: Not connected")

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)

        message_layout = QHBoxLayout()

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.on_send_clicked)

        message_layout.addWidget(self.message_input)
        message_layout.addWidget(self.send_button)

        main_layout.addLayout(connection_layout)
        main_layout.addWidget(self.status_label)
        main_layout.addWidget(self.log_area)
        main_layout.addLayout(message_layout)

        self.setLayout(main_layout)

    def on_host_clicked(self):
        try:
            port = int(self.port_input.text())
        except ValueError:
            QMessageBox.critical(self, "Invalid Port", "Port must be a number.")
            return

        #self.status_label.setText(f"Status: Hosting on port {port}")
        #self.log(f"[SYSTEM] Hosting on port {port}")
        self.connection.start_host(port)

    def on_connect_clicked(self):
        ip = self.ip_input.text()

        try:
            port = int(self.port_input.text())
        except ValueError:
            QMessageBox.critical(self, "Invalid Port", "Port must be a number.")
            return

        #self.status_label.setText(f"Status: Connecting to {ip}:{port}")
        #self.log(f"[SYSTEM] Connecting to {ip}:{port}")
        self.connection.connect_to_host(ip, port)

    def on_send_clicked(self):
        message = self.message_input.text()

        if not message:
            return

        try:
            self.connection.send_text(message)
            self.log(f"[SENT PLAINTEXT] {message}")
            self.message_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Send Error", str(e))

    def handle_network_status(self, message):
        self.status_signal.emit(message)

    def handle_network_message(self, message):
        self.message_signal.emit(message)

    def display_received_message(self, message):
        self.log(f"[RECEIVED PLAINTEXT] {message}")

    def update_status_from_thread(self, message):
        self.status_label.setText(f"Status: {message}")
        self.log(f"[NETWORK] {message}")

    def log(self, text):
        self.log_area.append(text)

    def run(self):
        self.show()


def run_app():
    app = QApplication(sys.argv)
    window = SecureMessengerGUI()
    window.run()
    sys.exit(app.exec())