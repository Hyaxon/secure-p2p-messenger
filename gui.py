# gui.py

import sys
from network import PeerToPeerConnection

from PySide6.QtCore import Signal
from PySide6.QtGui import QTextCursor, QTextCharFormat, QColor

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
    """
    GUI for the secure p2p messenger.

    The GUI collects connection information, starts host/client connections,
    sends messages, and displays plaintext, ciphertext, nonces, and status logs.
    """

    status_signal = Signal(str)
    message_signal = Signal(object)

    def __init__(self):
        """Initialize the GUI and connect network callbacks to Qt signals."""
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
        """Create and arrange all GUI widgets."""
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
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setEnabled(False)

        self.host_button.clicked.connect(self.on_host_clicked)
        self.connect_button.clicked.connect(self.on_connect_clicked)
        self.disconnect_button.clicked.connect(self.on_disconnect_clicked)

        connection_layout.addWidget(QLabel("IP:"))
        connection_layout.addWidget(self.ip_input)
        connection_layout.addWidget(QLabel("Port:"))
        connection_layout.addWidget(self.port_input)
        connection_layout.addWidget(QLabel("Password:"))
        connection_layout.addWidget(self.password_input)
        connection_layout.addWidget(self.host_button)
        connection_layout.addWidget(self.connect_button)
        connection_layout.addWidget(self.disconnect_button)

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
        self.set_disconnected_state()

    def on_host_clicked(self):
        """Validate input and start listening as the TCP host."""
        password = self.password_input.text()

        if not password:
            QMessageBox.critical(self, "Missing Password", "Password cannot be empty.")
            return

        try:
            port = int(self.port_input.text())
        except ValueError:
            QMessageBox.critical(self, "Invalid Port", "Port must be a number.")
            return

        self.set_connection_controls_enabled(False)
        self.disconnect_button.setEnabled(True)
        self.send_button.setEnabled(False)
        self.message_input.setEnabled(False)

        self.log("[SYSTEM] Starting host...", "gray")
        self.connection.start_host(port, password)

    def on_connect_clicked(self):
        """Validate input and connect to a TCP host."""
        ip = self.ip_input.text()
        password = self.password_input.text()

        if not password:
            QMessageBox.critical(self, "Missing Password", "Password cannot be empty.")
            return

        try:
            port = int(self.port_input.text())
        except ValueError:
            QMessageBox.critical(self, "Invalid Port", "Port must be a number.")
            return

        self.set_connection_controls_enabled(False)
        self.disconnect_button.setEnabled(True)
        self.send_button.setEnabled(False)
        self.message_input.setEnabled(False)

        self.status_label.setText(f"Status: Connecting to {ip}:{port}")
        self.log(f"[SYSTEM] Connecting to {ip}:{port}...", "gray")
        self.connection.connect_to_host(ip, port, password)

    def on_send_clicked(self):
        """Encrypt and send the typed message through the active connection."""
        message = self.message_input.text()

        if not message:
            return

        try:
            encrypted_payload = self.connection.send_text(message)

            self.log("-" * 60, "gray")
            self.log(f"[SENT PLAINTEXT] {message}")
            self.log(f"[SENT NONCE] {encrypted_payload['nonce']}", "gray")
            self.log(f"[SENT CIPHERTEXT] {encrypted_payload['ciphertext']}", "gray")

            self.message_input.clear()

        except Exception as e:
            QMessageBox.critical(self, "Send Error", str(e))

    def handle_network_status(self, message):
        """Forward network status updates to the GUI thread."""
        self.status_signal.emit(message)

    def handle_network_message(self, message):
        """Forward received message packets to the GUI thread."""
        self.message_signal.emit(message)

    def display_received_message(self, packet_info):
        """Display received ciphertext, nonce, key generation, and plaintext."""
        self.log("-" * 60, "gray")
        self.log(f"[RECEIVED CIPHERTEXT] {packet_info['ciphertext']}", "gray")
        self.log(f"[RECEIVED NONCE] {packet_info['nonce']}", "gray")
        self.log(f"[DECRYPTED PLAINTEXT] {packet_info['plaintext']}")
        self.log(f"[KEY GENERATION] {packet_info['rekey_counter']}", "gray")

    def set_connection_controls_enabled(self, enabled: bool):
        """Enable or disable connection-related inputs and buttons."""
        self.ip_input.setEnabled(enabled)
        self.port_input.setEnabled(enabled)
        self.password_input.setEnabled(enabled)
        self.host_button.setEnabled(enabled)
        self.connect_button.setEnabled(enabled)

    def set_connected_state(self):
        """Update the GUI for an active verified secure session."""
        self.set_connection_controls_enabled(False)
        self.disconnect_button.setEnabled(True)
        self.send_button.setEnabled(True)
        self.message_input.setEnabled(True)

    def set_disconnected_state(self):
        """Update the GUI for no active connection."""
        self.set_connection_controls_enabled(True)
        self.disconnect_button.setEnabled(False)
        self.send_button.setEnabled(False)
        self.message_input.setEnabled(False)

    def update_status_from_thread(self, message):
        """Display network status messages and update GUI connection state."""
        self.status_label.setText(f"Status: {message}")

        lowered = message.lower()
        is_error = (
            "disconnected" in lowered
            or "connection error" in lowered
            or "host error" in lowered
            or "failed" in lowered
            or "rejected" in lowered
        )

        self.log(f"[NETWORK] {message}", "red" if is_error else "gray")

        if "secure session verified" in lowered:
            self.set_connected_state()

        elif (
            "disconnected" in lowered
            or "connection error" in lowered
            or "host error" in lowered
        ):
            self.set_disconnected_state()

    def on_disconnect_clicked(self):
        """Close the current connection and reset the GUI."""
        self.connection.close()
        self.password_input.clear()
        self.status_label.setText("Status: Disconnected")
        self.log("[SYSTEM] Disconnected", "red")
        self.set_disconnected_state()

    def log(self, text, color=None):
        """Append a line to the log area with optional text color."""
        cursor = self.log_area.textCursor()
        cursor.movePosition(QTextCursor.End)

        text_format = QTextCharFormat()

        if color:
            text_format.setForeground(QColor(color))
        else:
            text_format.setForeground(self.log_area.palette().text().color())

        cursor.insertText(text + "\n", text_format)

        self.log_area.setTextCursor(cursor)
        self.log_area.ensureCursorVisible()

    def run(self):
        """Show the application window."""
        self.show()


def run_app():
    """Create the Qt application and start the GUI event loop."""
    app = QApplication(sys.argv)
    window = SecureMessengerGUI()
    window.run()
    sys.exit(app.exec())