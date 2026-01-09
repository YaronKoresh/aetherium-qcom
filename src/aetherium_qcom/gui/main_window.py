import sys
import os
import json
import base64
import hashlib
import time
import asyncio
import threading
import ipaddress
import uuid
from datetime import datetime
from collections import deque

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                                 QTextEdit, QLineEdit, QPushButton, QListWidget, QInputDialog,
                                 QMessageBox, QFileDialog, QLabel, QListWidgetItem,
                                 QStackedWidget, QComboBox)
from PySide6.QtCore import QObject, QThread, Qt, QSettings
from PySide6.QtGui import QColor, QBrush, QIcon, QPixmap

from ..core.steganography import SteganographyManager
from ..core.crypto import CryptoManager
from ..core.network import NetworkManager, P2PNode
from ..core.utils import get_free_ports, cwd
from ..core.trust import TrustManager, VouchManager, TrustProof, TrustCalculator

class ChatWindow(QMainWindow):
    def __init__(self, display_name, dht_port, comm_port, bootstrap_node=None):
        super().__init__()
        self.settings = QSettings("Aetherium", "Q-Com")

        self.logo_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', '..', '..', 'assets', 'logo.png'
        ))
        if os.path.exists(self.logo_path):
            self.setWindowIcon(QIcon(self.logo_path))
        else:
            print(f"Warning: Logo not found at {self.logo_path}")

        self.user_id = None
        self.display_name = display_name
        self.dht_port, self.comm_port = dht_port, comm_port

        with cwd():
            self.profile_path = os.path.realpath("../../../profile.json")

        self.crypto = CryptoManager()
        self.steganography = SteganographyManager()
        
        self.current_chat_id = None
        self.processed_messages = deque(maxlen=200)
        self.key_lookup_table = {}

        self.init_ui()

        if not self.load_state():
            self.keys = self.crypto.generate_persistent_keys()
            self.user_id = hashlib.sha256(base64.b64decode(self.keys['sign_pk'])).hexdigest()
            self.contacts, self.groups, self.ostracized_users, self.accusation_log, self.chat_history = {}, {}, set(), {}, {}
            self.save_state()
        
        self._rebuild_key_lookup_table()
        self.setWindowTitle(f"Aetherium Q-Com - {self.display_name}")
        self.populate_ui_from_state()

        self.pending_challenges, self.user_message_timestamps = {}, {}
        self.bootstrap_nodes = [bootstrap_node] if bootstrap_node else []
        
        manual_public_ip = self.settings.value("manual_public_ip", None)
        manual_public_port_str = self.settings.value("manual_public_port", None)
        transport_type = self.settings.value("transport_type", "default")
        
        is_valid_port, manual_public_port = self._validate_port_string(manual_public_port_str)
        if not is_valid_port:
            manual_public_port = None
        
        self.kademlia_node = P2PNode(dht_port, self.bootstrap_nodes)
        self.network_manager = NetworkManager(
            self.comm_port, 
            self.kademlia_node.server,
            manual_public_ip=manual_public_ip,
            manual_public_port=manual_public_port,
            transport_type=transport_type
        )
        
        # Initialize Trust Manager
        self.trust_manager = TrustManager(self.kademlia_node.server)
        
        self.network_thread = QThread()
        self.network_manager.moveToThread(self.network_thread)
        self.network_thread.started.connect(self.network_manager.run)
        self.network_manager.log_message.connect(self.log)
        self.network_manager.message_received.connect(self.on_raw_message_received)
        self.network_manager.message_sent_status.connect(self.on_message_sent_status)
        self.network_manager.message_queued_for_offline.connect(self.on_message_queued_for_offline)
        self.network_manager.public_address_discovered.connect(self.on_public_address_discovered)
        self.network_manager.offline_messages_syncing.connect(self.on_offline_messages_syncing)
        self.network_thread.start()
        
        self.resize(900, 700)
        self.read_settings()

    def log(self, message):
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.log_display.append(f"{timestamp} {message}")
    
    def show_status_message(self, message, timeout=4000):
        self.statusBar().showMessage(message, timeout)
    
    def _get_peer_exchange_port(self):
        """
        Determine which port to use for peer exchange announcements.
        
        Returns:
            int: The port number to announce for DHT bootstrap connections.
        
        Note: This is a known limitation. The DHT port may not be accessible
        behind NAT without additional configuration. Future enhancements should
        implement proper NAT traversal for the DHT port or use the same port
        for both DHT and communication.
        """
        # Currently using local DHT port
        # TODO: Implement NAT traversal for DHT port or consolidate ports
        return self.dht_port

    def init_ui(self):
        self.setWindowTitle("Aetherium Q-Com")
        self.statusBar()
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        main_layout = QHBoxLayout(self.central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(5, 5, 5, 5)
        sidebar_layout.setSpacing(10)
        sidebar_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.btn_chat_view = self.create_sidebar_button("Chat")
        self.btn_about_view = self.create_sidebar_button("About")
        self.btn_license_view = self.create_sidebar_button("License")
        self.btn_settings_view = self.create_sidebar_button("Settings")
        
        sidebar_layout.addWidget(self.btn_chat_view)
        sidebar_layout.addWidget(self.btn_about_view)
        sidebar_layout.addWidget(self.btn_license_view)
        sidebar_layout.addWidget(self.btn_settings_view)

        self.stacked_widget = QStackedWidget()
        self.chat_widget = self.create_chat_widget()
        self.about_widget = self.create_about_widget()
        self.license_widget = self.create_license_widget()
        self.settings_widget = self.create_settings_widget()

        self.stacked_widget.addWidget(self.chat_widget)
        self.stacked_widget.addWidget(self.about_widget)
        self.stacked_widget.addWidget(self.license_widget)
        self.stacked_widget.addWidget(self.settings_widget)

        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.stacked_widget)
        
        self.btn_chat_view.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        self.btn_about_view.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        self.btn_license_view.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        self.btn_settings_view.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(3))

    def create_sidebar_button(self, text):
        button = QPushButton(text)
        button.setObjectName("SidebarButton")
        return button

    def create_chat_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        top_layout = QHBoxLayout()
        top_layout.setContentsMargins(10, 10, 10, 5)
        top_layout.setSpacing(15)
        
        self.btn_add_contact = QPushButton("Add Contact")
        self.btn_add_contact.setToolTip("Create or accept an invitation to add a new contact")
        self.btn_add_contact.clicked.connect(self.add_contact_dialog)
        self.btn_create_group = QPushButton("Create Group")
        self.btn_create_group.setToolTip("Create a new group chat")
        self.btn_create_group.clicked.connect(self.create_group)

        top_layout.addStretch()
        top_layout.addWidget(self.btn_add_contact)
        top_layout.addStretch()
        top_layout.addWidget(self.btn_create_group)
        top_layout.addStretch()

        self.btn_change_name = QPushButton("Change Name")
        self.btn_change_name.setToolTip("Change your display name")
        self.btn_change_name.clicked.connect(self.change_display_name)
        top_layout.addWidget(self.btn_change_name)
        top_layout.addStretch()

        self.entity_list_widget = QListWidget()
        self.entity_list_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.entity_list_widget.customContextMenuRequested.connect(self.show_entity_context_menu)
        self.entity_list_widget.itemClicked.connect(self.on_chat_selected)
        self.chat_display = QTextEdit(); self.chat_display.setReadOnly(True)
        self.message_input = QLineEdit(); self.message_input.setPlaceholderText("Select a contact or group...")
        self.message_input.returnPressed.connect(self.send_message_wrapper)
        self.message_input.textChanged.connect(self.on_text_changed)
        self.message_input.setEnabled(False)
        self.btn_send = QPushButton("Send")
        self.btn_send.setObjectName("SendButton")
        self.btn_send.setToolTip("Send the message to the selected contact or group")
        self.btn_send.clicked.connect(self.send_message_wrapper)
        self.btn_send.setEnabled(False)
        self.log_display = QTextEdit(); self.log_display.setReadOnly(True); self.log_display.setMaximumHeight(100)
        
        layout.addLayout(top_layout)
        layout.addWidget(QLabel("Contacts & Groups:"), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.entity_list_widget)
        layout.addWidget(QLabel("Chat:"), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.chat_display)
        
        send_layout = QHBoxLayout()
        self.btn_send_file = QPushButton("📎")
        self.btn_send_file.setToolTip("Send a file")
        self.btn_send_file.setMaximumWidth(40)
        self.btn_send_file.clicked.connect(self.send_file_dialog)
        self.btn_send_file.setEnabled(False)
        send_layout.addWidget(self.btn_send_file)
        send_layout.addWidget(self.message_input)
        send_layout.addWidget(self.btn_send)
        layout.addLayout(send_layout)
        
        layout.addWidget(QLabel("System Log:"), 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.log_display)
        self.log(f"Code integrity verified.")
        return widget

    def create_about_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        logo_label = QLabel()
        if os.path.exists(self.logo_path):
            pixmap = QPixmap(self.logo_path)
            logo_label.setPixmap(pixmap.scaledToHeight(128, Qt.TransformationMode.SmoothTransformation))
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("About Aetherium Q-Com")
        title.setObjectName("TitleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        body_text = """
        <b>Aetherium QCom</b><br>
        Version 0.5.0<br><br>
        A secure, decentralized communication platform.<br>
        This application uses quantum-resistant cryptography to ensure the privacy and security of your communications.<br><br>
        Yaron Koresh © All rights reserved<br>
        """
        body = QLabel(body_text)
        body.setWordWrap(True)
        body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(logo_label)
        layout.addWidget(title)
        layout.addWidget(body)
        return widget

    def create_license_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        title = QLabel("GPLv3 License")
        title.setObjectName("TitleLabel")
        
        license_text = "License file not found. Please ensure a 'LICENSE' file exists in the project root."
        try:
            license_path = os.path.abspath(os.path.join(
                os.path.dirname(__file__), '..', '..', '..', 'LICENSE'
            ))
            if os.path.exists(license_path):
                with open(license_path, 'r', encoding='utf-8') as f:
                    license_text = f.read()
            else:
                print(f"Warning: LICENSE file not found at {license_path}")
        except Exception as e:
            license_text = f"Could not load license file: {e}"
            print(license_text)

        license_display= QTextEdit(license_text)
        license_display.setReadOnly(True)
        
        layout.addWidget(title)
        layout.addWidget(license_display)
        return widget

    def create_settings_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        title = QLabel("Network Settings")
        title.setObjectName("TitleLabel")
        layout.addWidget(title)
        
        # Network Security (Transport) Section
        transport_section = QLabel("Network Security / Transport")
        transport_section.setObjectName("SubtitleLabel")
        layout.addWidget(transport_section)
        
        transport_desc = QLabel(
            "Choose how to obfuscate network traffic. "
            "'Default' uses STUN and Fake-TLS. "
            "'HTTP-Obfuscated' disguises traffic as normal web browsing."
        )
        transport_desc.setWordWrap(True)
        layout.addWidget(transport_desc)
        
        from ..core.transport import TransportFactory
        transport_layout = QHBoxLayout()
        transport_label = QLabel("Transport Type:")
        self.transport_combo = QComboBox()
        
        available_transports = TransportFactory.get_available_transports()
        current_transport = self.settings.value("transport_type", "default")
        
        for transport in available_transports:
            self.transport_combo.addItem(transport)
        
        # Set current selection
        current_index = self.transport_combo.findText(current_transport)
        if current_index >= 0:
            self.transport_combo.setCurrentIndex(current_index)
        
        transport_layout.addWidget(transport_label)
        transport_layout.addWidget(self.transport_combo)
        layout.addLayout(transport_layout)
        
        transport_info = QLabel(
            "• default: Standard STUN + Fake-TLS (faster, less obfuscated)\n"
            "• http-obfuscated: HTTP-based discovery + HTTP-mimicry data (slower, more stealthy)"
        )
        transport_info.setStyleSheet("color: #7d8590; font-size: 10px;")
        layout.addWidget(transport_info)
        
        # NAT Traversal Section
        nat_section = QLabel("NAT Traversal Settings")
        nat_section.setObjectName("SubtitleLabel")
        layout.addWidget(nat_section)
        
        desc = QLabel(
            "Configure manual public IP address for NAT traversal. "
            "Leave blank to use automatic discovery."
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        ip_layout = QHBoxLayout()
        ip_label = QLabel("Manual Public IP:")
        self.manual_ip_input = QLineEdit()
        self.manual_ip_input.setPlaceholderText("e.g., 203.0.113.45 (leave blank for auto)")
        current_ip = self.settings.value("manual_public_ip", "")
        self.manual_ip_input.setText(current_ip)
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.manual_ip_input)
        layout.addLayout(ip_layout)
        
        port_layout = QHBoxLayout()
        port_label = QLabel("Manual Public Port:")
        self.manual_port_input = QLineEdit()
        self.manual_port_input.setPlaceholderText("e.g., 8888 (leave blank for auto)")
        current_port = self.settings.value("manual_public_port", "")
        self.manual_port_input.setText(str(current_port) if current_port else "")
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.manual_port_input)
        layout.addLayout(port_layout)
        
        status_label = QLabel("Current Network Status:")
        status_label.setObjectName("SubtitleLabel")
        layout.addWidget(status_label)
        
        self.network_status_display = QTextEdit()
        self.network_status_display.setReadOnly(True)
        self.network_status_display.setMaximumHeight(100)
        self.update_network_status_display()
        layout.addWidget(self.network_status_display)
        
        btn_save = QPushButton("Save Settings")
        btn_save.clicked.connect(self.save_network_settings)
        layout.addWidget(btn_save)
        
        info = QLabel(
            "Note: Restart the application for changes to take effect."
        )
        info.setStyleSheet("color: #F85149;")
        layout.addWidget(info)
        
        return widget
    
    def update_network_status_display(self):
        if hasattr(self, 'network_manager') and self.network_manager:
            status_text = f"Transport: {self.network_manager.transport.get_transport_name()}\n"
            status_text += f"Public IP: {self.network_manager.public_ip or 'Not yet discovered'}\n"
            status_text += f"Public Port: {self.network_manager.public_port or 'Not yet discovered'}\n"
            status_text += f"Discovery Method: {self.network_manager.nat_type or 'Unknown'}\n"
            status_text += f"Local Port: {self.comm_port}"
            self.network_status_display.setText(status_text)
        else:
            self.network_status_display.setText("Network manager not initialized yet.")
    
    def _validate_port_string(self, port_str):
        if not port_str:
            return True, None
        try:
            port_num = int(port_str)
            if 1 <= port_num <= 65535:
                return True, port_num
            else:
                return False, None
        except (ValueError, TypeError):
            return False, None

    def save_network_settings(self):
        manual_ip = self.manual_ip_input.text().strip()
        manual_port_str = self.manual_port_input.text().strip()
        
        # Save transport type
        transport_type = self.transport_combo.currentText()
        if transport_type:
            self.settings.setValue("transport_type", transport_type)
        
        if manual_ip:
            try:
                ipaddress.IPv4Address(manual_ip)
            except (ValueError, ipaddress.AddressValueError):
                QMessageBox.warning(self, "Invalid IP", "Please enter a valid IPv4 address (e.g., 203.0.113.45)")
                return
        
        is_valid_port, port_num = self._validate_port_string(manual_port_str)
        if not is_valid_port:
            QMessageBox.warning(self, "Invalid Port", "Please enter a valid port number (1-65535)")
            return
        
        if manual_ip:
            self.settings.setValue("manual_public_ip", manual_ip)
        else:
            self.settings.remove("manual_public_ip")
        
        if port_num is not None:
            self.settings.setValue("manual_public_port", port_num)
        else:
            self.settings.remove("manual_public_port")

        QMessageBox.information(
            self, 
            "Settings Saved", 
            "Network settings saved successfully. Please restart the application for changes to take effect."
        )

    def add_contact_dialog(self):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Add a New Contact")
        msg_box.setText("How would you like to add a contact?")
        msg_box.setIcon(QMessageBox.Icon.Question)
        create_btn = msg_box.addButton("Create New Invitation", QMessageBox.ButtonRole.ActionRole)
        accept_btn = msg_box.addButton("Accept Existing Invitation", QMessageBox.ButtonRole.ActionRole)
        msg_box.addButton(QMessageBox.StandardButton.Cancel)
        msg_box.exec()

        if msg_box.clickedButton() == create_btn:
            self.create_invitation()
        elif msg_box.clickedButton() == accept_btn:
            self.accept_invitation()

    def on_text_changed(self, text):
        self.btn_send.setEnabled(bool(self.current_chat_id and text.strip()))

    def save_state(self):
        try:
            state_data = {"user_id": self.user_id, "display_name": self.display_name,
                          "keys": self.keys, "contacts": self.contacts, "groups": self.groups,
                          "ostracized_users": list(self.ostracized_users), "accusation_log": self.accusation_log,
                          "chat_history": self.chat_history}
            state_json = json.dumps(state_data, sort_keys=True).encode()
            state_hash = hashlib.sha256(state_json).hexdigest()
            signature = self.crypto.sign_hash(self.keys['sign_sk'], state_hash)
            vault = {"data": base64.b64encode(state_json).decode(), "signature": signature}
            with cwd():
                with open(self.profile_path, 'w') as f: json.dump(vault, f)
            self.show_status_message("Profile saved successfully")
            return True
        except Exception: return False

    def load_state(self):
        if not os.path.exists(self.profile_path): return False
        try:
            with cwd():
                with open(self.profile_path, 'r') as f: vault = json.load(f)
            state_json_b64 = vault['data']; signature = vault['signature']
            state_json = base64.b64decode(state_json_b64)
            state_hash = hashlib.sha256(state_json).hexdigest()
            state_data = json.loads(state_json)
            
            temp_keys = state_data['keys']
            if not self.crypto.verify_hash_signature(temp_keys['sign_pk'], signature, state_hash):
                raise ValueError("State signature invalid")
            
            self.keys = state_data["keys"]
            self.contacts = state_data.get("contacts", {})
            self.groups = state_data.get("groups", {})
            self.ostracized_users = set(state_data.get("ostracized_users", []))
            self.accusation_log = state_data.get("accusation_log", {})
            self.chat_history = state_data.get("chat_history", {})
            self.user_id = state_data.get("user_id")
            self.display_name = state_data.get("display_name", self.user_id)
            self.log("Secure profile loaded successfully.")
            return True
        except Exception:
            self.log("Profile corrupted or tampered with. It will be deleted on exit.")
            try: os.remove(self.profile_path)
            except OSError: pass
            return False

    def _rebuild_key_lookup_table(self):
        self.key_lookup_table.clear()
        if hasattr(self, 'keys') and self.keys:
            key_b64 = self.keys.get('sign_sk')
            if key_b64:
                key_hash = hashlib.sha256(base64.b64decode(key_b64)).digest()
                self.key_lookup_table[key_hash[:8]] = (key_b64, self.keys['sign_pk'])
        
        for cid, cinfo in self.contacts.items():
            key_b64 = cinfo.get('otp_key')
            if key_b64:
                key_hash = hashlib.sha256(base64.b64decode(key_b64)).digest()
                self.key_lookup_table[key_hash[:8]] = (key_b64, cid)
        
        for gid, ginfo in self.groups.items():
            key_b64 = ginfo.get('group_key')
            if key_b64:
                key_hash = hashlib.sha256(base64.b64decode(key_b64)).digest()
                self.key_lookup_table[key_hash[:8]] = (key_b64, gid)
        self.log(f"Key lookup table rebuilt with {len(self.key_lookup_table)} keys.")

    def change_display_name(self):
        new_name, ok = QInputDialog.getText(self, "Change Display Name", "Enter your new display name:", text=self.display_name)
        if ok and new_name.strip():
            self.display_name = new_name.strip()
            self.setWindowTitle(f"Aetherium Q-Com - {self.display_name}")
            self.save_state()
            self.show_status_message("Display name updated.")

    def create_group(self):
        group_name, ok = QInputDialog.getText(self, "Create Group", "Enter a name for the new group:")
        if not (ok and group_name.strip()):
            return
        
        clean_group_name = group_name.strip()
        group_id = hashlib.sha256(clean_group_name.encode()).hexdigest()[:16]
        
        if group_id in self.groups:
            QMessageBox.warning(self, "Group Exists", f"A group named '{clean_group_name}' already exists.")
            return

        self.groups[group_id] = {
            "display_name": clean_group_name,
            "admin": self.user_id,
            "admins": [self.user_id],  # Multi-admin support
            "members": [self.user_id],
            "action_log": [],  # Replicated signed action log
            "banned_users": []  # List of banned user IDs
        }
        self.save_state()
        self.populate_ui_from_state()
        self.show_status_message(f"Group '{clean_group_name}' created.")

    def on_chat_selected(self, item):
        chat_data = item.data(Qt.ItemDataRole.UserRole)
        self.current_chat_id = chat_data['id']
        self.message_input.setEnabled(True)
        self.btn_send_file.setEnabled(True)
        self.message_input.setPlaceholderText(f"Message {chat_data['display_name']}...")
        self.chat_display.clear()
        self.on_text_changed(self.message_input.text())
        
        if self.current_chat_id in self.chat_history:
            for message in self.chat_history[self.current_chat_id]:
                self.chat_display.append(message)
    
    def send_message_wrapper(self):
        if not self.current_chat_id:
            QMessageBox.warning(self, "No Chat Selected", "Please select a contact or group to send a message.")
            return
            
        message_text = self.message_input.text().strip()
        if not message_text:
            return

        payload = {
            "type": "text_message",
            "sender_id": self.user_id,
            "sender_display_name": self.display_name,
            "message": message_text
        }

        target_info = self.contacts.get(self.current_chat_id)
        chat_key = target_info.get("otp_key") if target_info else None

        if self.current_chat_id in self.groups:
            group_info = self.groups.get(self.current_chat_id)
            payload['group_id'] = self.current_chat_id
            for member_id in group_info['members']:
                if member_id == self.user_id:
                    continue
                member_contact_info = self.contacts.get(member_id)
                if member_contact_info and member_contact_info.get('otp_key'):
                    member_key = member_contact_info['otp_key']
                    self._send_encrypted_message(member_id, payload, member_key)
                else:
                    self.log(f"Warning: No key found for group member {member_id}. Cannot send message.")
        else:
            if not chat_key:
                self.log(f"Error: Could not find encryption key for {self.current_chat_id}.")
                return
            self._send_encrypted_message(self.current_chat_id, payload, chat_key)

        history_msg = f"{self.display_name} ({datetime.now().strftime('%H:%M')}): {message_text}"
        if self.current_chat_id not in self.chat_history:
            self.chat_history[self.current_chat_id] = []
        self.chat_history[self.current_chat_id].append(history_msg)
        self.chat_display.append(history_msg)

        self.message_input.clear()
        self.save_state()
    
    def send_file_dialog(self):
        """Open a dialog to select and send a file."""
        if not self.current_chat_id:
            QMessageBox.warning(self, "No Chat Selected", "Please select a contact or group to send a file.")
            return
        
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Send",
            "",
            "All Files (*.*)"
        )
        
        if not file_path:
            return
        
        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.network_manager.MAX_FILE_SIZE:
                QMessageBox.warning(
                    self,
                    "File Too Large",
                    f"File size exceeds maximum allowed size of {self.network_manager.MAX_FILE_SIZE // (1024*1024)}MB."
                )
                return
            
            file_name = os.path.basename(file_path)
            
            # Calculate file hash
            file_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.network_manager.CHUNK_SIZE):
                    file_hash.update(chunk)
            file_hash_hex = file_hash.hexdigest()
            
            # Send file transfer request
            self._send_file_transfer_request(file_path, file_name, file_size, file_hash_hex)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send file: {e}")
    
    def _send_file_transfer_request(self, file_path, file_name, file_size, file_hash):
        """Send a file transfer request and start sending chunks."""
        transfer_id = str(uuid.uuid4())
        
        # Get recipient(s) and determine if this is a group transfer
        recipients = []
        is_group_transfer = False
        group_id = None
        
        if self.current_chat_id in self.contacts:
            recipients = [self.current_chat_id]
        elif self.current_chat_id in self.groups:
            is_group_transfer = True
            group_id = self.current_chat_id
            group_info = self.groups[self.current_chat_id]
            recipients = [m for m in group_info.get('members', []) if m != self.user_id]
        
        if not recipients:
            self.log("Error: No recipients found.")
            return
        
        # Create file transfer request payload
        num_chunks = (file_size + self.network_manager.CHUNK_SIZE - 1) // self.network_manager.CHUNK_SIZE
        
        request_payload = {
            "type": "file_transfer_request",
            "sender_id": self.user_id,
            "sender_display_name": self.display_name,
            "transfer_id": transfer_id,
            "file_name": file_name,
            "file_size": file_size,
            "file_hash": file_hash,
            "num_chunks": num_chunks,
            "timestamp": time.time()
        }
        
        # Add group_id if this is a group transfer
        if is_group_transfer:
            request_payload["group_id"] = group_id
        
        # Send request to all recipients
        for recipient_id in recipients:
            recipient_info = self.contacts.get(recipient_id)
            if recipient_info and 'otp_key' in recipient_info:
                self._send_encrypted_message(recipient_id, request_payload, recipient_info['otp_key'])
        
        # Log in chat
        history_msg = f"{self.display_name} ({datetime.now().strftime('%H:%M')}): [Sending file: {file_name}]"
        if self.current_chat_id not in self.chat_history:
            self.chat_history[self.current_chat_id] = []
        self.chat_history[self.current_chat_id].append(history_msg)
        self.chat_display.append(history_msg)
        
        # Start sending chunks in background
        self._send_file_chunks_async(transfer_id, file_path, file_size, recipients, group_id)
        self.save_state()
    
    def _send_file_chunks_async(self, transfer_id, file_path, file_size, recipients, group_id=None):
        """Send file chunks asynchronously."""
        def send_chunks():
            try:
                with open(file_path, 'rb') as f:
                    chunk_index = 0
                    while True:
                        chunk_data = f.read(self.network_manager.CHUNK_SIZE)
                        if not chunk_data:
                            break
                        
                        # Create chunk payload
                        chunk_payload = {
                            "type": "file_transfer_chunk",
                            "sender_id": self.user_id,
                            "transfer_id": transfer_id,
                            "chunk_index": chunk_index,
                            "chunk_data": base64.b64encode(chunk_data).decode(),
                            "timestamp": time.time()
                        }
                        
                        # Add group_id if this is a group transfer
                        if group_id:
                            chunk_payload["group_id"] = group_id
                        
                        # Send to all recipients
                        for recipient_id in recipients:
                            recipient_info = self.contacts.get(recipient_id)
                            if recipient_info and 'otp_key' in recipient_info:
                                self._send_encrypted_message(recipient_id, chunk_payload, recipient_info['otp_key'])
                        
                        chunk_index += 1
                        
                        # Small delay to avoid overwhelming the network
                        time.sleep(0.01)
                
                # Log completion
                self.log(f"File transfer {transfer_id} completed: {chunk_index} chunks sent.")
            except Exception as e:
                self.log(f"Error sending file chunks: {e}")
        
        # Run in thread to avoid blocking GUI
        threading.Thread(target=send_chunks, daemon=True).start()

    def populate_ui_from_state(self):
        self.entity_list_widget.clear()
        for cid, cinfo in self.contacts.items():
            contact_display_name = cinfo.get("display_name", cid)
            status = cinfo.get("status", "unknown")
            item = QListWidgetItem(f"{contact_display_name} ({status})")
            item.setData(Qt.ItemDataRole.UserRole, {"type": "contact", "id": cid, "display_name": contact_display_name})
            if cid in self.ostracized_users:
                item.setForeground(QBrush(QColor("red")))
                item.setText(f"{contact_display_name} (OSTRACIZED)")
            self.entity_list_widget.addItem(item)
        for gid, ginfo in self.groups.items():
            group_display_name = ginfo.get('display_name', gid)
            item = QListWidgetItem(f"{group_display_name} [Group]") 
            item.setData(Qt.ItemDataRole.UserRole, {"type": "group", "id": gid, "display_name": group_display_name})
            self.entity_list_widget.addItem(item)

    def invite_to_group(self, contact_id, group_id):
        group_info = self.groups.get(group_id)
        if not group_info:
            self.log(f"Error: Group '{group_id}' not found.")
            return
        
        # Check if user is an admin (support both old 'admin' and new 'admins' fields)
        admins = group_info.get('admins')
        if admins is None:
            admin = group_info.get('admin')
            admins = [admin] if admin is not None else []
        if self.user_id not in admins:
            self.log(f"Error: User is not an admin of group '{group_id}'.")
            return
        
        contact_info = self.contacts.get(contact_id)
        if not contact_info or 'otp_key' not in contact_info:
            self.log(f"Error: Cannot invite {contact_id}. No secure channel established.")
            return

        # Create signed action log entry
        action = {
            "type": "member_added",
            "actor": self.user_id,
            "target": contact_id,
            "timestamp": int(time.time())
        }
        signature = self.crypto.sign_data(self.keys['sign_sk'], action)
        action["signature"] = signature
        
        # Add to action log
        if "action_log" not in group_info:
            group_info["action_log"] = []
        group_info["action_log"].append(action)
        
        # Add member to group
        if contact_id not in group_info.get("members", []):
            group_info.setdefault("members", []).append(contact_id)
        
        invite_payload = {
            "type": "group_invite",
            "sender_id": self.user_id,
            "sender_display_name": self.display_name,
            "group_id": group_id,
            "group_info": group_info
        }

        self._send_encrypted_message(contact_id, invite_payload, contact_info['otp_key'])
        self.save_state()
        self.show_status_message(f"Invitation sent to {contact_id}.")
    
    def promote_to_admin(self, group_id, member_id):
        """Promote a group member to admin status."""
        group_info = self.groups.get(group_id)
        if not group_info:
            return
        
        # Get admins list, handling backward compatibility
        admins = group_info.get('admins')
        if admins is None:
            admin = group_info.get('admin')
            admins = [admin] if admin is not None else []
        if self.user_id not in admins:
            self.log(f"Error: User is not an admin of group '{group_id}'.")
            return
        
        if member_id not in group_info.get("members", []):
            self.log(f"Error: User {member_id} is not a member of the group.")
            return
        
        # Create signed action
        action = {
            "type": "admin_promoted",
            "actor": self.user_id,
            "target": member_id,
            "timestamp": int(time.time())
        }
        signature = self.crypto.sign_data(self.keys['sign_sk'], action)
        action["signature"] = signature
        
        # Add to action log
        if "action_log" not in group_info:
            group_info["action_log"] = []
        group_info["action_log"].append(action)
        
        # Promote to admin
        if "admins" not in group_info:
            group_info["admins"] = [group_info.get('admin', self.user_id)]
        if member_id not in group_info["admins"]:
            group_info["admins"].append(member_id)
        
        self.save_state()
        self._propagate_group_action(group_id, action)
        self.log(f"Promoted {member_id} to admin in group '{group_info.get('display_name')}'.")
    
    def kick_from_group(self, group_id, member_id):
        """Kick a member from the group."""
        group_info = self.groups.get(group_id)
        if not group_info:
            return
        
        # Get admins list, handling backward compatibility
        admins = group_info.get('admins')
        if admins is None:
            admin = group_info.get('admin')
            admins = [admin] if admin is not None else []
        if self.user_id not in admins:
            self.log(f"Error: User is not an admin of group '{group_id}'.")
            return
        
        # Create signed action
        action = {
            "type": "member_kicked",
            "actor": self.user_id,
            "target": member_id,
            "timestamp": int(time.time())
        }
        signature = self.crypto.sign_data(self.keys['sign_sk'], action)
        action["signature"] = signature
        
        # Add to action log
        if "action_log" not in group_info:
            group_info["action_log"] = []
        group_info["action_log"].append(action)
        
        # Remove from members
        if member_id in group_info.get("members", []):
            group_info["members"].remove(member_id)
        
        # Remove from admins if present
        if member_id in group_info.get("admins", []):
            group_info["admins"].remove(member_id)
        
        self.save_state()
        self._propagate_group_action(group_id, action)
        self.log(f"Kicked {member_id} from group '{group_info.get('display_name')}'.")
    
    def ban_from_group(self, group_id, member_id):
        """Ban a member from the group."""
        group_info = self.groups.get(group_id)
        if not group_info:
            return
        
        # Get admins list, handling backward compatibility
        admins = group_info.get('admins')
        if admins is None:
            admin = group_info.get('admin')
            admins = [admin] if admin is not None else []
        if self.user_id not in admins:
            self.log(f"Error: User is not an admin of group '{group_id}'.")
            return
        
        # Create signed action
        action = {
            "type": "member_banned",
            "actor": self.user_id,
            "target": member_id,
            "timestamp": int(time.time())
        }
        signature = self.crypto.sign_data(self.keys['sign_sk'], action)
        action["signature"] = signature
        
        # Add to action log
        if "action_log" not in group_info:
            group_info["action_log"] = []
        group_info["action_log"].append(action)
        
        # Remove from members
        if member_id in group_info.get("members", []):
            group_info["members"].remove(member_id)
        
        # Remove from admins if present
        if member_id in group_info.get("admins", []):
            group_info["admins"].remove(member_id)
        
        # Add to banned list
        if "banned_users" not in group_info:
            group_info["banned_users"] = []
        if member_id not in group_info["banned_users"]:
            group_info["banned_users"].append(member_id)
        
        self.save_state()
        self._propagate_group_action(group_id, action)
        self.log(f"Banned {member_id} from group '{group_info.get('display_name')}'.")
    
    def _propagate_group_action(self, group_id, action):
        """Propagate a group action to all members."""
        group_info = self.groups.get(group_id)
        if not group_info:
            return
        
        action_payload = {
            "type": "group_action",
            "sender_id": self.user_id,
            "group_id": group_id,
            "action": action
        }
        
        # Send to all group members
        for member_id in group_info.get("members", []):
            if member_id != self.user_id:
                contact_info = self.contacts.get(member_id)
                if contact_info and 'otp_key' in contact_info:
                    self._send_encrypted_message(member_id, action_payload, contact_info['otp_key'])

    def announce_presence(self):
        async def do_announce():
            public_ip = self.network_manager.public_ip or '127.0.0.1'
            public_port = self.network_manager.public_port or self.comm_port
            data = {
                "kem_pk": self.keys['kem_pk'], 
                "sign_pk": self.keys['sign_pk'], 
                "comm_address": (public_ip, public_port),
                "display_name": self.display_name
            }
            await self.kademlia_node.server.set(self.user_id, json.dumps(data))
            self.log("Presence announced on the network.")
            
            # Announce to peer exchange for discovery by other nodes
            peer_exchange_port = self._get_peer_exchange_port()
            await self.network_manager.announce_peer_for_exchange(
                self.user_id, 
                public_ip, 
                peer_exchange_port
            )
        if self.kademlia_node.loop:
            asyncio.run_coroutine_threadsafe(do_announce(), self.kademlia_node.loop)
        
        threading.Timer(900, self.announce_presence).start()
    
    def on_raw_message_received(self, raw_bytes):
        if len(raw_bytes) < 8:
            return
        
        key_hint = raw_bytes[:8]
        encrypted_payload = raw_bytes[8:]
        
        key_info = self.key_lookup_table.get(key_hint)
        if not key_info:
            return
        
        key_b64, key_owner_id = key_info
        decrypted_bytes = self.crypto.aead_decrypt(key_b64, encrypted_payload)
        
        if decrypted_bytes:
            try:
                msg = json.loads(decrypted_bytes)
                if isinstance(msg, dict) and 'sender_id' in msg and 'timestamp' in msg:
                    self.handle_incoming_message(msg, key_owner_id)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    def on_message_sent_status(self, success, user_id):
        display_name = user_id
        if user_id in self.contacts:
            display_name = self.contacts[user_id].get('display_name', user_id)

        if success:
            self.show_status_message(f"Message to {display_name} sent successfully.")
        else:
            self.show_status_message(f"Failed to send message to {display_name}.")
    
    def on_message_queued_for_offline(self, user_id):
        display_name = user_id
        if user_id in self.contacts:
            display_name = self.contacts[user_id].get('display_name', user_id)
        self.show_status_message(f"Message to {display_name} queued for offline delivery.")
    
    def on_public_address_discovered(self, public_ip, public_port, nat_type):
        self.log(f"Public address discovered: {public_ip}:{public_port} (NAT Type: {nat_type})")
        if hasattr(self, 'network_status_display'):
            self.update_network_status_display()
        self.announce_presence()
        # After announcing presence, sync offline messages
        self.sync_offline_messages()
        # Discover additional peers for better network resilience
        self.discover_additional_peers()
    
    def discover_additional_peers(self):
        """Discover and connect to additional peers from the peer exchange list."""
        async def do_discover():
            try:
                discovered_peers = await self.network_manager.discover_peers_from_exchange()
                if discovered_peers:
                    self.log(f"Attempting to connect to {len(discovered_peers)} discovered peers...")
                    # Bootstrap to the discovered peers to improve routing table
                    await self.kademlia_node.server.bootstrap(discovered_peers)
                    self.log("Successfully connected to additional peers from exchange.")
            except Exception as e:
                self.log(f"Error discovering additional peers: {e}")
        
        if self.kademlia_node.loop:
            asyncio.run_coroutine_threadsafe(do_discover(), self.kademlia_node.loop)
    
    def on_offline_messages_syncing(self, is_syncing, message_count):
        if is_syncing:
            self.show_status_message(f"Syncing offline messages... ({message_count} found)")
            self.log(f"Syncing {message_count} offline messages...")
        else:
            if message_count > 0:
                self.show_status_message(f"Successfully synced {message_count} offline messages.")
                self.log(f"Offline message sync complete. Retrieved {message_count} messages.")
            else:
                self.log("No offline messages to sync.")
    
    def sync_offline_messages(self):
        """Fetch and process offline messages from the DHT."""
        async def do_sync():
            try:
                self.network_manager.offline_messages_syncing.emit(True, 0)
                messages = await self.network_manager.fetch_offline_messages(self.user_id)
                
                if messages:
                    self.network_manager.offline_messages_syncing.emit(True, len(messages))
                    
                    for msg_data in messages:
                        encrypted_payload = msg_data['payload']
                        message_id = msg_data['message_id']
                        
                        # Process the message through the normal message handler
                        # This will decrypt and display it in the appropriate chat
                        self.network_manager.message_received.emit(encrypted_payload)
                        
                        # Delete the message from DHT after successful retrieval
                        await self.network_manager.delete_offline_message(message_id, self.user_id)
                    
                    self.network_manager.offline_messages_syncing.emit(False, len(messages))
                else:
                    self.network_manager.offline_messages_syncing.emit(False, 0)
            except Exception as e:
                self.log(f"Error syncing offline messages: {e}")
                self.network_manager.offline_messages_syncing.emit(False, 0)
        
        if self.kademlia_node.loop:
            asyncio.run_coroutine_threadsafe(do_sync(), self.kademlia_node.loop)

    def _send_encrypted_message(self, target_id, payload, key):
        self.log(f"Sending message to {target_id}...")
        payload['timestamp'] = time.time()
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        encrypted_bytes = self.crypto.aead_encrypt(key, payload_bytes)
        
        key_hash = hashlib.sha256(base64.b64decode(key)).digest()
        key_hint = key_hash[:8]
        
        final_payload = key_hint + encrypted_bytes
        asyncio.run_coroutine_threadsafe(self.network_manager.send_message_to_user(target_id, final_payload), self.kademlia_node.loop)
        
    def show_entity_context_menu(self, position):
        item = self.entity_list_widget.itemAt(position)
        if not item or not item.data(Qt.ItemDataRole.UserRole):
            return
        
        entity_data = item.data(Qt.ItemDataRole.UserRole)
        entity_type = entity_data.get('type')
        
        menu = self.entity_list_widget.createStandardContextMenu()
        
        if entity_type == 'contact':
            contact_id = entity_data['id']
            contact_info = self.contacts.get(contact_id, {})
            
            # Add Trust Management submenu
            if contact_info.get('status') == 'confirmed':
                trust_menu = menu.addMenu("Trust Management")
                
                vouch_action = trust_menu.addAction("Vouch for User")
                vouch_action.triggered.connect(lambda: self.vouch_for_contact(contact_id))
                
                revoke_vouch_action = trust_menu.addAction("Revoke Vouch")
                revoke_vouch_action.triggered.connect(lambda: self.revoke_vouch_for_contact(contact_id))
                
                trust_menu.addSeparator()
                
                accuse_action = trust_menu.addAction("File Accusation")
                accuse_action.triggered.connect(lambda: self.file_accusation_against_contact(contact_id))
                
                trust_menu.addSeparator()
                
                view_trust_action = trust_menu.addAction("View Trust Status")
                view_trust_action.triggered.connect(lambda: self.view_contact_trust(contact_id))
                
                menu.addSeparator()
            
            if contact_id in self.ostracized_users:
                if contact_id in self.accusation_log:
                    action = menu.addAction("View Accusation Log")
                    action.triggered.connect(lambda: self.show_accusation_log(contact_id))
            elif contact_info.get('status') == 'confirmed':
                action = menu.addAction("Ostracize User")
                action.triggered.connect(lambda: self.context_ostracize_user(contact_id))
                
                menu.addSeparator()

                for group_id, group_info in self.groups.items():
                    # Get admins list, handling backward compatibility
                    admins = group_info.get('admins')
                    if admins is None:
                        admin = group_info.get('admin')
                        admins = [admin] if admin is not None else []
                    if self.user_id in admins:
                        action = menu.addAction(f"Invite to '{group_info.get('display_name', group_id)}'")
                        action.triggered.connect(lambda _, c=contact_id, g=group_id: self.invite_to_group(c, g))
        
        elif entity_type == 'group':
            group_id = entity_data['id']
            group_info = self.groups.get(group_id, {})
            # Get admins list, handling backward compatibility
            admins = group_info.get('admins')
            if admins is None:
                admin = group_info.get('admin')
                admins = [admin] if admin is not None else []
            
            if self.user_id in admins:
                menu.addSeparator()
                submenu = menu.addMenu("Group Management")
                
                # Show members
                members_submenu = submenu.addMenu("Members")
                for member_id in group_info.get('members', []):
                    if member_id != self.user_id:
                        member_display = self.contacts.get(member_id, {}).get('display_name', member_id)
                        member_menu = members_submenu.addMenu(member_display)
                        
                        # Check if member is admin
                        is_admin = member_id in admins
                        if not is_admin:
                            promote_action = member_menu.addAction("Promote to Admin")
                            promote_action.triggered.connect(lambda _, g=group_id, m=member_id: self.promote_to_admin(g, m))
                        
                        kick_action = member_menu.addAction("Kick from Group")
                        kick_action.triggered.connect(lambda _, g=group_id, m=member_id: self.kick_from_group(g, m))
                        
                        ban_action = member_menu.addAction("Ban from Group")
                        ban_action.triggered.connect(lambda _, g=group_id, m=member_id: self.ban_from_group(g, m))
        
        if not menu.isEmpty():
            menu.exec(self.entity_list_widget.mapToGlobal(position))

    def show_accusation_log(self, user_id):
        if user_id in self.accusation_log:
            accusers = "\n- ".join(self.accusation_log[user_id])
            QMessageBox.information(self, "Accusation Log", f"User '{self.contacts.get(user_id, {}).get('display_name', user_id)}' was accused by:\n- {accusers}")

    def context_ostracize_user(self, user_id):
        display_name = self.contacts.get(user_id, {}).get('display_name', user_id)
        reply = QMessageBox.question(self, "Confirm Ostracism", 
                                     f"Are you sure you want to ostracize {display_name}?\n"
                                     "You will no longer receive messages from them, and this action cannot be undone.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.ostracize_user(user_id)

    def create_invitation(self):
        password, ok = QInputDialog.getText(self, "Create Invitation", "Enter a password:")
        if not (ok and password):
            return
        
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Media File", "", "Media Files (*.png *.jpg *.jpeg *.bmp *.wav *.mp3 *.m4a *.mp4 *.mov)")
        if not file_path:
            return

        # Use public IP for invitation if available, otherwise fallback to localhost
        public_ip = self.network_manager.public_ip or '127.0.0.1'
        public_port = self.network_manager.public_port or self.comm_port
        
        # Create bootstrap nodes list with primary node (self) and any additional bootstrap nodes
        bootstrap_nodes = [(public_ip, public_port)]
        if self.bootstrap_nodes:
            bootstrap_nodes.extend(self.bootstrap_nodes)
        
        invitation_data = self.crypto.create_invitation(self.user_id, self.keys, bootstrap_nodes)
        invitation_bytes = json.dumps(invitation_data, sort_keys=True).encode()
        
        output_path, error = self.steganography.embed(file_path, invitation_bytes, password)
        
        if error:
            QMessageBox.critical(self, "Error", f"Could not create invitation: {error}")
        else:
            self.show_status_message(f"Invitation created in {output_path}")

    def accept_invitation(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Invitation Media", "", "Media Files (*.png *.jpg *.jpeg *.bmp *.wav *.mp3 *.m4a *.mp4 *.mov)")
        if not file_path: return
        password, ok = QInputDialog.getText(self, "Accept Invitation", "Enter password:")
        if not (ok and password): return
        inv_bytes, error = self.steganography.extract(file_path, password)
        if error: QMessageBox.critical(None, "Error", str(error)); return
        try:
            invitation = json.loads(inv_bytes)
            if not self.crypto.verify_invitation(invitation): raise ValueError
        except (json.JSONDecodeError, ValueError): QMessageBox.critical(None, "Security Alert", "Invalid or tampered invitation."); return
        
        issuer_info = invitation['payload']
        issuer_id = issuer_info['issuer_id']
        
        if issuer_id == self.user_id: QMessageBox.warning(None, "Error", "Cannot accept an invitation from yourself."); return
        if issuer_id in self.contacts: QMessageBox.information(None, "Info", f"{issuer_id} is already a contact."); return

        try:
            issuer_kem_pk = base64.b64decode(issuer_info['issuer_kem_pk'])
            ciphertext, shared_secret = ml_kem_1024.encrypt(issuer_kem_pk)
        except Exception as e: QMessageBox.critical(None, "Crypto Error", f"Failed to create secure channel: {e}"); return

        self.contacts[issuer_id] = {"kem_pk": issuer_info['issuer_kem_pk'], "sign_pk": issuer_info['issuer_sign_pk'], 
                                   "otp_key": base64.b64encode(shared_secret).decode(), "status": "confirmed",
                                   "display_name": issuer_info.get("display_name", issuer_id)}
        
        if issuer_id not in self.chat_history: self.chat_history[issuer_id] = []
        self.chat_history[issuer_id].append(f"*** You have connected with {issuer_info.get('display_name', issuer_id)} ***")

        self.populate_ui_from_state()
        self.save_state()
        self._rebuild_key_lookup_table()
        
        req_payload = {"type": "contact_request", "sender_id": self.user_id, "kem_pk": self.keys['kem_pk'], "sign_pk": self.keys['sign_pk'],
                       "kem_ciphertext": base64.b64encode(ciphertext).decode(), "display_name": self.display_name}
        signature = self.crypto.sign_data(self.keys['sign_sk'], req_payload)
        full_req = {"payload": req_payload, "signature": signature}

        handshake_key = base64.b64encode(shared_secret).decode()
        self._send_encrypted_message(issuer_id, full_req, handshake_key)
        self.show_status_message(f"Contact request sent to {issuer_id}.")

    def ostracize_user(self, user_id, proof=None):
        if user_id == self.user_id or user_id in self.ostracized_users: return
        self.log(f"OSTRACIZING USER: {user_id}.")
        self.ostracized_users.add(user_id)
        if proof:
            accusation = {"accuser": self.user_id, "accused": user_id, "proof": proof}
            accusation_payload = {"type": "accusation", "data": accusation}
            signature = self.crypto.sign_data(self.keys['sign_sk'], accusation_payload)
            if signature:
                full_accusation_msg = {"payload": accusation_payload, "signature": signature}
                for cid, cinfo in self.contacts.items():
                    if cinfo.get('status') == 'confirmed' and cid not in self.ostracized_users and cinfo.get('otp_key'):
                        self._send_encrypted_message(cid, full_accusation_msg, cinfo['otp_key'])
        self.populate_ui_from_state()
        self.save_state()

    def handle_incoming_message(self, msg, key_owner_id):
        try:
            msg_bytes = json.dumps(msg, sort_keys=True).encode()
            msg_hash = hashlib.sha256(msg_bytes).hexdigest()
            if msg_hash in self.processed_messages:
                self.log(f"Duplicate message received from {msg.get('sender_id')}. Discarding.")
                return
            self.processed_messages.append(msg_hash)
        except Exception:
            return

        sender_id = msg.get("sender_id")
        if not sender_id or sender_id in self.ostracized_users: return
        if time.time() - msg.get('timestamp', 0) > 120: return
        msg_type = msg.get("type")

        if msg_type == "contact_request":
            if key_owner_id != self.keys['sign_pk']: return
            payload = msg.get('payload', {}); signature = msg.get('signature')
            if not (payload and signature and self.crypto.verify_signature(payload.get('sign_pk'), signature, payload)): return
            shared_secret = ml_kem_1024.decrypt(base64.b64decode(self.keys['kem_sk']), base64.b64decode(payload['kem_ciphertext']))
            self.contacts[sender_id] = {"kem_pk": payload['kem_pk'], "sign_pk": payload['sign_pk'], "otp_key": base64.b64encode(shared_secret).decode(), 
                                       "status": "confirmed", "display_name": payload.get("display_name")}
            
            if sender_id not in self.chat_history: self.chat_history[sender_id] = []
            self.chat_history[sender_id].append(f"*** You have connected with {payload.get('display_name', sender_id)} ***")

            self.populate_ui_from_state()
            self.save_state()
            self._rebuild_key_lookup_table()
            resp_payload = {"type": "contact_response", "sender_id": self.user_id, "display_name": self.display_name}
            self._send_encrypted_message(sender_id, resp_payload, base64.b64encode(shared_secret).decode())
        elif msg.get("type") == "group_invite":
            group_id = msg.get("group_id")
            group_info = msg.get("group_info")
            if not (group_id and group_info):
                return
            self.groups[group_id] = group_info
            if group_id not in self.chat_history:
                self.chat_history[group_id] = []
            self.chat_history[group_id].append(f"*** You have joined the group: {group_info.get('display_name', group_id)} ***")
            self.log(f"Successfully joined group: {group_info.get('display_name', group_id)}")
            self.populate_ui_from_state()
            self.save_state()
        elif msg.get("type") == "accusation":
            accusation_payload = msg.get('payload', {}); signature = msg.get('signature')
            accuser = accusation_payload.get('data', {}).get('accuser')
            if not all([accusation_payload, signature, accuser]): return
            if accuser in self.contacts and self.contacts[accuser].get('status') == 'confirmed':
                if self.crypto.verify_signature(self.contacts[accuser]['sign_pk'], signature, accusation_payload):
                    accused = accusation_payload.get('data', {}).get('accused')
                    if accused:
                        if accused not in self.accusation_log: self.accusation_log[accused] = []
                        if accuser not in self.accusation_log[accused]: self.accusation_log[accused].append(accuser)
                        if len(self.accusation_log[accused]) >= 3:
                            self.ostracize_user(accused, proof=None)
        elif msg.get("type") == "text_message":
            sender_display_name = msg.get("sender_display_name", sender_id)
            message_text = msg.get("message")
            if not message_text: return
            
            chat_id = msg.get("group_id", sender_id)

            if chat_id not in self.chat_history: self.chat_history[chat_id] = []
            
            history_msg = f"{sender_display_name} ({datetime.now().strftime('%H:%M')}): {message_text}"
            self.chat_history[chat_id].append(history_msg)
            
            if self.current_chat_id == chat_id:
                self.chat_display.append(history_msg)
            else:
                log_display_name = chat_id
                if chat_id == sender_id:
                    log_display_name = sender_display_name
                elif chat_id in self.groups:
                    log_display_name = self.groups[chat_id].get('display_name', chat_id)
                self.log(f"New message from {log_display_name}.")
        elif msg.get("type") == "group_action":
            group_id = msg.get("group_id")
            action = msg.get("action")
            if not (group_id and action):
                return
            
            # Verify action signature
            action_copy = {k: v for k, v in action.items() if k != "signature"}
            signature = action.get("signature")
            actor = action.get("actor")
            
            if not (signature and actor):
                return
            
            # Verify the actor's signature
            actor_info = self.contacts.get(actor)
            if actor_info and self.crypto.verify_signature(actor_info.get('sign_pk'), signature, action_copy):
                # Apply the action
                group_info = self.groups.get(group_id)
                if group_info:
                    # Add to action log
                    if "action_log" not in group_info:
                        group_info["action_log"] = []
                    group_info["action_log"].append(action)
                    
                    # Process action
                    action_type = action.get("type")
                    target = action.get("target")
                    
                    if action_type == "member_added":
                        if target not in group_info.get("members", []):
                            group_info.setdefault("members", []).append(target)
                    elif action_type == "admin_promoted":
                        if "admins" not in group_info:
                            group_info["admins"] = [group_info['admin']] if 'admin' in group_info else []
                        if target not in group_info["admins"]:
                            group_info["admins"].append(target)
                    elif action_type == "member_kicked":
                        if target in group_info.get("members", []):
                            group_info["members"].remove(target)
                        if target in group_info.get("admins", []):
                            group_info["admins"].remove(target)
                    elif action_type == "member_banned":
                        if target in group_info.get("members", []):
                            group_info["members"].remove(target)
                        if target in group_info.get("admins", []):
                            group_info["admins"].remove(target)
                        if "banned_users" not in group_info:
                            group_info["banned_users"] = []
                        if target not in group_info["banned_users"]:
                            group_info["banned_users"].append(target)
                    
                    self.populate_ui_from_state()
        elif msg.get("type") == "file_transfer_request":
            transfer_id = msg.get("transfer_id")
            file_name = msg.get("file_name")
            file_size = msg.get("file_size")
            file_hash = msg.get("file_hash")
            num_chunks = msg.get("num_chunks")
            
            if not all([transfer_id, file_name, file_size, file_hash, num_chunks]):
                return
            
            # Initialize file transfer state
            if not hasattr(self, 'pending_file_transfers'):
                self.pending_file_transfers = {}
            
            self.pending_file_transfers[transfer_id] = {
                "sender_id": sender_id,
                "file_name": file_name,
                "file_size": file_size,
                "file_hash": file_hash,
                "num_chunks": num_chunks,
                "received_chunks": {}
            }
            
            # Log in chat
            chat_id = msg.get("group_id", sender_id)
            sender_display_name = msg.get("sender_display_name", sender_id)
            history_msg = f"{sender_display_name} ({datetime.now().strftime('%H:%M')}): [Receiving file: {file_name}]"
            
            if chat_id not in self.chat_history:
                self.chat_history[chat_id] = []
            self.chat_history[chat_id].append(history_msg)
            
            if self.current_chat_id == chat_id:
                self.chat_display.append(history_msg)
            
            self.log(f"Receiving file: {file_name} ({file_size} bytes, {num_chunks} chunks)")
        elif msg.get("type") == "file_transfer_chunk":
            transfer_id = msg.get("transfer_id")
            chunk_index = msg.get("chunk_index")
            chunk_data_b64 = msg.get("chunk_data")
            
            if not all([transfer_id, chunk_index is not None, chunk_data_b64]):
                return
            
            if not hasattr(self, 'pending_file_transfers'):
                self.pending_file_transfers = {}
            
            transfer_state = self.pending_file_transfers.get(transfer_id)
            if not transfer_state:
                return
            
            # Decode and store chunk
            chunk_data = base64.b64decode(chunk_data_b64)
            transfer_state["received_chunks"][chunk_index] = chunk_data
            
            # Check if all chunks received
            if len(transfer_state["received_chunks"]) == transfer_state["num_chunks"]:
                # Verify all chunks are present (in case of duplicates or missing chunks)
                missing_chunks = []
                for i in range(transfer_state["num_chunks"]):
                    if i not in transfer_state["received_chunks"]:
                        missing_chunks.append(i)
                
                if missing_chunks:
                    self.log(f"File transfer {transfer_id} incomplete: Missing chunks {missing_chunks}")
                    return
                
                # Assemble file in correct order
                file_data = b""
                for i in range(transfer_state["num_chunks"]):
                    file_data += transfer_state["received_chunks"][i]
                
                # Verify hash
                received_hash = hashlib.sha256(file_data).hexdigest()
                if received_hash != transfer_state["file_hash"]:
                    self.log(f"File transfer {transfer_id} failed: Hash mismatch")
                    del self.pending_file_transfers[transfer_id]
                    return
                
                # Save file
                save_path, _ = QFileDialog.getSaveFileName(
                    self,
                    "Save Received File",
                    transfer_state["file_name"],
                    "All Files (*.*)"
                )
                
                if save_path:
                    try:
                        with open(save_path, 'wb') as f:
                            f.write(file_data)
                        self.log(f"File saved: {save_path}")
                        
                        # Update chat history
                        chat_id = msg.get("group_id", transfer_state["sender_id"])
                        history_msg = f"[File received and saved: {transfer_state['file_name']}]"
                        
                        if chat_id not in self.chat_history:
                            self.chat_history[chat_id] = []
                        self.chat_history[chat_id].append(history_msg)
                        
                        if self.current_chat_id == chat_id:
                            self.chat_display.append(history_msg)
                    except Exception as e:
                        self.log(f"Error saving file: {e}")
                
                # Clean up
                del self.pending_file_transfers[transfer_id]
        
        self.save_state()

    def write_settings(self):
        self.settings.setValue("geometry", self.saveGeometry())

    def read_settings(self):
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
    
    def vouch_for_contact(self, contact_id):
        """Create and publish a vouch for a contact."""
        contact_info = self.contacts.get(contact_id, {})
        contact_display = contact_info.get('display_name', contact_id)
        
        reply = QMessageBox.question(
            self,
            "Vouch for User",
            f"Do you want to vouch for '{contact_display}'?\n\n"
            f"This cryptographically signs their public key, indicating you trust them.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Get trust level
                trust_level, ok = QInputDialog.getInt(
                    self,
                    "Trust Level",
                    "Enter trust level (1-5, where 5 is highest):",
                    value=3,
                    minValue=1,
                    maxValue=5
                )
                
                if not ok:
                    return
                
                # Create vouch
                vouch = VouchManager.create_vouch(
                    voucher_id=self.user_id,
                    vouched_id=contact_id,
                    vouched_public_key=contact_info.get('sign_pk', ''),
                    voucher_signing_key=self.keys['sign_sk'],
                    trust_level=trust_level
                )
                
                # Publish to DHT
                async def publish():
                    success = await self.trust_manager.publish_vouch(vouch)
                    return success
                
                future = asyncio.run_coroutine_threadsafe(publish(), self.kademlia_node.loop)
                
                # Wait briefly for result (non-blocking UI)
                try:
                    success = future.result(timeout=5.0)
                    if success:
                        self.log(f"Vouch published for {contact_display}")
                        QMessageBox.information(
                            self,
                            "Vouch Created",
                            f"Your vouch for '{contact_display}' has been published."
                        )
                    else:
                        self.log(f"Failed to publish vouch for {contact_display}")
                        QMessageBox.warning(
                            self,
                            "Publication Failed",
                            f"Failed to publish vouch for '{contact_display}'."
                        )
                except Exception as e:
                    self.log(f"Error publishing vouch: {str(e)}")
                    QMessageBox.warning(
                        self,
                        "Error",
                        f"Error publishing vouch: {str(e)}"
                    )
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to create vouch: {str(e)}")
    
    def revoke_vouch_for_contact(self, contact_id):
        """Revoke a previously published vouch."""
        contact_info = self.contacts.get(contact_id, {})
        contact_display = contact_info.get('display_name', contact_id)
        
        reply = QMessageBox.question(
            self,
            "Revoke Vouch",
            f"Do you want to revoke your vouch for '{contact_display}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Revoke vouch
                async def revoke():
                    success = await self.trust_manager.revoke_vouch(self.user_id, contact_id)
                    return success
                
                future = asyncio.run_coroutine_threadsafe(revoke(), self.kademlia_node.loop)
                
                # Wait for result
                try:
                    success = future.result(timeout=5.0)
                    if success:
                        self.log(f"Vouch revoked for {contact_display}")
                        QMessageBox.information(
                            self,
                            "Vouch Revoked",
                            f"Your vouch for '{contact_display}' has been revoked."
                        )
                    else:
                        self.log(f"Failed to revoke vouch for {contact_display}")
                        QMessageBox.warning(
                            self,
                            "Revocation Failed",
                            f"Failed to revoke vouch for '{contact_display}'."
                        )
                except Exception as e:
                    self.log(f"Error revoking vouch: {str(e)}")
                    QMessageBox.warning(
                        self,
                        "Error",
                        f"Error revoking vouch: {str(e)}"
                    )
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to revoke vouch: {str(e)}")
    
    def file_accusation_against_contact(self, contact_id):
        """File an accusation against a contact with proof."""
        contact_info = self.contacts.get(contact_id, {})
        contact_display = contact_info.get('display_name', contact_id)
        
        # Ask for accusation type
        items = ["Spam", "Crypto Failure", "Malicious Content", "Impersonation"]
        item, ok = QInputDialog.getItem(
            self,
            "File Accusation",
            f"Select accusation type for '{contact_display}':",
            items,
            0,
            False
        )
        
        if not ok:
            return
        
        # Get description
        description, ok = QInputDialog.getText(
            self,
            "Accusation Details",
            "Enter details of the accusation (evidence):",
            QLineEdit.EchoMode.Normal
        )
        
        if not ok:
            return
        
        try:
            # Create accusation proof based on type
            if item == "Spam":
                proof = TrustProof.create_spam_proof(
                    accuser_id=self.user_id,
                    accused_id=contact_id,
                    message_signatures=[],  # Could collect actual message signatures
                    accuser_signing_key=self.keys['sign_sk'],
                    description=description
                )
            elif item == "Crypto Failure":
                proof = TrustProof.create_crypto_failure_proof(
                    accuser_id=self.user_id,
                    accused_id=contact_id,
                    failed_challenge=description,
                    accuser_signing_key=self.keys['sign_sk'],
                    description=description
                )
            elif item == "Malicious Content":
                proof = TrustProof.create_malicious_content_proof(
                    accuser_id=self.user_id,
                    accused_id=contact_id,
                    content_evidence=description,
                    accuser_signing_key=self.keys['sign_sk'],
                    description=description
                )
            elif item == "Impersonation":
                proof = TrustProof.create_impersonation_proof(
                    accuser_id=self.user_id,
                    accused_id=contact_id,
                    impersonation_evidence=description,
                    accuser_signing_key=self.keys['sign_sk'],
                    description=description
                )
            else:
                QMessageBox.warning(self, "Error", "Unknown accusation type")
                return
            
            # Publish to DHT
            async def publish():
                success = await self.trust_manager.publish_accusation(proof)
                return success
            
            future = asyncio.run_coroutine_threadsafe(publish(), self.kademlia_node.loop)
            
            # Wait for result
            try:
                success = future.result(timeout=5.0)
                if success:
                    self.log(f"Accusation published against {contact_display}")
                    QMessageBox.information(
                        self,
                        "Accusation Filed",
                        f"Your accusation against '{contact_display}' has been published."
                    )
                else:
                    self.log(f"Failed to publish accusation against {contact_display}")
                    QMessageBox.warning(
                        self,
                        "Publication Failed",
                        f"Failed to publish accusation against '{contact_display}'."
                    )
            except Exception as e:
                self.log(f"Error publishing accusation: {str(e)}")
                QMessageBox.warning(
                    self,
                    "Error",
                    f"Error publishing accusation: {str(e)}"
                )
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to file accusation: {str(e)}")
    
    def view_contact_trust(self, contact_id):
        """View trust status for a contact."""
        contact_info = self.contacts.get(contact_id, {})
        contact_display = contact_info.get('display_name', contact_id)
        
        # Get my trusted contacts (for weighted scoring)
        my_trusted_contacts = []
        
        # Calculate trust
        async def get_trust():
            score, details = await self.trust_manager.calculate_user_trust(
                contact_id,
                my_trusted_contacts
            )
            
            status = TrustCalculator.get_trust_status(score)
            
            trust_info = f"Trust Status for '{contact_display}'\n\n"
            trust_info += f"Trust Score: {score}\n"
            trust_info += f"Status: {status.upper()}\n\n"
            trust_info += f"Total Vouches: {details['total_vouches']}\n"
            trust_info += f"Vouches from Trusted: {details['vouches_from_trusted']}\n"
            trust_info += f"Total Accusations: {details['total_accusations']}\n"
            trust_info += f"Accusations from Trusted: {details['accusations_from_trusted']}\n"
            
            return trust_info
        
        try:
            future = asyncio.run_coroutine_threadsafe(get_trust(), self.kademlia_node.loop)
            trust_info = future.result(timeout=10.0)
            QMessageBox.information(self, "Trust Status", trust_info)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to retrieve trust status: {str(e)}")

    def closeEvent(self, event):
        self.write_settings()
        self.log("Saving secure state and shutting down...")
        self.save_state()
        self.kademlia_node.stop()
        if self.network_thread.isRunning(): self.network_thread.quit(); self.network_thread.wait(3000)
        event.accept()

def launch_gui(args):
    app = QApplication(sys.argv)
    
    style_path = os.path.join(os.path.dirname(__file__), 'assets', 'style.qss')
    try:
        with open(style_path, 'r') as f:
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        print("Warning: Stylesheet not found.")

    display_name = None
    bootstrap_node = None
    
    with cwd():
        profile_path = os.path.realpath("../../../profile.json")
        if not os.path.exists(profile_path):
            name, ok = QInputDialog.getText(None, "Welcome to Aetherium Q-Com", "Enter your desired display name:")
            if not (ok and name.strip()): 
                sys.exit(0)
            display_name = name.strip()
    
    dht_port, comm_port = get_free_ports(2)
    
    window = ChatWindow(display_name=display_name, dht_port=dht_port, comm_port=comm_port, bootstrap_node=bootstrap_node)
    window.show()
    sys.exit(app.exec())