import sys
import subprocess
import random
import hashlib
import os
import base64
import json
import time
import queue
import threading
import socket
import platform

def get_source_code_hash():
    file_path = os.path.realpath(__file__)
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

SOURCE_HASH = get_source_code_hash()

class DependencyManager:
    REQUIRED_PACKAGES = ['gradio', 'cryptography', 'Pillow']
    if platform.system() == "Windows":
        REQUIRED_PACKAGES.append('wmi')
    
    @staticmethod
    def ensure_dependencies():
        missing_packages = []
        for package in DependencyManager.REQUIRED_PACKAGES:
            try:
                __import__(package.split('>')[0].split('=')[0])
            except ImportError:
                missing_packages.append(package)
        if not missing_packages:
            return
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_packages])
        except subprocess.CalledProcessError as e:
            sys.exit(1)

DependencyManager.ensure_dependencies()

import wmi
import gradio as gr
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class Config:
    DEFAULT_PORT = 65123
    BROADCAST_PORT = 65124
    KEY_FILE = "otp_keys.dat"
    BLOCKED_MACHINES_FILE = "blocked_machines.json"
    GROUP_SETTINGS_FILE = "group_settings.json"
    BROADCAST_TIMEOUT = 2

class DigitalSignatureManager:
    def __init__(self, log_callback, machine_fingerprint):
        self.log = log_callback
        self.machine_fingerprint = machine_fingerprint
        self.private_key = None
        self.public_key = None
        self._generate_keys()

    def _generate_keys(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()

    def sign(self, message):
        message_bytes = message.encode('utf-8')
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify(public_key_pem, message, signature_b64):
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())
            message_bytes = message.encode('utf-8')
            signature = base64.b64decode(signature_b64.encode('utf-8'))
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

class MachineFingerprintManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.fingerprint = self._get_machine_fingerprint()

    def _get_machine_fingerprint(self):
        system = platform.system()
        identifiers = []
        try:
            if system == "Windows" and wmi:
                c = wmi.WMI()
                identifiers.append(c.Win32_ComputerSystemProduct()[0].UUID)
            elif system == "Linux":
                with open("/etc/machine-id", "r") as f:
                    identifiers.append(f.read().strip())
            elif system == "Darwin":
                identifiers.append(subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]).decode().split("IOPlatformUUID")[1].split("=")[1].strip().replace('"', ''))
        except Exception:
            pass

        try:
            identifiers.append(platform.processor())
        except Exception:
            pass

        if not identifiers:
            if os.path.exists(Config.MACHINE_FINGERPRINT_FILE):
                with open(Config.MACHINE_FINGERPRINT_FILE, 'r') as f:
                    identifiers.append(f.read().strip())
            else:
                new_id = os.urandom(32).hex()
                with open(Config.MACHINE_FINGERPRINT_FILE, 'w') as f:
                    f.write(new_id)
                identifiers.append(new_id)
        
        combined_string = "".join(identifiers)
        return hashlib.sha256(combined_string.encode('utf-8')).hexdigest()

class IdentityManager:
    ADJECTIVES = ['bright', 'dark', 'quiet', 'loud', 'happy', 'silly', 'fast', 'slow', 'warm', 'cold', 'red', 'blue', 'green', 'sharp', 'round']
    NOUNS = ['fox', 'dog', 'cat', 'tree', 'rock', 'bird', 'fish', 'sun', 'moon', 'star', 'river', 'lake', 'cloud', 'wind', 'fire']

    def __init__(self, log_callback, machine_fingerprint):
        self.log = log_callback
        self.machine_fingerprint = machine_fingerprint
        self.private_key = None
        self.public_id = None
        self.username = None
        self._generate_identity()

    def _generate_hash(self, data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def generate_username_from_id(self, public_id):
        random.seed(public_id)
        adj = random.choice(self.ADJECTIVES)
        noun = random.choice(self.NOUNS)
        unique_suffix = public_id[:4]
        return f"{adj}-{noun}-{unique_suffix}"

    def _generate_identity(self):
        seed = self.machine_fingerprint
        self.private_key = base64.b64encode(hashlib.sha256(seed.encode('utf-8')).digest()).decode('utf-8')
        self.public_id = self._generate_hash(self.private_key)
        self.username = self.generate_username_from_id(self.public_id)
        self.log(f"Identity loaded. Your permanent username is '{self.username}'")

class ContactManager:
    CONTACTS_FILE = "contacts.json"

    def __init__(self, log_callback, identity_manager):
        self.log = log_callback
        self.identity_manager = identity_manager
        self.contacts = {}
        self.load_contacts()

    def load_contacts(self):
        if os.path.exists(self.CONTACTS_FILE):
            with open(self.CONTACTS_FILE, 'r') as f:
                self.contacts = json.load(f)
            self.log(f"Loaded {len(self.contacts)} contacts.")
        else:
            self.log("No contacts file found. Starting with an empty list.")

    def save_contacts(self):
        with open(self.CONTACTS_FILE, 'w') as f:
            json.dump(self.contacts, f, indent=4)
        self.log("Contacts saved.")

    def add_contact(self, public_id):
        if not public_id:
            return "Public ID cannot be empty.", False
        
        username = self.identity_manager.generate_username_from_id(public_id)
        if username in self.contacts and self.contacts[username]['public_id'] != public_id:
             return f"Error: A different contact is already saved with the name '{username}'.", False
        
        self.contacts[username] = {'public_id': public_id, 'public_key': None}
        self.save_contacts()
        return f"Contact '{username}' added/updated successfully.", True
    
    def remove_contact(self, username):
        if username in self.contacts:
            del self.contacts[username]
            self.save_contacts()
            return f"Contact '{username}' removed."
        return "Contact not found."

    def get_public_id(self, username):
        return self.contacts.get(username, {}).get('public_id')

    def get_public_key(self, username):
        return self.contacts.get(username, {}).get('public_key')

    def get_username_by_id(self, public_id):
        generated_username = self.identity_manager.generate_username_from_id(public_id)
        if generated_username in self.contacts and self.contacts[generated_username]['public_id'] == public_id:
            return generated_username
        return None

class GroupChatManager:
    GROUPS_FILE = "groups.json"

    def __init__(self, log_callback):
        self.log = log_callback
        self.groups = {}
        self.load_groups()

    def load_groups(self):
        if os.path.exists(self.GROUPS_FILE):
            with open(self.GROUPS_FILE, 'r') as f:
                self.groups = json.load(f)
            self.log(f"Loaded {len(self.groups)} groups.")
        else:
            self.log("No groups file found. Starting with an empty list.")

    def save_groups(self):
        with open(self.GROUPS_FILE, 'w') as f:
            json.dump(self.groups, f, indent=4)
        self.log("Groups saved.")

    def create_group(self, group_name, member_usernames):
        if not group_name:
            return "Group name cannot be empty.", False
        if group_name in self.groups:
            return "A group with this name already exists.", False
        
        valid_members = [un.strip() for un in member_usernames.split('\n') if un.strip()]
        if not valid_members:
            return "Group must have at least one member.", False

        self.groups[group_name] = valid_members
        self.save_groups()
        return f"Group '{group_name}' created with {len(valid_members)} members.", True

    def get_group_members(self, group_name):
        return self.groups.get(group_name, [])

class KeyManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.keys = {}
        self.used_indices = set()
        self.lock = threading.Lock()
        self.load_keys()

    def generate_keys(self, num_keys, key_length):
        with open(Config.KEY_FILE, 'wb') as f:
            for i in range(num_keys):
                f.write(os.urandom(key_length))
        self.log(f"Generated {num_keys} keys of {key_length} bytes each and saved to {Config.KEY_FILE}.")
        self.load_keys()

    def load_keys(self):
        self.keys = {}
        self.used_indices = set()
        if os.path.exists(Config.KEY_FILE):
            with open(Config.KEY_FILE, 'rb') as f:
                index = 0
                while True:
                    key = f.read(1024)
                    if not key:
                        break
                    self.keys[index] = key
                    index += 1
            self.log(f"Loaded {len(self.keys)} keys from {Config.KEY_FILE}.")
        else:
            self.log(f"No key file found. Generate keys to start.")

    def get_key(self, index):
        with self.lock:
            if index in self.keys and index not in self.used_indices:
                self.used_indices.add(index)
                return self.keys[index]
        return None

    def get_next_available_key_index(self):
        with self.lock:
            for i in range(len(self.keys)):
                if i not in self.used_indices:
                    return i
        return -1

    def get_key_count(self):
        return len(self.keys) - len(self.used_indices)

    def is_key_used(self, index):
        return index in self.used_indices

class QuantumSentryCryptography:
    def encrypt(self, plaintext_or_bytes, key):
        if not key: raise ValueError("Key cannot be empty.")
        data_bytes = plaintext_or_bytes.encode('utf-8') if isinstance(plaintext_or_bytes, str) else plaintext_or_bytes
        if len(key) < len(data_bytes): raise ValueError("Key is shorter than data. Cannot use OTP.")
        encrypted_payload = bytes([p ^ k for p, k in zip(data_bytes, key)])
        return base64.b64encode(encrypted_payload).decode('utf-8')

    def decrypt(self, b64_ciphertext, key, is_text=True):
        if not key: raise ValueError("Key cannot be empty.")
        ciphertext = base64.b64decode(b64_ciphertext.encode('utf-8'))
        if len(key) < len(ciphertext): raise ValueError("Key is shorter than ciphertext. Cannot decrypt.")
        decrypted_bytes = bytes([c ^ k for c, k in zip(ciphertext, key)])
        if is_text:
            return decrypted_bytes.decode('utf-8', errors='ignore')
        return decrypted_bytes

class BlockManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.blocked_machines = set()
        self.load_blocked_users()

    def load_blocked_users(self):
        if os.path.exists(Config.BLOCKED_MACHINES_FILE):
            try:
                with open(Config.BLOCKED_MACHINES_FILE, 'r') as f:
                    self.blocked_machines = set(json.load(f))
                self.log(f"Loaded {len(self.blocked_machines)} blocked machines.")
            except (json.JSONDecodeError, KeyError):
                self.log("Error loading blocked machines file. Starting with empty lists.")
                self.blocked_machines = set()
        else:
            self.log("No blocked machines file found. Starting with empty lists.")

    def save_blocked_users(self):
        with open(Config.BLOCKED_MACHINES_FILE, 'w') as f:
            json.dump(list(self.blocked_machines), f)
        self.log("Blocked machines list saved.")

    def block_user(self, machine_fingerprint):
        self.blocked_machines.add(machine_fingerprint)
        self.save_blocked_users()
        return "User has been blocked."

    def is_blocked(self, machine_fingerprint):
        return machine_fingerprint in self.blocked_machines

class GroupSettingsManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.allow_all = True
        self.allowed_users = set()
        self.load_settings()

    def load_settings(self):
        if os.path.exists(Config.GROUP_SETTINGS_FILE):
            with open(Config.GROUP_SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
                self.allow_all = settings.get('allow_all', True)
                self.allowed_users = set(settings.get('allowed_users', []))
            self.log("Group settings loaded.")
        else:
            self.log("No group settings file found. Defaulting to 'allow all'.")

    def save_settings(self):
        settings = {
            'allow_all': self.allow_all,
            'allowed_users': list(self.allowed_users)
        }
        with open(Config.GROUP_SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=4)
        self.log("Group settings saved.")

    def set_allow_all(self, value):
        self.allow_all = value
        self.save_settings()

    def add_allowed_user(self, username):
        self.allowed_users.add(username)
        self.save_settings()

    def is_allowed(self, username):
        return self.allow_all or (username in self.allowed_users)

class P2PDiscovery:
    def __init__(self, identity_manager, log_callback):
        self.identity = identity_manager
        self.log = log_callback
        self.response_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.listener_thread = None

    def _broadcast_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('127.0.0.1', Config.BROADCAST_PORT))
        self.log("P2P Discovery listener started.")
        while not self.stop_event.is_set():
            try:
                sock.settimeout(0.5)
                data, addr = sock.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))
                if message.get('type') == 'discovery_request' and message.get('target_username') == self.identity.username:
                    self.log(f"Discovery request received from {addr[0]} for my identity.")
                    
                    public_key_pem = app_state.digital_signature_manager.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')

                    response_data = {
                        'type': 'discovery_response', 
                        'username': self.identity.username, 
                        'public_id': self.identity.public_id, 
                        'public_key': public_key_pem,
                        'ip': addr[0]
                    }
                    sock.sendto(json.dumps(response_data).encode('utf-8'), (addr[0], Config.BROADCAST_PORT))
            except (socket.timeout, json.JSONDecodeError):
                pass
            except Exception as e:
                self.log(f"Discovery listener error: {e}")
        sock.close()
        self.log("P2P Discovery listener stopped.")

    def _broadcast_sender(self, target_username):
        self.response_queue = queue.Queue()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(Config.BROADCAST_TIMEOUT)
        
        message = {'type': 'discovery_request', 'target_username': target_username}
        try:
            sock.sendto(json.dumps(message).encode('utf-8'), ('<broadcast>', Config.BROADCAST_PORT))
            
            data, addr = sock.recvfrom(1024)
            response = json.loads(data.decode('utf-8'))
            if response.get('type') == 'discovery_response' and response.get('username') == target_username:
                self.response_queue.put(response)
        except socket.timeout:
            self.log(f"Local discovery timeout for '{target_username}'.")
        except Exception as e:
            self.log(f"Discovery sender error: {e}")
        finally:
            sock.close()

    def discover_peer(self, target_username):
        self.log(f"Attempting local network discovery for '{target_username}'...")
        listener_thread = threading.Thread(target=self._broadcast_sender, args=(target_username,), daemon=True)
        listener_thread.start()
        listener_thread.join(timeout=Config.BROADCAST_TIMEOUT + 1)
        
        try:
            response = self.response_queue.get_nowait()
            return response.get('ip'), response.get('public_key')
        except queue.Empty:
            return None, None

class Node:
    def __init__(self, config, identity_manager, contact_manager, key_manager, digital_signature_manager, block_manager, machine_fingerprint_manager, log_queue, event_queue, source_hash):
        self.config = config
        self.identity = identity_manager
        self.contacts = contact_manager
        self.key_manager = key_manager
        self.digital_signature_manager = digital_signature_manager
        self.block_manager = block_manager
        self.machine_fingerprint_manager = machine_fingerprint_manager
        self.log_queue = log_queue
        self.event_queue = event_queue
        self.stop_event = threading.Event()
        self.sessions = {}
        self.server_socket = None
        self.offline_crypto_suite = QuantumSentryCryptography()
        self.local_discovery = P2PDiscovery(self.identity, self.log)
        self.source_code_hash = source_hash

    def log(self, message): 
        self.log_queue.put(f"[Node] {message}")

    def send_json(self, sock, data):
        try:
            message = json.dumps(data).encode('utf-8')
            sock.sendall(len(message).to_bytes(4, 'big') + message)
            return True
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            self.log(f"Send failed: {e}"); return False

    def recv_json(self, sock):
        try:
            len_bytes = sock.recv(4)
            if not len_bytes: return None
            msg_len = int.from_bytes(len_bytes, 'big')
            data = b''
            while len(data) < msg_len:
                packet = sock.recv(msg_len - len(data))
                if not packet: return None
                data += packet
            return json.loads(data.decode('utf-8'))
        except (json.JSONDecodeError, ConnectionResetError, ConnectionAbortedError, OSError, socket.timeout):
            return None

    def start(self):
        self.log(f"Node starting for user '{self.identity.username}'...")
        threading.Thread(target=self._listen_for_connections, daemon=True).start()
        threading.Thread(target=self.local_discovery._broadcast_listener, daemon=True).start()

    def stop(self):
        self.stop_event.set()
        if self.server_socket: self.server_socket.close()
        for session in self.sessions.values(): session['conn'].close()
        self.local_discovery.stop_event.set()
        self.log("Node stopped.")

    def initiate_otp_session(self, peer_username):
        peer_public_id = self.contacts.get_public_id(peer_username)
        peer_public_key_pem = self.contacts.get_public_key(peer_username)

        my_machine_fingerprint = self.machine_fingerprint_manager.fingerprint
        if self.block_manager.is_blocked(my_machine_fingerprint):
            self.log(f"Cannot connect: your machine fingerprint is blocked.")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': 'Your machine is blocked.'})
            return

        if not peer_public_id:
            self.log(f"Cannot connect: username '{peer_username}' not in contacts.")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': 'User not in contacts.'})
            return
        
        peer_ip, discovered_public_key_pem = self.local_discovery.discover_peer(peer_username)

        if not peer_ip:
            self.log("Local discovery failed.")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': 'Peer not found.'})
            return
        
        key_index = self.key_manager.get_next_available_key_index()
        if key_index == -1:
            self.log("No unused keys available.")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': 'No unused keys available.'})
            return
        
        session_key = self.key_manager.get_key(key_index)

        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((peer_ip, self.config.DEFAULT_PORT))
            
            pre_master_key = hashlib.sha256((str(session_key) + self.identity.public_id + peer_public_id).encode('utf-8')).hexdigest()
            pre_master_key_bytes = pre_master_key.encode('utf-8')[:len(self.source_code_hash)]

            dynamic_salt = os.urandom(16).hex()
            combined_hash_payload = self.source_code_hash + dynamic_salt + self.machine_fingerprint_manager.fingerprint
            combined_hash = hashlib.sha256(combined_hash_payload.encode('utf-8')).hexdigest()
            encrypted_source_hash = base64.b64encode(bytes([p ^ k for p, k in zip(combined_hash.encode('utf-8'), pre_master_key_bytes)])).decode('utf-8')

            my_public_key_pem = app_state.digital_signature_manager.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            payload = {
                'type': 'otp_session', 
                'public_id': self.identity.public_id, 
                'username': self.identity.username, 
                'key_index': key_index,
                'source_hash_encrypted': encrypted_source_hash,
                'dynamic_salt': dynamic_salt,
                'public_key': my_public_key_pem,
                'machine_fingerprint': self.machine_fingerprint_manager.fingerprint
            }
            self.send_json(conn, payload)
            
            self.log(f"Sent session request to {peer_username} at {peer_ip} with key index {key_index}.")
            
            peer_response = self.recv_json(conn)
            if peer_response and peer_response.get('status') == 'accepted':
                self.log(f"✅ Session established with '{peer_username}' using key index {key_index}!")
                crypto_suite = QuantumSentryCryptography()
                self.sessions[peer_username] = {
                    'conn': conn, 
                    'crypto': crypto_suite, 
                    'public_id': peer_public_id, 
                    'key': session_key,
                    'public_key': peer_public_key_pem
                }
                self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'success'})
                self._listen_for_messages(conn, peer_username)
            else:
                self.log(f"Connection rejected by '{peer_username}': {peer_response.get('reason')}")
                conn.close()
                self.key_manager.used_indices.remove(int(key_index))
                self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': peer_response.get('reason')})
        except Exception as e:
            self.log(f"Failed to connect to {peer_ip}: {e}")
            if key_index != -1: self.key_manager.used_indices.remove(int(key_index))
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': str(e)})

    def _listen_for_connections(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('127.0.0.1', self.config.DEFAULT_PORT))
            self.server_socket.listen(10)
            self.log(f"Listening for connections on port {self.config.DEFAULT_PORT}")
        except OSError as e:
            self.log(f"FATAL: Could not bind to port {self.config.DEFAULT_PORT}. Error: {e}")
            self.event_queue.put({'type': 'error', 'data': f"Could not bind to port {self.config.DEFAULT_PORT}."}); return
        while not self.stop_event.is_set():
            try:
                conn, addr = self.server_socket.accept()
                self.log(f"Incoming connection from {addr}")
                threading.Thread(target=self.handle_incoming_connection, args=(conn, addr), daemon=True).start()
            except OSError:
                if not self.stop_event.is_set(): self.log("Server socket error.")
                break
        self.log("Listener loop stopped.")

    def handle_incoming_connection(self, conn, addr):
        req = self.recv_json(conn)
        if not req or 'type' not in req:
            self.log(f"Invalid request from {addr}. Closing."); conn.close(); return
        
        if req['type'] == 'otp_session':
            self._handle_otp_responder(conn, req)
        else:
            self.log(f"Unknown request type '{req['type']}'. Closing."); conn.close()
    
    def _handle_otp_responder(self, conn, request):
        peer_public_id = request.get('public_id')
        received_username = request.get('username')
        key_index = request.get('key_index')
        peer_source_hash_encrypted = request.get('source_hash_encrypted')
        peer_public_key = request.get('public_key')
        dynamic_salt = request.get('dynamic_salt')
        peer_machine_fingerprint = request.get('machine_fingerprint')

        if self.block_manager.is_blocked(peer_machine_fingerprint):
            self.log(f"Blocked connection from '{received_username}'.")
            self.send_json(conn, {'status': 'rejected', 'reason': 'User is blocked.'}); conn.close(); return

        session_key_for_decryption = self.key_manager.get_key(int(key_index))
        if not session_key_for_decryption:
            self.log(f"Peer requested unavailable key index {key_index}. Rejecting.")
            self.send_json(conn, {'status': 'rejected', 'reason': 'Requested key not available.'}); conn.close(); return

        pre_master_key = hashlib.sha256((str(session_key_for_decryption) + peer_public_id + self.identity.public_id).encode('utf-8')).hexdigest()
        pre_master_key_bytes = pre_master_key.encode('utf-8')[:len(self.source_code_hash)]

        try:
            decrypted_hash = base64.b64decode(peer_source_hash_encrypted.encode('utf-8'))
            decrypted_hash = bytes([p ^ k for p, k in zip(decrypted_hash, pre_master_key_bytes)]).decode('utf-8')
            
            expected_hash_payload = self.source_code_hash + dynamic_salt + peer_machine_fingerprint
            expected_hash = hashlib.sha256(expected_hash_payload.encode('utf-8')).hexdigest()
            
            if decrypted_hash != expected_hash:
                 self.log(f"INTEGRITY ALERT: Connection from '{received_username}' rejected. Source code has been modified. Blocking user.")
                 self.block_manager.block_user(peer_machine_fingerprint)
                 self.send_json(conn, {'status': 'rejected', 'reason': 'Client source code integrity check failed.'})
                 conn.close()
                 return
        except (ValueError, IndexError):
            self.log(f"INTEGRITY ALERT: Connection from '{received_username}' rejected. Peer source code has been modified.")
            self.block_manager.block_user(peer_machine_fingerprint)
            self.send_json(conn, {'status': 'rejected', 'reason': 'Client source code integrity check failed.'})
            conn.close()
            return

        expected_username = self.identity.generate_username_from_id(peer_public_id)
        if expected_username != received_username:
            self.log(f"IDENTITY ALERT: Peer with Public ID {peer_public_id[:6]}... broadcasted username '{received_username}' but their key corresponds to '{expected_username}'. Rejecting.")
            self.send_json(conn, {'status': 'rejected', 'reason': 'Broadcasted username does not match public key.'}); conn.close(); return

        known_username = self.contacts.get_username_by_id(peer_public_id)
        if not known_username:
            self.log(f"Connection from unknown Public ID {peer_public_id[:10]}... ('{expected_username}'). Add them as a contact to connect.")
            self.send_json(conn, {'status': 'rejected', 'reason': 'Unknown public ID - not in contacts.'}); conn.close(); return
        
        known_public_key = self.contacts.get_public_key(known_username)
        if known_public_key and known_public_key != peer_public_key:
            self.log(f"IDENTITY ALERT: The public key received from '{known_username}' does not match the one in our contacts. Man-in-the-middle attack possible! Rejecting.")
            self.send_json(conn, {'status': 'rejected', 'reason': 'Peer public key mismatch.'}); conn.close(); return
        
        if not known_public_key:
            self.contacts[known_username]['public_key'] = peer_public_key
            self.contacts.save_contacts()

        self.log(f"Accepted P2P session with '{known_username}' ({peer_public_id[:10]}...) using key index {key_index}.")
        
        crypto_suite = QuantumSentryCryptography()
        self.sessions[known_username] = {
            'conn': conn, 
            'crypto': crypto_suite, 
            'public_id': peer_public_id, 
            'key': session_key_for_decryption,
            'public_key': peer_public_key,
            'queue': queue.Queue()
        }
        self.send_json(conn, {'status': 'accepted'})
        
        self.event_queue.put({'type': 'p2p_status', 'peer_username': known_username, 'status': 'success'})
        threading.Thread(target=self._listen_for_messages, args=(conn, known_username), daemon=True).start()

    def _listen_for_messages(self, conn, peer_username):
        while not self.stop_event.is_set():
            message = self.recv_json(conn)
            if message is None:
                self.log(f"Connection with '{peer_username}' lost.")
                self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'disconnected'})
                if peer_username in self.sessions: del self.sessions[peer_username]
                break
            
            payload_data = message.get('data', '')
            signature_b64 = message.get('signature', '')
            peer_public_key = self.sessions.get(peer_username, {}).get('public_key')
            
            if not peer_public_key:
                self.log(f"No public key for peer '{peer_username}'. Cannot verify message.")
                continue

            if not DigitalSignatureManager.verify(peer_public_key, payload_data, signature_b64):
                self.log(f"SECURITY ALERT: Invalid signature from '{peer_username}'. Message is spoofed or tampered with. Ignoring.")
                continue
            
            if message.get('type') == 'p2p_chat':
                self.event_queue.put({'type': 'p2p_message', 'from': peer_username, 'data': message['data'], 'length': message['length']})
            elif message.get('type') == 'group_chat':
                self.event_queue.put({'type': 'group_message', 'from': peer_username, 'group_name': message['group_name'], 'data': message['data'], 'length': message['length']})
            elif message.get('type') == 'file_transfer':
                self.event_queue.put({
                    'type': 'file_message', 
                    'from': peer_username, 
                    'data': message['data'], 
                    'length': message['length'],
                    'filename': message['filename']
                })

    def send_p2p_message(self, peer_username, text_message):
        if peer_username in self.sessions:
            session = self.sessions[peer_username]
            encrypted_msg = session['crypto'].encrypt(text_message, session['key'][:len(text_message)])
            
            signature = self.digital_signature_manager.sign(encrypted_msg)

            self.send_json(session['conn'], {
                'type': 'p2p_chat', 
                'data': encrypted_msg, 
                'length': len(text_message),
                'from_username': self.identity.username,
                'signature': signature
            })
            session['key'] = session['key'][len(text_message):]

    def send_file(self, peer_username, file_path):
        if peer_username not in self.sessions:
            return

        session = self.sessions[peer_username]
        file_name = os.path.basename(file_path)

        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
                file_len = len(file_bytes)
                if file_len > len(session['key']):
                    self.log(f"Key is too short to encrypt file {file_name}. Key size: {len(session['key'])} bytes, File size: {file_len} bytes.")
                    return
                
                encrypted_bytes = session['crypto'].encrypt(file_bytes, session['key'][:file_len])
                signature_payload = f"{file_name}:{encrypted_bytes}"
                signature = self.digital_signature_manager.sign(signature_payload)
                
                self.send_json(session['conn'], {
                    'type': 'file_transfer',
                    'filename': file_name,
                    'data': encrypted_bytes,
                    'length': file_len,
                    'from_username': self.identity.username,
                    'signature': signature
                })
                session['key'] = session['key'][file_len:]
                self.log(f"Successfully sent file '{file_name}' to '{peer_username}'.")
                self.event_queue.put({'type': 'file_sent', 'to': peer_username, 'filename': file_name})

        except Exception as e:
            self.log(f"Failed to send file '{file_name}': {e}")
            self.event_queue.put({'type': 'file_failed', 'to': peer_username, 'filename': file_name, 'reason': str(e)})

    def send_group_message(self, group_name, text_message, group_members):
        message_sent = False
        
        for member_username in group_members:
            if member_username == self.identity.username:
                continue
            
            if member_username in self.sessions and self.sessions[member_username]['conn']:
                try:
                    session = self.sessions[member_username]
                    encrypted_msg_for_peer = session['crypto'].encrypt(text_message, session['key'][:len(text_message)])
                    signature = self.digital_signature_manager.sign(encrypted_msg_for_peer)
                    
                    self.send_json(session['conn'], {
                        'type': 'group_chat', 
                        'data': encrypted_msg_for_peer, 
                        'length': len(text_message),
                        'from_username': self.identity.username,
                        'group_name': group_name,
                        'signature': signature
                    })
                    session['key'] = session['key'][len(text_message):]
                    message_sent = True
                except Exception as e:
                    self.log(f"Failed to send message to '{member_username}' in group '{group_name}': {e}")
        
        if not message_sent:
            self.log(f"No active connections to send group message to in group '{group_name}'.")

class AppState:
    def __init__(self):
        self.app_config = Config()
        self.log_queue = queue.Queue()
        self.event_queue = queue.Queue()
        self.system_log = ""
        self.source_code_hash = SOURCE_HASH
        self.machine_fingerprint_manager = MachineFingerprintManager(self.log)
        self.digital_signature_manager = DigitalSignatureManager(self.log, self.machine_fingerprint_manager.fingerprint)
        self.identity_manager = IdentityManager(self.log, self.machine_fingerprint_manager.fingerprint)
        self.contact_manager = ContactManager(self.log, self.identity_manager)
        self.group_manager = GroupChatManager(self.log)
        self.key_manager = KeyManager(self.log)
        self.block_manager = BlockManager(self.log)
        self.group_settings_manager = GroupSettingsManager(self.log)
        self.node = Node(self.app_config, self.identity_manager, self.contact_manager, self.key_manager, self.digital_signature_manager, self.block_manager, self.machine_fingerprint_manager, self.log_queue, self.event_queue, self.source_code_hash)
        self.offline_crypto_suite = QuantumSentryCryptography()
        self.p2p_chats = {}
        self.group_chats = {}

    def log(self, message):
        self.system_log += f"{time.strftime('%H:%M:%S')} - {message}\n"

    def add_p2p_chat(self, peer_username, message):
        chat_id = f"p2p:{peer_username}"
        if chat_id not in self.p2p_chats:
            self.p2p_chats[chat_id] = {'history': "", 'status': 'connecting'}
        self.p2p_chats[chat_id]['history'] += message + "\n"

    def add_group_chat(self, group_name, message):
        chat_id = f"group:{group_name}"
        if chat_id not in self.group_chats:
            self.group_chats[chat_id] = {'history': ""}
        self.group_chats[chat_id]['history'] += message + "\n"

app_state = AppState()

def update_ui_loop(current_chat_id, previous_p2p_histories, previous_group_histories):
    while not app_state.log_queue.empty(): app_state.log(app_state.log_queue.get_nowait())
    while not app_state.event_queue.empty():
        event = app_state.event_queue.get_nowait()
        
        if event['type'] == 'p2p_status':
            peer_username = event.get('peer_username')
            if not peer_username: continue
            chat_id = f"p2p:{peer_username}"
            if event['status'] == 'success':
                app_state.p2p_chats[chat_id] = {'history': f"[System] ✅ Secure connection established with '{peer_username}'.\n", 'status': 'connected'}
                app_state.log(f"Successfully connected to peer '{peer_username}'")
            else:
                status_msg = f"[System] ❌ Connection to '{peer_username}' failed or disconnected.\nReason: {event.get('reason', 'Connection lost.')}\n"
                if chat_id in app_state.p2p_chats:
                    app_state.p2p_chats[chat_id]['history'] += status_msg
                    app_state.p2p_chats[chat_id]['status'] = 'disconnected'
                else:
                    app_state.p2p_chats[chat_id] = {'history': status_msg, 'status': 'failed'}
                app_state.log(f"Connection with '{peer_username}' failed or ended.")
        
        elif event['type'] == 'p2p_message':
            peer_username = event.get('from')
            if peer_username in app_state.node.sessions:
                try:
                    session = app_state.node.sessions[peer_username]
                    decrypted_msg = session['crypto'].decrypt(event['data'], session['key'][:event['length']])
                    session['key'] = session['key'][event['length']:]
                    app_state.add_p2p_chat(peer_username, f"{peer_username}: {decrypted_msg}")
                except Exception as e:
                    app_state.log(f"P2P Decrypt Error from '{peer_username}': {e}")
        
        elif event['type'] == 'group_message':
            peer_username = event.get('from')
            group_name = event.get('group_name')
            if peer_username in app_state.node.sessions:
                try:
                    session = app_state.node.sessions[peer_username]
                    decrypted_msg = session['crypto'].decrypt(event['data'], session['key'][:event['length']])
                    session['key'] = session['key'][event['length']:]
                    app_state.add_group_chat(group_name, f"[{group_name}] {peer_username}: {decrypted_msg}")
                except Exception as e:
                    app_state.log(f"Group Decrypt Error from '{peer_username}' for group '{group_name}': {e}")

        elif event['type'] == 'file_message':
            peer_username = event.get('from')
            filename = event.get('filename')
            if peer_username in app_state.node.sessions:
                try:
                    session = app_state.node.sessions[peer_username]
                    decrypted_bytes = session['crypto'].decrypt(event['data'], session['key'][:event['length']], is_text=False)
                    session['key'] = session['key'][event['length']:]

                    save_path = f"received_{filename}"
                    with open(save_path, "wb") as f:
                        f.write(decrypted_bytes)
                    
                    app_state.log(f"Received file '{filename}' from '{peer_username}'. Saved to '{save_path}'.")
                    app_state.add_p2p_chat(peer_username, f"[System] Received file '{filename}'.")
                except Exception as e:
                    app_state.log(f"File Decrypt Error from '{peer_username}': {e}")

    new_p2p_histories = {un: chat['history'] for un, chat in app_state.p2p_chats.items()}
    new_group_histories = {un: chat['history'] for un, chat in app_state.group_chats.items()}
    
    old_p2p_history = previous_p2p_histories.get(current_chat_id, "")
    new_p2p_history = new_p2p_histories.get(current_chat_id, "")
    
    old_group_history = previous_group_histories.get(current_chat_id, "")
    new_group_history = new_group_histories.get(current_chat_id, "")
    
    trigger_value = gr.update()
    if old_p2p_history != new_p2p_history or old_group_history != new_group_history:
        trigger_value = str(time.time())

    p2p_chat_choices = [f"p2p:{c}" for c in app_state.contact_manager.contacts.keys()]
    group_chat_choices = [f"group:{g}" for g in app_state.group_manager.groups.keys()]
    
    all_chat_choices = p2p_chat_choices + group_chat_choices

    return (
        app_state.system_log,
        gr.update(choices=list(app_state.contact_manager.contacts.keys())),
        gr.update(value=app_state.key_manager.get_key_count()),
        new_p2p_histories,
        new_group_histories,
        gr.update(choices=all_chat_choices),
        trigger_value
    )

def connect_p2p(peer_username):
    if not peer_username:
        return "Please select a contact.", gr.update()
    
    app_state.log(f"Initiating P2P session with '{peer_username}'...")
    threading.Thread(target=app_state.node.initiate_otp_session, args=(peer_username,)).start()
    app_state.add_p2p_chat(peer_username, f"[System] Connecting to '{peer_username}'...\n")
    new_chat_choices = [f"p2p:{c}" for c in app_state.contact_manager.contacts.keys()] + [f"group:{g}" for g in app_state.group_manager.groups.keys()]
    return f"Connecting to {peer_username}...", gr.update(choices=new_chat_choices, value=f"p2p:{peer_username}")

def send_message_ui(message, current_chat_id):
    if not message or not current_chat_id: return ""
    
    chat_type, chat_name = current_chat_id.split(':', 1)

    if chat_type == 'p2p':
        if app_state.p2p_chats.get(current_chat_id, {}).get('status') != 'connected':
            app_state.log("Cannot send message: Not securely connected."); return ""
        app_state.add_p2p_chat(chat_name, f"You: {message}")
        app_state.node.send_p2p_message(chat_name, message)
    elif chat_type == 'group':
        group_members = app_state.group_manager.get_group_members(chat_name)
        if not any(member in app_state.node.sessions for member in group_members if member != app_state.identity_manager.username):
            app_state.log(f"No active connections to send group message to in group '{chat_name}'.")
        else:
            app_state.add_group_chat(chat_name, f"You: {message}")
            app_state.node.send_group_message(chat_name, message, group_members)
            
    return ""

def send_file_ui(file_path, current_chat_id):
    if not file_path or not current_chat_id:
        return "Please select a file and a chat to send to."

    chat_type, chat_name = current_chat_id.split(':', 1)
    if chat_type != 'p2p':
        return "File transfer is only supported for P2P chats."
    
    app_state.node.send_file(chat_name, file_path)
    return f"Sending file {os.path.basename(file_path)}..."

def change_active_chat(chat_id, p2p_histories, group_histories):
    chat_type, chat_name = chat_id.split(':', 1)
    
    if chat_type == 'p2p':
        history = p2p_histories.get(chat_id, "[System] Select a peer to view chat history.")
    elif chat_type == 'group':
        history = group_histories.get(chat_id, "[System] Select a group to view chat history.")
    else:
        history = ""

    return history

def create_group_ui(group_name, member_usernames_str):
    members_list = member_usernames_str.strip().split('\n')
    msg, success = app_state.group_manager.create_group(group_name, members_list)
    
    if success:
        new_chat_choices = [f"p2p:{c}" for c in app_state.contact_manager.contacts.keys()] + [f"group:{g}" for g in app_state.group_manager.groups.keys()]
        return gr.update(value=msg), gr.update(choices=new_chat_choices)
    
    return gr.update(value=msg), gr.update()

def add_contact_ui(public_id_str, public_key_str):
    msg, success = app_state.contact_manager.add_contact(public_id_str, public_key_str)

    if success:
        new_contact_choices = list(app_state.contact_manager.contacts.keys())
        new_chat_choices = [f"p2p:{c}" for c in new_contact_choices] + [f"group:{g}" for g in app_state.group_manager.groups.keys()]
        return msg, gr.update(choices=new_contact_choices), gr.update(choices=new_chat_choices)
    
    return msg, gr.update(), gr.update()

def get_contact_username_for_id(public_ids_str):
    if not public_ids_str:
        return "[Enter a valid Public ID above]"
    first_id = public_ids_str.splitlines()[0].strip()
    if not first_id or len(first_id) != 64:
        return "[Enter a valid Public ID above]"
    return app_state.identity_manager.generate_username_from_id(first_id)

def get_my_public_key():
    return app_state.digital_signature_manager.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def generate_keys_ui(num_keys, key_length):
    if not num_keys or not key_length:
        return "Number of keys and key length are required."
    app_state.key_manager.generate_keys(int(num_keys), int(key_length))
    return f"Keys generated successfully. You have {app_state.key_manager.get_key_count()} keys available."

def get_key_count_ui():
    return f"You have {app_state.key_manager.get_key_count()} unused keys."

def encrypt_ui(plaintext, key_index):
    if not plaintext or not key_index: return ""
    try:
        key = app_state.key_manager.get_key(int(key_index))
        if not key:
            return "Key not available or already used."
        encrypted_text = app_state.offline_crypto_suite.encrypt(plaintext, key[:len(plaintext)])
        return encrypted_text
    except Exception as e:
        return f"ENCRYPTION FAILED: {e}"

def decrypt_ui(ciphertext, key_index, message_len):
    if not ciphertext or not key_index or not message_len: return ""
    try:
        key = app_state.key_manager.get_key(int(key_index))
        if not key:
            return "Key not available or already used."
        decrypted_text = app_state.offline_crypto_suite.decrypt(ciphertext, key[:int(message_len)])
        return decrypted_text
    except Exception as e:
        return f"DECRYPTION FAILED: {e}"

def block_user_ui(username):
    if not username:
        return "Please enter a username to block."
    public_key = app_state.contact_manager.get_public_key(username)
    if not public_key:
        return f"User '{username}' not found in contacts. Cannot block."
    
    return app_state.block_manager.block_user(app_state.contact_manager.get_public_key(username))

def unblock_user_ui(username):
    if not username:
        return "Please enter a username to unblock."
    public_key = app_state.contact_manager.get_public_key(username)
    if not public_key:
        return f"User '{username}' not found in contacts. Cannot unblock."
    return app_state.block_manager.unblock_user(public_key)

def set_group_permission_ui(allow_all, allowed_users_str):
    app_state.group_settings_manager.set_allow_all(allow_all)
    if not allow_all:
        allowed_users = [u.strip() for u in allowed_users_str.split('\n') if u.strip()]
        for user in allowed_users:
            app_state.group_settings_manager.add_allowed_user(user)
    return "Group permissions updated."

def main():
    app_state.node.start()

    with gr.Blocks(theme=gr.themes.Soft(), title="Aetherium Q-Com") as demo:
        gr.Markdown("# Aetherium Q-Com")
        p2p_chat_histories = gr.State({})
        group_chat_histories = gr.State({})
        chat_update_trigger = gr.Textbox(visible=False)

        with gr.Tabs():
            with gr.TabItem("Network & P2P"):
                with gr.Row():
                    with gr.Column(scale=1):
                        gr.Markdown("## Connect to a Peer")
                        gr.Markdown("Select a contact to connect. The app will automatically discover their IP on your local network.")
                        p2p_contact_selector = gr.Dropdown(label="Select Contact to Connect", choices=list(app_state.contact_manager.contacts.keys()), interactive=True)
                        connect_p2p_btn = gr.Button("Connect Securely to Selected Contact")
                        p2p_status_box = gr.Textbox(label="Connection Status", interactive=False)
                    with gr.Column(scale=2):
                        gr.Markdown("## P2P & Group Chat")
                        all_chat_choices = [f"p2p:{c}" for c in app_state.contact_manager.contacts.keys()] + [f"group:{g}" for g in app_state.group_manager.groups.keys()]
                        chat_selector = gr.Dropdown(label="Active Chat", choices=all_chat_choices, interactive=True)
                        chat_output = gr.Textbox(label="Secure Chat", lines=10, interactive=False, autoscroll=True)
                        chat_input = gr.Textbox(show_label=False, placeholder="Type your secure message...")
                        
                        with gr.Row():
                            file_to_send = gr.File(label="Select File to Send")
                            send_file_btn = gr.Button("Send File")

            with gr.TabItem("Key Management"):
                gr.Markdown("## Manage Keys")
                gr.Markdown("OTP keys must be pre-shared physically (e.g., via USB drive).")
                with gr.Row():
                    with gr.Column():
                        otp_gen_num = gr.Number(label="Number of Keys to Generate", precision=0, value=100)
                        otp_gen_len = gr.Number(label="Key Length (in bytes)", precision=0, value=1024)
                        generate_keys_btn = gr.Button("Generate New Keys & Save to File")
                    with gr.Column():
                        otp_status_box = gr.Textbox(label="Key Manager Status", interactive=False)
                        otp_count_box = gr.Textbox(label="Available Keys", interactive=False, value=f"You have {app_state.key_manager.get_key_count()} unused keys.")
                        refresh_key_count_btn = gr.Button("Refresh Key Count")
            
            with gr.TabItem("Identity & Contacts"):
                 with gr.Row():
                    with gr.Column():
                        gr.Markdown("## Your Identity (OTP)")
                        gr.Textbox(label="Your Permanent, Key-Generated Username", value=app_state.identity_manager.username, interactive=False)
                        gr.Textbox(label="Your Full Public ID (Share this with peers)", value=app_state.identity_manager.public_id, interactive=False, lines=3)
                    with gr.Column():
                        gr.Markdown("## Manage Contacts")
                        contact_status = gr.Textbox(label="Status", interactive=False)
                        contact_public_id = gr.Textbox(label="Contact's Full Public ID", lines=1)
                        add_contact_btn = gr.Button("Add/Update Contact")

            with gr.TabItem("Digital Identity"):
                gr.Markdown("## Your Digital Signature Public Key")
                gr.Textbox(label="Your Digital Public Key (Share with contacts)", lines=10, interactive=False, value=get_my_public_key())
                gr.Markdown("---")
                gr.Markdown("## Your Machine Fingerprint")
                gr.Textbox(label="Your Machine Fingerprint (Unique, Permanent ID)", lines=1, interactive=False, value=app_state.machine_fingerprint_manager.fingerprint)
            
            with gr.TabItem("Groups"):
                gr.Markdown("## Create a Group")
                with gr.Row():
                    with gr.Column():
                        group_name_input = gr.Textbox(label="Group Name")
                        group_members_input = gr.Textbox(label="Members (usernames, one per line)", lines=5)
                        create_group_btn = gr.Button("Create Group")
                    with gr.Column():
                        group_status_box = gr.Textbox(label="Group Status", interactive=False)

            with gr.TabItem("Privacy & Security"):
                gr.Markdown("## Blocking")
                with gr.Row():
                    block_user_input = gr.Textbox(label="Username to Block")
                    block_btn = gr.Button("Block User")
                    unblock_btn = gr.Button("Unblock User")
                block_status = gr.Textbox(label="Block Status", interactive=False)

                gr.Markdown("---")

                gr.Markdown("## Group Permissions")
                with gr.Row():
                    allow_all_checkbox = gr.Checkbox(label="Allow all contacts to add me to groups", value=app_state.group_settings_manager.allow_all)
                allowed_users_input = gr.Textbox(label="Allowed users (usernames, one per line)", lines=5)
                update_permissions_btn = gr.Button("Update Group Permissions")
                permission_status = gr.Textbox(label="Permission Status", interactive=False)

            with gr.TabItem("Offline Cryptography"):
                gr.Markdown("## Encryption/Decryption")
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### Encrypt")
                        crypto_in_plain = gr.Textbox(label="Plaintext", lines=8)
                        crypto_enc_key_index = gr.Number(label="OTP Key Index", precision=0)
                        crypto_encrypt_btn = gr.Button("Encrypt")
                        crypto_out_cipher = gr.Textbox(label="Ciphertext", lines=8)
                    with gr.Column():
                        gr.Markdown("### Decrypt")
                        crypto_in_cipher = gr.Textbox(label="Ciphertext", lines=8)
                        crypto_dec_key_index = gr.Number(label="OTP Key Index", precision=0)
                        crypto_dec_len = gr.Number(label="Plaintext Length (in bytes)", precision=0)
                        crypto_decrypt_btn = gr.Button("Decrypt")
                        crypto_out_plain = gr.Textbox(label="Plaintext", lines=8)

            with gr.TabItem("System Log"):
                log_output = gr.Textbox(label="Log", lines=20, interactive=False, autoscroll=True)

        connect_p2p_btn.click(connect_p2p, [p2p_contact_selector], [p2p_status_box, chat_selector])
        chat_input.submit(send_message_ui, [chat_input, chat_selector], [chat_input])
        send_file_btn.click(send_file_ui, [file_to_send, chat_selector], [])
        chat_selector.change(change_active_chat, [chat_selector, p2p_chat_histories, group_chat_histories], [chat_output])
        
        create_group_btn.click(create_group_ui, [group_name_input, group_members_input], [group_status_box, chat_selector])
        
        add_contact_btn.click(add_contact_ui, [contact_public_id], [contact_status, p2p_contact_selector, chat_selector])
        
        generate_keys_btn.click(generate_keys_ui, [otp_gen_num, otp_gen_len], [otp_status_box]).then(
            get_key_count_ui, None, otp_count_box)
        refresh_key_count_btn.click(get_key_count_ui, None, otp_count_box)

        crypto_encrypt_btn.click(encrypt_ui, [crypto_in_plain, crypto_enc_key_index], [crypto_out_cipher])
        crypto_decrypt_btn.click(decrypt_ui, [crypto_in_cipher, crypto_dec_key_index, crypto_dec_len], [crypto_out_plain])

        block_btn.click(block_user_ui, [block_user_input], [block_status])
        unblock_btn.click(unblock_user_ui, [block_user_input], [block_status])
        update_permissions_btn.click(set_group_permission_ui, [allow_all_checkbox, allowed_users_input], [permission_status])

        timer = gr.Timer(1, active=False)
        timer.tick(
            update_ui_loop,
            inputs=[chat_selector, p2p_chat_histories, group_chat_histories],
            outputs=[log_output, p2p_contact_selector, otp_count_box, p2p_chat_histories, group_chat_histories, chat_selector, chat_update_trigger]
        )
        chat_update_trigger.change(
            change_active_chat,
            inputs=[chat_selector, p2p_chat_histories, group_chat_histories],
            outputs=[chat_output]
        )
        demo.load(lambda: gr.Timer(active=True), None, outputs=timer).then(
            lambda: "[System] Select a peer or group to view chat history.", None, [chat_output]
        )

    demo.launch(inbrowser=True)
    app_state.node.stop()

if __name__ == "__main__":
    main()
