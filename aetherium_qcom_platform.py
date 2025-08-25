import sys
import subprocess
import random
import math
import numpy as np
from collections import Counter
import socket
import threading
import json
import time
import queue
import hashlib
import os
import base64
import io
import requests

def get_source_code_hash():
    file_path = os.path.realpath(__file__)
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

SOURCE_HASH = get_source_code_hash()

class DependencyManager:
    REQUIRED_PACKAGES = ['numpy', 'Pillow', 'gradio', 'requests']

    @staticmethod
    def ensure_dependencies():
        missing_packages = []
        for package in DependencyManager.REQUIRED_PACKAGES:
            try:
                __import__(package.split('>')[0].split('=')[0])
            except ImportError:
                missing_packages.append(package)

        if not missing_packages:
            print("All dependencies are satisfied.")
            return

        print(f"Installing missing packages: {missing_packages}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_packages])
        except subprocess.CalledProcessError as e:
            print(f"Error installing packages: {e}")
            sys.exit(1)

DependencyManager.ensure_dependencies()

import gradio as gr
from PIL import Image

class Config:
    DEFAULT_PORT = 65123
    BROADCAST_PORT = 65124
    DHT_PORT = 65125
    KEY_FILE = "otp_keys.dat"
    BROADCAST_TIMEOUT = 2
    BOOTSTRAP_NODES = [("router.bittorrent.com", 6881), ("dht.transmissionbt.com", 6881)]

class IdentityManager:
    IDENTITY_FILE = "identity.key"
    ADJECTIVES = ['bright', 'dark', 'quiet', 'loud', 'happy', 'silly', 'fast', 'slow', 'warm', 'cold', 'red', 'blue', 'green', 'sharp', 'round']
    NOUNS = ['fox', 'dog', 'cat', 'tree', 'rock', 'bird', 'fish', 'sun', 'moon', 'star', 'river', 'lake', 'cloud', 'wind', 'fire']

    def __init__(self, log_callback):
        self.log = log_callback
        self.private_key = None
        self.public_id = None
        self.username = None
        self._load_or_create_identity()

    def _generate_hash(self, data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def generate_username_from_id(self, public_id):
        random.seed(public_id)
        adj = random.choice(self.ADJECTIVES)
        noun = random.choice(self.NOUNS)
        unique_suffix = public_id[:4]
        return f"{adj}-{noun}-{unique_suffix}"

    def _load_or_create_identity(self):
        if os.path.exists(self.IDENTITY_FILE):
            self.log(f"Loading identity from {self.IDENTITY_FILE}...")
            with open(self.IDENTITY_FILE, 'r') as f:
                self.private_key = f.read().strip()
        else:
            self.log("No identity key found. Generating a new one...")
            self.private_key = base64.b64encode(os.urandom(32)).decode('utf-8')
            with open(self.IDENTITY_FILE, 'w') as f:
                f.write(self.private_key)
            self.log(f"New identity key created and saved to {self.IDENTITY_FILE}.")
        
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
        
        if username in self.contacts and self.contacts[username] != public_id:
             return f"Error: A different contact is already saved with the name '{username}'.", False
        
        self.contacts[username] = public_id
        self.save_contacts()
        return f"Contact '{username}' added/updated successfully.", True
    
    def remove_contact(self, username):
        if username in self.contacts:
            del self.contacts[username]
            self.save_contacts()
            return f"Contact '{username}' removed."
        return "Contact not found."

    def get_public_id(self, username):
        return self.contacts.get(username)

    def get_username_by_id(self, public_id):
        generated_username = self.identity_manager.generate_username_from_id(public_id)
        if generated_username in self.contacts and self.contacts[generated_username] == public_id:
            return generated_username
        return None

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
    def encrypt(self, plaintext, key):
        if not key: raise ValueError("Key cannot be empty.")
        plaintext_bytes = plaintext.encode('utf-8')
        if len(key) < len(plaintext_bytes): raise ValueError("Key is shorter than plaintext. Cannot use OTP.")
        encrypted_payload = bytes([p ^ k for p, k in zip(plaintext_bytes, key)])
        return base64.b64encode(encrypted_payload).decode('utf-8')

    def decrypt(self, b64_ciphertext, key):
        if not key: raise ValueError("Key cannot be empty.")
        ciphertext = base64.b64decode(b64_ciphertext.encode('utf-8'))
        if len(key) < len(ciphertext): raise ValueError("Key is shorter than ciphertext. Cannot decrypt.")
        return bytes([c ^ k for c, k in zip(ciphertext, key)]).decode('utf-8', errors='ignore')

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
        sock.bind(('127.0.0.1', Config.BROADCAST_PORT))
        self.log("P2P Discovery listener started.")
        while not self.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))
                if message.get('type') == 'discovery_request' and message.get('target_username') == self.identity.username:
                    self.log(f"Discovery request received from {addr[0]} for my identity.")
                    response_data = {'type': 'discovery_response', 'username': self.identity.username, 'public_id': self.identity.public_id, 'ip': addr[0]}
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
            return response.get('ip')
        except queue.Empty:
            return None

class KademliaDHT:
    def __init__(self, log_callback, identity_manager):
        self.log = log_callback
        self.identity = identity_manager
        self.storage = {}
        self.peers = {}
        self.stop_event = threading.Event()
        self.node_thread = None

    def _run_node(self):
        self.log(f"Kademlia DHT node started on port {Config.DHT_PORT}")
        self.store_value(self.identity.public_id, self.get_my_ip())
        
        while not self.stop_event.is_set():
            time.sleep(1)
        self.log("Kademlia DHT node stopped.")

    def start(self):
        self.node_thread = threading.Thread(target=self._run_node, daemon=True)
        self.node_thread.start()

    def stop(self):
        self.stop_event.set()

    def get_my_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def store_value(self, public_id, ip):
        self.log(f"DHT: Storing Public ID {public_id[:10]}... with IP {ip}")
        self.storage[public_id] = ip

    def find_value(self, public_id):
        return self.storage.get(public_id)

class Node:
    def __init__(self, config, identity_manager, contact_manager, key_manager, log_queue, event_queue, source_hash):
        self.config = config
        self.identity = identity_manager
        self.contacts = contact_manager
        self.key_manager = key_manager
        self.log_queue = log_queue
        self.event_queue = event_queue
        self.stop_event = threading.Event()
        self.sessions = {}
        self.server_socket = None
        self.offline_crypto_suite = QuantumSentryCryptography()
        self.local_discovery = P2PDiscovery(self.identity, self.log)
        self.dht_node = KademliaDHT(self.log, self.identity)
        self.source_code_hash = source_hash

    def log(self, message): self.log_queue.put(f"[Node] {message}")

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
        self.dht_node.start()

    def stop(self):
        self.stop_event.set()
        if self.server_socket: self.server_socket.close()
        for session in self.sessions.values(): session['conn'].close()
        self.local_discovery.stop_event.set()
        self.dht_node.stop()
        self.log("Node stopped.")

    def initiate_otp_session(self, peer_username):
        peer_public_id = self.contacts.get_public_id(peer_username)
        if not peer_public_id:
            self.log(f"Cannot connect: username '{peer_username}' not in contacts.")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': 'User not in contacts.'})
            return
        
        peer_ip = None
        self.log(f"Attempting local network discovery for '{peer_username}'...")
        peer_ip = self.local_discovery.discover_peer(peer_username)

        if not peer_ip:
            self.log("Local discovery failed. Falling back to decentralized network (DHT)...")
            peer_ip = self.dht_node.find_value(peer_public_id)

        if not peer_ip:
            self.log(f"Could not find IP for '{peer_username}' via any method.")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': 'Peer not found on network.'})
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

            encrypted_source_hash = base64.b64encode(bytes([p ^ k for p, k in zip(self.source_code_hash.encode('utf-8'), pre_master_key_bytes)])).decode('utf-8')

            payload = {
                'type': 'otp_session', 
                'public_id': self.identity.public_id, 
                'username': self.identity.username, 
                'key_index': key_index,
                'source_hash_encrypted': encrypted_source_hash
            }
            self.send_json(conn, payload)
            
            self.log(f"Sent session request to {peer_username} at {peer_ip} with key index {key_index}.")
            
            peer_response = self.recv_json(conn)
            if peer_response and peer_response.get('status') == 'accepted':
                self.log(f"✅ Session established with '{peer_username}' using key index {key_index}!")
                crypto_suite = QuantumSentryCryptography()
                self.sessions[peer_username] = {'conn': conn, 'crypto': crypto_suite, 'public_id': peer_public_id, 'key': session_key}
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

        session_key_for_decryption = self.key_manager.get_key(int(key_index))
        if not session_key_for_decryption:
            self.log(f"Peer requested unavailable key index {key_index}. Rejecting.")
            self.send_json(conn, {'status': 'rejected', 'reason': 'Requested key not available.'}); conn.close(); return

        pre_master_key = hashlib.sha256((str(session_key_for_decryption) + peer_public_id + self.identity.public_id).encode('utf-8')).hexdigest()
        pre_master_key_bytes = pre_master_key.encode('utf-8')[:len(self.source_code_hash)]

        try:
            decrypted_hash = base64.b64decode(peer_source_hash_encrypted.encode('utf-8'))
            decrypted_hash = bytes([p ^ k for p, k in zip(decrypted_hash, pre_master_key_bytes)]).decode('utf-8')
            if decrypted_hash != self.source_code_hash:
                 raise ValueError("Hash mismatch")
        except (ValueError, IndexError):
            self.log(f"INTEGRITY ALERT: Connection from '{received_username}' rejected. Peer source code has been modified.")
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

        self.log(f"Accepted P2P session with '{known_username}' ({peer_public_id[:10]}...) using key index {key_index}.")
        
        crypto_suite = QuantumSentryCryptography()
        self.sessions[known_username] = {'conn': conn, 'crypto': crypto_suite, 'public_id': peer_public_id, 'key': session_key_for_decryption}
        self.send_json(conn, {'status': 'accepted'})
        
        self.event_queue.put({'type': 'p2p_status', 'peer_username': known_username, 'status': 'success'})
        self._listen_for_messages(conn, known_username)

    def _listen_for_messages(self, conn, peer_username):
        while not self.stop_event.is_set():
            message = self.recv_json(conn)
            if message is None:
                self.log(f"Connection with '{peer_username}' lost.")
                self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'disconnected'})
                if peer_username in self.sessions: del self.sessions[peer_username]
                break
            
            if message.get('type') == 'p2p_chat':
                self.event_queue.put({'type': 'p2p_message', 'from': peer_username, 'data': message['data'], 'length': message['length']})

    def send_p2p_message(self, peer_username, text_message):
        if peer_username in self.sessions:
            session = self.sessions[peer_username]
            encrypted_msg = session['crypto'].encrypt(text_message, session['key'][:len(text_message)])
            self.send_json(session['conn'], {'type': 'p2p_chat', 'data': encrypted_msg, 'length': len(text_message)})
            session['key'] = session['key'][len(text_message):]
        else:
            self.log(f"Not connected to peer '{peer_username}'.")

class AppState:
    def __init__(self):
        self.app_config = Config()
        self.log_queue = queue.Queue()
        self.event_queue = queue.Queue()
        self.system_log = ""
        self.source_code_hash = SOURCE_HASH
        self.identity_manager = IdentityManager(self.log)
        self.contact_manager = ContactManager(self.log, self.identity_manager)
        self.key_manager = KeyManager(self.log)
        self.node = Node(self.app_config, self.identity_manager, self.contact_manager, self.key_manager, self.log_queue, self.event_queue, self.source_code_hash)
        self.offline_crypto_suite = QuantumSentryCryptography()
        self.p2p_chats = {}

    def log(self, message):
        self.system_log += f"{time.strftime('%H:%M:%S')} - {message}\n"

    def add_p2p_chat(self, peer_username, message):
        if peer_username not in self.p2p_chats:
            self.p2p_chats[peer_username] = {'history': "", 'status': 'connecting'}
        self.p2p_chats[peer_username]['history'] += message + "\n"

app_state = AppState()

def update_ui_loop(current_peer, previous_histories):
    while not app_state.log_queue.empty(): app_state.log(app_state.log_queue.get_nowait())
    while not app_state.event_queue.empty():
        event = app_state.event_queue.get_nowait()
        peer_username = event.get('peer_username') or event.get('from')
        if not peer_username: continue
        
        if event['type'] == 'p2p_status':
            if event['status'] == 'success':
                app_state.p2p_chats[peer_username] = {'history': f"[System] ✅ Secure connection established with '{peer_username}'.\n", 'status': 'connected'}
                app_state.log(f"Successfully connected to peer '{peer_username}'")
            else:
                status_msg = f"[System] ❌ Connection to '{peer_username}' failed or disconnected.\nReason: {event.get('reason', 'Connection lost.')}\n"
                if peer_username in app_state.p2p_chats:
                    app_state.p2p_chats[peer_username]['history'] += status_msg
                    app_state.p2p_chats[peer_username]['status'] = 'disconnected'
                else:
                    app_state.p2p_chats[peer_username] = {'history': status_msg, 'status': 'failed'}
                app_state.log(f"Connection with '{peer_username}' failed or ended.")
        
        elif event['type'] == 'p2p_message':
            if peer_username in app_state.p2p_chats:
                try:
                    session = app_state.node.sessions[peer_username]
                    decrypted_msg = session['crypto'].decrypt(event['data'], session['key'][:event['length']])
                    session['key'] = session['key'][event['length']:]
                    app_state.add_p2p_chat(peer_username, f"{peer_username}: {decrypted_msg}")
                except Exception as e:
                    app_state.log(f"P2P Decrypt Error from '{peer_username}': {e}")
    
    new_histories = {un: chat['history'] for un, chat in app_state.p2p_chats.items()}
    old_peer_history = previous_histories.get(current_peer, "")
    new_peer_history = new_histories.get(current_peer, "")
    
    trigger_value = gr.update()
    if old_peer_history != new_peer_history:
        trigger_value = str(time.time())

    return (
        app_state.system_log,
        gr.update(choices=list(app_state.contact_manager.contacts.keys())),
        gr.update(value=app_state.key_manager.get_key_count()),
        new_histories,
        gr.update(choices=list(app_state.p2p_chats.keys())),
        trigger_value
    )

def connect_p2p(peer_username):
    if not peer_username:
        return "Please select a contact.", gr.update()
    
    app_state.log(f"Initiating P2P session with '{peer_username}'...")
    threading.Thread(target=app_state.node.initiate_otp_session, args=(peer_username,)).start()
    app_state.add_p2p_chat(peer_username, f"[System] Connecting to '{peer_username}'...\n")
    new_chat_choices = list(app_state.p2p_chats.keys())
    return f"Connecting to {peer_username}...", gr.update(choices=new_chat_choices, value=peer_username)

def send_p2p_message_ui(message, current_peer):
    if not message or not current_peer: return ""
    if app_state.p2p_chats.get(current_peer, {}).get('status') != 'connected':
        app_state.log("Cannot send message: Not securely connected."); return ""
    app_state.add_p2p_chat(current_peer, f"You: {message}")
    app_state.node.send_p2p_message(current_peer, message); return ""

def change_active_chat(peer_username, all_histories_state):
    return all_histories_state.get(peer_username, "[System] Select a peer to view chat history.")

def add_contact_ui(public_ids_str):
    messages = []
    ids_to_process = [pid.strip() for pid in public_ids_str.splitlines() if pid.strip()]

    if not ids_to_process:
        return "Public ID input is empty.", gr.update()

    for pid in ids_to_process:
        msg, _ = app_state.contact_manager.add_contact(pid)
        messages.append(msg)
    
    return "\n".join(messages), gr.update(choices=list(app_state.contact_manager.contacts.keys()))

def get_contact_username_for_id(public_ids_str):
    if not public_ids_str:
        return "[Enter a valid Public ID above]"
    first_id = public_ids_str.splitlines()[0].strip()
    if not first_id or len(first_id) != 64:
        return "[Enter a valid Public ID above]"
    return app_state.identity_manager.generate_username_from_id(first_id)

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
        app_state.log(f"Offline encrypt error: {e}"); return f"ENCRYPTION FAILED: {e}"

def decrypt_ui(ciphertext, key_index, message_len):
    if not ciphertext or not key_index or not message_len: return ""
    try:
        key = app_state.key_manager.get_key(int(key_index))
        if not key:
            return "Key not available or already used."
        decrypted_text = app_state.offline_crypto_suite.decrypt(ciphertext, key[:int(message_len)])
        return decrypted_text
    except Exception as e:
        app_state.log(f"Offline decrypt error: {e}"); return f"DECRYPTION FAILED: {e}"

def main():
    DependencyManager.ensure_dependencies()
    app_state.node.start()

    with gr.Blocks(theme=gr.themes.Soft(), title="Aetherium Q-Com (OTP)") as demo:
        gr.Markdown("# Aetherium Q-Com (One-Time Pad)")
        all_chat_histories = gr.State({})
        chat_update_trigger = gr.Textbox(visible=False)

        with gr.Tabs():
            with gr.TabItem("Network & P2P"):
                with gr.Row():
                    with gr.Column(scale=1):
                        gr.Markdown("## Connect to a Peer")
                        gr.Markdown("Select a contact to connect. The app will automatically discover their IP on your local network or via the decentralized network (DHT).")
                        p2p_contact_selector = gr.Dropdown(label="Select Contact to Connect", choices=list(app_state.contact_manager.contacts.keys()), interactive=True)
                        connect_p2p_btn = gr.Button("Connect Securely to Selected Contact")
                        p2p_status_box = gr.Textbox(label="Connection Status", interactive=False)
                    with gr.Column(scale=2):
                        gr.Markdown("## P2P Chat")
                        p2p_chat_selector = gr.Dropdown(label="Active P2P Chat", interactive=True)
                        p2p_chat_output = gr.Textbox(label="Secure Chat", lines=10, interactive=False, autoscroll=True)
                        p2p_chat_input = gr.Textbox(show_label=False, placeholder="Type your secure message...")

            with gr.TabItem("Key Management"):
                gr.Markdown("## Manage One-Time Pad Keys")
                gr.Markdown("OTP keys must be pre-shared physically (e.g., via USB drive). This section helps you manage your local pool of keys.")
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
                        gr.Markdown("## Your Identity")
                        gr.Textbox(label="Your Permanent, Key-Generated Username", value=app_state.identity_manager.username, interactive=False)
                        gr.Textbox(label="Your Full Public ID (Share this with peers)", value=app_state.identity_manager.public_id, interactive=False, lines=3)
                    with gr.Column():
                        gr.Markdown("## Manage Contacts")
                        contact_status = gr.Textbox(label="Status", interactive=False)
                        contact_public_id = gr.Textbox(label="Contact's Full Public ID(s) (one per line)", lines=3)
                        contact_generated_username = gr.Textbox(label="Generated Username (from first ID)", interactive=False)
                        add_contact_btn = gr.Button("Add/Update Contact(s)")

            with gr.TabItem("Offline Cryptography"):
                gr.Markdown("## One-Time Pad Encryption/Decryption")
                gr.Markdown("Perform encryption and decryption using pre-shared OTP keys and their indices.")
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

        connect_p2p_btn.click(connect_p2p, [p2p_contact_selector], [p2p_status_box, p2p_chat_selector])
        p2p_chat_input.submit(send_p2p_message_ui, [p2p_chat_input, p2p_chat_selector], [p2p_chat_input])
        p2p_chat_selector.change(change_active_chat, [p2p_chat_selector, all_chat_histories], [p2p_chat_output])
        
        contact_public_id.change(get_contact_username_for_id, [contact_public_id], [contact_generated_username])
        add_contact_btn.click(add_contact_ui, [contact_public_id], [contact_status, p2p_contact_selector])
        
        generate_keys_btn.click(generate_keys_ui, [otp_gen_num, otp_gen_len], [otp_status_box]).then(
            get_key_count_ui, None, otp_count_box)
        refresh_key_count_btn.click(get_key_count_ui, None, otp_count_box)

        crypto_encrypt_btn.click(encrypt_ui, [crypto_in_plain, crypto_enc_key_index], [crypto_out_cipher])
        crypto_decrypt_btn.click(decrypt_ui, [crypto_in_cipher, crypto_dec_key_index, crypto_dec_len], [crypto_out_plain])

        timer = gr.Timer(1, active=False)
        timer.tick(
            update_ui_loop,
            inputs=[p2p_chat_selector, all_chat_histories],
            outputs=[log_output, p2p_contact_selector, otp_count_box, all_chat_histories, p2p_chat_selector, chat_update_trigger]
        )
        chat_update_trigger.change(
            change_active_chat,
            inputs=[p2p_chat_selector, all_chat_histories],
            outputs=[p2p_chat_output]
        )
        demo.load(lambda: gr.Timer(active=True), None, outputs=timer).then(
            lambda: "[System] Select a peer to view chat history.", None, [p2p_chat_output]
        )

    demo.launch(inbrowser=True)
    app_state.node.stop()

if __name__ == "__main__":
    main()