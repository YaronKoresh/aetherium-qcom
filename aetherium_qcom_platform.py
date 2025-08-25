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
import gradio as gr
from PIL import Image
import io

class DependencyManager:
    REQUIRED_PACKAGES = ['numpy', 'Pillow', 'gradio']

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

class Config:
    NUM_PULSES = 10000
    EPOCH_SIZE = 2000
    DIFFIE_HELLMAN_PRIME = 23
    DIFFIE_HELLMAN_GENERATOR = 5
    CHAOTIC_MAP_R = 3.99
    COUPLING_STRENGTH = 0.01
    HEARTBEAT_PERIOD = 10
    AI_SECURITY_CONFIDENCE = 0.7
    OSCILLATOR_SYNC_TOLERANCE = 0.01
    DEFAULT_PORT = 65123

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

class IntelligentDefense:
    def __init__(self):
        self.beliefs = {'no_attack': 0.9, 'subtle_pns': 0.05, 'jitter': 0.05}
    def _likelihood(self, e, h):
        q, s, f = e['qber'], e['snr'], e['fingerprint_dev']
        if h == 'no_attack': return (1 - q)**10 * (1 - math.exp(-s)) * (1 - f)
        if h == 'subtle_pns': return q * 2 * (1 - math.exp(-s)) * (1 - f)
        if h == 'jitter': return (1 - q)**10 * math.exp(-s) * (1 - f)
        return 0
    def update(self, evidence, log_callback):
        prob_e = sum(self._likelihood(evidence, h) * self.beliefs[h] for h in self.beliefs)
        if prob_e == 0: return
        for h in self.beliefs: self.beliefs[h] = (self._likelihood(evidence, h) * self.beliefs[h]) / prob_e
        log_callback(f"[Bayes] Beliefs: " + ", ".join([f"{k}: {v:.2%}" for k, v in self.beliefs.items()]))
    def is_secure(self, t): return self.beliefs['no_attack'] > t

class CoupledChaoticSystem:
    def __init__(self, s, r, c): self.state, self.r, self.coupling = s, r, c
    def get_basis(self): return 'Z' if self.state < 0.5 else 'X'
    def evolve(self, sig): self.state = self.r * self.state * (1 - self.state) + self.coupling * sig

class QuantumSentryCryptography:
    def __init__(self, secure_key_seed):
        self.secure_seed = secure_key_seed
        self.chaotic_map = CoupledChaoticSystem(secure_key_seed, 3.99, 0)

    def _generate_keystream(self, length, nonce, seed_override=None):
        temp_seed = seed_override if seed_override is not None else self.secure_seed
        if not isinstance(temp_seed, float) or not (0.0 <= temp_seed < 1.0):
             temp_seed = int(hashlib.sha256(str(temp_seed).encode()).hexdigest(), 16) / (2**256)

        for byte in nonce:
            temp_seed = (temp_seed + byte / 255.0) / 2.0
        temp_map = CoupledChaoticSystem(temp_seed, 3.99, 0)
        keystream = bytearray(length)
        for i in range(length):
            temp_map.evolve(0)
            keystream[i] = int(temp_map.state * 255)
        return keystream

    def encrypt(self, plaintext, seed_override=None):
        nonce = os.urandom(8)
        keystream = self._generate_keystream(len(plaintext.encode('utf-8')), nonce, seed_override)
        encrypted_payload = bytes([p ^ k for p, k in zip(plaintext.encode('utf-8'), keystream)])
        return base64.b64encode(nonce + encrypted_payload).decode('utf-8')

    def decrypt(self, b64_ciphertext, seed_override=None):
        ciphertext = base64.b64decode(b64_ciphertext.encode('utf-8'))
        nonce, encrypted_payload = ciphertext[:8], ciphertext[8:]
        keystream = self._generate_keystream(len(encrypted_payload), nonce, seed_override)
        return bytes([c ^ k for c, k in zip(encrypted_payload, keystream)]).decode('utf-8')

    def _data_to_byte_array(self, data):
        if isinstance(data, (bytes, bytearray)): return bytearray(data)
        if isinstance(data, Image.Image): return bytearray(data.tobytes())
        if isinstance(data, np.ndarray): return bytearray(data.tobytes())
        raise TypeError(f"Unsupported data type for steganography: {type(data)}")

    def steg_embed(self, cover_data, secret_message):
        data_bytes = self._data_to_byte_array(cover_data)
        message_bits = ''.join(format(byte, '08b') for byte in secret_message.encode('utf-8'))
        if len(message_bits) > len(data_bytes): raise ValueError("Secret message is too large for the cover data.")
        self.chaotic_map.evolve(0)
        key_float = self.chaotic_map.state
        steganography_key = hex(int(key_float * (10**16)))
        indices = list(range(len(data_bytes))); random.Random(key_float).shuffle(indices)
        for i, bit in enumerate(message_bits):
            pixel_index = indices[i]
            data_bytes[pixel_index] = (data_bytes[pixel_index] & 0xFE) | int(bit)
        return data_bytes, steganography_key

    def steg_extract(self, cover_data, message_length_bytes, steganography_key):
        data_bytes = self._data_to_byte_array(cover_data)
        key_int = int(steganography_key, 16)
        key_float = key_int / (10**16)
        indices = list(range(len(data_bytes))); random.Random(key_float).shuffle(indices)
        num_bits = message_length_bytes * 8
        if num_bits > len(data_bytes): raise ValueError("Message length is larger than the cover data.")
        bits = "".join(str(data_bytes[indices[i]] & 1) for i in range(num_bits))
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode('utf-8', errors='ignore')

    def get_security_words(self):
        adjectives = ['happy', 'silly', 'fast', 'slow', 'bright', 'dark', 'warm', 'cold']
        nouns = ['fox', 'dog', 'cat', 'tree', 'rock', 'bird', 'fish', 'sun']
        seed_int = int(hashlib.sha256(str(self.secure_seed).encode()).hexdigest(), 16)
        random.seed(seed_int)
        word1 = random.choice(adjectives)
        word2 = random.choice(nouns)
        return f"{word1}-{word2}"

class ChannelHeartbeat:
    def __init__(self, p): self.period, self.counter = p, 0
    def get_timing_delay(self): self.counter += 1; return 1e-12 if self.counter % self.period == 0 else 0
    def get_snr(self, t):
        if len(t) < 2 * self.period: return 10.0
        s = np.array(t); f = np.fft.fft(s - np.mean(s)); fr = np.fft.fftfreq(len(s)); ti = np.argmin(np.abs(fr - (1/self.period))); sig = np.abs(f[ti]); n = np.mean(np.abs(np.delete(f, [0, ti]))); return sig / n if n > 0 else 10.0

class ProtocolEngine:
    def __init__(self, name, config, log_callback):
        self.name = name; self.config = config; self.log_callback = log_callback
        self.bits, self.bases, self.timestamps = [], [], []
        self.chaotic_system = None; self.heartbeat = ChannelHeartbeat(config.HEARTBEAT_PERIOD)
        self.defense_ai = IntelligentDefense(); self.baseline_fingerprint = None
    def establish_chaotic_seed(self, private_key, other_public_key):
        p, g = self.config.DIFFIE_HELLMAN_PRIME, self.config.DIFFIE_HELLMAN_GENERATOR
        shared_secret = pow(other_public_key, private_key, p)
        self.chaotic_system = CoupledChaoticSystem(shared_secret / p, self.config.CHAOTIC_MAP_R, self.config.COUPLING_STRENGTH)
    def prepare_pulse_data(self, current_time):
        bit, basis = random.choice([0, 1]), self.chaotic_system.get_basis()
        delay = self.heartbeat.get_timing_delay() if self.name == 'initiator' else 0
        self.bits.append(bit); self.bases.append(basis); self.timestamps.append(current_time + delay)
        intensity = random.choice(['vacuum', 'decoy', 'signal'])
        return {'bit': bit, 'basis': basis, 'mean_photon_number': {'vacuum': 0.0, 'decoy': 0.1, 'signal': 0.5}[intensity], 'timestamp': current_time + delay}
    def analyze_epoch(self, results, all_bases_other):
        sifted_indices = [i for i, res in enumerate(results) if res['success'] and self.bases[i] == all_bases_other[i]]
        mismatches = sum(1 for i in sifted_indices if self.bits[i] != (1 - results[i]['bit_other'] if results[i]['outcome'] == 'Psi-' else results[i]['bit_other']))
        qber = mismatches / len(sifted_indices) if sifted_indices else 0
        timestamps = [res['timestamp'] for i, res in enumerate(results) if i in sifted_indices]
        snr = self.heartbeat.get_snr(timestamps)
        outcomes = [res['outcome'] for res in results if res['success']]
        current_fingerprint = Counter(outcomes)
        fingerprint_dev = 0.0
        if self.baseline_fingerprint is None:
            if outcomes: self.baseline_fingerprint = {k: v / len(outcomes) for k, v in current_fingerprint.items()}
        else:
            dev = sum(abs(self.baseline_fingerprint.get(k, 0) - current_fingerprint.get(k, 0) / len(outcomes)) for k in set(self.baseline_fingerprint) | set(current_fingerprint)) if outcomes else 0
            fingerprint_dev = dev
        evidence = {'qber': qber, 'snr': snr, 'fingerprint_dev': fingerprint_dev}
        self.defense_ai.update(evidence, self.log_callback)
        return self.defense_ai.is_secure(self.config.AI_SECURITY_CONFIDENCE)
    def get_final_key_seed(self):
        return self.chaotic_system.state
class Node:
    def __init__(self, config, identity_manager, contact_manager, log_queue, event_queue):
        self.config = config
        self.identity = identity_manager
        self.contacts = contact_manager
        self.log_queue = log_queue
        self.event_queue = event_queue
        self.stop_event = threading.Event()
        self.sessions = {}
        self.server_socket = None

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

    def stop(self):
        self.stop_event.set()
        if self.server_socket: self.server_socket.close()
        for session in self.sessions.values(): session['conn'].close()
        self.log("Node stopped.")

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
        
        if req['type'] == 'p2p_qkd':
            self._handle_p2p_qkd_responder(conn, req)
        else:
            self.log(f"Unknown request type '{req['type']}'. Closing."); conn.close()
    
    def initiate_p2p_session(self, peer_ip, peer_username):
        peer_public_id = self.contacts.get_public_id(peer_username)
        if not peer_public_id:
            self.log(f"Cannot connect: username '{peer_username}' not in contacts.")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': 'User not in contacts.'})
            return

        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((peer_ip, self.config.DEFAULT_PORT))
            self.send_json(conn, {'type': 'p2p_qkd', 'public_id': self.identity.public_id, 'username': self.identity.username})
            self._run_qkd_and_auth(conn, 'initiator', peer_public_id, peer_username)
        except Exception as e:
            self.log(f"Failed to connect to {peer_ip}: {e}")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': str(e)})

    def _handle_p2p_qkd_responder(self, conn, request):
        peer_public_id = request.get('public_id')
        received_username = request.get('username')
        
        expected_username = self.identity.generate_username_from_id(peer_public_id)
        if expected_username != received_username:
            self.log(f"IDENTITY ALERT: Peer with Public ID {peer_public_id[:6]}... broadcasted username '{received_username}' but their key corresponds to '{expected_username}'. Rejecting.")
            self.send_json(conn, {'control': 'abort', 'reason': 'Broadcasted username does not match public key.'}); conn.close(); return

        known_username = self.contacts.get_username_by_id(peer_public_id)
        if not known_username:
            self.log(f"Connection from unknown Public ID {peer_public_id[:10]}... ('{expected_username}'). Add them as a contact to connect.")
            self.send_json(conn, {'control': 'abort', 'reason': 'Unknown public ID - not in contacts.'}); conn.close(); return

        self.log(f"Accepted P2P session with '{known_username}' ({peer_public_id[:10]}...)")
        self._run_qkd_and_auth(conn, 'responder', peer_public_id, known_username)

    def _run_qkd_and_auth(self, conn, role, peer_public_id, peer_username):
        engine = ProtocolEngine(role, self.config, self.log)
        private_key = random.randint(1, self.config.DIFFIE_HELLMAN_PRIME - 1)
        public_key = pow(self.config.DIFFIE_HELLMAN_GENERATOR, private_key, self.config.DIFFIE_HELLMAN_PRIME)
        self.send_json(conn, {'dh_pub_key': public_key})
        peer_dh_data = self.recv_json(conn)
        if not peer_dh_data: self.log("QKD Failed: No DH key."); conn.close(); return
        engine.establish_chaotic_seed(private_key, peer_dh_data['dh_pub_key'])
        self.log("Chaotic seed established.")
        
        results = []
        for i in range(self.config.NUM_PULSES):
            pulse_data = engine.prepare_pulse_data(i * 1e-9)
            if not self.send_json(conn, {'pulse': pulse_data}): break
            response = self.recv_json(conn)
            if not response or 'pulse' not in response: break
            peer_pulse = response['pulse']
            prob = (1 - math.exp(-pulse_data['mean_photon_number'])) * (1 - math.exp(-peer_pulse['mean_photon_number'])) * 0.5
            success = random.random() < prob
            outcome = random.choice(['Psi-', 'Psi+', 'Phi-', 'Phi+']) if success else None
            results.append({'success': success, 'outcome': outcome, 'bit_other': peer_pulse['bit'] if success else -1, 'timestamp': pulse_data['timestamp']})
            if not self.send_json(conn, {'bsm_result': {'success': success, 'outcome': outcome, 'bit_other': pulse_data['bit'] if success else -1, 'timestamp': peer_pulse['timestamp']}}): break
            if (i + 1) % self.config.EPOCH_SIZE == 0:
                if not self.send_json(conn, {'bases': engine.bases[-self.config.EPOCH_SIZE:]}): break
                peer_bases_data = self.recv_json(conn)
                if not peer_bases_data: break
                if not engine.analyze_epoch(results[-self.config.EPOCH_SIZE:], peer_bases_data['bases']):
                    self.log("AI Anomaly Detected! Aborting."); self.send_json(conn, {'control': 'abort', 'reason': 'AI Anomaly'}); conn.close(); return
        
        self.send_json(conn, {'state': engine.chaotic_system.state})
        peer_state_data = self.recv_json(conn)
        if not peer_state_data: self.log("QKD Failed: No final state."); conn.close(); return
        
        sync_error = abs(engine.chaotic_system.state - peer_state_data['state'])
        if sync_error >= self.config.OSCILLATOR_SYNC_TOLERANCE:
            self.log("QKD Failed: Sync error too high."); conn.close(); return
        
        qkd_key = engine.get_final_key_seed()
        self.log("QKD key exchange successful.")

        my_info = {'pid': self.identity.public_id, 'un': self.identity.username}
        peer_info = {'pid': peer_public_id, 'un': peer_username}
        participants = sorted([my_info, peer_info], key=lambda x: x['pid'])
        p1, p2 = participants[0], participants[1]

        secret_string = f"{qkd_key}:{p1['pid']}:{p1['un']}:{p2['pid']}:{p2['un']}:{self.identity.private_key}"
        final_session_key_str = hashlib.sha256(secret_string.encode()).hexdigest()
        final_session_key = int(final_session_key_str, 16) / (2**256)

        verification_hash = hashlib.sha256(final_session_key_str.encode()).hexdigest()
        self.send_json(conn, {'verify_hash': verification_hash})
        
        peer_verify_data = self.recv_json(conn)
        if not peer_verify_data or peer_verify_data.get('verify_hash') != verification_hash:
            self.log("FATAL: CRYPTOGRAPHIC IDENTITY VERIFICATION FAILED! Impersonation or MITM attack likely.")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': 'Cryptographic identity verification failed!'})
            conn.close(); return

        self.log(f"✅ Identity Verified & Secure P2P Session Established with '{peer_username}'!")
        
        crypto_suite = QuantumSentryCryptography(final_session_key)
        self.sessions[peer_username] = {'conn': conn, 'crypto': crypto_suite, 'public_id': peer_public_id}
        
        self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'success', 'security_words': crypto_suite.get_security_words()})
        self._listen_for_messages(conn, peer_username)

    def _listen_for_messages(self, conn, peer_username):
        while not self.stop_event.is_set():
            message = self.recv_json(conn)
            if message is None:
                self.log(f"Connection with '{peer_username}' lost.")
                self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'disconnected'})
                if peer_username in self.sessions: del self.sessions[peer_username]
                break
            
            if message.get('type') == 'p2p_chat':
                self.event_queue.put({'type': 'p2p_message', 'from': peer_username, 'data': message['data']})

    def send_p2p_message(self, peer_username, text_message):
        if peer_username in self.sessions:
            session = self.sessions[peer_username]
            encrypted_msg = session['crypto'].encrypt(text_message)
            self.send_json(session['conn'], {'type': 'p2p_chat', 'data': encrypted_msg})
        else:
            self.log(f"Not connected to peer '{peer_username}'.")

class AppState:
    def __init__(self):
        self.app_config = Config()
        self.log_queue = queue.Queue()
        self.event_queue = queue.Queue()
        self.system_log = ""
        self.identity_manager = IdentityManager(self.log)
        self.contact_manager = ContactManager(self.log, self.identity_manager)
        self.node = Node(self.app_config, self.identity_manager, self.contact_manager, self.log_queue, self.event_queue)
        
        offline_seed = int(hashlib.sha256(self.identity_manager.private_key.encode()).hexdigest(), 16) / (2**256)
        self.offline_crypto_suite = QuantumSentryCryptography(offline_seed)
        
        self.system_log = ""
        self.p2p_chats = {}

    def log(self, message):
        self.system_log += f"{time.strftime('%H:%M:%S')} - {message}\n"

    def add_p2p_chat(self, peer_username, message):
        if peer_username not in self.p2p_chats:
            self.p2p_chats[peer_username] = {'history': "", 'crypto': None, 'status': 'connecting'}
        self.p2p_chats[peer_username]['history'] += message + "\n"

app_state = AppState()

def update_ui_loop():
    while not app_state.log_queue.empty(): app_state.log(app_state.log_queue.get_nowait())
    while not app_state.event_queue.empty():
        event = app_state.event_queue.get_nowait()
        peer_username = event.get('peer_username') or event.get('from')
        if not peer_username: continue
        
        if event['type'] == 'p2p_status':
            if event['status'] == 'success':
                app_state.p2p_chats[peer_username] = {'history': f"[System] ✅ Secure connection established with '{peer_username}'.\nSecurity Words: {event['security_words']}\n", 'crypto': app_state.node.sessions[peer_username]['crypto'], 'status': 'connected'}
                app_state.log(f"Successfully connected to peer '{peer_username}'")
            else:
                status_msg = f"[System] ❌ Connection to '{peer_username}' failed or disconnected.\nReason: {event.get('reason', 'Connection lost.')}\n"
                if peer_username in app_state.p2p_chats:
                    app_state.p2p_chats[peer_username]['history'] += status_msg
                    app_state.p2p_chats[peer_username]['status'] = 'disconnected'
                else:
                    app_state.p2p_chats[peer_username] = {'history': status_msg, 'crypto': None, 'status': 'failed'}
                app_state.log(f"Connection with '{peer_username}' failed or ended.")
        
        elif event['type'] == 'p2p_message':
            if peer_username in app_state.p2p_chats:
                try:
                    decrypted_msg = app_state.p2p_chats[peer_username]['crypto'].decrypt(event['data'])
                    app_state.add_p2p_chat(peer_username, f"{peer_username}: {decrypted_msg}")
                except Exception as e:
                    app_state.log(f"P2P Decrypt Error from '{peer_username}': {e}")

    chat_histories = {un: chat['history'] for un, chat in app_state.p2p_chats.items()}
    return app_state.system_log, gr.update(choices=list(app_state.contact_manager.contacts.keys())), chat_histories, list(app_state.p2p_chats.keys())

def connect_p2p(peer_ip, peer_username):
    if not peer_ip or not peer_username: return "Peer IP and Username are required.", gr.update()
    app_state.log(f"Initiating P2P session with '{peer_username}' at {peer_ip}")
    threading.Thread(target=app_state.node.initiate_p2p_session, args=(peer_ip, peer_username)).start()
    app_state.add_p2p_chat(peer_username, f"[System] Connecting to '{peer_username}'...\n")
    return f"Connecting to {peer_username}...", gr.update(value=peer_username)

def send_p2p_message_ui(message, current_peer):
    if not message or not current_peer: return ""
    if app_state.p2p_chats.get(current_peer, {}).get('status') != 'connected':
        app_state.log("Cannot send message: Not securely connected."); return ""
    app_state.add_p2p_chat(current_peer, f"You: {message}")
    app_state.node.send_p2p_message(current_peer, message); return ""

def change_active_chat(peer_username, all_histories_state):
    return all_histories_state.get(peer_username, "[System] Select a peer to view chat history.")

def add_contact_ui(public_id):
    msg, success = app_state.contact_manager.add_contact(public_id)
    return msg, gr.update(choices=list(app_state.contact_manager.contacts.keys()))

def get_contact_username_for_id(public_id):
    if not public_id or len(public_id) != 64: return "[Enter a valid Public ID above]"
    return app_state.identity_manager.generate_username_from_id(public_id)

def steg_embed_ui(cover_image, secret_message):
    if cover_image is None or not secret_message: return None, "Error: Cover image and secret message are required."
    try:
        data_bytes, steganography_key = app_state.offline_crypto_suite.steg_embed(cover_image, secret_message)
        stego_image = Image.frombytes(cover_image.mode, cover_image.size, bytes(data_bytes))
        app_state.log("Message embedded successfully.")
        return stego_image, steganography_key
    except Exception as e:
        app_state.log(f"Steganography Embed Error: {e}"); return None, str(e)

def steg_extract_ui(stego_image, steganography_key, message_length):
    if stego_image is None or not steganography_key or not message_length: return "Error: Stego image, key, and message length are required."
    try:
        extracted_message = app_state.offline_crypto_suite.steg_extract(stego_image, int(message_length), steganography_key)
        app_state.log("Message extracted successfully."); return extracted_message
    except Exception as e:
        app_state.log(f"Steganography Extract Error: {e}"); return f"Extraction Failed: {e}"

def get_crypto_suite(key_str=None):
    if key_str:
        seed = int(hashlib.sha256(key_str.encode()).hexdigest(), 16) / (2**256)
        return QuantumSentryCryptography(seed)
    return app_state.offline_crypto_suite

def encrypt_ui(plaintext, key):
    if not plaintext: return ""
    return get_crypto_suite(key).encrypt(plaintext)

def decrypt_ui(ciphertext, key):
    if not ciphertext: return ""
    try:
        return get_crypto_suite(key).decrypt(ciphertext)
    except Exception as e:
        app_state.log(f"Offline decrypt error: {e}"); return f"DECRYPTION FAILED: {e}"
        
def main():
    DependencyManager.ensure_dependencies()
    app_state.node.start()

    with gr.Blocks(theme=gr.themes.Soft(), title="Aetherium Q-Com") as demo:
        gr.Markdown("# Aetherium Q-Com")
        all_chat_histories = gr.State({})

        with gr.Tabs():
            with gr.TabItem("Network & P2P"):
                with gr.Row():
                    with gr.Column(scale=1):
                        gr.Markdown("## Connect to a Peer")
                        p2p_contact_selector = gr.Dropdown(label="Select Contact to Connect", choices=list(app_state.contact_manager.contacts.keys()), interactive=True)
                        peer_ip_input = gr.Textbox(label="Peer IP Address", value="127.0.0.1")
                        connect_p2p_btn = gr.Button("Connect Securely to Selected Contact")
                        p2p_status_box = gr.Textbox(label="Connection Status", interactive=False)
                    with gr.Column(scale=2):
                        gr.Markdown("## P2P Chat")
                        p2p_chat_selector = gr.Dropdown(label="Active P2P Chat", interactive=True)
                        p2p_chat_output = gr.Textbox(label="Secure Chat", lines=10, interactive=False, autoscroll=True)
                        p2p_chat_input = gr.Textbox(show_label=False, placeholder="Type your secure message...")

            with gr.TabItem("Identity & Contacts"):
                 with gr.Row():
                    with gr.Column():
                        gr.Markdown("## Your Identity")
                        gr.Textbox(label="Your Permanent, Key-Generated Username", value=app_state.identity_manager.username, interactive=False)
                        gr.Textbox(label="Your Full Public ID (Share this with peers)", value=app_state.identity_manager.public_id, interactive=False, lines=3)
                    with gr.Column():
                        gr.Markdown("## Manage Contacts")
                        contact_status = gr.Textbox(label="Status", interactive=False)
                        contact_public_id = gr.Textbox(label="Contact's Full Public ID")
                        contact_generated_username = gr.Textbox(label="Generated Username", interactive=False)
                        add_contact_btn = gr.Button("Add/Update Contact")
                        
            with gr.TabItem("Offline Tools"):
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("## Steganography")
                        gr.Markdown("### Embed Message in Image")
                        steg_in_image = gr.Image(type="pil", label="Cover Image")
                        steg_in_message = gr.Textbox(label="Secret Message")
                        steg_embed_btn = gr.Button("Embed")
                        steg_out_image = gr.Image(type="pil", label="Stego Image (with hidden message)")
                        steg_out_key = gr.Textbox(label="Steganography Key (Required for extraction)", interactive=False)
                        gr.Markdown("---")
                        gr.Markdown("### Extract Message from Image")
                        steg_extract_in_image = gr.Image(type="pil", label="Stego Image")
                        steg_extract_in_key = gr.Textbox(label="Steganography Key")
                        steg_extract_in_len = gr.Number(label="Secret Message Length (in bytes)", precision=0)
                        steg_extract_btn = gr.Button("Extract")
                        steg_extract_out_message = gr.Textbox(label="Extracted Secret Message", interactive=False)
                    with gr.Column():
                        gr.Markdown("## Cryptography")
                        crypto_in_key = gr.Textbox(label="Custom Key / Seed (Optional)", placeholder="Uses your identity key by default")
                        gr.Markdown("### Encrypt")
                        crypto_in_plain = gr.Textbox(label="Plaintext", lines=8)
                        crypto_encrypt_btn = gr.Button("Encrypt")
                        gr.Markdown("### Decrypt")
                        crypto_out_cipher = gr.Textbox(label="Ciphertext", lines=8)
                        crypto_decrypt_btn = gr.Button("Decrypt")

            with gr.TabItem("System Log"):
                log_output = gr.Textbox(label="Log", lines=20, interactive=False, autoscroll=True)

        connect_p2p_btn.click(connect_p2p, [peer_ip_input, p2p_contact_selector], [p2p_status_box, p2p_chat_selector])
        p2p_chat_input.submit(send_p2p_message_ui, [p2p_chat_input, p2p_chat_selector], [p2p_chat_input])
        p2p_chat_selector.change(change_active_chat, [p2p_chat_selector, all_chat_histories], [p2p_chat_output])
        
        contact_public_id.change(get_contact_username_for_id, [contact_public_id], [contact_generated_username])
        add_contact_btn.click(add_contact_ui, [contact_public_id], [contact_status, p2p_contact_selector])
        
        steg_embed_btn.click(steg_embed_ui, [steg_in_image, steg_in_message], [steg_out_image, steg_out_key])
        steg_extract_btn.click(steg_extract_ui, [steg_extract_in_image, steg_extract_in_key, steg_extract_in_len], [steg_extract_out_message])
        crypto_encrypt_btn.click(encrypt_ui, [crypto_in_plain, crypto_in_key], [crypto_out_cipher])
        crypto_decrypt_btn.click(decrypt_ui, [crypto_out_cipher, crypto_in_key], [crypto_in_plain])

        demo.load(update_ui_loop, None, [log_output, p2p_contact_selector, all_chat_histories, p2p_chat_selector], every=1).then(
            change_active_chat, [p2p_chat_selector, all_chat_histories], [p2p_chat_output]
        )

    demo.launch()
    app_state.node.stop()

if __name__ == "__main__":
    main()
