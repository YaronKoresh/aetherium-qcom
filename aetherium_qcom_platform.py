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

        os.system(f"pip install {' '.join(missing_packages)}")

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
    DISCOVERY_PORT = 65100
    CHARLIE_PORT = 65000
    ALICE_PORT = 65001
    BOB_PORT = 65002
    GROUP_HOST_PORT = 65003
    CHAT_PORT_OFFSET = 100

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
        for byte in nonce:
            temp_seed = (temp_seed + byte / 255.0) / 2.0
        temp_map = CoupledChaoticSystem(temp_seed, 3.99, 0)
        return bytes([max(1, int(temp_map.evolve(0) or temp_map.state * 255)) for _ in range(length)])
    def encrypt(self, plaintext, seed_override=None):
        nonce = os.urandom(8)
        keystream = self._generate_keystream(len(plaintext), nonce, seed_override)
        encrypted_payload = bytes([p ^ k for p, k in zip(plaintext.encode('utf-8'), keystream)])
        return (nonce + encrypted_payload).hex()
    def decrypt(self, hex_ciphertext, seed_override=None):
        ciphertext = bytes.fromhex(hex_ciphertext)
        nonce = ciphertext[:8]
        encrypted_payload = ciphertext[8:]
        keystream = self._generate_keystream(len(encrypted_payload), nonce, seed_override)
        return bytes([c ^ k for c, k in zip(encrypted_payload, keystream)]).decode('utf-8')
    def hash(self, message):
        temp_map = CoupledChaoticSystem(0.5, 3.99, 0)
        for byte in message.encode('utf-8'):
            temp_map.state = (temp_map.state + byte / 255.0) / 2.0
            temp_map.evolve(0)
        return hex(int(temp_map.state * (10**16)))
    def _data_to_byte_array(self, data):
        if isinstance(data, bytearray): return data
        if isinstance(data, bytes): return bytearray(data)
        if isinstance(data, str):
            try:
                with open(data, 'rb') as f: return bytearray(f.read())
            except Exception as e: raise IOError(f"Could not read file: {data}\n{e}")
        if isinstance(data, np.ndarray): return bytearray(data.tobytes())
        raise TypeError(f"Unsupported data type: {type(data)}")
    def steg_embed(self, cover_data, secret_message):
        data_bytes = self._data_to_byte_array(cover_data)
        message_bits = ''.join(format(byte, '08b') for byte in secret_message.encode('utf-8'))
        if len(message_bits) > len(data_bytes): raise ValueError("Secret message is too large.")
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
        bits = "".join(str(data_bytes[indices[i]] & 1) for i in range(message_length_bytes * 8))
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode('utf-8')
    def get_security_words(self):
        adjectives = ['happy', 'silly', 'fast', 'slow', 'bright', 'dark', 'warm', 'cold']
        nouns = ['fox', 'dog', 'cat', 'tree', 'rock', 'bird', 'fish', 'sun']
        random.seed(self.secure_seed)
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
        delay = self.heartbeat.get_timing_delay() if self.name == 'User 1' else 0
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
            dev = 0
            if outcomes: [dev := dev + abs(v - current_fingerprint.get(k, 0) / len(outcomes)) for k, v in self.baseline_fingerprint.items()]
            fingerprint_dev = dev
        evidence = {'qber': qber, 'snr': snr, 'fingerprint_dev': fingerprint_dev}
        self.defense_ai.update(evidence, self.log_callback)
        return self.defense_ai.is_secure(self.config.AI_SECURITY_CONFIDENCE)
    def get_final_key_seed(self):
        return self.chaotic_system.state

class NetworkNode(threading.Thread):
    def __init__(self, name, log_queue):
        super().__init__(daemon=True)
        self.name = name; self.log_queue = log_queue
    def log(self, message): self.log_queue.put(f"[{self.name}] {message}")
    def send_json(self, sock, data):
        try:
            message = json.dumps(data).encode('utf-8')
            sock.sendall(len(message).to_bytes(4, 'big') + message)
        except (ConnectionResetError, BrokenPipeError, OSError): pass
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
        except (json.JSONDecodeError, ConnectionResetError, ConnectionAbortedError, OSError): return None

class SessionHostNode(NetworkNode):
    def __init__(self, config, log_queue):
        super().__init__("Session Host", log_queue)
        self.config = config
        self.stop_event = threading.Event()
        self.sessions = {}
    def run(self):
        self.log("Session Host starting...")
        threading.Thread(target=self.broadcast_presence, daemon=True).start()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', self.config.CHARLIE_PORT)); s.listen(10)
            self.log(f"Listening for connections on port {self.config.CHARLIE_PORT}")
            while not self.stop_event.is_set():
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
                except OSError:
                    break
    def handle_client(self, conn, addr):
        client_info = self.recv_json(conn)
        if not client_info: conn.close(); return
        session_code = client_info['session_code']
        self.log(f"Client '{client_info['name']}' from {addr[0]} wants to join session '{session_code}'")
        if session_code not in self.sessions:
            self.sessions[session_code] = []
        self.sessions[session_code].append({'conn': conn, 'pub_key': client_info['pub_key'], 'ip': addr[0], 'name': client_info['name']})
        if len(self.sessions[session_code]) == 2:
            self.log(f"Session '{session_code}' is full. Pairing users for P2P QKD...")
            client1, client2 = self.sessions[session_code]
            self.send_json(client1['conn'], {'pub_key': client2['pub_key'], 'peer_ip': client2['ip'], 'peer_name': client2['name']})
            self.send_json(client2['conn'], {'pub_key': client1['pub_key'], 'peer_ip': client1['ip'], 'peer_name': client1['name']})
            self.run_qkd_session(client1['conn'], client2['conn'])
            del self.sessions[session_code]
    def run_qkd_session(self, conn1, conn2):
        for _ in range(self.config.NUM_PULSES):
            pulse1 = self.recv_json(conn1); pulse2 = self.recv_json(conn2)
            if pulse1 is None or pulse2 is None: break
            prob = (1 - math.exp(-pulse1['mean_photon_number'])) * (1 - math.exp(-pulse2['mean_photon_number'])) * 0.5
            success = random.random() < prob
            outcome = random.choice(['Psi-', 'Psi+', 'Phi-', 'Phi+']) if success else None
            result1 = {'success': success, 'outcome': outcome, 'bit_other': pulse2['bit'] if success else -1}
            self.send_json(conn1, result1)
            result2 = {'success': success, 'outcome': outcome, 'bit_other': pulse1['bit'] if success else -1}
            self.send_json(conn2, result2)
        self.log("QKD session finished.")
    def broadcast_presence(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            message = json.dumps({"type": "AETHERIUM_RELAY_DISCOVERY", "port": self.config.CHARLIE_PORT}).encode('utf-8')
            while not self.stop_event.is_set():
                sock.sendto(message, ('<broadcast>', self.config.DISCOVERY_PORT))
                time.sleep(3)

class GroupSessionHostNode(NetworkNode):
    def __init__(self, config, log_queue):
        super().__init__("Group Host", log_queue)
        self.config = config
        self.stop_event = threading.Event()
        self.sessions = {}
    def run(self):
        self.log("Group Session Host starting...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', self.config.GROUP_HOST_PORT))
            s.listen(10)
            self.log(f"Listening for group connections on port {self.config.GROUP_HOST_PORT}")
            while not self.stop_event.is_set():
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
                except OSError:
                    break
    def handle_client(self, conn, addr):
        self.log(f"New group client connection from {addr}")
        while not self.stop_event.is_set():
            msg = self.recv_json(conn)
            if msg is None:
                self.remove_client(conn)
                break
            command = msg.get('command')
            session_code = msg.get('session_code')
            user_name = msg.get('name')
            if command == 'create':
                self.sessions[session_code] = {'owner': user_name, 'members': {user_name: conn}}
                self.log(f"User '{user_name}' created group session '{session_code}'")
                self.broadcast_user_list(session_code)
            elif command == 'join':
                if session_code in self.sessions:
                    self.sessions[session_code]['members'][user_name] = conn
                    self.log(f"User '{user_name}' joined group session '{session_code}'")
                    self.broadcast_user_list(session_code)
                else:
                    self.send_json(conn, {'type': 'error', 'message': 'Session not found'})
            elif command == 'message':
                self.log(f"Broadcasting message from '{user_name}' in session '{session_code}'")
                self.broadcast(session_code, {'type': 'group_message', 'from': user_name, 'data': msg.get('data')}, exclude=user_name)
            elif command == 'distribute_key':
                self.log(f"Distributing wrapped key for session '{session_code}'")
                self.broadcast(session_code, {'type': 'key_distribution', 'from': user_name, 'wrapped_keys': msg.get('wrapped_keys')}, exclude=user_name)
    def broadcast(self, session_code, message, exclude=None):
        if session_code in self.sessions:
            members = self.sessions[session_code]['members']
            for name, conn in list(members.items()):
                if name != exclude:
                    try:
                        self.send_json(conn, message)
                    except:
                        self.remove_client(conn)
    def broadcast_user_list(self, session_code):
        if session_code in self.sessions:
            user_list = list(self.sessions[session_code]['members'].keys())
            self.broadcast(session_code, {'type': 'user_list_update', 'users': user_list})
    def remove_client(self, conn):
        for code, session in self.sessions.items():
            for name, client_conn in list(session['members'].items()):
                if client_conn == conn:
                    self.log(f"Client '{name}' disconnected.")
                    del session['members'][name]
                    self.broadcast_user_list(code)
                    return

class UserNode(NetworkNode):
    def __init__(self, name, session_code, config, log_queue, result_queue, chat_queue):
        super().__init__(name, log_queue)
        self.session_code = session_code; self.config = config; self.result_queue = result_queue; self.chat_queue = chat_queue
        self.engine = ProtocolEngine(name, config, self.log)
        self.chat_socket = None; self.peer_ip = None; self.peer_port = None
    def run(self):
        self.log("Client Node starting...")
        relay_ip = self.discover_relay()
        if not relay_ip:
            self.result_queue.put({'type': 'request_ip'})
            relay_ip = self.result_queue.get()
            if not relay_ip: self.log("No Host IP provided. Aborting."); self.result_queue.put(None); return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_charlie:
                s_charlie.connect((relay_ip, self.config.CHARLIE_PORT))
                self.log(f"Connected to Host at {relay_ip}:{self.config.CHARLIE_PORT}")
                private_key = random.randint(1, self.config.DIFFIE_HELLMAN_PRIME - 1)
                public_key = pow(self.config.DIFFIE_HELLMAN_GENERATOR, private_key, self.config.DIFFIE_HELLMAN_PRIME)
                self.send_json(s_charlie, {'name': self.name, 'pub_key': public_key, 'session_code': self.session_code})
                other_data = self.recv_json(s_charlie)
                if not other_data or 'pub_key' not in other_data:
                    self.log("Failed to get peer data from host.")
                    self.result_queue.put(None)
                    return
                other_public_key = other_data['pub_key']
                self.peer_ip = other_data['peer_ip']
                self.peer_port = self.config.BOB_PORT if self.name == "User 1" else self.config.ALICE_PORT
                self.log(f"Peer '{other_data['peer_name']}' is at {self.peer_ip}")
                self.engine.establish_chaotic_seed(private_key, other_public_key); self.log("Chaotic seed established.")
                results = []
                for i in range(self.config.NUM_PULSES):
                    pulse_data = self.engine.prepare_pulse_data(i * 1e-9)
                    self.send_json(s_charlie, pulse_data)
                    result = self.recv_json(s_charlie)
                    if result is None: break
                    results.append(result)
                    if (i + 1) % self.config.EPOCH_SIZE == 0:
                        if not self.perform_epoch_analysis(results[-self.config.EPOCH_SIZE:]):
                            self.result_queue.put(None); return
                final_key = self.perform_final_sync()
                final_key_package = {'key': final_key, 'peer_name': other_data['peer_name']}
                self.result_queue.put(final_key_package)
        except Exception as e: self.log(f"QKD Error: {e}"); self.result_queue.put(None)
        self.log("QKD process finished.")
    def discover_relay(self):
        self.log("Searching for Session Host on the local network...")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("", self.config.DISCOVERY_PORT))
            sock.settimeout(5)
            try:
                data, addr = sock.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))
                if message.get("type") == "AETHERIUM_RELAY_DISCOVERY":
                    self.log(f"Found Host at {addr[0]}"); return addr[0]
            except socket.timeout: self.log("Automatic discovery timed out."); return None
        return None
    def perform_epoch_analysis(self, results):
        my_port = self.config.ALICE_PORT if self.name == "User 1" else self.config.BOB_PORT
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_peer:
                if self.name == 'User 1':
                    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    serv.bind(('', my_port)); serv.listen(1)
                    conn, addr = serv.accept()
                    with conn:
                        self.send_json(conn, {'bases': self.engine.bases[-self.config.EPOCH_SIZE:]})
                        other_bases = self.recv_json(conn)['bases']
                    serv.close()
                else:
                    time.sleep(0.5)
                    s_peer.connect((self.peer_ip, self.peer_port))
                    other_bases = self.recv_json(s_peer)['bases']
                    self.send_json(s_peer, {'bases': self.engine.bases[-self.config.EPOCH_SIZE:]})
            is_secure = self.engine.analyze_epoch(results, other_bases)
            if not is_secure: self.log("AI detected anomaly. Aborting."); return False
            return True
        except Exception as e: self.log(f"Epoch Sync Error: {e}"); return False
    def perform_final_sync(self):
        my_port = self.config.ALICE_PORT if self.name == "User 1" else self.config.BOB_PORT
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_peer:
                if self.name == 'User 1':
                    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    serv.bind(('', my_port)); serv.listen(1)
                    conn, addr = serv.accept()
                    with conn:
                        self.send_json(conn, {'state': self.engine.chaotic_system.state})
                        other_state = self.recv_json(conn)['state']
                    serv.close()
                else:
                    time.sleep(0.5)
                    s_peer.connect((self.peer_ip, self.peer_port))
                    other_state = self.recv_json(s_peer)['state']
                    self.send_json(s_peer, {'state': self.engine.chaotic_system.state})
            sync_error = abs(self.engine.chaotic_system.state - other_state)
            self.log(f"Final oscillator sync error: {sync_error:.6f}")
            if sync_error < self.config.OSCILLATOR_SYNC_TOLERANCE: return self.engine.get_final_key_seed()
            return None
        except Exception as e: self.log(f"Final Sync Error: {e}"); return None
    def start_chat_listener(self):
        my_port = self.config.ALICE_PORT if self.name == "User 1" else self.config.BOB_PORT
        threading.Thread(target=self._chat_listener_thread, args=(my_port,), daemon=True).start()
    def _chat_listener_thread(self, my_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', my_port + self.config.CHAT_PORT_OFFSET))
            s.listen(1)
            self.log(f"Chat listener started on port {my_port + self.config.CHAT_PORT_OFFSET}")
            conn, addr = s.accept()
            with conn:
                self.log(f"Chat connection established with {addr}")
                while True:
                    encrypted_msg = self.recv_json(conn)
                    if encrypted_msg is None: break
                    self.chat_queue.put({'type': 'received', 'data': encrypted_msg['data']})
            self.log("Chat connection closed.")
    def connect_and_send_chat(self, encrypted_msg):
        if not self.chat_socket or self.chat_socket.fileno() == -1:
            self.chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.chat_socket.connect((self.peer_ip, self.peer_port + self.config.CHAT_PORT_OFFSET))
                self.log(f"Connected to peer for chat at {self.peer_ip}:{self.peer_port + self.config.CHAT_PORT_OFFSET}")
            except Exception as e:
                self.log(f"Chat connection failed: {e}"); return
        self.send_json(self.chat_socket, {'data': encrypted_msg})

class AppState:
    def __init__(self):
        self.app_config = Config()
        self.secure_key_seed = None
        self.crypto_suite = None
        self.log_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.chat_queue = queue.Queue()
        self.user_node = None
        self.password_vault = {}
        self.group_chat_socket = None
        self.group_session_code = None
        self.group_key = None
        self.user_name = "User" + str(random.randint(100, 999))
        self.p2p_keys = {}
        self.system_log = ""
        self.p2p_chat_history = ""
        self.group_chat_history = ""
        self.group_user_list = []
        self.is_owner = False

    def log(self, message):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.system_log += f"{timestamp} - {message}\n"

    def add_p2p_chat(self, message):
        self.p2p_chat_history += message + "\n"

    def add_group_chat(self, message):
        self.group_chat_history += message + "\n"

app_state = AppState()

def log_to_state(message):
    app_state.log(message)

def launch_p2p_host():
    app_state.log("Launching P2P Session Host...")
    charlie = SessionHostNode(app_state.app_config, app_state.log_queue)
    charlie.start()
    return "P2P Host is running...", gr.update(interactive=False), gr.update(interactive=False), gr.update(interactive=False), gr.update(interactive=False)

def launch_group_host():
    app_state.log("Launching Group Session Host...")
    group_host = GroupSessionHostNode(app_state.app_config, app_state.log_queue)
    group_host.start()
    return "Group Host is running...", gr.update(interactive=False), gr.update(interactive=False), gr.update(interactive=False), gr.update(interactive=False)

def create_p2p_session():
    word1 = random.choice(['blue', 'red', 'green', 'fast', 'slow', 'dark', 'light'])
    word2 = random.choice(['cat', 'dog', 'fox', 'bird', 'fish', 'tree', 'rock'])
    num = random.randint(1, 99)
    session_code = f"{word1}-{word2}-{num}"
    app_state.log(f"Generated P2P session code: {session_code}")
    app_state.user_node = UserNode(app_state.user_name, session_code, app_state.app_config, app_state.log_queue, app_state.result_queue, app_state.chat_queue)
    app_state.user_node.start()
    return f"Session code: {session_code}. Waiting for peer...", gr.update(interactive=False), gr.update(interactive=False), gr.update(interactive=False), gr.update(interactive=False)

def join_p2p_session(session_code):
    if not session_code:
        return "Please enter a session code.", gr.update(), gr.update(), gr.update(), gr.update()
    app_state.log(f"Joining P2P session '{session_code}'...")
    app_state.user_node = UserNode(app_state.user_name, session_code, app_state.app_config, app_state.log_queue, app_state.result_queue, app_state.chat_queue)
    app_state.user_node.start()
    return f"Joining session '{session_code}'...", gr.update(interactive=False), gr.update(interactive=False), gr.update(interactive=False), gr.update(interactive=False)

def update_logs():
    while not app_state.log_queue.empty():
        msg = app_state.log_queue.get_nowait()
        app_state.log(msg)
    
    while not app_state.chat_queue.empty():
        msg_obj = app_state.chat_queue.get_nowait()
        if msg_obj.get('type') == 'received':
            try:
                decrypted = app_state.crypto_suite.decrypt(msg_obj['data'])
                app_state.add_p2p_chat(f"Peer: {decrypted}")
            except Exception as e:
                app_state.log(f"P2P decrypt error: {e}")
        else:
            handle_group_message(msg_obj)
            
    if not app_state.result_queue.empty():
        result_package = app_state.result_queue.get_nowait()
        if result_package and result_package.get('key'):
            result = result_package['key']
            peer_name = result_package['peer_name']
            app_state.secure_key_seed = result
            app_state.crypto_suite = QuantumSentryCryptography(app_state.secure_key_seed)
            app_state.p2p_keys[peer_name] = app_state.secure_key_seed
            app_state.log(f"✅ SECURE P2P KEY ESTABLISHED with {peer_name}!")
            app_state.add_p2p_chat(f"[System] Secure connection with {peer_name} established. Security words: {app_state.crypto_suite.get_security_words()}")
        else:
            app_state.log("❌ KEY EXCHANGE FAILED!")
        
    return app_state.system_log, app_state.p2p_chat_history, app_state.group_chat_history, app_state.group_user_list

def handle_group_message(msg_obj):
    msg_type = msg_obj.get('type')
    if msg_type == 'group_message' and app_state.group_key:
        try:
            decrypted = app_state.crypto_suite.decrypt(msg_obj['data'], seed_override=app_state.group_key)
            app_state.add_group_chat(f"{msg_obj['from']}: {decrypted}")
        except Exception as e:
            app_state.log(f"Group decrypt error: {e}")
    elif msg_type == 'user_list_update':
        app_state.group_user_list = msg_obj['users']
        if app_state.is_owner:
            distribute_group_key()
    elif msg_type == 'key_distribution':
        wrapped_keys = msg_obj['wrapped_keys']
        if app_state.user_name in wrapped_keys:
            my_wrapped_key = wrapped_keys[app_state.user_name]
            owner_name = msg_obj['from']
            if owner_name in app_state.p2p_keys:
                p2p_key_with_owner = app_state.p2p_keys[owner_name]
                try:
                    decrypted_group_key_str = app_state.crypto_suite.decrypt(my_wrapped_key, seed_override=p2p_key_with_owner)
                    app_state.group_key = float(decrypted_group_key_str)
                    app_state.log(f"Successfully unwrapped and set group key from {owner_name}!")
                    app_state.add_group_chat("[System] Group chat is now secured.")
                except Exception as e:
                    app_state.log(f"Failed to decrypt group key: {e}")
            else:
                app_state.log(f"Cannot decrypt group key: No P2P key with owner {owner_name}")

def send_p2p_message(message):
    if not message: return ""
    app_state.add_p2p_chat(f"You: {message}")
    encrypted = app_state.crypto_suite.encrypt(message)
    if app_state.user_node:
        app_state.user_node.connect_and_send_chat(encrypted)
    return ""

def connect_to_group_host(host_ip):
    if app_state.group_chat_socket: return True
    try:
        if not host_ip:
            app_state.log("Group Host IP is required.")
            return False
        app_state.group_chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        app_state.group_chat_socket.connect((host_ip, app_state.app_config.GROUP_HOST_PORT))
        threading.Thread(target=group_listener_thread, daemon=True).start()
        return True
    except Exception as e:
        app_state.log(f"Failed to connect to group host: {e}")
        app_state.group_chat_socket = None
        return False

def group_listener_thread():
    while True:
        try:
            msg = NetworkNode.recv_json(app_state, app_state.group_chat_socket)
            if msg is None:
                app_state.log("Disconnected from group host.")
                app_state.group_chat_socket = None
                break
            app_state.chat_queue.put(msg)
        except:
            app_state.log("Connection to group host lost.")
            app_state.group_chat_socket = None
            break

def create_group_session(host_ip, session_code):
    if not app_state.crypto_suite: return "Establish a P2P key first."
    if not connect_to_group_host(host_ip): return "Failed to connect to group host."
    if not session_code: return "Please enter a group session code."
    
    app_state.group_session_code = session_code
    app_state.is_owner = True
    NetworkNode.send_json(app_state, app_state.group_chat_socket, {'command': 'create', 'session_code': session_code, 'name': app_state.user_name})
    
    app_state.group_key = random.random()
    app_state.log(f"Generated new group key: {app_state.group_key:.4f}")
    
    time.sleep(1) 
    distribute_group_key()
    app_state.add_group_chat(f"[System] Created group '{session_code}'. Chat is now secured for you.")
    return f"Group '{session_code}' created."

def join_group_session(host_ip, session_code):
    if not app_state.crypto_suite: return "Establish a P2P key first."
    if not connect_to_group_host(host_ip): return "Failed to connect to group host."
    if not session_code: return "Please enter a group session code."
    
    app_state.group_session_code = session_code
    app_state.is_owner = False
    NetworkNode.send_json(app_state, app_state.group_chat_socket, {'command': 'join', 'session_code': session_code, 'name': app_state.user_name})
    app_state.add_group_chat(f"[System] Joined group '{session_code}'. Waiting for owner to provide key...")
    return f"Joined group '{session_code}'."

def distribute_group_key():
    if not app_state.is_owner: return
    current_users = app_state.group_user_list
    if len(current_users) <= 1: return

    wrapped_keys = {}
    for user in current_users:
        if user == app_state.user_name: continue
        if user in app_state.p2p_keys:
            p2p_key = app_state.p2p_keys[user]
            wrapped_key = app_state.crypto_suite.encrypt(str(app_state.group_key), seed_override=p2p_key)
            wrapped_keys[user] = wrapped_key
            app_state.log(f"Wrapped group key for {user}")
        else:
            app_state.log(f"Cannot wrap key for {user}: No P2P key established.")
    
    if wrapped_keys:
        NetworkNode.send_json(app_state, app_state.group_chat_socket, {
            'command': 'distribute_key',
            'session_code': app_state.group_session_code,
            'name': app_state.user_name,
            'wrapped_keys': wrapped_keys
        })
        app_state.log("Key distribution payload sent to host.")

def send_group_message(message):
    if not app_state.group_key: return ""
    if not message: return ""
    
    app_state.add_group_chat(f"You: {message}")
    encrypted_msg = app_state.crypto_suite.encrypt(message, seed_override=app_state.group_key)
    
    NetworkNode.send_json(app_state, app_state.group_chat_socket, {
        'command': 'message',
        'session_code': app_state.group_session_code,
        'name': app_state.user_name,
        'data': encrypted_msg
    })
    return ""

def set_username(username):
    if username:
        app_state.user_name = username.strip().replace(" ", "_")
        return f"Username set to: {app_state.user_name}"
    return f"Username is currently: {app_state.user_name}"

def main():
    DependencyManager.ensure_dependencies()

    with gr.Blocks(theme=gr.themes.Soft(), title="Aetherium Q-Com") as demo:
        gr.Markdown("# Aetherium Quantum Comms")
        
        with gr.Tabs():
            with gr.TabItem("Network Control"):
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("## 1. Host a Session (Optional)")
                        status_box = gr.Textbox(label="Host Status", interactive=False)
                        with gr.Row():
                            p2p_host_btn = gr.Button("Launch P2P Host")
                            group_host_btn = gr.Button("Launch Group Host")
                    with gr.Column():
                        gr.Markdown("## 2. P2P Connection")
                        p2p_status_box = gr.Textbox(label="P2P Status", interactive=False)
                        p2p_code_input = gr.Textbox(label="P2P Session Code")
                        with gr.Row():
                            create_p2p_btn = gr.Button("Create P2P Session")
                            join_p2p_btn = gr.Button("Join P2P Session")
                
                gr.Markdown("## System Log")
                log_output = gr.Textbox(label="Log", lines=15, max_lines=15, interactive=False, autoscroll=True)

            with gr.TabItem("P2P Chat"):
                p2p_chat_output = gr.Textbox(label="P2P Chat", lines=20, interactive=False, autoscroll=True)
                p2p_chat_input = gr.Textbox(label="Send Message", show_label=False, placeholder="Type your secure message...")
                p2p_chat_input.submit(send_p2p_message, [p2p_chat_input], [p2p_chat_input])

            with gr.TabItem("Group Chat"):
                with gr.Row():
                    group_host_ip = gr.Textbox(label="Group Host IP", value="127.0.0.1")
                    group_code_input = gr.Textbox(label="Group Session Code")
                    create_group_btn = gr.Button("Create Group")
                    join_group_btn = gr.Button("Join Group")
                group_status_box = gr.Textbox(label="Group Status", interactive=False)
                with gr.Row():
                    group_chat_output = gr.Textbox(label="Group Chat", lines=20, interactive=False, autoscroll=True, scale=3)
                    group_user_list_output = gr.Textbox(label="Members", lines=20, interactive=False, scale=1)
                group_chat_input = gr.Textbox(label="Send Group Message", show_label=False, placeholder="Type your group message...")
                group_chat_input.submit(send_group_message, [group_chat_input], [group_chat_input])

            with gr.TabItem("Settings"):
                username_input = gr.Textbox(label="Username", value=app_state.user_name)
                username_output = gr.Textbox(label="Status", interactive=False)
                username_input.submit(set_username, [username_input], [username_output])

        p2p_host_btn.click(launch_p2p_host, outputs=[status_box, p2p_host_btn, group_host_btn, create_p2p_btn, join_p2p_btn])
        group_host_btn.click(launch_group_host, outputs=[status_box, p2p_host_btn, group_host_btn, create_p2p_btn, join_p2p_btn])
        create_p2p_btn.click(create_p2p_session, outputs=[p2p_status_box, p2p_host_btn, group_host_btn, create_p2p_btn, join_p2p_btn])
        join_p2p_btn.click(join_p2p_session, inputs=[p2p_code_input], outputs=[p2p_status_box, p2p_host_btn, group_host_btn, create_p2p_btn, join_p2p_btn])
        
        create_group_btn.click(create_group_session, inputs=[group_host_ip, group_code_input], outputs=[group_status_box])
        join_group_btn.click(join_group_session, inputs=[group_host_ip, group_code_input], outputs=[group_status_box])

        demo.load(update_logs, None, [log_output, p2p_chat_output, group_chat_output, group_user_list_output], stream_every=1.0)

    demo.launch()

if __name__ == "__main__":
    main()
    
