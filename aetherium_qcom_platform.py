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
import math
from collections import deque

def get_source_code_hash():
    file_path = os.path.realpath(__file__)
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

SOURCE_HASH = get_source_code_hash()

class DependencyManager:
    REQUIRED_PACKAGES = ['gradio', 'cryptography', 'Pillow', 'opencv-python', 'numpy']
    if platform.system() == "Windows":
        REQUIRED_PACKAGES.append('wmi')
    
    @staticmethod
    def ensure_dependencies():
        missing_packages = []
        for package in DependencyManager.REQUIRED_PACKAGES:
            try:
                if package == 'Pillow': __import__('PIL')
                elif package == 'opencv-python': __import__('cv2')
                else: __import__(package.split('>')[0].split('=')[0])
            except ImportError:
                missing_packages.append(package)
        if not missing_packages:
            return
        print(f"Installing missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_packages])
        except subprocess.CalledProcessError:
            print("ERROR: Could not install dependencies. Please install them manually and restart.")
            sys.exit(1)

DependencyManager.ensure_dependencies()

if platform.system() == "Windows":
    import wmi
import gradio as gr
import numpy as np
import cv2
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Config:
    UNSUSPICIOUS_PORTS = [8080, 8443, 443, 80, 5000, 8888, 9000]
    BLOCKED_MACHINES_FILE = "blocked_machines.json"
    GROUP_SETTINGS_FILE = "group_settings.json"
    DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

class PacketObfuscator:
    TLS_HEADER = b'\x17\x03\x03'

    def wrap(self, data: bytes) -> bytes:
        length = len(data).to_bytes(2, 'big')
        return self.TLS_HEADER + length + data

    def unwrap(self, sock: socket.socket) -> bytes | None:
        try:
            header = sock.recv(5)
            if not header or len(header) < 5:
                return None
            
            content_type, version, length = header[0:1], header[1:3], header[3:5]
            if content_type != b'\x17' or version != b'\x03\x03':
                return None

            payload_len = int.from_bytes(length, 'big')
            
            payload = b''
            while len(payload) < payload_len:
                packet = sock.recv(payload_len - len(payload))
                if not packet:
                    return None
                payload += packet
            return payload
        except (socket.timeout, ConnectionResetError, OSError):
            return None

class MediaSteganographyManager:
    def __init__(self, shared_secret: str):
        if not shared_secret:
            raise ValueError("A shared secret is required for steganography.")
        self.shared_secret = shared_secret.encode('utf-8')

    def _get_seed(self, carrier_path: str) -> bytes:
        carrier_hash = hashlib.sha256()
        with open(carrier_path, 'rb') as f:
            while chunk := f.read(4096):
                carrier_hash.update(chunk)
        
        combined_seed = carrier_hash.digest() + self.shared_secret
        return hashlib.sha256(combined_seed).digest()

    def _get_pixel_sequence(self, seed: bytes, width: int, height: int, num_pixels: int):
        rng = random.Random(seed)
        total_pixels = width * height
        if num_pixels > total_pixels:
            raise ValueError("Not enough pixels in the image/frame to store the data.")
        
        all_indices = list(range(total_pixels))
        rng.shuffle(all_indices)
        
        for i in range(num_pixels):
            index = all_indices[i]
            x = index % width
            y = index // width
            yield (x, y)
            
    def _get_frame_sequence(self, seed: bytes, total_frames: int, num_frames: int):
        rng = random.Random(seed)
        if num_frames > total_frames:
            raise ValueError("Not enough frames in the video to store the data.")
        
        all_indices = list(range(total_frames))
        rng.shuffle(all_indices)
        return sorted(all_indices[:num_frames])

    def _embed_in_image(self, image_path: str, payload_bits: str) -> str:
        img = Image.open(image_path).convert('RGB')
        width, height = img.size
        required_pixels = math.ceil(len(payload_bits) / 3)
        
        seed = self._get_seed(image_path)
        pixel_sequence = self._get_pixel_sequence(seed, width, height, required_pixels)
        
        pixels = img.load()
        bit_index = 0
        
        for x, y in pixel_sequence:
            if bit_index >= len(payload_bits): break
            r, g, b = pixels[x, y]
            
            if bit_index < len(payload_bits):
                r = (r & 0xFE) | int(payload_bits[bit_index]); bit_index += 1
            if bit_index < len(payload_bits):
                g = (g & 0xFE) | int(payload_bits[bit_index]); bit_index += 1
            if bit_index < len(payload_bits):
                b = (b & 0xFE) | int(payload_bits[bit_index]); bit_index += 1
            
            pixels[x, y] = (r, g, b)

        output_path = f"invitation_{os.path.basename(image_path)}.png"
        img.save(output_path, "PNG")
        return output_path

    def _embed_in_video(self, video_path: str, payload_bits: str) -> str:
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened(): raise RuntimeError("Could not open video file.")
        
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        
        pixels_per_frame = width * height
        bits_per_frame = pixels_per_frame * 3
        required_frames = math.ceil(len(payload_bits) / bits_per_frame)
        
        seed = self._get_seed(video_path)
        frame_indices_to_modify = self._get_frame_sequence(seed, total_frames, required_frames)
        
        output_path = f"invitation_{os.path.basename(video_path)}.mp4"
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

        frame_num = 0
        bits_embedded = 0
        
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret: break

            if frame_num in frame_indices_to_modify:
                bits_for_this_frame = payload_bits[bits_embedded : bits_embedded + bits_per_frame]
                
                required_pixels = math.ceil(len(bits_for_this_frame) / 3)
                pixel_sequence = self._get_pixel_sequence(seed + frame_num.to_bytes(4,'big'), width, height, required_pixels)
                
                bit_index = 0
                for x, y in pixel_sequence:
                    if bit_index >= len(bits_for_this_frame): break
                    
                    b, g, r = frame[y, x]
                    if bit_index < len(bits_for_this_frame):
                        b = (b & 0xFE) | int(bits_for_this_frame[bit_index]); bit_index += 1
                    if bit_index < len(bits_for_this_frame):
                        g = (g & 0xFE) | int(bits_for_this_frame[bit_index]); bit_index += 1
                    if bit_index < len(bits_for_this_frame):
                        r = (r & 0xFE) | int(bits_for_this_frame[bit_index]); bit_index += 1
                    frame[y, x] = [b, g, r]
                
                bits_embedded += len(bits_for_this_frame)

            out.write(frame)
            frame_num += 1
            
        cap.release()
        out.release()
        return output_path

    def embed(self, carrier_path: str, data: dict) -> str:
        try:
            data_json = json.dumps(data).encode('utf-8')
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'steg-aes-key').derive(self.shared_secret)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            encrypted_data = nonce + aesgcm.encrypt(nonce, data_json, None)

            payload = len(encrypted_data).to_bytes(4, 'big') + encrypted_data
            payload_bits = ''.join(format(byte, '08b') for byte in payload)
            
            _, ext = os.path.splitext(carrier_path.lower())
            if ext in ['.png', '.jpg', '.jpeg', '.bmp']:
                return self._embed_in_image(carrier_path, payload_bits)
            elif ext in ['.mp4', '.mov', '.avi']:
                return self._embed_in_video(carrier_path, payload_bits)
            else:
                raise ValueError("Unsupported file type for steganography. Use an image or video.")
        except Exception as e:
            raise RuntimeError(f"Failed to embed data: {e}")

    def _extract_from_image(self, image_path: str) -> dict:
        img = Image.open(image_path).convert('RGB')
        width, height = img.size
        pixels = img.load()
        seed = self._get_seed(image_path)
        
        header_bits = ""
        header_pixels = math.ceil(32 / 3)
        pixel_sequence_header = self._get_pixel_sequence(seed, width, height, header_pixels)
        for x, y in pixel_sequence_header:
            r, g, b = pixels[x, y]
            header_bits += str(r & 1) + str(g & 1) + str(b & 1)
            if len(header_bits) >= 32: break
        
        data_len_bytes = int(header_bits[:32], 2)
        
        total_bits_to_extract = 32 + (data_len_bytes * 8)
        required_pixels = math.ceil(total_bits_to_extract / 3)
        pixel_sequence_full = self._get_pixel_sequence(seed, width, height, required_pixels)
        
        extracted_bits = ""
        for x, y in pixel_sequence_full:
            r, g, b = pixels[x, y]
            extracted_bits += str(r & 1) + str(g & 1) + str(b & 1)

        payload_bits = extracted_bits[:total_bits_to_extract]
        payload_bytes_list = [payload_bits[i:i+8] for i in range(32, len(payload_bits), 8)]
        encrypted_data = bytes([int(b, 2) for b in payload_bytes_list])
        
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'steg-aes-key').derive(self.shared_secret)
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        decrypted_json = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_json)

    def _extract_from_video(self, video_path: str) -> dict:
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened(): raise RuntimeError("Could not open video file.")

        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        seed = self._get_seed(video_path)

        header_bits = ""
        pixels_per_frame = width * height
        bits_per_frame = pixels_per_frame * 3
        
        header_frames_count = math.ceil( (32/3) / pixels_per_frame ) + 1
        frame_indices_header = self._get_frame_sequence(seed, total_frames, header_frames_count)
        
        for frame_index in frame_indices_header:
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
            ret, frame = cap.read()
            if not ret: continue

            pixel_sequence = self._get_pixel_sequence(seed + frame_index.to_bytes(4,'big'), width, height, pixels_per_frame)
            for x,y in pixel_sequence:
                if len(header_bits) >= 32: break
                b, g, r = frame[y, x]
                header_bits += str(b & 1) + str(g & 1) + str(r & 1)
            if len(header_bits) >= 32: break

        data_len_bytes = int(header_bits[:32], 2)
        total_bits_to_extract = 32 + (data_len_bytes * 8)
        required_frames = math.ceil(total_bits_to_extract / bits_per_frame)
        frame_indices_full = self._get_frame_sequence(seed, total_frames, required_frames)
        
        extracted_bits = ""
        for frame_index in frame_indices_full:
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
            ret, frame = cap.read()
            if not ret: continue
            
            pixel_sequence = self._get_pixel_sequence(seed + frame_index.to_bytes(4,'big'), width, height, pixels_per_frame)
            for x, y in pixel_sequence:
                if len(extracted_bits) >= total_bits_to_extract: break
                b, g, r = frame[y, x]
                extracted_bits += str(b & 1) + str(g & 1) + str(r & 1)
            if len(extracted_bits) >= total_bits_to_extract: break
        
        cap.release()

        payload_bits = extracted_bits[:total_bits_to_extract]
        payload_bytes_list = [payload_bits[i:i+8] for i in range(32, len(payload_bits), 8)]
        encrypted_data = bytes([int(b, 2) for b in payload_bytes_list])

        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'steg-aes-key').derive(self.shared_secret)
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        decrypted_json = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_json)
        
    def extract(self, carrier_path: str) -> dict:
        try:
            _, ext = os.path.splitext(carrier_path.lower())
            if ext in ['.png', '.jpg', '.jpeg', '.bmp']:
                return self._extract_from_image(carrier_path)
            elif ext in ['.mp4', '.mov', '.avi']:
                return self._extract_from_video(carrier_path)
            else:
                raise ValueError("Unsupported file type for steganography. Use an image or video.")
        except Exception as e:
            raise RuntimeError(f"Failed to extract data. Is the secret phrase correct? Error: {e}")

class DigitalSignatureManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.private_key = None
        self.public_key = None
        self._generate_keys()

    def _generate_keys(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()
        self.log("New RSA key pair generated for digital signatures.")

    def sign(self, message):
        message_bytes = message if isinstance(message, bytes) else message.encode('utf-8')
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify(public_key_pem, message, signature_b64):
        message_bytes = message if isinstance(message, bytes) else message.encode('utf-8')
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())
            signature = base64.b64decode(signature_b64.encode('utf-8'))
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

class MachineFingerprintManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.fingerprint = self._get_machine_fingerprint()
        self.log(f"Machine fingerprint loaded: {self.fingerprint[:12]}...")

    def _get_machine_fingerprint(self):
        system = platform.system()
        identifiers = []
        try:
            if system == "Windows" and 'wmi' in sys.modules:
                c = wmi.WMI()
                identifiers.append(c.Win32_ComputerSystemProduct()[0].UUID)
            elif system == "Linux" and os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f:
                    identifiers.append(f.read().strip())
            elif system == "Darwin":
                output = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]).decode()
                identifiers.append(output.split("IOPlatformUUID")[1].split("=")[1].strip().replace('"', ''))
        except Exception:
            pass

        identifiers.append(platform.processor())
        identifiers.append(str(socket.gethostname()))
        
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

    def add_contact(self, full_public_id: str, public_key=None):
        if not full_public_id or len(full_public_id) != 64:
            return "Internal Error: Invalid Public ID provided.", False
        
        username = self.identity_manager.generate_username_from_id(full_public_id)
        if username in self.contacts and self.contacts[username]['public_id'] != full_public_id:
             return f"Error: A different contact is already saved with the name '{username}'.", False
        
        self.contacts[username] = {'public_id': full_public_id, 'public_key': public_key}
        self.save_contacts()
        return f"Contact '{username}' added/updated successfully.", True
    
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
            with open(self.GROUPS_FILE, 'r') as f: self.groups = json.load(f)
            self.log(f"Loaded {len(self.groups)} groups.")
        else: self.log("No groups file found.")

    def save_groups(self):
        with open(self.GROUPS_FILE, 'w') as f: json.dump(self.groups, f, indent=4)
        self.log("Groups saved.")

    def create_group(self, group_name, member_usernames):
        if not group_name: return "Group name cannot be empty.", False
        if group_name in self.groups: return "A group with this name already exists.", False
        
        valid_members = [un for un in member_usernames if un]
        if not valid_members: return "Group must have at least one member.", False

        self.groups[group_name] = valid_members
        self.save_groups()
        return f"Group '{group_name}' created.", True

    def get_group_members(self, group_name):
        return self.groups.get(group_name, [])

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

class KeyStreamGenerator:
    def __init__(self, shared_secret):
        self.hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'aetherium-qcom-key-stream',
            backend=default_backend()
        )
        self.seed = self.hkdf.derive(shared_secret)
        self.counter = 0

    def get_bytes(self, num_bytes):
        key_material = b''
        while len(key_material) < num_bytes:
            block = hashlib.sha256(self.seed + self.counter.to_bytes(4, 'big')).digest()
            key_material += block
            self.counter += 1
        return key_material[:num_bytes]

class AnomalyDetector:
    def __init__(self, log_callback):
        self.log = log_callback
        self.message_timestamps = deque(maxlen=20)
        self.min_delay = 0.1
        self.alert_threshold = 5

    def check_anomaly(self):
        now = time.time()
        self.message_timestamps.append(now)
        
        if len(self.message_timestamps) > self.alert_threshold:
            time_span = self.message_timestamps[-1] - self.message_timestamps[-self.alert_threshold]
            if time_span < (self.alert_threshold * self.min_delay):
                self.log(f"SECURITY ALERT: Anomaly detected! Received {self.alert_threshold} messages in {time_span:.2f} seconds. Possible bot activity.")
                self.message_timestamps.clear()
                return True
        return False

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
                self.log("Error loading blocked machines file.")
        else: self.log("No blocked machines file found.")

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

class Node:
    def __init__(self, config, identity_manager, contact_manager, digital_signature_manager, block_manager, machine_fingerprint_manager, log_queue, event_queue, source_hash):
        self.config = config
        self.identity = identity_manager
        self.contacts = contact_manager
        self.digital_signature_manager = digital_signature_manager
        self.block_manager = block_manager
        self.machine_fingerprint_manager = machine_fingerprint_manager
        self.log_queue = log_queue
        self.event_queue = event_queue
        self.stop_event = threading.Event()
        self.sessions = {}
        self.server_socket = None
        self.source_code_hash = source_hash
        self.recent_nonces = {}
        self.nonce_lock = threading.Lock()
        self.listening_port = None
        self.packet_obfuscator = PacketObfuscator()

    def log(self, message): self.log_queue.put(f"[Node] {message}")
    
    def get_my_public_key_pem(self):
        return self.digital_signature_manager.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def send_payload(self, sock, data_dict):
        try:
            json_bytes = json.dumps(data_dict).encode('utf-8')
            obfuscated_packet = self.packet_obfuscator.wrap(json_bytes)
            sock.sendall(obfuscated_packet)
            return True
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            self.log(f"Send failed: {e}"); return False

    def recv_payload(self, sock):
        json_bytes = self.packet_obfuscator.unwrap(sock)
        if json_bytes is None:
            return None
        try:
            return json.loads(json_bytes.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def start(self):
        self.log(f"Node starting for user '{self.identity.username}'...")
        for port in self.config.UNSUSPICIOUS_PORTS:
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('', port))
                self.listening_port = port
                self.log(f"Successfully bound to unsuspicious port {self.listening_port}")
                break
            except OSError:
                self.log(f"Port {port} is already in use. Trying next...")
                self.server_socket.close()
                self.server_socket = None
        
        if not self.listening_port:
            self.log("FATAL: Could not bind to any unsuspicious ports. Cannot receive connections.")
            self.event_queue.put({'type': 'error', 'data': "Could not open a port to listen for connections."})
            return

        threading.Thread(target=self._listen_for_connections, daemon=True).start()
        threading.Thread(target=self._cleanup_nonces, daemon=True).start()

    def stop(self):
        self.stop_event.set()
        if self.server_socket: self.server_socket.close()
        for session in self.sessions.values(): session['conn'].close()
        self.log("Node stopped.")

    def initiate_direct_session(self, peer_ip, peer_port, peer_public_id):
        peer_username = self.identity.generate_username_from_id(peer_public_id)
        self.log(f"Attempting direct connection to {peer_username} at {peer_ip}:{peer_port}...")
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((peer_ip, peer_port))
            
            self.send_payload(conn, {'type': 'hello'})
            challenge_response = self.recv_payload(conn)
            if not challenge_response or 'challenge' not in challenge_response:
                raise Exception("Did not receive a valid challenge from the host.")
            challenge = challenge_response['challenge']

            dh_private_key = Config.DH_PARAMETERS.generate_private_key()
            dh_public_key_bytes = dh_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            response_payload = {
                'public_id': self.identity.public_id, 
                'machine_fingerprint': self.machine_fingerprint_manager.fingerprint,
                'dh_public_key': dh_public_key_bytes.decode('utf-8'),
                'timestamp': time.time(),
                'nonce': os.urandom(16).hex(),
                'challenge': challenge
            }
            response_payload_json = json.dumps(response_payload, sort_keys=True)
            signature = self.digital_signature_manager.sign(response_payload_json)
            
            self.send_payload(conn, {'type': 'challenge_response', 'payload': response_payload, 'signature': signature})
            self.log(f"Sent challenge response to {peer_username}.")
            
            peer_final_response = self.recv_payload(conn)
            if not peer_final_response: raise Exception("No final response from peer.")

            peer_payload = peer_final_response.get('payload')
            peer_signature = peer_final_response.get('signature')
            peer_public_key_pem = self.contacts.get_public_key(peer_username)

            if not DigitalSignatureManager.verify(peer_public_key_pem, json.dumps(peer_payload, sort_keys=True), peer_signature):
                raise Exception("Peer's final response signature is invalid! Possible MitM attack.")

            if peer_payload.get('status') == 'accepted':
                peer_dh_public_key_pem = peer_payload.get('dh_public_key')
                peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_pem.encode('utf-8'), backend=default_backend())
                shared_key = dh_private_key.exchange(peer_dh_public_key)

                self.log(f"✅ Session established with '{peer_username}'!")
                self.sessions[peer_username] = {
                    'conn': conn, 
                    'crypto': QuantumSentryCryptography(), 
                    'key_stream': KeyStreamGenerator(shared_key),
                    'anomaly_detector': AnomalyDetector(self.log),
                    'public_id': peer_public_id,
                    'public_key': peer_public_key_pem
                }
                self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'success'})
                self._listen_for_messages(conn, peer_username)
            else:
                raise Exception(f"Connection rejected by '{peer_username}': {peer_payload.get('reason')}")
        except Exception as e:
            self.log(f"Failed to connect to {peer_ip}: {e}")
            self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'failed', 'reason': str(e)})

    def _listen_for_connections(self):
        self.server_socket.listen(10)
        self.log(f"Listening for connections on port {self.listening_port}")
        while not self.stop_event.is_set():
            try:
                conn, addr = self.server_socket.accept()
                self.log(f"Incoming connection from {addr}")
                threading.Thread(target=self.handle_incoming_connection, args=(conn, addr), daemon=True).start()
            except OSError:
                if not self.stop_event.is_set(): self.log("Server socket error.")
                break
        self.log("Listener loop stopped.")

    def _cleanup_nonces(self):
        while not self.stop_event.is_set():
            with self.nonce_lock:
                cutoff = time.time() - 60
                old_nonces = [k for k, v in self.recent_nonces.items() if v < cutoff]
                for k in old_nonces:
                    del self.recent_nonces[k]
            time.sleep(30)

    def handle_incoming_connection(self, conn, addr):
        initial_request = self.recv_payload(conn)
        if not initial_request or initial_request.get('type') != 'hello':
            self.log(f"Invalid initial request from {addr}. Closing."); conn.close(); return
        
        challenge = os.urandom(32).hex()
        self.send_payload(conn, {'challenge': challenge})

        response_wrapper = self.recv_payload(conn)
        if not response_wrapper or response_wrapper.get('type') != 'challenge_response':
            self.log(f"Invalid challenge response from {addr}. Closing."); conn.close(); return
        
        req_payload = response_wrapper.get('payload')
        req_signature = response_wrapper.get('signature')

        if not req_payload or not req_signature:
            self.log(f"Malformed challenge response from {addr}. Closing."); conn.close(); return

        if req_payload.get('challenge') != challenge:
            self._send_rejection(conn, "Challenge mismatch (replay attack?).")
            return

        self._handle_session_responder(conn, req_payload, req_signature)
    
    def _handle_session_responder(self, conn, request, signature):
        req_time = request.get('timestamp', 0)
        if time.time() - req_time > 10:
            self._send_rejection(conn, "Request is too old (replay attack?).")
            return
        
        req_nonce = request.get('nonce')
        with self.nonce_lock:
            if not req_nonce or req_nonce in self.recent_nonces:
                self._send_rejection(conn, "Invalid or re-used nonce (replay attack?).")
                return
            self.recent_nonces[req_nonce] = time.time()

        peer_public_id = request.get('public_id')
        peer_machine_fingerprint = request.get('machine_fingerprint')

        if self.block_manager.is_blocked(peer_machine_fingerprint):
            self._send_rejection(conn, "User is blocked.")
            return

        known_username = self.contacts.get_username_by_id(peer_public_id)
        if not known_username:
            self._send_rejection(conn, "Unknown public ID - not in contacts.")
            return

        peer_public_key_pem = self.contacts.get_public_key(known_username)
        if not peer_public_key_pem:
             self._send_rejection(conn, "Contact exists but public key is missing.")
             return

        if not DigitalSignatureManager.verify(peer_public_key_pem, json.dumps(request, sort_keys=True), signature):
            self.log(f"SIGNATURE ALERT: Invalid signature from '{known_username}'. Rejecting.")
            self._send_rejection(conn, "Invalid digital signature.")
            return

        try:
            dh_private_key = Config.DH_PARAMETERS.generate_private_key()
            dh_public_key_bytes = dh_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            peer_dh_public_key_pem = request.get('dh_public_key')
            peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_pem.encode('utf-8'), backend=default_backend())
            shared_key = dh_private_key.exchange(peer_dh_public_key)

            response_payload = {
                'status': 'accepted',
                'dh_public_key': dh_public_key_bytes.decode('utf-8')
            }
            response_json = json.dumps(response_payload, sort_keys=True)
            response_signature = self.digital_signature_manager.sign(response_json)
            self.send_payload(conn, {'payload': response_payload, 'signature': response_signature})

            self.log(f"Accepted P2P session with '{known_username}'.")
            self.sessions[known_username] = {
                'conn': conn, 
                'crypto': QuantumSentryCryptography(), 
                'key_stream': KeyStreamGenerator(shared_key),
                'anomaly_detector': AnomalyDetector(self.log),
                'public_id': peer_public_id,
                'public_key': peer_public_key_pem
            }
            self.event_queue.put({'type': 'p2p_status', 'peer_username': known_username, 'status': 'success'})
            threading.Thread(target=self._listen_for_messages, args=(conn, known_username), daemon=True).start()

        except Exception as e:
            self.log(f"Error during session handshake with '{known_username}': {e}")
            self._send_rejection(conn, f"Handshake error: {e}")

    def _send_rejection(self, conn, reason):
        payload = {'status': 'rejected', 'reason': reason}
        payload_json = json.dumps(payload, sort_keys=True)
        signature = self.digital_signature_manager.sign(payload_json)
        self.send_payload(conn, {'payload': payload, 'signature': signature})
        conn.close()

    def _listen_for_messages(self, conn, peer_username):
        session = self.sessions.get(peer_username)
        if not session: return

        while not self.stop_event.is_set():
            message = self.recv_payload(conn)
            if message is None:
                self.log(f"Connection with '{peer_username}' lost.")
                self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'disconnected'})
                if peer_username in self.sessions: del self.sessions[peer_username]
                break
            
            if session['anomaly_detector'].check_anomaly():
                pass

            payload_data = message.get('data', '')
            signature_b64 = message.get('signature', '')
            peer_public_key = session.get('public_key')
            
            if not peer_public_key or not DigitalSignatureManager.verify(peer_public_key, payload_data, signature_b64):
                self.log(f"SECURITY ALERT: Invalid signature from '{peer_username}'. Message ignored.")
                continue
            
            event = message
            event['from'] = peer_username
            self.event_queue.put(event)

    def send_p2p_message(self, peer_username, text_message):
        if peer_username in self.sessions:
            session = self.sessions[peer_username]
            key_bytes = session['key_stream'].get_bytes(len(text_message))
            encrypted_msg = session['crypto'].encrypt(text_message, key_bytes)
            signature = self.digital_signature_manager.sign(encrypted_msg)
            self.send_payload(session['conn'], {
                'type': 'p2p_chat', 
                'data': encrypted_msg, 
                'length': len(text_message),
                'signature': signature
            })

    def send_file(self, peer_username, file_path):
        if peer_username not in self.sessions: return
        session = self.sessions[peer_username]
        file_name = os.path.basename(file_path)
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
            file_len = len(file_bytes)
            key_bytes = session['key_stream'].get_bytes(file_len)
            
            encrypted_bytes = session['crypto'].encrypt(file_bytes, key_bytes)
            signature = self.digital_signature_manager.sign(encrypted_bytes)
            
            self.send_payload(session['conn'], {
                'type': 'file_transfer',
                'filename': file_name,
                'data': encrypted_bytes,
                'length': file_len,
                'signature': signature
            })
            self.log(f"Successfully sent file '{file_name}' to '{peer_username}'.")
            self.event_queue.put({'type': 'file_sent', 'to': peer_username, 'filename': file_name})
        except Exception as e:
            self.log(f"Failed to send file '{file_name}': {e}")

    def send_group_message(self, group_name, text_message, group_members):
        for member_username in group_members:
            if member_username != self.identity.username and member_username in self.sessions:
                session = self.sessions[member_username]
                key_bytes = session['key_stream'].get_bytes(len(text_message))
                encrypted_msg = session['crypto'].encrypt(text_message, key_bytes)
                signature = self.digital_signature_manager.sign(encrypted_msg)
                self.send_payload(session['conn'], {
                    'type': 'group_chat', 
                    'data': encrypted_msg, 
                    'length': len(text_message),
                    'group_name': group_name,
                    'signature': signature
                })

class AppState:
    def __init__(self):
        self.app_config = Config()
        self.log_queue = queue.Queue()
        self.event_queue = queue.Queue()
        self.system_log = ""
        self.source_code_hash = SOURCE_HASH
        self.machine_fingerprint_manager = MachineFingerprintManager(self.log)
        self.digital_signature_manager = DigitalSignatureManager(self.log)
        self.identity_manager = IdentityManager(self.log, self.machine_fingerprint_manager.fingerprint)
        self.contact_manager = ContactManager(self.log, self.identity_manager)
        self.group_manager = GroupChatManager(self.log)
        self.block_manager = BlockManager(self.log)
        self.node = Node(self.app_config, self.identity_manager, self.contact_manager, self.digital_signature_manager, self.block_manager, self.machine_fingerprint_manager, self.log_queue, self.event_queue, self.source_code_hash)
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
        event_type = event.get('type')
        peer_username = event.get('from', event.get('peer_username'))

        if event_type == 'p2p_status':
            chat_id = f"p2p:{peer_username}"
            if event['status'] == 'success':
                app_state.p2p_chats[chat_id] = {'history': f"[System] ✅ Secure connection established with '{peer_username}'.\n", 'status': 'connected'}
            else:
                status_msg = f"[System] ❌ Connection to '{peer_username}' failed or disconnected.\nReason: {event.get('reason', 'Connection lost.')}\n"
                if chat_id in app_state.p2p_chats:
                    app_state.p2p_chats[chat_id]['history'] += status_msg
                    app_state.p2p_chats[chat_id]['status'] = 'disconnected'
                else:
                    app_state.p2p_chats[chat_id] = {'history': status_msg, 'status': 'failed'}
        
        elif event_type in ['p2p_chat', 'group_chat', 'file_transfer']:
            session = app_state.node.sessions.get(peer_username)
            if not session: continue
            
            if event_type == 'p2p_chat':
                key_bytes = session['key_stream'].get_bytes(event['length'])
                decrypted_msg = session['crypto'].decrypt(event['data'], key_bytes)
                app_state.add_p2p_chat(peer_username, f"{peer_username}: {decrypted_msg}")
            
            elif event_type == 'group_chat':
                key_bytes = session['key_stream'].get_bytes(event['length'])
                decrypted_msg = session['crypto'].decrypt(event['data'], key_bytes)
                app_state.add_group_chat(event['group_name'], f"[{event['group_name']}] {peer_username}: {decrypted_msg}")

            elif event_type == 'file_transfer':
                key_bytes = session['key_stream'].get_bytes(event['length'])
                decrypted_bytes = session['crypto'].decrypt(event['data'], key_bytes, is_text=False)
                save_path = f"received_{event['filename']}"
                with open(save_path, "wb") as f:
                    f.write(decrypted_bytes)
                app_state.log(f"Received file '{event['filename']}' from '{peer_username}'. Saved to '{save_path}'.")
                app_state.add_p2p_chat(peer_username, f"[System] Received file '{event['filename']}'.")

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
        new_p2p_histories,
        new_group_histories,
        gr.update(choices=all_chat_choices),
        trigger_value
    )

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def create_invitation_ui(carrier_file, secret_phrase):
    if carrier_file is None or not secret_phrase:
        return None, "Please upload a carrier file and provide a secret phrase."
    
    try:
        steg_manager = MediaSteganographyManager(secret_phrase)
        data_to_hide = {
            "ip": get_local_ip(),
            "port": app_state.node.listening_port,
            "public_id": app_state.identity_manager.public_id,
            "public_key": app_state.node.get_my_public_key_pem()
        }
        output_path = steg_manager.embed(carrier_file.name, data_to_hide)
        app_state.log(f"Invitation created: {output_path}. Send this file to your contact.")
        return output_path, f"Invitation file created: {os.path.basename(output_path)}. Send this to your contact and tell them to use the same secret phrase."
    except Exception as e:
        app_state.log(f"ERROR creating invitation: {e}")
        return None, f"Error: {e}"

def use_invitation_ui(invitation_file, secret_phrase):
    if invitation_file is None or not secret_phrase:
        return "Please upload the invitation file and provide the secret phrase."
    
    try:
        steg_manager = MediaSteganographyManager(secret_phrase)
        extracted_data = steg_manager.extract(invitation_file.name)
        
        peer_ip = extracted_data.get("ip")
        peer_port = extracted_data.get("port")
        peer_public_id = extracted_data.get("public_id")
        peer_public_key = extracted_data.get("public_key")

        if not all([peer_ip, peer_port, peer_public_id, peer_public_key]):
            return "Invitation file is invalid or corrupted."

        msg, success = app_state.contact_manager.add_contact(peer_public_id, peer_public_key)
        app_state.log(msg)
        if not success and "already saved" not in msg:
             return f"Failed to add contact: {msg}"

        threading.Thread(target=app_state.node.initiate_direct_session, args=(peer_ip, peer_port, peer_public_id)).start()
        return f"Invitation decoded. Attempting to connect to {peer_ip}:{peer_port}..."

    except Exception as e:
        app_state.log(f"ERROR using invitation: {e}")
        return f"Error: {e}"

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
        app_state.add_group_chat(chat_name, f"You: {message}")
        app_state.node.send_group_message(chat_name, message, group_members)
            
    return ""

def send_file_ui(file, current_chat_id):
    if not file or not current_chat_id:
        return
    chat_type, chat_name = current_chat_id.split(':', 1)
    if chat_type != 'p2p':
        app_state.log("File transfer is only supported for P2P chats.")
        return
    app_state.node.send_file(chat_name, file.name)

def change_active_chat(chat_id, p2p_histories, group_histories):
    if not chat_id or ':' not in chat_id:
        return "[System] Select a chat to view history."

    chat_type, chat_name = chat_id.split(':', 1)
    
    if chat_type == 'p2p':
        history = p2p_histories.get(chat_id, "")
    elif chat_type == 'group':
        history = group_histories.get(chat_id, "")
    else:
        history = ""
    return history

def create_group_ui(group_name, member_usernames_str):
    members_list = [m.strip() for m in member_usernames_str.strip().split('\n') if m.strip()]
    msg, success = app_state.group_manager.create_group(group_name, members_list)
    
    if success:
        new_chat_choices = [f"p2p:{c}" for c in app_state.contact_manager.contacts.keys()] + [f"group:{g}" for g in app_state.group_manager.groups.keys()]
        return gr.update(value=msg), gr.update(choices=new_chat_choices)
    return gr.update(value=msg), gr.update()

def main():
    app_state.node.start()

    with gr.Blocks(theme=gr.themes.Soft(), title="Aetherium Q-Com") as demo:
        gr.Markdown("# Aetherium Q-Com")
        p2p_chat_histories = gr.State({})
        group_chat_histories = gr.State({})
        chat_update_trigger = gr.Textbox(visible=False)

        with gr.Tabs():
            with gr.TabItem("Chat & Network"):
                with gr.Row():
                    with gr.Column(scale=1):
                        gr.Markdown("### 1. Create or Use an Invitation")
                        with gr.Tabs():
                            with gr.TabItem("Create Invitation (Host)"):
                                host_file_input = gr.File(label="Upload any Carrier File (Image or Video)")
                                host_secret_input = gr.Textbox(label="Enter a Shared Secret Passphrase", type="password")
                                create_invitation_btn = gr.Button("Create Invitation File")
                                invitation_file_output = gr.File(label="Download Your Invitation File")
                            with gr.TabItem("Use Invitation (Connect)"):
                                connect_file_input = gr.File(label="Upload Invitation File")
                                connect_secret_input = gr.Textbox(label="Enter the Shared Secret Passphrase", type="password")
                                connect_btn = gr.Button("Connect using Invitation")
                        p2p_status_box = gr.Textbox(label="Connection Status", interactive=False)

                    with gr.Column(scale=2):
                        gr.Markdown("### 2. Secure Chat")
                        all_chat_choices = [f"p2p:{c}" for c in app_state.contact_manager.contacts.keys()] + [f"group:{g}" for g in app_state.group_manager.groups.keys()]
                        chat_selector = gr.Dropdown(label="Active Chat", choices=all_chat_choices, interactive=True)
                        chat_output = gr.Textbox(label="Chat History", lines=10, interactive=False, autoscroll=True)
                        chat_input = gr.Textbox(show_label=False, placeholder="Type your secure message and press Enter...")
                        with gr.Row():
                            file_to_send = gr.File(label="Send a File (P2P only)")
                            send_file_btn = gr.Button("Send File")
            
            with gr.TabItem("Identity & Contacts"):
                 with gr.Row():
                    with gr.Column():
                        gr.Markdown("## Your Identity")
                        gr.Textbox(label="Your Permanent Username", value=app_state.identity_manager.username, interactive=False)
                        gr.Textbox(label="Your Public ID", value=app_state.identity_manager.public_id, interactive=False, lines=2)
                        gr.Textbox(label="Your Digital Public Key", lines=5, interactive=False, value=app_state.node.get_my_public_key_pem)
                    with gr.Column():
                        gr.Markdown("## Your Contacts")
                        contact_list_output = gr.Textbox(label="Contacts", value="\n".join(app_state.contact_manager.contacts.keys()), interactive=False, lines=10)
            
            with gr.TabItem("Groups"):
                gr.Markdown("## Create a Group")
                with gr.Row():
                    with gr.Column():
                        group_name_input = gr.Textbox(label="Group Name")
                        group_members_input = gr.Textbox(label="Members (add their usernames, one per line)", lines=5)
                        create_group_btn = gr.Button("Create Group")
                    with gr.Column():
                        group_status_box = gr.Textbox(label="Group Status", interactive=False)

            with gr.TabItem("System Log"):
                log_output = gr.Textbox(label="Log", lines=20, interactive=False, autoscroll=True)

        create_invitation_btn.click(create_invitation_ui, [host_file_input, host_secret_input], [invitation_file_output, p2p_status_box])
        connect_btn.click(use_invitation_ui, [connect_file_input, connect_secret_input], [p2p_status_box])
        
        chat_input.submit(send_message_ui, [chat_input, chat_selector], [chat_input])
        send_file_btn.click(send_file_ui, [file_to_send, chat_selector], None)
        chat_selector.change(change_active_chat, [chat_selector, p2p_chat_histories, group_chat_histories], [chat_output])
        
        create_group_btn.click(create_group_ui, [group_name_input, group_members_input], [group_status_box, chat_selector])
        
        timer = gr.Timer(1, active=False)
        timer.tick(
            update_ui_loop,
            inputs=[chat_selector, p2p_chat_histories, group_chat_histories],
            outputs=[log_output, chat_selector, p2p_chat_histories, group_chat_histories, chat_selector, chat_update_trigger]
        )
        chat_update_trigger.change(
            change_active_chat,
            inputs=[chat_selector, p2p_chat_histories, group_chat_histories],
            outputs=[chat_output]
        )
        demo.load(lambda: gr.Timer(active=True), None, outputs=timer).then(
            lambda: "[System] Select a peer or group to view history.", None, [chat_output]
        )

    demo.launch(inbrowser=True)
    app_state.node.stop()

if __name__ == "__main__":
    main()
