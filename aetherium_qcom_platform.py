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
from collections import deque, OrderedDict
import asyncio
import urllib.request
import xml.etree.ElementTree as ET
from enum import Enum

def get_source_code_hash(full_code=False):
    file_path = os.path.realpath(__file__)
    with open(file_path, 'rb') as f:
        code_bytes = f.read()
    if full_code:
        return code_bytes
    return hashlib.sha256(code_bytes).hexdigest()

SOURCE_CODE_BYTES = get_source_code_hash(full_code=True)
SOURCE_HASH = hashlib.sha256(SOURCE_CODE_BYTES).hexdigest()

REQUIRED_PACKAGES = ['gradio', 'cryptography', 'Pillow', 'opencv-python', 'numpy==1.26.4', 'scikit-learn', 'pandas==2.2.1']
if platform.system() == "Windows":
    REQUIRED_PACKAGES.append('wmi')

try:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall", *REQUIRED_PACKAGES])
except subprocess.CalledProcessError:
    print("ERROR: Could not install dependencies. Please install them manually and restart.")
    sys.exit(1)

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
from sklearn.ensemble import IsolationForest
from sklearn.mixture import GaussianMixture

class NativeUPnP:
    def __init__(self, log_callback=print):
        self.log = log_callback
        self.control_url = None
        self.service_type = None
        self.base_url = None
        self.lan_addr = get_local_ip()

    def discover(self):
        ssdp_request = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 2\r\n'
            'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n'
            '\r\n'
        ).encode('utf-8')
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(3)
        sock.sendto(ssdp_request, ('239.255.255.250', 1900))
        
        try:
            while True:
                resp, addr = sock.recvfrom(1024)
                resp_text = resp.decode('utf-8', errors='ignore').lower()
                if 'location:' in resp_text:
                    for line in resp_text.split('\r\n'):
                        if line.startswith('location:'):
                            location_url = line.split(':', 1)[1].strip()
                            self.base_url = location_url.split('/rootDesc.xml')[0]
                            return self._fetch_and_parse_description(location_url)
        except socket.timeout:
            self.log("UPnP discovery timed out. No gateway found.")
            return False
        finally:
            sock.close()
        return False

    def _fetch_and_parse_description(self, url):
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                xml_content = response.read()
            
            root = ET.fromstring(xml_content)
            namespaces = {'ns': 'urn:schemas-upnp-org:device-1-0'}
            
            for service in root.findall('.//ns:service', namespaces):
                service_type_elem = service.find('ns:serviceType', namespaces)
                if service_type_elem is not None and ('WANIPConnection' in service_type_elem.text or 'WANPPPConnection' in service_type_elem.text):
                    self.service_type = service_type_elem.text
                    control_url_elem = service.find('ns:controlURL', namespaces)
                    if control_url_elem is not None:
                        self.control_url = self.base_url + control_url_elem.text
                        return True
        except Exception as e:
            self.log(f"Failed to parse UPnP description: {e}")
            return False
        return False

    def _send_soap_request(self, action, args):
        if not self.control_url:
            if not self.discover():
                return False
        
        soap_body = f"""<?xml version="1.0"?>
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <s:Body>
        <u:{action} xmlns:u="{self.service_type}">
        """
        for k, v in args.items():
            soap_body += f"<{k}>{v}</{k}>"
        soap_body += f"</u:{action}></s:Body></s:Envelope>"

        headers = {
            'SOAPAction': f'"{self.service_type}#{action}"',
            'Content-Type': 'text/xml',
            'Host': self.base_url.split('//')[1].split('/')[0]
        }

        try:
            req = urllib.request.Request(self.control_url, soap_body.encode('utf-8'), headers)
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status == 200
        except Exception as e:
            self.log(f"SOAP request failed for action {action}: {e}")
            return False

    def add_port_mapping(self, port, protocol, description):
        args = {
            'NewRemoteHost': '',
            'NewExternalPort': port,
            'NewProtocol': protocol,
            'NewInternalPort': port,
            'NewInternalClient': self.lan_addr,
            'NewEnabled': 1,
            'NewPortMappingDescription': description,
            'NewLeaseDuration': 0
        }
        return self._send_soap_request('AddPortMapping', args)

    def delete_port_mapping(self, port, protocol):
        args = {'NewRemoteHost': '', 'NewExternalPort': port, 'NewProtocol': protocol}
        return self._send_soap_request('DeletePortMapping', args)

class KBucket(OrderedDict):
    def __init__(self, k_size):
        super().__init__()
        self.k_size = k_size
    def add_node(self, node):
        if node['id'] in self:
            self.move_to_end(node['id'])
        elif len(self) < self.k_size:
            self[node['id']] = node
        else:
            return False
        return True

class MiniDHT(asyncio.Protocol):
    def __init__(self, udp_port=8468, k_size=8, alpha=3):
        self.udp_port = udp_port
        self.k_size = k_size
        self.alpha = alpha
        self.node_id = os.urandom(20)
        self.storage = {}
        self.buckets = [KBucket(self.k_size) for _ in range(160)]
        self.transport = None
        self.rpc_callbacks = {}
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        try:
            message = json.loads(data.decode())
            rpc_id = message.get('rpc_id')
            if rpc_id and rpc_id in self.rpc_callbacks:
                future, timeout_handle = self.rpc_callbacks.pop(rpc_id)
                timeout_handle.cancel()
                if not future.done():
                    future.set_result((message, addr))
                return
            if 'method' in message:
                self._handle_request(message, addr)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    def error_received(self, exc):
        pass
    async def _send_rpc(self, address, message):
        loop = asyncio.get_running_loop()
        rpc_id = os.urandom(8).hex()
        message['rpc_id'] = rpc_id
        future = loop.create_future()
        timeout_handle = loop.call_later(2.0, self._rpc_timeout, rpc_id, future)
        self.rpc_callbacks[rpc_id] = (future, timeout_handle)
        self.transport.sendto(json.dumps(message).encode(), address)
        try:
            return await future
        except asyncio.CancelledError:
            return None, None
    def _rpc_timeout(self, rpc_id, future):
        if rpc_id in self.rpc_callbacks:
            self.rpc_callbacks.pop(rpc_id)
            if not future.done():
                future.cancel()
    def _get_bucket_index(self, other_id):
        distance = int.from_bytes(self.node_id, 'big') ^ int.from_bytes(other_id, 'big')
        return (distance.bit_length() - 1) if distance != 0 else 0
    def _add_node(self, node):
        index = self._get_bucket_index(node['id'])
        self.buckets[index].add_node(node)
    def _handle_request(self, message, addr):
        method = message['method']
        sender_id = bytes.fromhex(message['sender']['id'])
        sender_node = {'id': sender_id, 'ip': addr[0], 'port': addr[1]}
        self._add_node(sender_node)
        response = {'rpc_id': message['rpc_id'], 'sender': {'id': self.node_id.hex()}}
        if method == 'ping':
            response['result'] = 'pong'
        elif method == 'find_node':
            target_id = bytes.fromhex(message['params']['target_id'])
            response['result'] = self._find_closest_nodes(target_id)
        elif method == 'store':
            key = bytes.fromhex(message['params']['key'])
            self.storage[key] = message['params']['value']
            response['result'] = True
        elif method == 'find_value':
            key = bytes.fromhex(message['params']['key'])
            if key in self.storage:
                response['result'] = {'value': self.storage[key]}
            else:
                response['result'] = {'nodes': self._find_closest_nodes(key)}
        self.transport.sendto(json.dumps(response).encode(), addr)
    def _find_closest_nodes(self, target_id, count=None):
        if count is None:
            count = self.k_size
        nodes = []
        for bucket in self.buckets:
            nodes.extend(bucket.values())
        nodes.sort(key=lambda n: int.from_bytes(target_id, 'big') ^ int.from_bytes(n['id'], 'big'))
        return [{'id': n['id'].hex(), 'ip': n['ip'], 'port': n['port']} for n in nodes[:count]]
    async def _iterative_find(self, key, find_value=False):
        shortlist = self._find_closest_nodes(key, self.alpha)
        queried = set()
        while True:
            nodes_to_query = []
            for node_info in shortlist:
                if node_info['id'] not in queried and len(nodes_to_query) < self.alpha:
                    nodes_to_query.append(node_info)
            if not nodes_to_query:
                break
            tasks = []
            for node_info in nodes_to_query:
                queried.add(node_info['id'])
                address = (node_info['ip'], node_info['port'])
                method = 'find_value' if find_value else 'find_node'
                params = {'key': key.hex()} if find_value else {'target_id': key.hex()}
                message = {'method': method, 'sender': {'id': self.node_id.hex()}, 'params': params}
                tasks.append(self._send_rpc(address, message))
            responses = await asyncio.gather(*tasks)
            new_nodes_found = False
            for resp, addr in responses:
                if resp and resp.get('result'):
                    self._add_node({'id': bytes.fromhex(resp['sender']['id']), 'ip': addr[0], 'port': addr[1]})
                    if find_value and 'value' in resp['result']:
                        return resp['result']['value']
                    nodes = resp['result'].get('nodes', [])
                    for node in nodes:
                        node['id'] = bytes.fromhex(node['id'])
                        if node['id'] not in [n['id'] for n in shortlist]:
                            shortlist.append(node)
                            new_nodes_found = True
            if not new_nodes_found:
                break
            shortlist.sort(key=lambda n: int.from_bytes(key, 'big') ^ int.from_bytes(n['id'], 'big'))
        return None if find_value else shortlist[:self.k_size]
    async def listen(self):
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(lambda: self, local_addr=('0.0.0.0', self.udp_port))
    async def bootstrap(self, nodes):
        for ip, port in nodes:
            try:
                message = {'method': 'ping', 'sender': {'id': self.node_id.hex()}}
                resp, addr = await self._send_rpc((ip, port), message)
                if resp and resp.get('result') == 'pong':
                    self._add_node({'id': bytes.fromhex(resp['sender']['id']), 'ip': addr[0], 'port': addr[1]})
            except Exception:
                pass
        await self._iterative_find(self.node_id)
    async def get(self, key):
        return await self._iterative_find(key, find_value=True)
    async def set(self, key, value):
        closest_nodes_info = await self._iterative_find(key)
        if not closest_nodes_info:
            return
        message = {
            'method': 'store',
            'sender': {'id': self.node_id.hex()},
            'params': {'key': key.hex(), 'value': value}
        }
        tasks = [self._send_rpc((n['ip'], n['port']), message) for n in closest_nodes_info]
        await asyncio.gather(*tasks)

class Config:
    UNSUSPICIOUS_PORTS = list(range(49152, 65536))
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
            if not header or len(header) < 5: return None
            content_type, version, length = header[0:1], header[1:3], header[3:5]
            if content_type != b'\x17' or version != b'\x03\x03': return None
            payload_len = int.from_bytes(length, 'big')
            payload = b''
            while len(payload) < payload_len:
                packet = sock.recv(payload_len - len(payload))
                if not packet: return None
                payload += packet
            return payload
        except (socket.timeout, ConnectionResetError, OSError):
            return None

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
        self.is_vm = self._check_for_vm()
        log_msg = f"Machine fingerprint loaded: {self.fingerprint[:12]}..."
        if self.is_vm:
            log_msg += " (Warning: Virtual Machine detected)"
        self.log(log_msg)

    def _check_for_vm(self):
        vm_identifiers = ['vmware', 'virtualbox', 'qemu', 'xen', 'hyper-v']
        try:
            if platform.system() == "Windows" and 'wmi' in sys.modules:
                c = wmi.WMI()
                for s in c.Win32_ComputerSystem():
                    if s.Model and any(vm_id in s.Model.lower() for vm_id in vm_identifiers):
                        return True
        except Exception:
            return False
        return False

    def _get_machine_fingerprint(self):
        system = platform.system()
        identifiers = []
        try:
            if system == "Windows" and 'wmi' in sys.modules:
                c = wmi.WMI()
                identifiers.append(c.Win32_ComputerSystemProduct()[0].UUID)
            elif system == "Linux" and os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f: identifiers.append(f.read().strip())
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
            with open(self.CONTACTS_FILE, 'r') as f: self.contacts = json.load(f)
            self.log(f"Loaded {len(self.contacts)} contacts.")
        else:
            self.log("No contacts file found. Starting with an empty list.")
    def save_contacts(self):
        with open(self.CONTACTS_FILE, 'w') as f: json.dump(self.contacts, f, indent=4)
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

class MediaSteganographyManager:
    def __init__(self, shared_secret: str):
        if not shared_secret:
            raise ValueError("A shared secret is required for steganography.")
        self.shared_secret = shared_secret.encode('utf-8')

    def _get_seed(self, carrier_path: str) -> bytes:
        return hashlib.sha256(self.shared_secret).digest()

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

        output_path = f"{os.path.splitext(os.path.basename(image_path))[0]}_invite.png"
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
        
        output_path = f"{os.path.splitext(os.path.basename(video_path))[0]}_invite.mp4"
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
    def __init__(self, shared_secret, machine_fingerprint):
        info_str = b'aetherium-qcom-key-stream' + machine_fingerprint.encode('utf-8')
        self.hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info_str, backend=default_backend())
        self.seed = self.hkdf.derive(shared_secret)
        self.counter = 0
    def get_bytes(self, num_bytes):
        key_material = b''
        while len(key_material) < num_bytes:
            block = hashlib.sha256(self.seed + self.counter.to_bytes(4, 'big')).digest()
            key_material += block
            self.counter += 1
        return key_material[:num_bytes]

class SecurityTier(Enum):
    NORMAL = 0
    INTEGRITY_PROOF_FAILED = 1
    SUSPICIOUS_TIMING = 2
    UNUSUAL_PAYLOAD = 3
    VM_DETECTED = 4

class SecurityMonitor:
    def __init__(self, log_callback):
        self.log = log_callback
        self.last_timestamp = None
        self.is_calibrated = False
        self.trust_score = 100
        self.timing_model = GaussianMixture(n_components=2, random_state=42)
        self.payload_model = IsolationForest(contamination=0.05, random_state=42)

    def _extract_features(self, message_dict):
        current_time = time.time()
        inter_arrival_time = current_time - self.last_timestamp if self.last_timestamp else 0
        self.last_timestamp = current_time
        timing_features = [inter_arrival_time]
        
        message_size = len(message_dict.get('data', ''))
        payload_complexity = len(message_dict.keys())
        payload_features = [inter_arrival_time, message_size, payload_complexity]

        return timing_features, payload_features

    def calibrate(self, calibration_packets):
        self.log("Performing security calibration with peer...")
        timing_feature_buffer = [self._extract_features(p)[0] for p in calibration_packets]
        payload_feature_buffer = [self._extract_features(p)[1] for p in calibration_packets]
        
        self.timing_model.fit(np.array(timing_feature_buffer))
        self.payload_model.fit(np.array(payload_feature_buffer))
        
        self.is_calibrated = True
        self.log("✅ Security models are calibrated and active.")

    def analyze_packet(self, message_dict, is_peer_on_vm):
        if not self.is_calibrated: return SecurityTier.NORMAL

        if is_peer_on_vm: self.trust_score -= 1

        timing_features, payload_features = self._extract_features(message_dict)

        timing_score = self.timing_model.score_samples(np.array([timing_features]))[0]
        if timing_score < -5:
            self.log(f"SECURITY ALERT: Atypical message timing detected (possible bot). Score: {timing_score:.3f}")
            self.trust_score -= 25
            return SecurityTier.SUSPICIOUS_TIMING

        payload_prediction = self.payload_model.predict(np.array([payload_features]))
        if payload_prediction[0] == -1:
            self.log(f"SECURITY ALERT: Anomalous message payload detected.")
            self.trust_score -= 15
            return SecurityTier.UNUSUAL_PAYLOAD
            
        return SecurityTier.NORMAL

class BlockManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.blocked_machines = set()
        self.load_blocked_users()
    def load_blocked_users(self):
        if os.path.exists(Config.BLOCKED_MACHINES_FILE):
            try:
                with open(Config.BLOCKED_MACHINES_FILE, 'r') as f: self.blocked_machines = set(json.load(f))
                self.log(f"Loaded {len(self.blocked_machines)} blocked machines.")
            except (json.JSONDecodeError, KeyError):
                self.log("Error loading blocked machines file.")
        else: self.log("No blocked machines file found.")
    def save_blocked_users(self):
        with open(Config.BLOCKED_MACHINES_FILE, 'w') as f: json.dump(list(self.blocked_machines), f)
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
        return self.digital_signature_manager.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

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
        if json_bytes is None: return None
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

    def _perform_security_calibration(self, conn, peer_username, is_initiator):
        session = self.sessions[peer_username]
        calibration_packets_to_send = []
        received_calibration_packets = []
        
        for i in range(30):
            packet = {'type': 'calibration', 'seq': i, 'data': os.urandom(random.randint(16, 128)).hex()}
            calibration_packets_to_send.append(packet)

        conn.settimeout(5.0)
        try:
            for packet in calibration_packets_to_send:
                self.send_payload(conn, packet)
                if not is_initiator:
                    received = self.recv_payload(conn)
                    if received and received.get('type') == 'calibration':
                        received_calibration_packets.append(received)
                time.sleep(random.uniform(0.01, 0.05))
            
            if is_initiator:
                 for _ in range(30):
                    received = self.recv_payload(conn)
                    if received and received.get('type') == 'calibration':
                        received_calibration_packets.append(received)

        except socket.timeout:
            self.log("Calibration failed: Peer communication timed out.")
            return False
        finally:
            conn.settimeout(None)

        if len(received_calibration_packets) < 30:
             self.log("Calibration failed: Did not receive all packets from peer.")
             return False

        session['security_monitor'].calibrate(received_calibration_packets)
        return True

    def _generate_dip_challenge(self):
        nonce = os.urandom(16).hex()
        start = random.randint(0, len(SOURCE_CODE_BYTES) - 1024)
        end = start + 1024
        return {'nonce': nonce, 'start': start, 'end': end}

    def _solve_dip_challenge(self, challenge, peer_public_id):
        nonce = challenge['nonce']
        start = challenge['start']
        end = challenge['end']
        code_slice = SOURCE_CODE_BYTES[start:end]
        
        hasher = hashlib.sha256()
        hasher.update(nonce.encode())
        hasher.update(peer_public_id.encode())
        hasher.update(code_slice)
        return hasher.hexdigest()

    def initiate_direct_session(self, peer_ip, peer_port, peer_public_id, peer_public_key_pem):
        peer_username = self.identity.generate_username_from_id(peer_public_id)
        self.log(f"Attempting direct connection to {peer_username} at {peer_ip}:{peer_port}...")
        try:
            msg, success = self.contacts.add_contact(peer_public_id, peer_public_key_pem)
            self.log(msg)
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((peer_ip, peer_port))
            
            self.send_payload(conn, {'type': 'hello'})
            challenge_response = self.recv_payload(conn)
            if not challenge_response or 'challenge' not in challenge_response:
                raise Exception("Did not receive a valid challenge from the host.")
            
            dh_private_key = Config.DH_PARAMETERS.generate_private_key()
            dh_public_key_bytes = dh_private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            
            response_payload = {
                'public_id': self.identity.public_id, 
                'machine_fingerprint': self.machine_fingerprint_manager.fingerprint,
                'is_vm': self.machine_fingerprint_manager.is_vm,
                'dh_public_key': dh_public_key_bytes.decode('utf-8'),
                'timestamp': time.time(),
                'nonce': os.urandom(16).hex(),
                'challenge_solution': self._solve_dip_challenge(challenge_response['challenge'], peer_public_id),
                'public_key': self.get_my_public_key_pem()
            }
            response_payload_json = json.dumps(response_payload, sort_keys=True)
            signature = self.digital_signature_manager.sign(response_payload_json)
            self.send_payload(conn, {'type': 'challenge_response', 'payload': response_payload, 'signature': signature})
            self.log(f"Sent challenge response to {peer_username}.")

            peer_final_response = self.recv_payload(conn)
            if not peer_final_response: raise Exception("No final response from peer.")
            peer_payload = peer_final_response.get('payload')
            peer_signature = peer_final_response.get('signature')
            if not DigitalSignatureManager.verify(peer_public_key_pem, json.dumps(peer_payload, sort_keys=True), peer_signature):
                raise Exception("Peer's final response signature is invalid! Possible MitM attack.")
            
            if peer_payload.get('status') == 'accepted':
                final_ack_payload = {'dip_solution': self._solve_dip_challenge(peer_payload['dip_challenge'], peer_public_id)}
                self.send_payload(conn, final_ack_payload)

                peer_dh_public_key_pem = peer_payload.get('dh_public_key')
                peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_pem.encode('utf-8'), backend=default_backend())
                shared_key = dh_private_key.exchange(peer_dh_public_key)
                self.log(f"Handshake complete. Establishing secure session with '{peer_username}'...")
                
                self.sessions[peer_username] = {
                    'conn': conn, 'crypto': QuantumSentryCryptography(), 
                    'key_stream': KeyStreamGenerator(shared_key, self.machine_fingerprint_manager.fingerprint),
                    'security_monitor': SecurityMonitor(self.log), 
                    'public_id': peer_public_id, 'public_key': peer_public_key_pem,
                    'is_vm': peer_payload.get('is_peer_on_vm')
                }
                
                if not self._perform_security_calibration(conn, peer_username, is_initiator=True):
                    raise Exception("Security calibration failed. Aborting connection.")

                self.log(f"✅ Secure session established with '{peer_username}'!")
                self.event_queue.put({'type': 'p2p_status', 'peer_username': peer_username, 'status': 'success'})
                threading.Thread(target=self._listen_for_messages, args=(conn, peer_username), daemon=True).start()
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
                for k in old_nonces: del self.recent_nonces[k]
            time.sleep(30)

    def handle_incoming_connection(self, conn, addr):
        initial_request = self.recv_payload(conn)
        if not initial_request or initial_request.get('type') != 'hello':
            self.log(f"Invalid initial request from {addr}. Closing."); conn.close(); return
        
        dip_challenge = self._generate_dip_challenge()
        self.send_payload(conn, {'challenge': dip_challenge})
        
        response_wrapper = self.recv_payload(conn)
        if not response_wrapper or response_wrapper.get('type') != 'challenge_response':
            self.log(f"Invalid challenge response from {addr}. Closing."); conn.close(); return
        
        req_payload = response_wrapper.get('payload')
        req_signature = response_wrapper.get('signature')
        peer_public_id = req_payload.get('public_id')
        
        expected_solution = self._solve_dip_challenge(dip_challenge, peer_public_id)
        if req_payload.get('challenge_solution') != expected_solution:
            self._send_rejection(conn, "Integrity proof failed. Client may be modified."); return

        self.log("Peer has passed Dynamic Integrity Proof.")
        self._handle_session_responder(conn, req_payload, req_signature)
    
    def _handle_session_responder(self, conn, request, signature):
        peer_public_key_pem = request.get('public_key')
        if not DigitalSignatureManager.verify(peer_public_key_pem, json.dumps(request, sort_keys=True), signature):
            self._send_rejection(conn, "Invalid digital signature."); return
        
        peer_public_id = request.get('public_id')
        peer_machine_fingerprint = request.get('machine_fingerprint')
        if self.block_manager.is_blocked(peer_machine_fingerprint):
            self._send_rejection(conn, "User is blocked."); return
        
        msg, success = self.contacts.add_contact(peer_public_id, peer_public_key_pem)
        self.log(msg)
        known_username = self.contacts.get_username_by_id(peer_public_id)
        
        try:
            dh_private_key = Config.DH_PARAMETERS.generate_private_key()
            dh_public_key_bytes = dh_private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            
            response_payload = {
                'status': 'accepted', 
                'dh_public_key': dh_public_key_bytes.decode('utf-8'),
                'is_peer_on_vm': request.get('is_vm'),
                'dip_challenge': self._generate_dip_challenge()
            }
            response_json = json.dumps(response_payload, sort_keys=True)
            response_signature = self.digital_signature_manager.sign(response_json)
            self.send_payload(conn, {'payload': response_payload, 'signature': response_signature})

            final_ack = self.recv_payload(conn)
            expected_solution = self._solve_dip_challenge(response_payload['dip_challenge'], self.identity.public_id)
            if not final_ack or final_ack.get('dip_solution') != expected_solution:
                 raise Exception("Peer failed final integrity proof.")

            self.log("Mutual integrity proof successful.")
            peer_dh_public_key_pem = request.get('dh_public_key')
            peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_pem.encode('utf-8'), backend=default_backend())
            shared_key = dh_private_key.exchange(peer_dh_public_key)

            self.sessions[known_username] = {
                'conn': conn, 'crypto': QuantumSentryCryptography(), 
                'key_stream': KeyStreamGenerator(shared_key, self.machine_fingerprint_manager.fingerprint),
                'security_monitor': SecurityMonitor(self.log), 
                'public_id': peer_public_id, 'public_key': peer_public_key_pem,
                'is_vm': request.get('is_vm')
            }
            
            if not self._perform_security_calibration(conn, known_username, is_initiator=False):
                raise Exception("Security calibration failed.")

            self.log(f"✅ Secure session established with '{known_username}'.")
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
            
            if message.get('type') == 'calibration': continue

            monitor = session['security_monitor']
            monitor.analyze_packet(message, session['is_vm'])
            
            if monitor.trust_score < 50:
                self.log(f"CRITICAL: Trust score for {peer_username} fell to {monitor.trust_score}. Terminating connection.")
                conn.close()
                break

            payload_data = message.get('data', '')
            signature_b64 = message.get('signature', '')
            peer_public_key = session.get('public_key')
            if not peer_public_key or not DigitalSignatureManager.verify(peer_public_key, payload_data, signature_b64):
                self.log(f"SECURITY ALERT: Invalid signature from '{peer_username}'. Message ignored."); continue
            event = message
            event['from'] = peer_username
            self.event_queue.put(event)
    
    def send_p2p_message(self, peer_username, text_message):
        if peer_username in self.sessions:
            session = self.sessions[peer_username]
            key_bytes = session['key_stream'].get_bytes(len(text_message))
            encrypted_msg = session['crypto'].encrypt(text_message, key_bytes)
            signature = self.digital_signature_manager.sign(encrypted_msg)
            self.send_payload(session['conn'], {'type': 'p2p_chat', 'data': encrypted_msg, 'length': len(text_message), 'signature': signature})

    def send_file(self, peer_username, file_path):
        if peer_username not in self.sessions: return
        session = self.sessions[peer_username]
        file_name = os.path.basename(file_path)
        try:
            with open(file_path, "rb") as f: file_bytes = f.read()
            file_len = len(file_bytes)
            key_bytes = session['key_stream'].get_bytes(file_len)
            encrypted_bytes = session['crypto'].encrypt(file_bytes, key_bytes)
            signature = self.digital_signature_manager.sign(encrypted_bytes)
            self.send_payload(session['conn'], {'type': 'file_transfer', 'filename': file_name, 'data': encrypted_bytes, 'length': file_len, 'signature': signature})
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
                self.send_payload(session['conn'], {'type': 'group_chat', 'data': encrypted_msg, 'length': len(text_message), 'group_name': group_name, 'signature': signature})

class AppState:
    def __init__(self):
        self.app_config = Config()
        self.log_queue = queue.Queue()
        self.event_queue = queue.Queue()
        self.system_log = ""
        self.machine_fingerprint_manager = MachineFingerprintManager(self.log)
        self.digital_signature_manager = DigitalSignatureManager(self.log)
        self.identity_manager = IdentityManager(self.log, self.machine_fingerprint_manager.fingerprint)
        self.contact_manager = ContactManager(self.log, self.identity_manager)
        self.group_manager = GroupChatManager(self.log)
        self.block_manager = BlockManager(self.log)
        self.node = Node(self.app_config, self.identity_manager, self.contact_manager, self.digital_signature_manager, self.block_manager, self.machine_fingerprint_manager, self.log_queue, self.event_queue, SOURCE_HASH)
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
    new_connection_status = ""
    while not app_state.log_queue.empty(): app_state.log(app_state.log_queue.get_nowait())
    while not app_state.event_queue.empty():
        event = app_state.event_queue.get_nowait()
        event_type = event.get('type')
        peer_username = event.get('from', event.get('peer_username'))
        if event_type == 'update_status':
            new_connection_status = event['data']
            app_state.log(f"UI Status: {new_connection_status}")
        elif event_type == 'p2p_status':
            chat_id = f"p2p:{peer_username}"
            if event['status'] == 'success':
                new_connection_status = f"✅ Securely connected to '{peer_username}'."
                app_state.p2p_chats[chat_id] = {'history': f"[System] {new_connection_status}\n", 'status': 'connected'}
            else:
                reason = event.get('reason', 'Connection lost.')
                new_connection_status = f"❌ Connection to '{peer_username}' failed. Reason: {reason}"
                status_msg = f"[System] {new_connection_status}\n"
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
                with open(save_path, "wb") as f: f.write(decrypted_bytes)
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
    p2p_chat_choices = sorted([f"p2p:{c}" for c in app_state.contact_manager.contacts.keys()])
    group_chat_choices = sorted([f"group:{g}" for g in app_state.group_manager.groups.keys()])
    all_chat_choices = p2p_chat_choices + group_chat_choices
    connection_status_update = gr.update(value=new_connection_status) if new_connection_status else gr.update()
    return (app_state.system_log, connection_status_update, new_p2p_histories, new_group_histories, gr.update(choices=all_chat_choices) if all_chat_choices else gr.update(), trigger_value)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception: IP = '127.0.0.1'
    finally: s.close()
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

        threading.Thread(target=app_state.node.initiate_direct_session, args=(peer_ip, peer_port, peer_public_id, peer_public_key)).start()
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
    if not file or not current_chat_id: return
    chat_type, chat_name = current_chat_id.split(':', 1)
    if chat_type != 'p2p':
        app_state.log("File transfer is only supported for P2P chats."); return
    app_state.node.send_file(chat_name, file.name)

def change_active_chat(chat_id, p2p_histories, group_histories):
    if not chat_id or ':' not in chat_id: return "[System] Select a chat to view history."
    chat_type, chat_name = chat_id.split(':', 1)
    if chat_type == 'p2p': history = p2p_histories.get(chat_id, "")
    elif chat_type == 'group': history = group_histories.get(chat_id, "")
    else: history = ""
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
                        connection_status_output = gr.Textbox(label="Connection Status", interactive=False, lines=3)
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
        
        create_invitation_btn.click(create_invitation_ui, [host_file_input, host_secret_input], [invitation_file_output, connection_status_output])
        connect_btn.click(use_invitation_ui, [connect_file_input, connect_secret_input], [connection_status_output])
        
        chat_input.submit(send_message_ui, [chat_input, chat_selector], [chat_input])
        send_file_btn.click(send_file_ui, [file_to_send, chat_selector], None)
        chat_selector.change(change_active_chat, [chat_selector, p2p_chat_histories, group_chat_histories], [chat_output])
        create_group_btn.click(create_group_ui, [group_name_input, group_members_input], [group_status_box, chat_selector])
        
        timer = gr.Timer(1, active=False)
        timer.tick(
            update_ui_loop,
            inputs=[chat_selector, p2p_chat_histories, group_chat_histories],
            outputs=[log_output, connection_status_output, p2p_chat_histories, group_chat_histories, chat_selector, chat_update_trigger]
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
