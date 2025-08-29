import sys
import os
import hashlib
import json
import base64
import time
import inspect
import asyncio
import threading
import socket
import argparse
import cmd
import shlex
import wave
import tempfile
import shutil
from datetime import datetime
from contextlib import contextmanager
from collections import deque

try:
    from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                                 QTextEdit, QLineEdit, QPushButton, QListWidget, QInputDialog,
                                 QMessageBox, QFileDialog, QLabel, QListWidgetItem, QFrame,
                                 QStackedWidget)
    from PySide6.QtCore import Signal, QObject, QThread, Qt, QSettings, QSize
    from PySide6.QtGui import QColor, QBrush, QIcon, QPixmap
    from PIL import Image
    from kademlia.network import Server
    import numpy as np
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from pqcrypto.sign import ml_dsa_87
    from pqcrypto.kem import ml_kem_1024
    from pydub import AudioSegment
    from moviepy import VideoFileClip, AudioFileClip
except ImportError as e:
    print(f"Fatal Error: A required library is missing: {e.name}. Please run 'pip install {e.name}'")
    sys.exit(1)

class SteganographyManager:
    # Recommended constant salt (public, not secret):
    _PBKDF2_SALT = b"StegSalt"
    def _get_magic_number(self, password):
        # Use PBKDF2HMAC for password-derived magic number
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=5,
            salt=self._PBKDF2_SALT,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.generate(password.encode())

    def embed(self, input_path, data_bytes, password):
        _, ext = os.path.splitext(input_path.lower())
        img_ext = ['.png', '.jpg', '.jpeg', '.bmp', '.webp']
        aud_ext = ['.wav', '.mp3', '.m4a', '.flac', '.ogg']
        vid_ext = ['.mp4', '.mov', '.avi', '.mkv']

        magic_number = self._get_magic_number(password)
        data_with_header = magic_number + data_bytes

        if ext in img_ext:
            return self._embed_in_image(input_path, data_with_header, password)
        elif ext in aud_ext:
            return self._embed_in_audio(input_path, data_with_header, password)
        elif ext in vid_ext:
            return self._embed_in_video(input_path, data_with_header, password)
        else:
            return None, f"Unsupported file type: {ext}"

    def extract(self, input_path, password):
        _, ext = os.path.splitext(input_path.lower())
        img_ext = ['.png', '.jpg', '.jpeg', '.bmp', '.webp']
        aud_ext = ['.wav', '.mp3', '.m4a', '.flac', '.ogg']
        vid_ext = ['.mp4', '.mov', '.avi', '.mkv']

        data_with_header, error = None, None
        magic_number = self._get_magic_number(password)

        if ext in img_ext:
            data_with_header, error = self._extract_from_image(input_path, password)
        elif ext in aud_ext:
            data_with_header, error = self._extract_from_audio(input_path, password)
        elif ext in vid_ext:
            data_with_header, error = self._extract_from_video(input_path, password)
        else:
            return None, f"Unsupported file type: {ext}"

        if error:
            return None, error
        
        if data_with_header and data_with_header.startswith(magic_number):
            return data_with_header[len(magic_number):], None
        else:
            return None, "No invitation data found in media file or incorrect password."

    def _embed_in_image(self, image_path, data, password):
        try:
            with Image.open(image_path) as img:
                img = img.convert("RGB")
                w, h = img.size
                bits = ''.join(format(byte, '08b') for byte in data)
                data_len_bits = format(len(bits), '032b')
                total_bits = data_len_bits + bits
                
                if len(total_bits) > w * h * 3: return None, "Data too large for image."
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self._PBKDF2_SALT,
                    iterations=100_000,
                    backend=default_backend()
                )
                seed_bytes = kdf.derive(password.encode())
                rng = np.random.default_rng(int.from_bytes(seed_bytes, 'big'))
                indices = rng.choice(w * h * 3, len(total_bits), replace=False)
                
                flat_pixel_data = [chan for pix in img.getdata() for chan in pix]

                for i, bit in enumerate(total_bits):
                    idx = indices[i]
                    flat_pixel_data[idx] = (flat_pixel_data[idx] & 0xFE) | int(bit)

                img.putdata(list(zip(*[iter(flat_pixel_data)]*3)))
                
                output_path = f"invitation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                img.save(output_path, 'PNG')
                return output_path, None
        except Exception as e: return None, f"Image embedding error: {e}"

    def _extract_from_image(self, image_path, password):
        try:
            with Image.open(image_path) as img:
                img = img.convert("RGB")
                w, h = img.size
                seed_bytes = hashlib.pbkdf2_hmac(
                    "sha256",
                    password.encode(),
                    self._PBKDF2_SALT,
                    100_000,
                    dklen=32
                )
                rng = np.random.default_rng(int.from_bytes(seed_bytes, 'big'))
                
                flat_pixel_data = [chan for pix in img.getdata() for chan in pix]

                len_indices = rng.choice(w * h * 3, 32, replace=False)
                len_bits = "".join(str(flat_pixel_data[i] & 1) for i in len_indices)
                data_len = int(len_bits, 2)

                if data_len > w * h * 3: return None, "Corrupt data length."
                
                all_indices = rng.choice(w * h * 3, 32 + data_len, replace=False)
                data_indices = all_indices[32:]
                
                bits = "".join(str(flat_pixel_data[i] & 1) for i in data_indices)
                return bytearray(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)), None
        except Exception as e: return None, f"Image extraction error: {e}"

    def _lsb_embed_in_wav(self, wav_path, data_to_embed):
        with wave.open(wav_path, 'rb') as wav_file:
            frames = bytearray(wav_file.readframes(wav_file.getnframes()))
        
        bits_to_embed = ''.join(format(byte, '08b') for byte in data_to_embed)
        data_len_bits = format(len(bits_to_embed), '032b')
        total_bits = data_len_bits + bits_to_embed

        if len(total_bits) > len(frames):
            raise ValueError("Data is too large for the audio file.")

        for i, bit in enumerate(total_bits):
            frames[i] = (frames[i] & 0xFE) | int(bit)

        return bytes(frames)

    def _lsb_extract_from_wav(self, wav_path):
        with wave.open(wav_path, 'rb') as wav_file:
            frames = wav_file.readframes(wav_file.getnframes())

        len_bits = "".join([str(frames[i] & 1) for i in range(32)])
        data_len = int(len_bits, 2)
        
        if data_len > (len(frames) - 32):
             raise ValueError("Corrupt data length found in audio.")

        data_bits = "".join([str(frames[i] & 1) for i in range(32, 32 + data_len)])
        return bytearray(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))

    def _embed_in_audio(self, audio_path, data, password):
        try:
            audio = AudioSegment.from_file(audio_path)
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_wav:
                audio.export(temp_wav.name, format="wav")
            
            modified_frames = self._lsb_embed_in_wav(temp_wav.name, data)

            with wave.open(temp_wav.name, 'rb') as wav_file:
                params = wav_file.getparams()

            output_path = f"invitation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
            with wave.open(output_path, 'wb') as new_wav:
                new_wav.setparams(params)
                new_wav.writeframes(modified_frames)
            
            os.remove(temp_wav.name)
            return output_path, None
        except Exception as e:
            if 'temp_wav' in locals() and os.path.exists(temp_wav.name): os.remove(temp_wav.name)
            return None, f"Audio embedding error: {e}"

    def _extract_from_audio(self, audio_path, password):
        try:
            audio = AudioSegment.from_file(audio_path)
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_wav:
                audio.export(temp_wav.name, format="wav")
            
            extracted_data = self._lsb_extract_from_wav(temp_wav.name)
            os.remove(temp_wav.name)
            return extracted_data, None
        except Exception as e:
            if 'temp_wav' in locals() and os.path.exists(temp_wav.name): os.remove(temp_wav.name)
            return None, f"Audio extraction error: {e}"

    def _embed_in_video(self, video_path, data, password):
        try:
            video_clip = VideoFileClip(video_path)
            if not video_clip.audio:
                return None, "Video has no audio track to embed data in."

            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_audio:
                video_clip.audio.write_audiofile(temp_audio.name, verbose=False, logger=None)
            
            modified_frames = self._lsb_embed_in_wav(temp_audio.name, data)

            with wave.open(temp_audio.name, 'rb') as wav_file:
                params = wav_file.getparams()
            
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as modified_audio_file:
                 with wave.open(modified_audio_file.name, 'wb') as new_wav:
                    new_wav.setparams(params)
                    new_wav.writeframes(modified_frames)

            new_audio_clip = AudioFileClip(modified_audio_file.name)
            final_clip = video_clip.set_audio(new_audio_clip)
            
            output_path = f"invitation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4"
            final_clip.write_videofile(output_path, codec='libx264', audio_codec='aac', verbose=False, logger=None)
            
            os.remove(temp_audio.name)
            os.remove(modified_audio_file.name)
            return output_path, None
        except Exception as e:
            if 'temp_audio' in locals() and os.path.exists(temp_audio.name): os.remove(temp_audio.name)
            if 'modified_audio_file' in locals() and os.path.exists(modified_audio_file.name): os.remove(modified_audio_file.name)
            return None, f"Video embedding error: {e}"

    def _extract_from_video(self, video_path, password):
        try:
            video_clip = VideoFileClip(video_path)
            if not video_clip.audio:
                return None, "Video has no audio track."

            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_audio:
                video_clip.audio.write_audiofile(temp_audio.name, verbose=False, logger=None)

            extracted_data = self._lsb_extract_from_wav(temp_audio.name)
            os.remove(temp_audio.name)
            return extracted_data, None
        except Exception as e:
            if 'temp_audio' in locals() and os.path.exists(temp_audio.name): os.remove(temp_audio.name)
            return None, f"Video extraction error: {e}"
            
class CodeHasher:
    @staticmethod
    def get_source_hash():
        try:
            with cwd():
                with open(__file__, 'r', encoding='utf-8') as f:
                    source_code = f.read()
            return hashlib.sha256(source_code.encode('utf-8')).hexdigest()
        except (TypeError, OSError): return None

class CryptoManager:
    @staticmethod
    def generate_ephemeral_keys():
        pk, sk = ml_dsa_87.generate_keypair()
        return base64.b64encode(pk).decode(), base64.b64encode(sk).decode()

    @staticmethod
    def generate_persistent_keys():
        pk_d, sk_d = ml_dsa_87.generate_keypair()
        pk_k, sk_k = ml_kem_1024.generate_keypair()
        return {"sign_pk": base64.b64encode(pk_d).decode(), "sign_sk": base64.b64encode(sk_d).decode(),
                "kem_pk": base64.b64encode(pk_k).decode(), "kem_sk": base64.b64encode(sk_k).decode()}

    @staticmethod
    def sign_hash(signing_key_b64, hash_hex):
        try:
            sk_bytes = base64.b64decode(signing_key_b64)
            return base64.b64encode(ml_dsa_87.sign(sk_bytes, hash_hex.encode())).decode()
        except Exception: return None

    @staticmethod
    def verify_hash_signature(public_key_b64, signature_b64, hash_hex):
        try:
            pk_bytes = base64.b64decode(public_key_b64)
            sig_bytes = base64.b64decode(signature_b64)
            return ml_dsa_87.verify(pk_bytes, hash_hex.encode(), sig_bytes)
        except Exception: return False
    
    @staticmethod
    def sign_data(signing_key, data):
        try:
            return base64.b64encode(ml_dsa_87.sign(base64.b64decode(signing_key), json.dumps(data, sort_keys=True).encode())).decode()
        except Exception: return None

    @staticmethod
    def verify_signature(signing_pk, signature, data):
        try:
            data_bytes = json.dumps(data, sort_keys=True).encode()
            return ml_dsa_87.verify(base64.b64decode(signing_pk), data_bytes, base64.b64decode(signature))
        except Exception: return False

    @staticmethod
    def create_invitation(issuer_id, issuer_keys, bootstrap_nodes):
        data = {"issuer_id": issuer_id, "issuer_kem_pk": issuer_keys["kem_pk"], 
                "issuer_sign_pk": issuer_keys["sign_pk"], "bootstrap_nodes": bootstrap_nodes}
        sig = ml_dsa_87.sign(base64.b64decode(issuer_keys["sign_sk"]), json.dumps(data, sort_keys=True).encode())
        return {"payload": data, "signature": base64.b64encode(sig).decode()}

    @staticmethod
    def verify_invitation(invitation):
        try:
            payload_bytes = json.dumps(invitation['payload'], sort_keys=True).encode()
            return ml_dsa_87.verify(base64.b64decode(invitation['payload']['issuer_sign_pk']), payload_bytes, base64.b64decode(invitation['signature']))
        except Exception: return False
    
    @staticmethod
    def aead_encrypt(key_b64, data_bytes):
        key = hashlib.sha256(base64.b64decode(key_b64)).digest()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
        return nonce + ciphertext

    @staticmethod
    def aead_decrypt(key_b64, encrypted_data_with_nonce):
        key = hashlib.sha256(base64.b64decode(key_b64)).digest()
        nonce = encrypted_data_with_nonce[:12]
        ciphertext = encrypted_data_with_nonce[12:]
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return None

class NetworkManager(QObject):
    message_received = Signal(bytes)
    log_message = Signal(str)
    message_sent_status = Signal(bool, str)
    TLS_HANDSHAKE = b'\x16\x03\x01'; TLS_APPDATA = b'\x17\x03\x03'
    
    def __init__(self, port, kademlia_server):
        super().__init__()
        self.port = port
        self.kademlia_server = kademlia_server

    def run(self):
        self.log_message.emit(f"Obfuscated listener starting on port {self.port}")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.listen_for_messages())
        finally:
            loop.close()

    async def listen_for_messages(self):
        try:
            server = await asyncio.start_server(self.handle_connection, '0.0.0.0', self.port)
            async with server:
                await server.serve_forever()
        except OSError as e:
            self.log_message.emit(f"FATAL: Could not bind to port {self.port}. {e}")

    async def handle_connection(self, reader, writer):
        try:
            header = await reader.readexactly(3)
            if header != self.TLS_HANDSHAKE:
                return
            writer.write(self.TLS_HANDSHAKE + os.urandom(32))
            await writer.drain()
            app_header = await reader.readexactly(3)
            if app_header != self.TLS_APPDATA:
                return
            data_len = int.from_bytes(await reader.readexactly(4), 'big')
            if data_len > 16384:
                return
            encrypted_payload = await reader.readexactly(data_len)
            self.message_received.emit(encrypted_payload)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()

    async def send_message_to_user(self, user_id, payload_bytes):
        status = False
        try:
            user_presence_str = await self.kademlia_server.get(user_id)
            if not user_presence_str:
                self.message_sent_status.emit(False, user_id)
                return
            host, port = json.loads(user_presence_str)['comm_address']
        except (json.JSONDecodeError, KeyError):
            self.message_sent_status.emit(False, user_id)
            return

        writer = None
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(self.TLS_HANDSHAKE + os.urandom(64))
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            if not response.startswith(self.TLS_HANDSHAKE):
                raise ConnectionError()
            writer.write(self.TLS_APPDATA + len(payload_bytes).to_bytes(4, 'big') + payload_bytes)
            await writer.drain()
            status = True
        except Exception:
            status = False
        finally:
            if writer and not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            self.message_sent_status.emit(status, user_id)

class P2PNode:
    def __init__(self, port, bootstrap_nodes=None):
        self.port, self.bootstrap_nodes = port, bootstrap_nodes
        self.server = Server(); self.loop = None
        threading.Thread(target=self.run_server, daemon=True).start()
    def run_server(self):
        try:
            self.loop = asyncio.new_event_loop(); asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.server.listen(self.port))
            if self.bootstrap_nodes: self.loop.run_until_complete(self.server.bootstrap(self.bootstrap_nodes))
            self.loop.run_forever()
        except Exception: pass
    def stop(self):
        if self.loop and self.loop.is_running(): self.loop.call_soon_threadsafe(self.loop.stop)

class ChatWindow(QMainWindow):
    def __init__(self, display_name, dht_port, comm_port, bootstrap_node=None):
        super().__init__()
        self.settings = QSettings("Aetherium", "Q-Com")
        self.user_id = None
        self.display_name = display_name
        self.dht_port, self.comm_port = dht_port, comm_port
        self.profile_path = "profile.json"
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
        self.kademlia_node = P2PNode(dht_port, self.bootstrap_nodes)
        self.network_manager = NetworkManager(self.comm_port, self.kademlia_node.server)
        self.network_thread = QThread()
        self.network_manager.moveToThread(self.network_thread)
        self.network_thread.started.connect(self.network_manager.run)
        self.network_manager.log_message.connect(self.log)
        self.network_manager.message_received.connect(self.on_raw_message_received)
        self.network_manager.message_sent_status.connect(self.on_message_sent_status)
        self.network_thread.start()
        self.announce_presence()
        self.resize(900, 700)
        self.read_settings()
    
    def log(self, message):
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.log_display.append(f"{timestamp} {message}")
    
    def show_status_message(self, message, timeout=4000):
        self.statusBar().showMessage(message, timeout)

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
        
        sidebar_layout.addWidget(self.btn_chat_view)
        sidebar_layout.addWidget(self.btn_about_view)
        sidebar_layout.addWidget(self.btn_license_view)

        self.stacked_widget = QStackedWidget()
        self.chat_widget = self.create_chat_widget()
        self.about_widget = self.create_about_widget()
        self.license_widget = self.create_license_widget()

        self.stacked_widget.addWidget(self.chat_widget)
        self.stacked_widget.addWidget(self.about_widget)
        self.stacked_widget.addWidget(self.license_widget)

        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.stacked_widget)
        
        self.btn_chat_view.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        self.btn_about_view.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        self.btn_license_view.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))

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
        title = QLabel("About Aetherium Q-Com")
        title.setObjectName("TitleLabel")
        
        body_text = """
        <b>Aetherium QCom</b><br>
        Version 0.1.0<br><br>
        A secure, decentralized communication platform.<br>
        This application uses quantum-resistant cryptography to ensure the privacy and security of your communications.<br><br>
        Yaron Koresh © All rights reserved<br>
        """
        body = QLabel(body_text)
        body.setWordWrap(True)
        
        layout.addWidget(title)
        layout.addWidget(body)
        return widget

    def create_license_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        title = QLabel("GPLv3 License")
        title.setObjectName("TitleLabel")
        
        license_text = """
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must pass on to the recipients the same
freedoms that you received.  You must make sure that they, too, receive
or can get the source code.  And you must show them these terms so they
know their rights.

  Developers that use the GNU GPL protect your rights with two steps:
(1) assert copyright on the software, and (2) offer you this License
giving you legal permission to copy, distribute and/or modify it.

  For the developers' and authors' protection, the GPL clearly explains
that there is no warranty for this free software.  For both users' and
authors' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions.

  Some devices are designed to deny users access to install or run
modified versions of the software inside them, although the manufacturer
can do so.  This is fundamentally incompatible with the aim of
protecting users' freedom to change the software.  The systematic
pattern of such abuse occurs in the area of products for individuals to
use, which is precisely where it is most unacceptable.  Therefore, we
have designed this version of the GPL to prohibit the practice for those
products.  If such problems arise substantially in other domains, we
stand ready to extend this provision to those domains in future versions
of the GPL, as needed to protect the freedom of users.

  Finally, every program is threatened constantly by software patents.
States should not allow patents to restrict development and use of
software on general-purpose computers, but in those that do, we wish to
avoid the special danger that patents applied to a free program could
make it effectively proprietary.  To prevent this, the GPL assures that
patents cannot be used to render the program non-free.

  The precise terms and conditions for copying, distribution and
modification follow.

                       TERMS AND CONDITIONS

  0. Definitions.

  "This License" refers to version 3 of the GNU General Public License.

  "Copyright" also means copyright-like laws that apply to other kinds of
works, such as semiconductor masks.

  "The Program" refers to any copyrightable work licensed under this
License.  Each licensee is addressed as "you".  "Licensees" and
"recipients" may be individuals or organizations.

  To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of an
exact copy.  The resulting work is called a "modified version" of the
earlier work or a work "based on" the earlier work.

  A "covered work" means either the unmodified Program or a work based
on the Program.

  To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or modifying a private copy.  Propagation includes copying,
distribution (with or without modification), making available to the
public, and in some countries other activities as well.

  To "convey" a work means any kind of propagation that enables other
parties to make or receive copies.  Mere interaction with a user through
a computer network, with no transfer of a copy, is not conveying.

  An interactive user interface displays "Appropriate Legal Notices"
to the extent that it includes a convenient and prominently visible
feature that (1) displays an appropriate copyright notice, and (2)
tells the user that there is no warranty for the work (except to the
extent that warranties are provided), that licensees may convey the
work under this License, and how to view a copy of this License.  If
the interface presents a list of user commands or options, such as a
menu, a prominent item in the list meets this criterion.

  1. Source Code.

  The "source code" for a work means the preferred form of the work
for making modifications to it.  "Object code" means any non-source
form of a work.

  A "Standard Interface" means an interface that either is an official
standard defined by a recognized standards body, or, in the case of
interfaces specified for a particular programming language, one that
is widely used among developers working in that language.

  The "System Libraries" of an executable work include anything, other
than the work as a whole, that (a) is included in the normal form of
packaging a Major Component, but which is not part of that Major
Component, and (b) serves only to enable use of the work with that
Major Component, or to implement a Standard Interface for which an
implementation is available to the public in source code form.  A
"Major Component", in this context, means a major essential component
(kernel, window system, and so on) of the specific operating system
(if any) on which the executable work runs, or a compiler used to
produce the work, or an object code interpreter used to run it.

  The "Corresponding Source" for a work in object code form means all
the source code needed to generate, install, and (for an executable
work) run the object code and to modify the work, including scripts to
control those activities.  However, it does not include the work's
System Libraries, or general-purpose tools or generally available free
programs which are used unmodified in performing those activities but
which are not part of the work.  For example, Corresponding Source
includes interface definition files associated with source files for
the work, and the source code for shared libraries and dynamically
linked subprograms that the work is specifically designed to require,
such as by intimate data communication or control flow between those
subprograms and other parts of the work.

  The Corresponding Source need not include anything that users
can regenerate automatically from other parts of the Corresponding
Source.

  The Corresponding Source for a work in source code form is that
same work.

  2. Basic Permissions.

  All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met.  This License explicitly affirms your unlimited
permission to run the unmodified Program.  The output from running a
covered work is covered by this License only if the output, given its
content, constitutes a covered work.  This License acknowledges your
rights of fair use or other equivalent, as provided by copyright law.

  You may make, run and propagate covered works that you do not
convey, without conditions so long as your license otherwise remains
in force.  You may convey covered works to others for the sole purpose
of having them make modifications exclusively for you, or provide you
with facilities for running those works, provided that you comply with
the terms of this License in conveying all material for which you do
not control copyright.  Those thus making or running the covered works
for you must do so exclusively on your behalf, under your direction
and control, on terms that prohibit them from making any copies of
your copyrighted material outside their relationship with you.

  Conveying under any other circumstances is permitted solely under
the conditions stated below.  Sublicensing is not allowed; section 10
makes it unnecessary.

  3. Protecting Users' Legal Rights From Anti-Circumvention Law.

  No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996, or
similar laws prohibiting or restricting circumvention of such
measures.

  When you convey a covered work, you waive any legal power to forbid
circumvention of technological measures to the extent such circumvention
is effected by exercising rights under this License with respect to
the covered work, and you disclaim any intention to limit operation or
modification of the work as a means of enforcing, against the work's
users, your or third parties' legal rights to forbid circumvention of
technological measures.

  4. Conveying Verbatim Copies.

  You may convey verbatim copies of the Program's source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

  You may charge any price or no price for each copy that you convey,
and you may offer support or warranty protection for a fee.

  5. Conveying Modified Source Versions.

  You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these conditions:

    a) The work must carry prominent notices stating that you modified
    it, and giving a relevant date.

    b) The work must carry prominent notices stating that it is
    released under this License and any conditions added under section
    7.  This requirement modifies the requirement in section 4 to
    "keep intact all notices".

    c) You must license the entire work, as a whole, under this
    License to anyone who comes into possession of a copy.  This
    License will therefore apply, along with any applicable section 7
    additional terms, to the whole of the work, and all its parts,
    regardless of how they are packaged.  This License gives no
    permission to license the work in any other way, but it does not
    invalidate such permission if you have separately received it.

    d) If the work has interactive user interfaces, each must display
    Appropriate Legal Notices; however, if the Program has interactive
    interfaces that do not display Appropriate Legal Notices, your
    work need not make them do so.

  A compilation of a covered work with other separate and independent
works, which are not by their nature extensions of the covered work,
and which are not combined with it such as to form a larger program,
in or on a volume of a storage or distribution medium, is called an
"aggregate" if the compilation and its resulting copyright are not
used to limit the access or legal rights of the compilation's users
beyond what the individual works permit.  Inclusion of a covered work
in an aggregate does not cause this License to apply to the other
parts of the aggregate.

  6. Conveying Non-Source Forms.

  You may convey a covered work in object code form under the terms
of sections 4 and 5, provided that you also convey the
machine-readable Corresponding Source under the terms of this License,
in one of these ways:

    a) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by the
    Corresponding Source fixed on a durable physical medium
    customarily used for software interchange.

    b) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by a
    written offer, valid for at least three years and valid for as
    long as you offer spare parts or customer support for that product
    model, to give anyone who possesses the object code either (1) a
    copy of the Corresponding Source for all the software in the
    product that is covered by this License, on a durable physical
    medium customarily used for software interchange, for a price no
    more than your reasonable cost of physically performing this
    conveying of source, or (2) access to copy the
    Corresponding Source from a network server at no charge.

    c) Convey individual copies of the object code with a copy of the
    written offer to provide the Corresponding Source.  This
    alternative is allowed only occasionally and noncommercially, and
    only if you received the object code with such an offer, in accord
    with subsection 6b.

    d) Convey the object code by offering access from a designated
    place (gratis or for a charge), and offer equivalent access to the
    Corresponding Source in the same way through the same place at no
    further charge.  You need not require recipients to copy the
    Corresponding Source along with the object code.  If the place to
    copy the object code is a network server, the Corresponding Source
    may be on a different server (operated by you or a third party)
    that supports equivalent copying facilities, provided you maintain
    clear directions next to the object code saying where to find the
    Corresponding Source.  Regardless of what server hosts the
    Corresponding Source, you remain obligated to ensure that it is
    available for as long as needed to satisfy these requirements.

    e) Convey the object code using peer-to-peer transmission, provided
    you inform other peers where the object code and Corresponding
    Source of the work are being offered to the general public at no
    charge under subsection 6d.

  A separable portion of the object code, whose source code is excluded
from the Corresponding Source as a System Library, need not be
included in conveying the object code work.

  A "User Product" is either (1) a "consumer product", which means any
tangible personal property which is normally used for personal, family,
or household purposes, or (2) anything designed or sold for incorporation
into a dwelling.  In determining whether a product is a consumer product,
doubtful cases shall be resolved in favor of coverage.  For a particular
product received by a particular user, "normally used" refers to a
typical or common use of that class of product, regardless of the status
of the particular user or of the way in which the particular user
actually uses, or expects or is expected to use, the product.  A product
is a consumer product regardless of whether the product has substantial
commercial, industrial or non-consumer uses, unless such uses represent
the only significant mode of use of the product.

  "Installation Information" for a User Product means any methods,
procedures, authorization keys, or other information required to install
and execute modified versions of a covered work in that User Product from
a modified version of its Corresponding Source.  The information must
suffice to ensure that the continued functioning of the modified object
code is in no case prevented or interfered with solely because
modification has been made.

  If you convey an object code work under this section in, or with, or
specifically for use in, a User Product, and the conveying occurs as
part of a transaction in which the right of possession and use of the
User Product is transferred to the recipient in perpetuity or for a
fixed term (regardless of how the transaction is characterized), the
Corresponding Source conveyed under this section must be accompanied
by the Installation Information.  But this requirement does not apply
if neither you nor any third party retains the ability to install
modified object code on the User Product (for example, the work has
been installed in ROM).

  The requirement to provide Installation Information does not include a
requirement to continue to provide support service, warranty, or updates
for a work that has been modified or installed by the recipient, or for
the User Product in which it has been modified or installed.  Access to a
network may be denied when the modification itself materially and
adversely affects the operation of the network or violates the rules and
protocols for communication across the network.

  Corresponding Source conveyed, and Installation Information provided,
in accord with this section must be in a format that is publicly
documented (and with an implementation available to the public in
source code form), and must require no special password or key for
unpacking, reading or copying.

  7. Additional Terms.

  "Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.
Additional permissions that are applicable to the entire Program shall
be treated as though they were included in this License, to the extent
that they are valid under applicable law.  If additional permissions
apply only to part of the Program, that part may be used separately
under those permissions, but the entire Program remains governed by
this License without regard to the additional permissions.

  When you convey a copy of a covered work, you may at your option
remove any additional permissions from that copy, or from any part of
it.  (Additional permissions may be written to require their own
removal in certain cases when you modify the work.)  You may place
additional permissions on material, added by you to a covered work,
for which you have or can give appropriate copyright permission.

  Notwithstanding any other provision of this License, for material you
add to a covered work, you may (if authorized by the copyright holders of
that material) supplement the terms of this License with terms:

    a) Disclaiming warranty or limiting liability differently from the
    terms of sections 15 and 16 of this License; or

    b) Requiring preservation of specified reasonable legal notices or
    author attributions in that material or in the Appropriate Legal
    Notices displayed by works containing it; or

    c) Prohibiting misrepresentation of the origin of that material, or
    requiring that modified versions of such material be marked in
    reasonable ways as different from the original version; or

    d) Limiting the use for publicity purposes of names of licensors or
    authors of the material; or

    e) Declining to grant rights under trademark law for use of some
    trade names, trademarks, or service marks; or

    f) Requiring indemnification of licensors and authors of that
    material by anyone who conveys the material (or modified versions of
    it) with contractual assumptions of liability to the recipient, for
    any liability that these contractual assumptions directly impose on
    those licensors and authors.

  All other non-permissive additional terms are considered "further
restrictions" within the meaning of section 10.  If the Program as you
received it, or any part of it, contains a notice stating that it is
governed by this License along with a term that is a further
restriction, you may remove that term.  If a license document contains
a further restriction but permits relicensing or conveying under this
License, you may add to a covered work material governed by the terms
of that license document, provided that the further restriction does
not survive such relicensing or conveying.

  If you add terms to a covered work in accord with this section, you
must place, in the relevant source files, a statement of the
additional terms that apply to those files, or a notice indicating
where to find the applicable terms.

  Additional terms, permissive or non-permissive, may be stated in the
form of a separately written license, or stated as exceptions;
the above requirements apply either way.

  8. Termination.

  You may not propagate or modify a covered work except as expressly
provided under this License.  Any attempt otherwise to propagate or
modify it is void, and will automatically terminate your rights under
this License (including any patent licenses granted under the third
paragraph of section 11).

  However, if you cease all violation of this License, then your
license from a particular copyright holder is reinstated (a)
provisionally, unless and until the copyright holder explicitly and
finally terminates your license, and (b) permanently, if the copyright
holder fails to notify you of the violation by some reasonable means
prior to 60 days after the cessation.

  Moreover, your license from a particular copyright holder is
reinstated permanently if the copyright holder notifies you of the
violation by some reasonable means, this is the first time you have
received notice of violation of this License (for any work) from that
copyright holder, and you cure the violation prior to 30 days after
your receipt of the notice.

  Termination of your rights under this section does not terminate the
licenses of parties who have received copies or rights from you under
this License.  If your rights have been terminated and not permanently
reinstated, you do not qualify to receive new licenses for the same
material under section 10.

  9. Acceptance Not Required for Having Copies.

  You are not required to accept this License in order to receive or
run a copy of the Program.  Ancillary propagation of a covered work
occurring solely as a consequence of using peer-to-peer transmission
to receive a copy likewise does not require acceptance.  However,
nothing other than this License grants you permission to propagate or
modify any covered work.  These actions infringe copyright if you do
not accept this License.  Therefore, by modifying or propagating a
covered work, you indicate your acceptance of this License to do so.

  10. Automatic Licensing of Downstream Recipients.

  Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License.  You are not responsible
for enforcing compliance by third parties with this License.

  An "entity transaction" is a transaction transferring control of an
organization, or substantially all assets of one, or subdividing an
organization, or merging organizations.  If propagation of a covered
work results from an entity transaction, each party to that
transaction who receives a copy of the work also receives whatever
licenses to the work the party's predecessor in interest had or could
give under the previous paragraph, plus a right to possession of the
Corresponding Source of the work from the predecessor in interest, if
the predecessor has it or can get it with reasonable efforts.

  You may not impose any further restrictions on the exercise of the
rights granted or affirmed under this License.  For example, you may
not impose a license fee, royalty, or other charge for exercise of
rights granted under this License, and you may not initiate litigation
(including a cross-claim or counterclaim in a lawsuit) alleging that
any patent claim is infringed by making, using, selling, offering for
sale, or importing the Program or any portion of it.

  11. Patents.

  A "contributor" is a copyright holder who authorizes use under this
License of the Program or a work on which the Program is based.  The
work thus licensed is called the contributor's "contributor version".

  A contributor's "essential patent claims" are all patent claims
owned or controlled by the contributor, whether already acquired or
hereafter acquired, that would be infringed by some manner, permitted
by this License, of making, using, or selling its contributor version,
but do not include claims that would be infringed only as a
consequence of further modification of the contributor version.  For
purposes of this definition, "control" includes the right to grant
patent sublicenses in a manner consistent with the requirements of
this License.

  Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor's essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

  In the following three paragraphs, a "patent license" is any express
agreement or commitment, however denominated, not to enforce a patent
(such as an express permission to practice a patent or covenant not to
sue for patent infringement).  To "grant" such a patent license to a
party means to make such an agreement or commitment not to enforce a
patent against the party.

  If you convey a covered work, knowingly relying on a patent license,
and the Corresponding Source of the work is not available for anyone
to copy, free of charge and under the terms of this License, through a
publicly available network server or other readily accessible means,
then you must either (1) cause the Corresponding Source to be so
available, or (2) arrange to deprive yourself of the benefit of the
patent license for this particular work, or (3) arrange, in a manner
consistent with the requirements of this License, to extend the patent
license to downstream recipients.  "Knowingly relying" means you have
actual knowledge that, but for the patent license, your conveying the
covered work in a country, or your recipient's use of the covered work
in a country, would infringe one or more identifiable patents in that
country that you have reason to believe are valid.

  If, pursuant to or in connection with a single transaction or
arrangement, you convey, or propagate by procuring conveyance of, a
covered work, and grant a patent license to some of the parties
receiving the covered work authorizing them to use, propagate, modify
or convey a specific copy of the covered work, then the patent license
you grant is automatically extended to all recipients of the covered
work and works based on it.

  A patent license is "discriminatory" if it does not include within
the scope of its coverage, prohibits the exercise of, or is
conditioned on the non-exercise of one or more of the rights that are
specifically granted under this License.  You may not convey a covered
work if you are a party to an arrangement with a third party that is
in the business of distributing software, under which you make payment
to the third party based on the extent of your activity of conveying
the work, and under which the third party grants, to any of the
parties who would receive the covered work from you, a discriminatory
patent license (a) in connection with copies of the covered work
conveyed by you (or copies made from those copies), or (b) primarily
for and in connection with specific products or compilations that
contain the covered work, unless you entered into that arrangement,
or that patent license was granted, prior to 28 March 2007.

  Nothing in this License shall be construed as excluding or limiting
any implied license or other defenses to infringement that may
otherwise be available to you under applicable patent law.

  12. No Surrender of Others' Freedom.

  If conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot convey a
covered work so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you may
not convey it at all.  For example, if you agree to terms that obligate you
to collect a royalty for further conveying from those to whom you convey
the Program, the only way you could satisfy both those terms and this
License would be to refrain entirely from conveying the Program.

  13. Use with the GNU Affero General Public License.

  Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU Affero General Public License into a single
combined work, and to convey the resulting work.  The terms of this
License will continue to apply to the part which is the covered work,
but the special requirements of the GNU Affero General Public License,
section 13, concerning interaction through a network will apply to the
combination as such.

  14. Revised Versions of this License.

  The Free Software Foundation may publish revised and/or new versions of
the GNU General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

  Each version is given a distinguishing version number.  If the
Program specifies that a certain numbered version of the GNU General
Public License "or any later version" applies to it, you have the
option of following the terms and conditions either of that numbered
version or of any later version published by the Free Software
Foundation.  If the Program does not specify a version number of the
GNU General Public License, you may choose any version ever published
by the Free Software Foundation.

  If the Program specifies that a proxy can decide which future
versions of the GNU General Public License can be used, that proxy's
public statement of acceptance of a version permanently authorizes you
to choose that version for the Program.

  Later license versions may give you additional or different
permissions.  However, no additional obligations are imposed on any
author or copyright holder as a result of your choosing to follow a
later version.

  15. Disclaimer of Warranty.

  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

  16. Limitation of Liability.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

  17. Interpretation of Sections 15 and 16.

  If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the
Program, unless a warranty or assumption of liability accompanies a
copy of the Program in return for a fee.

                     END OF TERMS AND CONDITIONS

            How to Apply These Terms to Your New Programs

  If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

  To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
state the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

    Aetherium Q-Com is a decentralized, untraceable, and unblockable communication platform engineered for truly private, censorship-resistant messaging.
    Copyright (C) 2025  Yaron Koresh

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

  If the program does terminal interaction, make it output a short
notice like this when it starts in an interactive mode:

    Aetherium Q-Com  Copyright (C) 2025  Yaron Koresh
    This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, your program's commands
might be different; for a GUI interface, you would use an "about box".

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU GPL, see
<https://www.gnu.org/licenses/>.

  The GNU General Public License does not permit incorporating your program
into proprietary programs.  If your program is a subroutine library, you
may consider it more useful to permit linking proprietary applications with
the library.  If this is what you want to do, use the GNU Lesser General
Public License instead of this License.  But first, please read
<https://www.gnu.org/licenses/why-not-lgpl.html>.
        """
        license_label = QTextEdit(license_text)
        license_label.setReadOnly(True)
        
        layout.addWidget(title)
        layout.addWidget(license_label)
        return widget

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
            "members": [self.user_id]
        }
        self.save_state()
        self.populate_ui_from_state()
        self.show_status_message(f"Group '{clean_group_name}' created.")

    def on_chat_selected(self, item):
        chat_data = item.data(Qt.ItemDataRole.UserRole)
        self.current_chat_id = chat_data['id']
        self.message_input.setEnabled(True)
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
        if group_id not in self.groups or self.groups[group_id]['admin'] != self.user_id:
            self.log(f"Error: User is not an admin of group '{group_id}'.")
            return
        
        contact_info = self.contacts.get(contact_id)
        if not contact_info or 'otp_key' not in contact_info:
            self.log(f"Error: Cannot invite {contact_id}. No secure channel established.")
            return

        group_info = self.groups[group_id]
        
        invite_payload = {
            "type": "group_invite",
            "sender_id": self.user_id,
            "sender_display_name": self.display_name,
            "group_id": group_id,
            "group_info": group_info
        }

        self._send_encrypted_message(contact_id, invite_payload, contact_info['otp_key'])
        self.show_status_message(f"Invitation sent to {contact_id}.")

    def announce_presence(self):
        async def do_announce():
            data = {"kem_pk": self.keys['kem_pk'], "sign_pk": self.keys['sign_pk'], "comm_address": ('127.0.0.1', self.comm_port),
                    "display_name": self.display_name}
            await self.kademlia_node.server.set(self.user_id, json.dumps(data))
            self.log("Presence announced on the network.")
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
        if not item or not item.data(Qt.ItemDataRole.UserRole) or item.data(Qt.ItemDataRole.UserRole)['type'] != 'contact':
            return
        contact_id = item.data(Qt.ItemDataRole.UserRole)['id']
        contact_info = self.contacts.get(contact_id, {})
        
        menu = self.entity_list_widget.createStandardContextMenu()

        if contact_id in self.ostracized_users:
            if contact_id in self.accusation_log:
                action = menu.addAction("View Accusation Log")
                action.triggered.connect(lambda: self.show_accusation_log(contact_id))
        elif contact_info.get('status') == 'confirmed':
            action = menu.addAction("Ostracize User")
            action.triggered.connect(lambda: self.context_ostracize_user(contact_id))
            
            menu.addSeparator()

            has_admin_groups = False
            for group_id, group_info in self.groups.items():
                if group_info['admin'] == self.user_id:
                    has_admin_groups = True
                    action = menu.addAction(f"Invite to '{group_info.get('display_name', group_id)}'")
                    action.triggered.connect(lambda _, c=contact_id, g=group_id: self.invite_to_group(c, g))
        
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

        invitation_data = self.crypto.create_invitation(self.user_id, self.keys, [('127.0.0.1', self.dht_port)])
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
        
        self.save_state()

    def write_settings(self):
        self.settings.setValue("geometry", self.saveGeometry())

    def read_settings(self):
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)

    def closeEvent(self, event):
        self.write_settings()
        self.log("Saving secure state and shutting down...")
        self.save_state()
        self.kademlia_node.stop()
        if self.network_thread.isRunning(): self.network_thread.quit(); self.network_thread.wait(3000)
        event.accept()

def get_free_ports(count=2):
    sockets, ports = [], []
    for _ in range(count):
        s = socket.socket(); s.bind(('', 0)); ports.append(s.getsockname()[1]); sockets.append(s)
    for s in sockets: s.close()
    return ports

@contextmanager
def cwd(dir=None):
    if not dir:
        dir = os.path.dirname(os.path.realpath(__file__))
    owd = os.getcwd()
    try:
        os.chdir(dir)
        yield dir
    finally:
        os.chdir(owd)

class InteractiveShell(cmd.Cmd):
    intro = 'Welcome to the Aetherium Q-Com interactive shell. Type help or ? to list commands.\n'
    prompt = 'Aetherium> '

    def do_exit(self, arg):
        'Exit the interactive shell.'
        print('Goodbye.')
        return True

    def do_keygen(self, arg):
        'Generate new developer master keys.'
        handle_keygen()

    def do_sign(self, arg):
        'Sign the application source code.'
        handle_sign()

    def do_invite(self, arg):
        'Manage invitations. Usage: invite <create|read> --media <path> --password <pass>'
        parser = argparse.ArgumentParser(prog='invite', description='Create or read invitations from media files.')
        subparsers = parser.add_subparsers(dest='invite_command', required=True)
        
        create_parser = subparsers.add_parser('create')
        create_parser.add_argument('--media', required=True)
        create_parser.add_argument('--password', required=True)

        read_parser = subparsers.add_parser('read')
        read_parser.add_argument('--media', required=True)
        read_parser.add_argument('--password', required=True)

        try:
            args = parser.parse_args(shlex.split(arg))
            handle_invite(args)
        except SystemExit:
            pass
        except Exception as e:
            print(f"Error: {e}")

def load_cli_profile():
    profile_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "profile.json")
    if not os.path.exists(profile_path):
        print("FATAL: No profile.json found. Please run the GUI first to create a profile.")
        return None
    try:
        with open(profile_path, 'r') as f:
            vault = json.load(f)
        state_json = base64.b64decode(vault['data'])
        state_data = json.loads(state_json)
        return state_data
    except Exception as e:
        print(f"FATAL: Could not load or parse profile.json. Error: {e}")
        return None

def handle_gui(args):
    app = QApplication(sys.argv)
    
    qss_style = """
        QMainWindow, QWidget { background-color: #263238; }
        QLabel { color: #CFD8DC; font-size: 14px; }
        QLabel#TitleLabel { color: white; font-size: 20px; font-weight: bold; }
        QPushButton { background-color: #00796B; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-size: 14px; }
        QPushButton:hover { background-color: #00897B; }
        QPushButton:disabled { background-color: #455A64; }
        QPushButton#SendButton { background-color: #4CAF50; }
        QPushButton#SendButton:hover { background-color: #66BB6A; }
        QPushButton#SidebarButton { background-color: transparent; text-align: left; padding: 10px; font-size: 16px; border-radius: 0px; }
        QPushButton#SidebarButton:hover { background-color: #37474F; }
        QLineEdit, QTextEdit, QListWidget { background-color: #37474F; color: #CFD8DC; border: 1px solid #263238; border-radius: 4px; padding: 5px; font-size: 14px; }
        QStatusBar { color: #CFD8DC; }
        QScrollBar:vertical { border: none; background: #37474F; width: 10px; margin: 0px 0px 0px 0px; }
        QScrollBar::handle:vertical { background: #546E7A; min-height: 20px; border-radius: 5px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        QWidget#Sidebar { background-color: #212121; }
    """
    app.setStyleSheet(qss_style)

    display_name = None
    bootstrap_node = None
    profile_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "profile.json")
    if not os.path.exists(profile_path):
        name, ok = QInputDialog.getText(None, "Welcome to Aetherium Q-Com", "Enter your desired display name:")
        if not (ok and name.strip()): 
            sys.exit(0)
        display_name = name.strip()
    
    dht_port, comm_port = get_free_ports(2)
    
    window = ChatWindow(display_name=display_name, dht_port=dht_port, comm_port=comm_port, bootstrap_node=bootstrap_node)
    window.show()
    sys.exit(app.exec())

def handle_keygen(args=None):
    pk, sk = CryptoManager.generate_ephemeral_keys()
    with cwd():
        with open("./dev_public.key", "w") as f: f.write(pk)
        with open("../dev_private.key", "w") as f: f.write(sk)
    print("--- GENERATED DEV MASTER KEYS ---\n")
    print("dev_public.key and dev_private.key files created.")
    print("KEEP dev_private.key ABSOLUTELY SECRET.")

def handle_sign(args=None):
    with cwd():
        if not os.path.exists("../dev_private.key"):
            print("FATAL: dev_private.key not found. Run 'keygen' first.")
            sys.exit(1)
    dev_private_key = None
    with cwd():
        with open("../dev_private.key", "r") as f: dev_private_key = f.read()
    code_hash = CodeHasher.get_source_hash()
    if not code_hash:
        print("Could not generate code hash for signing.")
        sys.exit(1)
    signature = CryptoManager.sign_hash(dev_private_key, code_hash)
    if not signature:
        print("Could not sign code hash.")
        sys.exit(1)
    with cwd():
        with open("./code_signature.sig", "w") as f: f.write(signature)
    print(f"--- CODE SIGNED SUCCESSFULLY ---\n")
    print(f"Code Hash: {code_hash}")
    print(f"Signature written to code_signature.sig")

def handle_invite(args):
    profile = load_cli_profile()
    if not profile:
        return

    stego = SteganographyManager()
    crypto = CryptoManager()

    if args.invite_command == 'create':
        print(f"Creating invitation from {profile['display_name']}...")
        dht_port, _ = get_free_ports(1)
        invitation_data = crypto.create_invitation(profile['user_id'], profile['keys'], [('127.0.0.1', dht_port)])
        invitation_bytes = json.dumps(invitation_data, sort_keys=True).encode()
        
        output_path, error = stego.embed(args.media, invitation_bytes, args.password)
        if error:
            print(f"Error creating invitation: {error}")
        else:
            print(f"Successfully created invitation: {output_path}")

    elif args.invite_command == 'read':
        print(f"Reading invitation from {args.media}...")
        inv_bytes, error = stego.extract(args.media, args.password)
        if error:
            print(f"Error reading invitation: {error}")
            return
        
        try:
            invitation = json.loads(inv_bytes)
            if not crypto.verify_invitation(invitation):
                print("Security Alert: Invitation signature is invalid or tampered with.")
                return
            
            issuer_info = invitation['payload']
            print("\n--- Invitation Details ---")
            print(f"Issuer ID: {issuer_info['issuer_id']}")
            print(f"Issuer KEM PK: {issuer_info['issuer_kem_pk'][:32]}...")
            print(f"Issuer Sign PK: {issuer_info['issuer_sign_pk'][:32]}...")
            print("Signature: VERIFIED")
            print("--------------------------")

        except Exception as e:
            print(f"Could not parse invitation data. It may be corrupt. Error: {e}")

def handle_interactive(args):
    InteractiveShell().cmdloop()

def main():
    parser = argparse.ArgumentParser(description="A secure, decentralized communication platform.", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest='command', help='commands')

    gui_parser = subparsers.add_parser('gui', help='Launch the graphical user interface (default).')
    gui_parser.set_defaults(func=handle_gui)

    keygen_parser = subparsers.add_parser('keygen', help='Generate new developer master keys.')
    keygen_parser.set_defaults(func=handle_keygen)

    sign_parser = subparsers.add_parser('sign', help='Sign the application source code.')
    sign_parser.set_defaults(func=handle_sign)

    interactive_parser = subparsers.add_parser('interactive', help='Launch an interactive command shell.')
    interactive_parser.set_defaults(func=handle_interactive)
    
    invite_parser = subparsers.add_parser('invite', help='Manage invitations.')
    invite_subparsers = invite_parser.add_subparsers(dest='invite_command', required=True)
    
    invite_create_parser = invite_subparsers.add_parser('create', help='Create and embed an invitation in a media file.')
    invite_create_parser.add_argument('--media', required=True, help='Path to the source media file (image, audio, video).')
    invite_create_parser.add_argument('--password', required=True, help='Password to encrypt the invitation.')
    invite_create_parser.set_defaults(func=handle_invite)

    invite_read_parser = invite_subparsers.add_parser('read', help='Read and verify an invitation from a media file.')
    invite_read_parser.add_argument('--media', required=True, help='Path to the invitation media file.')
    invite_read_parser.add_argument('--password', required=True, help='Password to decrypt the invitation.')
    invite_read_parser.set_defaults(func=handle_invite)

    args = parser.parse_args()

    if args.command not in ['gui', None]:
        if hasattr(args, 'func'):
            args.func(args)
        else:
            parser.print_help()
        sys.exit(0)

    dev_public_key, code_signature = None, None
    try:
        with cwd():
            with open("./dev_public.key", "r") as f: dev_public_key = f.read()
            with open("./code_signature.sig", "r") as f: code_signature = f.read()
    except FileNotFoundError:
        print("FATAL: This client is not signed. dev_public.key or code_signature.sig not found.")
        sys.exit(1)

    current_hash = CodeHasher.get_source_hash()
    if not current_hash or not CryptoManager.verify_hash_signature(dev_public_key, code_signature, current_hash):
        print("FATAL: CODE TAMPERING DETECTED OR SIGNATURE IS FOR A DIFFERENT VERSION. TERMINATING.")
        sys.exit(1)

    if hasattr(args, 'func'):
        args.func(args)
    else:
        handle_gui(None)

if __name__ == "__main__":
    main()

