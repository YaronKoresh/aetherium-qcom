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
        return hashlib.sha256(password.encode()).digest()[:5]

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
                
                rng = np.random.default_rng(int.from_bytes(hashlib.sha256(password.encode()).digest(), 'big'))
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
        title = QLabel("MIT License")
        title.setObjectName("TitleLabel")
        
        license_text = """
        Copyright (c) 2025 Yaron Koresh

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.
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
