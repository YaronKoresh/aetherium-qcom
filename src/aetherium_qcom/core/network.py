# aetherium_qcom/core/network.py
import asyncio
import json
import os
import threading
from PySide6.QtCore import Signal, QObject
from kademlia.network import Server

class NetworkManager(QObject):
    message_received = Signal(bytes)
    log_message = Signal(str)
    message_sent_status = Signal(bool, str)
    TLS_HANDSHAKE = b'\x16\x03\x01'
    TLS_APPDATA = b'\x17\x03\x03'
    
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
            if data_len > 16384: # Security limit
                return
            encrypted_payload = await reader.readexactly(data_len)
            self.message_received.emit(encrypted_payload)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass # Normal disconnects
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
                raise ConnectionError("Invalid handshake response")
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
        self.port = port
        self.bootstrap_nodes = bootstrap_nodes
        self.server = Server()
        self.loop = None
        threading.Thread(target=self.run_server, daemon=True).start()

    def run_server(self):
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.server.listen(self.port))
            if self.bootstrap_nodes:
                self.loop.run_until_complete(self.server.bootstrap(self.bootstrap_nodes))
            self.loop.run_forever()
        except Exception:
            pass # Handle specific exceptions as needed

    def stop(self):
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)