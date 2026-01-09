# aetherium_qcom/core/network.py
import asyncio
import json
import os
import threading
import socket
import base64
import time
import uuid
from PySide6.QtCore import Signal, QObject
from kademlia.network import Server
from .transport import TransportFactory

try:
    import stun
except ImportError:
    stun = None

class NATTraversal:
    """Utility class for NAT traversal using STUN to discover public IP and port."""
    
    # Default STUN servers (Google's public STUN servers)
    DEFAULT_STUN_SERVERS = [
        'stun.l.google.com:19302',
        'stun1.l.google.com:19302',
        'stun2.l.google.com:19302',
        'stun3.l.google.com:19302',
        'stun4.l.google.com:19302'
    ]

    @staticmethod
    async def discover_public_address(local_port, stun_server=None):
        """
        Discover the public IP address and port using STUN asynchronously.
        
        Args:
            local_port: The local port to use for discovery
            stun_server: Optional specific STUN server to use (host:port format)
            
        Returns:
            Tuple of (public_ip, public_port, nat_type) or (None, None, None) on failure
        """
        if stun is None:
            return None, None, None
        
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
            
        # Helper function to run the blocking STUN call in an executor
        async def get_stun_info(host, port):
            return await loop.run_in_executor(
                None,  # Use the default ThreadPoolExecutor
                stun.get_ip_info,
                source_port=local_port,
                stun_host=host,
                stun_port=port
            )

        # Parse STUN server if provided
        if stun_server:
            if ':' in stun_server:
                stun_host, stun_port = stun_server.split(':', 1)
                stun_port = int(stun_port)
            else:
                stun_host = stun_server
                stun_port = 3478
            
            # Try the specific STUN server
            try:
                nat_type, external_ip, external_port = await get_stun_info(stun_host, stun_port)
                return external_ip, external_port, nat_type
            except Exception:
                return None, None, None
        
        else:
            # Try default STUN servers
            for server in NATTraversal.DEFAULT_STUN_SERVERS:
                stun_host, stun_port = server.split(':', 1)
                stun_port = int(stun_port)
                try:
                    nat_type, external_ip, external_port = await get_stun_info(stun_host, stun_port)
                    if external_ip and external_port:
                        return external_ip, external_port, nat_type
                except Exception:
                    continue
            return None, None, None
        
        # Try the specific STUN server
        try:
            nat_type, external_ip, external_port = stun.get_ip_info(
                source_port=local_port,
                stun_host=stun_host,
                stun_port=stun_port
            )
            return external_ip, external_port, nat_type
        except Exception:
            return None, None, None
    
    @staticmethod
    def perform_udp_hole_punch(local_port, remote_ip, remote_port):
        """
        Perform UDP hole punching to establish a direct connection.
        
        This sends a UDP packet to the remote peer to create a NAT mapping,
        allowing the remote peer to send packets back through the NAT.
        
        Args:
            local_port: Local port to bind to
            remote_ip: Remote peer's public IP
            remote_port: Remote peer's public port
            
        Returns:
            True if hole punch was sent, False otherwise
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Allow port reuse to avoid conflicts with TCP listener on same port
            # SO_REUSEADDR allows UDP and TCP to share the same port number
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Intentionally bind to all interfaces (0.0.0.0) for P2P NAT traversal
            # This is required to receive UDP packets from remote peers for hole punching
            sock.bind(('0.0.0.0', local_port))
            # Send a small packet to "punch" a hole in the NAT
            sock.sendto(b'PUNCH', (remote_ip, remote_port))
            return True
        except (OSError, socket.error):
            # Socket operation failed - NAT hole punching unsuccessful
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

class NetworkManager(QObject):
    message_received = Signal(bytes)
    log_message = Signal(str)
    message_sent_status = Signal(bool, str)
    message_queued_for_offline = Signal(str)  # user_id for queued messages
    public_address_discovered = Signal(str, int, str)  # ip, port, nat_type
    offline_messages_syncing = Signal(bool, int)  # syncing status, message count
    file_transfer_progress = Signal(str, int, int)  # transfer_id, bytes_sent, total_bytes
    file_transfer_complete = Signal(str, bool)  # transfer_id, success
    
    # Legacy constants (for backward compatibility)
    TLS_HANDSHAKE = b'\x16\x03\x01'
    TLS_APPDATA = b'\x17\x03\x03'
    
    # Peer exchange constants
    MAX_PEER_EXCHANGE_LIST_SIZE = 100
    PEER_TIMEOUT_SECONDS = 86400  # 24 hours
    
    # File transfer constants
    CHUNK_SIZE = 65536  # 64 KiB chunks
    MAX_FILE_SIZE = 104857600  # 100 MiB max file size
    
    def __init__(self, port, kademlia_server, manual_public_ip=None, manual_public_port=None, transport_type="default", transport_config=None):
        super().__init__()
        self.port = port
        self.kademlia_server = kademlia_server
        self.manual_public_ip = manual_public_ip
        self.manual_public_port = manual_public_port
        self.public_ip = None
        self.public_port = None
        self.nat_type = None
        
        # Initialize pluggable transport
        self.transport = TransportFactory.create_transport(transport_type, transport_config)
        self.transport_type = transport_type
        
        # File transfer management
        self.active_file_transfers = {}  # transfer_id -> transfer_state
        self.pending_file_chunks = {}  # transfer_id -> {chunk_index -> chunk_data}
    
    async def discover_public_address(self):
        """Discover the public IP address and port using the configured transport or manual settings."""
        if (
            self.manual_public_ip
            and self.manual_public_port
            and str(self.manual_public_ip).strip()
            and str(self.manual_public_port).strip()
        ):
            self.public_ip = self.manual_public_ip
            self.public_port = self.manual_public_port
            self.nat_type = "Manual"
            self.log_message.emit(f"Using manual public address: {self.public_ip}:{self.public_port}")
            self.public_address_discovered.emit(self.public_ip, self.public_port, self.nat_type)
            return
        
        self.log_message.emit(f"Discovering public IP address via {self.transport.get_transport_name()} transport...")
        ip, port, nat_type = await self.transport.discover_public_address(self.port)
        
        if ip and port:
            self.public_ip = ip
            self.public_port = port
            self.nat_type = nat_type
            self.log_message.emit(f"Public address discovered: {ip}:{port} (Method: {nat_type})")
            self.public_address_discovered.emit(ip, port, nat_type)
        else:
            # Fallback to localhost if discovery fails
            self.public_ip = "127.0.0.1"
            self.public_port = self.port
            self.nat_type = "Failed"
            self.log_message.emit("Address discovery failed. Falling back to localhost. Manual configuration may be required.")
            self.public_address_discovered.emit(self.public_ip, self.public_port, self.nat_type)

    def run(self):
        # Log this immediately, so the user knows the server is starting
        self.log_message.emit(f"Obfuscated listener starting on port {self.port}")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def main_task():
            # Create tasks for both the listener and the discovery
            listener_task = asyncio.create_task(self.listen_for_messages())
            discovery_task = asyncio.create_task(self.discover_public_address())
            
            # Run them concurrently.
            # The listener_task will run until the server is stopped,
            # and the discovery_task will run and complete in the background.
            await asyncio.gather(listener_task, discovery_task)

        try:
            loop.run_until_complete(main_task())
        finally:
            loop.close()

    async def listen_for_messages(self):
        try:
            # Intentionally bind to all interfaces (0.0.0.0) for P2P communication
            # This allows the client to accept direct connections from peers over the internet
            # Security is enforced through cryptographic verification, not network isolation
            server = await asyncio.start_server(self.handle_connection, '0.0.0.0', self.port)
            async with server:
                await server.serve_forever()
        except OSError as e:
            self.log_message.emit(f"FATAL: Could not bind to port {self.port}. {e}")

    async def handle_connection(self, reader, writer):
        try:
            # Read initial handshake using transport
            # Determine handshake length required by the transport
            handshake_len = getattr(self.transport, "handshake_length", 64)
            header = await reader.readexactly(handshake_len)
            if not self.transport.verify_handshake(header):
                return
            writer.write(self.transport.get_handshake_bytes())
            await writer.drain()

            # Delegate reading and unwrapping to the transport implementation
            encrypted_payload = await self.transport.read_and_unwrap_incoming_data(reader)
            if encrypted_payload is None:
                return
            self.message_received.emit(encrypted_payload)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass # Normal disconnects
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()

    async def send_message_to_user(self, user_id, payload_bytes, enable_store_and_forward=True):
        """
        Send a message to a user. If the user is offline and S&F is enabled,
        store the message in the DHT for later retrieval.
        
        Returns:
            tuple: (success: bool, was_queued: bool) where:
                - success: True if message was sent or queued successfully
                - was_queued: True if message was queued for offline delivery, False if sent directly
        """
        try:
            user_presence_str = await self.kademlia_server.get(user_id)
            if not user_presence_str:
                # User is offline
                if enable_store_and_forward:
                    # Store message in DHT for offline delivery
                    await self.store_offline_message(user_id, payload_bytes)
                    self.log_message.emit(f"User {user_id} is offline. Message queued for delivery.")
                    self.message_queued_for_offline.emit(user_id)
                    return (True, True)  # Successfully queued
                else:
                    self.message_sent_status.emit(False, user_id)
                    return (False, False)
            host, port = json.loads(user_presence_str)['comm_address']
        except (json.JSONDecodeError, KeyError):
            if enable_store_and_forward:
                await self.store_offline_message(user_id, payload_bytes)
                self.log_message.emit(f"User {user_id} is offline. Message queued for delivery.")
                self.message_queued_for_offline.emit(user_id)
                return (True, True)  # Successfully queued
            else:
                self.message_sent_status.emit(False, user_id)
                return (False, False)

        writer = None
        status = False
        try:
            reader, writer = await asyncio.open_connection(host, port)
            # Send handshake using transport
            writer.write(self.transport.get_handshake_bytes())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            if not self.transport.verify_handshake(response):
                raise ConnectionError("Invalid handshake response")
            
            # Wrap payload using transport
            wrapped_payload = await self.transport.wrap_outgoing_data(payload_bytes)
            writer.write(wrapped_payload)
            await writer.drain()
            status = True
        except Exception:
            # Connection failed, try S&F if enabled
            if enable_store_and_forward:
                await self.store_offline_message(user_id, payload_bytes)
                self.log_message.emit(f"Failed to connect to {user_id}. Message queued for offline delivery.")
                self.message_queued_for_offline.emit(user_id)
                return (True, True)  # Successfully queued for offline delivery
            else:
                status = False
        finally:
            if writer and not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            if status:
                self.message_sent_status.emit(status, user_id)
            return (status, False)  # Sent directly (or failed), not queued
    
    async def store_offline_message(self, recipient_id, encrypted_payload):
        """
        Store an encrypted message in the DHT for offline delivery.
        Uses a key format: "offline_msg_{recipient_id}_{timestamp}"
        """
        try:
            timestamp = int(time.time() * 1000)  # Millisecond precision
            message_id = f"offline_msg_{recipient_id}_{timestamp}"
            
            # Store the encrypted payload as base64 to ensure it's JSON-serializable
            message_data = {
                "recipient_id": recipient_id,
                "payload": base64.b64encode(encrypted_payload).decode(),
                "timestamp": timestamp
            }
            
            await self.kademlia_server.set(message_id, json.dumps(message_data))
            
            # Also maintain a list of offline message IDs for this recipient
            # This helps with efficient retrieval
            msg_list_key = f"offline_msgs_list_{recipient_id}"
            msg_list_str = await self.kademlia_server.get(msg_list_key)
            
            if msg_list_str:
                msg_list = json.loads(msg_list_str)
            else:
                msg_list = []
            
            msg_list.append(message_id)
            await self.kademlia_server.set(msg_list_key, json.dumps(msg_list))
            
            self.log_message.emit(f"Offline message stored with ID: {message_id}")
        except Exception as e:
            self.log_message.emit(f"Failed to store offline message: {e}")
    
    async def fetch_offline_messages(self, user_id):
        """
        Fetch all offline messages for the given user_id from the DHT.
        Returns a list of encrypted message payloads.
        """
        try:
            msg_list_key = f"offline_msgs_list_{user_id}"
            msg_list_str = await self.kademlia_server.get(msg_list_key)
            
            if not msg_list_str:
                return []
            
            msg_list = json.loads(msg_list_str)
            messages = []
            
            for message_id in msg_list:
                try:
                    message_data_str = await self.kademlia_server.get(message_id)
                    if message_data_str:
                        message_data = json.loads(message_data_str)
                        encrypted_payload = base64.b64decode(message_data['payload'])
                        timestamp = message_data.get('timestamp', 0)
                        messages.append({
                            'payload': encrypted_payload,
                            'timestamp': timestamp,
                            'message_id': message_id
                        })
                except Exception as e:
                    self.log_message.emit(f"Error fetching message {message_id}: {e}")
                    continue
            
            return messages
        except Exception as e:
            self.log_message.emit(f"Error fetching offline messages: {e}")
            return []
    
    async def delete_offline_message(self, message_id, user_id):
        """
        Delete an offline message from the DHT after successful retrieval.
        
        Note: Kademlia doesn't have native delete functionality. We remove the message 
        from the index list, and the actual message data will eventually expire from 
        the DHT based on the Kademlia TTL mechanism. This prevents the message from 
        being retrieved again while allowing DHT nodes to naturally expire old data.
        
        Implications:
        - Message payload data persists in DHT until TTL expiration (typically 1-3 hours)
        - This adds temporary storage overhead on DHT nodes
        - The message is not immediately accessible since it's removed from the index
        - Future enhancement: Implement explicit cleanup by overwriting with null data
        """
        try:
            msg_list_key = f"offline_msgs_list_{user_id}"
            msg_list_str = await self.kademlia_server.get(msg_list_key)
            
            if msg_list_str:
                msg_list = json.loads(msg_list_str)
                if message_id in msg_list:
                    msg_list.remove(message_id)
                    await self.kademlia_server.set(msg_list_key, json.dumps(msg_list))
                    self.log_message.emit(f"Deleted offline message: {message_id}")
        except Exception as e:
            self.log_message.emit(f"Error deleting offline message {message_id}: {e}")
    
    async def announce_peer_for_exchange(self, user_id, public_ip, public_port):
        """
        Announce this peer's DHT address to a peer exchange list.
        This allows other peers to discover bootstrap nodes beyond the initial invitation.
        """
        try:
            peer_exchange_key = "peer_exchange_list"
            peer_list_str = await self.kademlia_server.get(peer_exchange_key)
            
            if peer_list_str:
                peer_list = json.loads(peer_list_str)
            else:
                peer_list = []
            
            # Add this peer's info (with timestamp for potential cleanup)
            # Store address as a list for JSON compatibility
            peer_info = {
                "user_id": user_id,
                "address": [public_ip, public_port],
                "last_seen": int(time.time())
            }
            
            # Remove old entries for this user_id if they exist
            peer_list = [p for p in peer_list if p.get("user_id") != user_id]
            
            # Add current peer info
            peer_list.append(peer_info)
            
            # Limit the list size to avoid DHT storage issues
            if len(peer_list) > self.MAX_PEER_EXCHANGE_LIST_SIZE:
                # Sort by last_seen and keep the most recent peers
                peer_list.sort(key=lambda x: x.get("last_seen", 0), reverse=True)
                peer_list = peer_list[:self.MAX_PEER_EXCHANGE_LIST_SIZE]
            
            await self.kademlia_server.set(peer_exchange_key, json.dumps(peer_list))
            self.log_message.emit(f"Peer info announced for exchange.")
        except Exception as e:
            self.log_message.emit(f"Error announcing peer for exchange: {e}")
    
    async def discover_peers_from_exchange(self):
        """
        Discover additional bootstrap peers from the peer exchange list.
        Returns a list of (ip, port) tuples.
        """
        try:
            peer_exchange_key = "peer_exchange_list"
            peer_list_str = await self.kademlia_server.get(peer_exchange_key)
            
            if not peer_list_str:
                return []
            
            peer_list = json.loads(peer_list_str)
            
            # Filter out stale peers
            current_time = int(time.time())
            active_peers = []
            
            for peer_info in peer_list:
                last_seen = peer_info.get("last_seen", 0)
                if current_time - last_seen < self.PEER_TIMEOUT_SECONDS:
                    address = peer_info.get("address")
                    if address and isinstance(address, list) and len(address) == 2:
                        active_peers.append(tuple(address))
            
            self.log_message.emit(f"Discovered {len(active_peers)} peers from exchange list.")
            return active_peers
        except Exception as e:
            self.log_message.emit(f"Error discovering peers from exchange: {e}")
            return []
    
    async def initiate_file_transfer(self, recipient_id, file_path, file_name, file_size, file_hash):
        """
        Initiate a file transfer by sending a file_transfer_request message.
        Returns transfer_id if successful, None otherwise.
        """
        transfer_id = str(uuid.uuid4())
        
        # Calculate number of chunks
        num_chunks = (file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        
        # Store transfer state
        self.active_file_transfers[transfer_id] = {
            "type": "sending",
            "recipient_id": recipient_id,
            "file_path": file_path,
            "file_name": file_name,
            "file_size": file_size,
            "file_hash": file_hash,
            "num_chunks": num_chunks,
            "chunks_sent": 0,
            "paused": False,
            "cancelled": False
        }
        
        self.log_message.emit(f"Initiated file transfer: {file_name} ({file_size} bytes, {num_chunks} chunks)")
        return transfer_id
    
    async def send_file_chunk(self, transfer_id, chunk_index, chunk_data):
        """
        Send a file chunk. The chunk data is encrypted using the session key by the caller.
        Returns True if successful, False otherwise.
        """
        if transfer_id not in self.active_file_transfers:
            return False
        
        transfer_state = self.active_file_transfers[transfer_id]
        
        if transfer_state.get("paused") or transfer_state.get("cancelled"):
            return False
        
        # Update progress
        transfer_state["chunks_sent"] = chunk_index + 1
        bytes_sent = min((chunk_index + 1) * self.CHUNK_SIZE, transfer_state["file_size"])
        
        self.file_transfer_progress.emit(transfer_id, bytes_sent, transfer_state["file_size"])
        
        # Check if transfer is complete
        if transfer_state["chunks_sent"] >= transfer_state["num_chunks"]:
            self.file_transfer_complete.emit(transfer_id, True)
            del self.active_file_transfers[transfer_id]
        
        return True
    
    def receive_file_chunk(self, transfer_id, chunk_index, chunk_data):
        """
        Receive and store a file chunk.
        """
        if transfer_id not in self.pending_file_chunks:
            self.pending_file_chunks[transfer_id] = {}
        
        self.pending_file_chunks[transfer_id][chunk_index] = chunk_data
    
    def assemble_received_file(self, transfer_id, num_chunks):
        """
        Assemble all received chunks into the complete file data.
        Returns file bytes if all chunks received, None otherwise.
        """
        if transfer_id not in self.pending_file_chunks:
            return None
        
        chunks = self.pending_file_chunks[transfer_id]
        
        # Check if all chunks are present
        if len(chunks) != num_chunks:
            return None
        
        # Assemble chunks in order
        file_data = b""
        for i in range(num_chunks):
            if i not in chunks:
                return None
            file_data += chunks[i]
        
        # Clean up
        del self.pending_file_chunks[transfer_id]
        
        return file_data

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