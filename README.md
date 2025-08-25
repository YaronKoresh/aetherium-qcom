[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

# Aetherium Q-Com

Aetherium Q-Com is a decentralized and secure communication platform engineered for end-to-end encrypted messaging. It is built on a direct peer-to-peer (P2P) architecture, ensuring that all communication remains private and censorship-resistant without reliance on central servers.

**Author**: [Yaron Koresh](mailto:aharonkoresh1@gmail.com)

---

# Key Features

- Cryptographic Identity: Your username is a permanent, verifiable title derived from your unique private key, preventing spoofing.
- Dynamic Integrity Check: A pre-master key-based handshake verifies that all clients are running the same, unmodified code, protecting against compromised clients.
- Decentralized Discovery: The application utilizes a robust Kademlia-based Distributed Hash Table (DHT) for peer discovery, eliminating the need for a central registry or IP address sharing.
- Secure Messaging: All messages are encrypted with a One-Time Pad (OTP) using pre-shared keys, guaranteeing perfect secrecy.

---

# Usage

1. Launch: Run the script to start the application and its background discovery node.
2. Add Contact: Use a peer's public ID to add them to your contact list.
3. Connect: Select a contact, and the application will automatically discover their location on the network and establish a secure, private connection.

---

# License

This project is licensed under the **MIT** License.

---

## Contributing

- Before asking for support, please make sure you are using the [latest version](https://github.com/YaronKoresh/aetherium-qcom).
- To report bugs or suggest enhancements, please search the [open or closed issues](https://github.com/YaronKoresh/aetherium-qcom/issues?q=is%3Aissue) before opening a new one.
