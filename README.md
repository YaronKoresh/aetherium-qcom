<div align="center">

# Aetherium Q-Com

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

</div>

> A decentralized, serverless, and secure communication platform engineered for truly private, censorship-resistant messaging in the most hostile digital environments.

---

## **Core Philosophy**

Aetherium Q-Com is built on a direct peer-to-peer (P2P) architecture, ensuring that all communication is invisible to network monitoring and free from any central point of failure. The project's philosophy is that true security is achieved not just through strong encryption, but through a design that produces **no discernible or suspicious footprint**. This allows it to operate undetected where other platforms would be blocked, making it ideal for users facing sophisticated, state-level surveillance where the very act of using an identifiable encryption tool can attract unwanted attention.

**Author**: [Yaron Koresh](mailto:aharonkoresh1@gmail.com)

---

## **Key Features**

### 🛡️ **Cryptographic Identity**

Your identity is not just a username; it's a cryptographic proof. It is mathematically derived from a **unique hardware fingerprint** of your machine, creating a permanent and verifiable identity that cannot be spoofed or stolen without physical access to your device. This provides a strong guarantee of non-repudiation and authenticity for every message sent.

### 🖼️ **Stealth Connection via Steganography**

The platform's core innovation is its connection method, which completely avoids discoverable network traffic. Users create a **one-time visual invitation** by hiding connection data (IP, Public Key) invisibly within the pixels of an ordinary image file. This process uses content-aware steganography, where a shared secret passphrase and the unique hash of the image itself generate a secret, pseudo-random map of pixel locations for embedding data. This makes the connection request itself indistinguishable from sending a photo to a friend, providing perfect plausible deniability.

### 🌐 **Serverless P2P Architecture**

There are no central servers to attack, monitor, or shut down. All communication is a **direct, end-to-end encrypted connection** between two peers. This makes the network incredibly resilient and unblockable by design. Unlike centralized or federated messaging apps, Aetherium Q-Com's network exists only in the transient connections between its users, making it a moving target that is nearly impossible to disrupt.

### 🔒 **Quantum-Resistant OTP Encryption**

The core messaging system uses the `QuantumSentryCryptography` algorithm, based on the principles of the **One-Time Pad (OTP)**. Each session key, securely established via a Diffie-Hellman exchange, is used to seed a cryptographically secure stream generator. This stream acts as a unique, single-use OTP for the session, providing perfect forward secrecy and ensuring that messages are information-theoretically secure against all known and future computational attacks, including those from quantum computers.

### 겹 **Multi-Layered Security**

Security is a comprehensive strategy built in layers:

* **Authenticated Handshake**: Connections are established using an authenticated Diffie-Hellman exchange, protected by **RSA-2048 digital signatures** to prevent Man-in-the-Middle (MitM) attacks.

* **Anti-Replay Protection**: Every request includes a **unique nonce and a precise timestamp**. The receiving client will instantly reject any request that is more than a few seconds old or uses a repeated nonce, rendering captured data useless.

* **AI Anomaly Detection**: A background process monitors the timing and frequency of incoming messages to detect anomalies, such as a burst of messages sent faster than a human could type, flagging potential bot activity.

---

## **How It Works: The "Invisible Ink" Method**

The platform is designed to be completely silent. To connect with a contact, you follow a simple, secure process that mimics ordinary digital behavior:

1.  **Create Invitation (Host)**
    The user wishing to host a session selects any image file from their computer and enters a shared, secret passphrase. The application then generates a new image file (`invitation_...png`) with the connection data invisibly woven into its pixel structure.

2.  **Share Invitation**
    The host sends this single, innocent-looking image file to their contact through any existing, conventional channel (email, a standard messaging app, etc.). The act of sharing is unremarkable and blends in with the billions of images shared online every day.

3.  **Use Invitation (Connect)**
    The recipient loads the invitation image into their application and enters the same secret passphrase. The application extracts the hidden data and establishes a direct, secure, and fully authenticated P2P connection. The invitation image has served its one-time purpose and cannot be reused.

---

## **License**

This project is licensed under the **MIT License**.

---

## **Contributing**

* Before asking for support, please make sure you are using the latest version.

* To report bugs or suggest enhancements, please search the open or closed issues before opening a new one.
