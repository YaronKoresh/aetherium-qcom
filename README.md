# Aetherium Q-Com

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

Aetherium Q-Com is a secure, fully decentralized communication platform featuring a novel, quantum-inspired key exchange protocol, an unchangeable cryptographic identity system, and a full suite of chaos-based tools for end-to-end encrypted messaging.

**Author:** [Yaron Koresh](mailto:aharonkoresh1@gmail.com)

---

## Table of Contents
- [Quick Install & Run](#quick-install--run)
- [Project Overview](#project-overview)
- [Core Concepts](#core-concepts)
- [Key Features](#key-features)
- [How It Works: The Secure Connection Protocol](#how-it-works-the-secure-connection-protocol)
- [Usage Guide](#usage-guide)
- [Offline Tools](#offline-tools)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Quick Install & Run

This is the easiest way to get started. These scripts will automatically install Python dependencies and the application itself.

### Windows
1.  Download the `run_aeterium.bat` file.
2.  Double-click the file to run it. A command prompt will open and install the necessary components from GitHub.
3.  Once complete, the application will launch automatically.

### macOS & Linux
1.  Download the `run_aeterium.sh` file.
2.  Open your terminal and navigate to the directory where you saved the file.
3.  Make the script executable by running: `chmod +x run_aeterium.sh`
4.  Execute the script: `./run_aeterium.sh`
5.  The script will install the dependencies and launch the application.

After the first installation, you can run the application anytime by simply typing `aetherium-qcom` in your terminal.

---

## Project Overview

Aetherium Q-Com is a decentralized, end-to-end encrypted communication platform built on three core principles: a **quantum-inspired key exchange** for initial secrecy, **chaos-based cryptography** for high-speed communication, and a **cryptographically-bound identity system** to prevent spoofing and ensure you always know who you're talking to.

Unlike traditional messaging apps, Aetherium uses a direct **peer-to-peer architecture**, meaning there are no central servers to intercept, log, or censor your messages. Every connection is authenticated at the deepest cryptographic level, making your identity an inseparable part of your security. The result is a self-contained, serverless communication ecosystem where security and identity are mathematically guaranteed, not promised.

---

## Core Concepts

### 1. Cryptographic Identity
Your identity in Aetherium is not just a name you choose; it's a permanent, unchangeable title generated directly from your secret cryptographic key. When you first run the app, a unique private key is created and saved locally. From this key, a Public ID and a unique, human-readable username (e.g., `bright-fox-5a7f`) are generated. This username is your permanent, tamper-proof identity. Any attempt to modify your client or impersonate another user will fail a cryptographic check, making communication impossible.

### 2. Quantum-Inspired Key Exchange
The platform simulates a quantum key distribution (QKD) protocol without requiring specialized quantum hardware. It establishes a secure channel by combining a classical Diffie-Hellman exchange with synchronized chaotic oscillators to generate quantum-style measurement bases. An AI-powered agent monitors the channel for statistical anomalies that would indicate an eavesdropping attempt, providing a high degree of confidence in the secrecy of the generated key.

### 3. Chaos-Based Cryptography
Once the secure key is established, all communication is encrypted using a fast and secure stream cipher derived from the synchronized state of a logistic map (a chaotic system). This provides robust, end-to-end encryption for all messages and tools within the application.

---

## Key Features

- **Fully Decentralized Architecture:** All communication is direct peer-to-peer (P2P). There are no central servers, ensuring privacy and censorship resistance.
- **Permanent, Key-Generated Identity:** Your username is algorithmically and unchangeably derived from your secret key, making it a verifiable and spoof-proof title.
- **Tamper-Proof Identity Verification:** The identity of your contact is cryptographically verified at the core of the connection protocol. Any mismatch between a user's key and their broadcasted username results in a failed connection.
- **Quantum-Inspired Key Exchange:** Utilizes a protocol simulating Bell State Measurements and synchronized chaotic systems to securely generate a shared cryptographic key.
- **AI-Powered Anomaly Detection:** An intelligent Bayesian defense system monitors channel statistics in real-time to detect and thwart man-in-the-middle attacks.
- **Full Suite of Offline Tools:** Includes standalone utilities for chaos-based file encryption/decryption and image steganography, using your cryptographic identity as the default key.

---

## How It Works: The Secure Connection Protocol

The key exchange and identity verification process is an integrated, multi-stage protocol that guarantees security and authenticity.

1.  **Phase 1: Initial Handshake & Identity Pre-Verification:**
    - User A initiates a connection to User B's IP address.
    - They exchange their Public IDs and their algorithmically generated usernames.
    - B's client immediately and independently generates the username that *should* belong to A's Public ID.
    - If the broadcasted username from A does not exactly match the generated username, the connection is instantly dropped. This prevents a modified client with a fake username from even starting the key exchange.

2.  **Phase 2: Quantum-Inspired Key Generation (QKD):**
    - The two peers perform a direct, simulated Quantum Key Distribution. This involves a Diffie-Hellman exchange to seed a pair of chaotic oscillators, followed by a simulated Bell State Measurement process to generate a shared, secret QKD key.

3.  **Phase 3: AI-Powered Channel Analysis:**
    - Throughout the QKD process, a Bayesian AI agent monitors the channel for statistical anomalies (Quantum Bit Error Rate, Signal-to-Noise Ratio, etc.) that could indicate an eavesdropping attempt. If the AI deems the channel insecure, the connection is aborted.

4.  **Phase 4: Identity-Bound Key Finalization:**
    - This is the most critical security step. The QKD key is **not** used directly for communication.
    - A final, master session key is created by cryptographically hashing a combined string containing: the QKD key, both users' Public IDs, both users' verified usernames, and **each user's own secret private key**.
    - This makes the final key intrinsically and inseparably bound to the verified identities of both participants.

5.  **Phase 5: Mutual Cryptographic Verification:**
    - Both users exchange a hash of this final, identity-bound key.
    - If the hashes match, it serves as a definitive cryptographic proof that both parties are who they claim to be and that no Man-in-the-Middle attacker is present.
    - Only after this final, successful verification is the connection considered secure and ready for communication.

---

## Usage Guide

Aetherium is a live platform requiring at least two users who have exchanged identity information beforehand.

1.  **Launch the Application:**
    - After following the **Quick Install** guide, open a new terminal (or Command Prompt) and run the command: `aetherium-qcom`
    - The application window will open.

2.  **Share Your Identity:**
    - Navigate to the **"Identity & Contacts"** tab.
    - Copy your **"Full Public ID"**.
    - Securely share this ID with the person you want to communicate with (e.g., over a different trusted channel).

3.  **Add a Contact:**
    - Once you have received your contact's Public ID, paste it into the **"Contact's Full Public ID"** field in the "Manage Contacts" section.
    - The application will automatically generate their unique, permanent username.
    - Click **"Add/Update Contact"** to save them to your contact list. You must do this before you can connect.

4.  **Connect to a Contact:**
    - Navigate to the **"Network & P2P"** tab.
    - Select your contact from the **"Select Contact to Connect"** dropdown menu.
    - Enter their current **IP Address**.
    - Click **"Connect Securely to Selected Contact"**. The application will perform the full secure protocol.

---

## Offline Tools

The **"Offline Tools"** tab provides standalone utilities that use the same core chaos-based cryptography engine.

- **Steganography:** Hide a secret text message within an image file. The tool produces a new image and a unique key required for extraction. This is useful for hiding information in plain sight.
- **Cryptography:** A simple tool to encrypt and decrypt text. By default, it uses your secure identity key, but you can provide any custom key or password for compatibility with others.

---

## Troubleshooting

- **Command not found:** If the `aetherium-qcom` command is not found after running the installation script, try closing and reopening your terminal. Your system's PATH may need to be refreshed. On Windows, you may need to restart your computer.
- **Firewall Issues:** For connections over the internet, both users may need to configure port forwarding on their routers to allow incoming traffic on port **65123**.

---

## Contributing

- Before asking for support, please make sure you are using the [latest version](https://github.com/YaronKoresh/aetherium-qcom).
- To report bugs or suggest enhancements, please search the [open or closed issues](https://github.com/YaronKoresh/aetherium-qcom/issues?q=is%3Aissue) before opening a new one.