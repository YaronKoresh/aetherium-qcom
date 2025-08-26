<div align="center">

# 🛡️ Aetherium Q-Com 🛡️

### _Decentralized, Untraceable, and Unblockable Communication_

<div>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
    </a>
    <a href="https://www.python.org/downloads/">
        <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python: 3.10+">
    </a>
    <a href="https://github.com/YaronKoresh/aetherium-qcom/">
        <img src="https://img.shields.io/badge/status-active-success.svg" alt="Status: Active">
    </a>
    <a href="https://en.wikipedia.org/wiki/Zero_trust_architecture">
        <img src="https://img.shields.io/badge/security-zero--trust-critical" alt="Security: Zero-Trust">
    </a>
    <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey" alt="Platform: Windows | Linux | macOS">
</div>
<div>
    <a href="https://github.com/YaronKoresh/aetherium-qcom/stargazers">
        <img src="https://img.shields.io/github/stars/YaronKoresh/aetherium-qcom.svg?style=social&label=Star" alt="GitHub stars">
    </a>
    <a href="https://github.com/YaronKoresh/aetherium-qcom/network/members">
        <img src="https://img.shields.io/github/forks/YaronKoresh/aetherium-qcom.svg?style=social&label=Fork" alt="GitHub forks">
    </a>
</div>

</div>

> A **zero-trust** communication platform engineered for truly private, censorship-resistant messaging. It establishes direct, peer-to-peer connections that are invisible to network monitoring and protected by a multi-layered AI security system.

---

## 💭 Core Philosophy

Aetherium Q-Com operates on a simple but powerful principle: **"Never Trust, Always Verify."**

It assumes all networks are hostile. There are no central servers to attack, monitor, or shut down. True security is achieved not just with strong encryption, but through a design that produces **no discernible footprint**. This allows it to operate undetected where other platforms are blocked, making it ideal for users facing sophisticated, state-level surveillance.

---

## ✨ Key Features

### 🔐 Zero-Trust Architecture
Every connection is treated as hostile until proven otherwise. Clients are forced to cryptographically prove their integrity before any communication is allowed.
* **Dynamic Integrity Proof (DIP)**: A real-time, interactive challenge that verifies the client's source code has not been tampered with. It's impossible to pass with a modified client.
* **Cryptographic Identity Binding**: Your unique hardware fingerprint is fused with the session's encryption keys, making identity spoofing nearly impossible even if a private key is stolen.
* **AI-Powered Trust Score**: A multi-layered AI security monitor analyzes every packet for suspicious behavior. If a client acts like a bot or sends malformed data, its trust score drops, and the connection is automatically terminated.

### 🖼️ Undetectable Invitations via Steganography
The platform avoids discoverable connection requests. Users create a **one-time visual invitation** by hiding encrypted connection data (IP, Public Key) invisibly within the pixels of an ordinary image or video file. This "invisible ink" method provides perfect plausible deniability.

### 🌐 Serverless & Unblockable
All communication is a **direct, end-to-end encrypted connection** between two peers. The network exists only in the transient connections between its users, making it a moving target that is impossible to centrally block or disrupt.

### 🔒 Quantum-Resistant Encryption
The core messaging system is based on the principles of the **One-Time Pad (OTP)**. Each session key, established via a secure Diffie-Hellman exchange, seeds a unique, single-use cryptographic stream, providing perfect forward secrecy against all known and future computational attacks.

---

## 🚀 Installation & Usage

Installation is handled by automated scripts for your operating system.

### 🪟 Windows

1.  **Install**: Download and run `install_aeterium.bat`. It will automatically request administrator privileges to install Python (if needed) and all required dependencies.
2.  **Run**: After installation, simply run `run_aeterium.bat` to launch the application.

### 🐧 Linux & 🍏 macOS

1.  **Make Scripts Executable**:
    ```sh
    chmod +x install_aeterium.sh
    chmod +x run_aeterium.sh
    ```
2.  **Install**:
    ```sh
    ./install_aeterium.sh
    ```
    The script will use your system's package manager (apt, dnf, brew, etc.) to install Python and all dependencies, requesting `sudo` permission when necessary.
3.  **Run**:
    ```sh
    ./run_aeterium.sh
    ```

---

## 🤝 How It Works: The Connection Flow

The platform is designed to be completely silent. To connect with a contact, you follow a simple, secure process:

1.  **Create Invitation (Host)**
    The user wishing to host a session selects any image or video file and enters a shared, secret passphrase. The application generates a new media file (`..._invite.png`) with the connection data (both public and private IPs) invisibly woven into its pixel structure.

2.  **Share Invitation**
    The host sends this single, innocent-looking file to their contact through any conventional channel (email, standard messaging app, etc.). The act of sharing is unremarkable.

3.  **Use Invitation (Connect)**
    The recipient loads the invitation file, enters the same secret passphrase, and clicks "Connect". The application **automatically determines the correct IP to use**. If the recipient's public IP matches the host's, it connects via the local IP; otherwise, it uses the public IP. A direct, secure, and fully authenticated P2P session is established.

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 🧑‍💻 Contributing

To report bugs or suggest enhancements, please search the open or closed issues before opening a new one.

