# aetherium_qcom/main.py
import sys
import os
import argparse

# Import core modules and handlers from the new structure
from .core.utils import CodeHasher
from .core.crypto import CryptoManager
from .cli.handlers import handle_keygen, handle_sign, handle_invite
from .cli.shell import InteractiveShell
from .gui.main_window import launch_gui

def handle_interactive(args):
    """Launches the interactive command shell."""
    InteractiveShell().cmdloop()

def main():
    """Main function to parse arguments and run the application."""
    
    # --- 1. Argument Parsing ---
    # We parse arguments first to see if a developer command is being run.
    parser = argparse.ArgumentParser(description="A secure, decentralized communication platform.", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest='command', help='commands')

    gui_parser = subparsers.add_parser('gui', help='Launch the graphical user interface (default).')
    gui_parser.set_defaults(func=launch_gui)

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

    # --- 2. Handle Developer Commands ---
    # If the command is keygen or sign, run it immediately and exit.
    # This BYPASSES the integrity check, allowing you to create the keys and signature.
    if args.command in ['keygen', 'sign']:
        print(f"Running developer command: {args.command}...")
        args.func(args)
        sys.exit(0)

    # --- 3. Code Integrity Check ---
    # This check now ONLY runs for regular user commands (gui, invite, etc.).
    print("Verifying code integrity...")
    try:
        root_dir = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.realpath(__file__)
        )))
        with open(os.path.join(root_dir, "dev_public.key"), "r") as f:
            dev_public_key = f.read()
        with open(os.path.join(root_dir, "code_signature.sig"), "r") as f:
            code_signature = f.read()
    except FileNotFoundError:
        print("FATAL: This client is not signed. dev_public.key or code_signature.sig not found.")
        sys.exit(1)

    # The hasher now correctly uses this file's path to find and hash all other source files.
    current_hash = CodeHasher.get_source_hash(__file__)
    if not current_hash or not CryptoManager.verify_hash_signature(dev_public_key, code_signature, current_hash):
        print("FATAL: CODE TAMPERING DETECTED OR SIGNATURE IS FOR A DIFFERENT VERSION. TERMINATING.")
        sys.exit(1)
    
    print("Integrity check passed.")

    # --- 4. Run User Command ---
    if hasattr(args, 'func'):
        args.func(args)
    else:
        # Default to GUI if no command is given
        launch_gui(None)

if __name__ == "__main__":
    main()