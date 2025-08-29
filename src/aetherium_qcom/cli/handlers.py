# aetherium_qcom/cli/handlers.py
import os
import sys
import json
import base64

# Import from the new core structure
from ..core.crypto import CryptoManager
from ..core.steganography import SteganographyManager
from ..core.utils import CodeHasher, get_free_ports, cwd


def load_cli_profile():
    with cwd():
        profile_path = "profile.json"
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

def handle_keygen(args=None):
    pk, sk = CryptoManager.generate_ephemeral_keys()
    with cwd():
        with open("../../../dev_public.key", "w") as f: f.write(pk)
        with open("../../../../dev_private.key", "w") as f: f.write(sk)
    print("--- GENERATED DEV MASTER KEYS ---\n")
    print("dev_public.key and dev_private.key files created.")
    print("KEEP dev_private.key ABSOLUTELY SECRET.")

def handle_sign(args=None):
    with cwd():
        if not os.path.exists("../../../../dev_private.key"):
            print("FATAL: dev_private.key not found. Run 'keygen' first.")
            sys.exit(1)
        with open("../../../../dev_private.key", "r") as f:
            dev_private_key = f.read()
    
    main_py_path = os.path.join(os.path.dirname(__file__), '..', '__main__.py')
    code_hash = CodeHasher.get_source_hash(main_py_path)
    
    if not code_hash:
        print("Could not generate code hash for signing.")
        sys.exit(1)
    signature = CryptoManager.sign_hash(dev_private_key, code_hash)
    if not signature:
        print("Could not sign code hash.")
        sys.exit(1)
    with cwd():
        with open("../../../code_signature.sig", "w") as f: f.write(signature)
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