# aetherium_qcom/cli/shell.py
import cmd
import shlex
import argparse

# Import handlers from the same cli package
from .handlers import handle_keygen, handle_sign, handle_invite

class InteractiveShell(cmd.Cmd):
    intro = 'Welcome to the Aetherium Q-Com interactive shell. Type help or ? to list commands.\n'
    prompt = 'Aetherium> '

    def do_exit(self, arg):
        'Exit the interactive shell.'
        print('Goodbye.')
        return True

    def do_keygen(self, arg):
        'Generate new developer master keys.'
        handle_keygen(None)

    def do_sign(self, arg):
        'Sign the application source code.'
        handle_sign(None)

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
            # Argparse calls SystemExit on --help or error, so we catch it
            pass
        except Exception as e:
            print(f"Error: {e}")