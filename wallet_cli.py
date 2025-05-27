from wallet import Wallet
import argparse

parser = argparse.ArgumentParser(description="Simple wallet CLI")
parser.add_argument('command', choices=['create'], help='Command')
args = parser.parse_args()

if args.command == 'create':
    wallet = Wallet()
    print('Public Key:', wallet.get_public_key())
    print('Address:', wallet.get_address())
