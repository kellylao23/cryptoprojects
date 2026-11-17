#python3

# Generates a new long-term Ed25519 key pair for the SiFT v0.7 server.
# The private key is saved in encrypted PKCS#8 PEM format (scrypt + AES-256),
# protected by a passphrase; the public key is saved in an unencrypted PEM file.

import sys, getpass
from pathlib import Path
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256

base_dir = Path(__file__).resolve().parent
privkey_file = base_dir / 'server_privkey.pem'
pubkey_file = base_dir / 'server_pubkey.pem'

if __name__ == '__main__':
    if privkey_file.exists() and '--force' not in sys.argv:
        print(str(privkey_file) + ' already exists, use --force to overwrite it')
        sys.exit(1)

    passphrase = getpass.getpass('Passphrase for the private key: ')
    if passphrase != getpass.getpass('Repeat passphrase: '):
        print('Passphrases do not match')
        sys.exit(1)
    if not passphrase:
        print('Empty passphrase is not allowed')
        sys.exit(1)

    key = ECC.generate(curve='Ed25519')
    privkey_pem = key.export_key(format='PEM', passphrase=passphrase,
                                 protection='scryptAndAES256-CBC')
    pubkey_pem = key.public_key().export_key(format='PEM')

    with open(privkey_file, 'w') as f:
        f.write(privkey_pem)
    privkey_file.chmod(0o600)
    with open(pubkey_file, 'w') as f:
        f.write(pubkey_pem)

    fingerprint = SHA256.new(key.public_key().export_key(format='DER')).hexdigest()
    print('Private key saved to ' + str(privkey_file))
    print('Public key saved to ' + str(pubkey_file))
    print('Server key fingerprint (SHA-256): ' + fingerprint)
