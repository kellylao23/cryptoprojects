#python3

import re
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement, import_x25519_public_key
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Signature import eddsa
from siftprotocols.siftmtp import SiFT_MTP_Error


class SiFT_INIT_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)


class SiFT_INIT:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.size_random = 32
        self.size_ecdh_pubkey = 32
        self.size_server_pubkey = 44   # Ed25519 SubjectPublicKeyInfo (DER)
        self.size_signature = 64
        self.size_key = 32
        self.sig_label = b'SiFT v0.7 init_res'
        self.kdf_label = b'SiFT v0.7 MTP key'
        # hex field lengths of init_req and init_res
        self.init_req_fields = (2 * self.size_random, 2 * self.size_ecdh_pubkey)
        self.init_res_fields = (2 * self.size_random, 2 * self.size_ecdh_pubkey,
                                2 * self.size_server_pubkey, 2 * self.size_signature)
        # --------- STATE ------------
        self.mtp = mtp
        self.server_sigkey = None  # long-term Ed25519 private key (server only)


    # sets the server's long-term Ed25519 private key (to be used by the server)
    def set_server_sigkey(self, sigkey):
        if not sigkey.has_private() or sigkey.curve != 'Ed25519':
            raise SiFT_INIT_Error('Server key must be an Ed25519 private key')
        self.server_sigkey = sigkey


    # returns the DER (SubjectPublicKeyInfo) encoding of an Ed25519 public key
    @staticmethod
    def export_server_pubkey(key):
        return key.public_key().export_key(format='DER')


    # SHA-256 fingerprint of the DER-encoded server public key, as hex string
    @staticmethod
    def fingerprint(server_pubkey_der):
        return SHA256.new(server_pubkey_der).hexdigest()


    # splits a payload into fixed-length lowercase hex fields and decodes them
    def parse_hex_fields(self, payload, field_lengths):
        try:
            payload_str = payload.decode(self.coding)
        except UnicodeDecodeError:
            raise SiFT_INIT_Error('Init message is not valid UTF-8')
        fields = payload_str.split(self.delimiter)
        if len(fields) != len(field_lengths):
            raise SiFT_INIT_Error('Init message has wrong number of fields')
        values = []
        for field, length in zip(fields, field_lengths):
            if not re.fullmatch('[0-9a-f]{%d}' % length, field):
                raise SiFT_INIT_Error('Init message has a malformed field')
            values.append(bytes.fromhex(field))
        return values


    # builds an init request from a dictionary
    def build_init_req(self, init_req_struct):
        init_req_str = init_req_struct['client_random'].hex()
        init_req_str += self.delimiter + init_req_struct['client_ecdh_pubkey'].hex()
        return init_req_str.encode(self.coding)


    # parses an init request into a dictionary
    def parse_init_req(self, init_req):
        values = self.parse_hex_fields(init_req, self.init_req_fields)
        return {'client_random': values[0], 'client_ecdh_pubkey': values[1]}


    # builds the to-be-signed part of the init response (all fields but the signature)
    def build_init_res_tbs(self, init_res_struct):
        tbs_str = init_res_struct['server_random'].hex()
        tbs_str += self.delimiter + init_res_struct['server_ecdh_pubkey'].hex()
        tbs_str += self.delimiter + init_res_struct['server_pubkey'].hex()
        return tbs_str.encode(self.coding)


    # builds an init response from its to-be-signed part and the signature
    def build_init_res(self, init_res_tbs, signature):
        return init_res_tbs + (self.delimiter + signature.hex()).encode(self.coding)


    # parses an init response into a dictionary (also returns the to-be-signed part)
    def parse_init_res(self, init_res):
        values = self.parse_hex_fields(init_res, self.init_res_fields)
        return {
            'server_random': values[0],
            'server_ecdh_pubkey': values[1],
            'server_pubkey': values[2],
            'signature': values[3],
            'tbs': init_res[:init_res.rfind(self.delimiter.encode(self.coding))],
        }


    # computes the X25519 shared secret with the peer's raw public key
    def compute_shared_secret(self, own_ecdh_key, peer_ecdh_pubkey_raw):
        try:
            peer_key = import_x25519_public_key(peer_ecdh_pubkey_raw)
            z = key_agreement(static_priv=own_ecdh_key, static_pub=peer_key,
                              kdf=lambda x: x)
        except ValueError:
            raise SiFT_INIT_Error('Invalid ECDH public key received')
        if z == b'\x00' * len(z):
            raise SiFT_INIT_Error('ECDH shared secret is all-zero')
        return bytes(z)


    # derives the MTP key with HKDF-SHA256 as defined in the specification
    def derive_key(self, z, client_random, server_random, init_req, init_res):
        transcript_hash = SHA256.new(init_req + init_res).digest()
        return HKDF(z, self.size_key, client_random + server_random, SHA256,
                    context=self.kdf_label + transcript_hash)


    def _debug_payload(self, direction, payload):
        if self.DEBUG:
            print(direction + ' payload (' + str(len(payload)) + '):')
            print(payload.decode(self.coding, errors='replace'))
            print('------------------------------------------')


    # handles the init exchange (to be used by the server)
    def handle_init_server(self):

        if self.server_sigkey is None:
            raise SiFT_INIT_Error('Server signing key is required for handling init at server')

        # trying to receive an init request
        try:
            msg_type, init_req = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to receive init request --> ' + e.err_msg)

        self._debug_payload('Incoming', init_req)

        if msg_type != self.mtp.type_init_req:
            raise SiFT_INIT_Error('Init request expected, but received something else')

        init_req_struct = self.parse_init_req(init_req)

        # generating fresh randomness and ephemeral ECDH key pair
        server_random = get_random_bytes(self.size_random)
        ecdh_key = ECC.generate(curve='X25519')

        # building and signing the init response
        init_res_struct = {
            'server_random': server_random,
            'server_ecdh_pubkey': ecdh_key.public_key().export_key(format='raw'),
            'server_pubkey': self.export_server_pubkey(self.server_sigkey),
        }
        init_res_tbs = self.build_init_res_tbs(init_res_struct)
        signer = eddsa.new(self.server_sigkey, 'rfc8032')
        signature = signer.sign(self.sig_label + init_req + init_res_tbs)
        init_res = self.build_init_res(init_res_tbs, signature)

        self._debug_payload('Outgoing', init_res)

        # sending the init response
        try:
            self.mtp.send_msg(self.mtp.type_init_res, init_res)
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to send init response --> ' + e.err_msg)

        # deriving and installing the MTP key
        z = self.compute_shared_secret(ecdh_key, init_req_struct['client_ecdh_pubkey'])
        key = self.derive_key(z, init_req_struct['client_random'], server_random,
                              init_req, init_res)
        del ecdh_key, z
        self.mtp.set_key(key)

        if self.DEBUG:
            print('Init completed, MTP key installed')


    # handles the init exchange (to be used by the client)
    # accept_server_key is called with the fingerprint (hex string) of the
    # server's public key and must return True if the user accepts the key
    def handle_init_client(self, accept_server_key):

        # generating fresh randomness and ephemeral ECDH key pair
        client_random = get_random_bytes(self.size_random)
        ecdh_key = ECC.generate(curve='X25519')

        init_req_struct = {
            'client_random': client_random,
            'client_ecdh_pubkey': ecdh_key.public_key().export_key(format='raw'),
        }
        init_req = self.build_init_req(init_req_struct)

        self._debug_payload('Outgoing', init_req)

        # trying to send init request
        try:
            self.mtp.send_msg(self.mtp.type_init_req, init_req)
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to send init request --> ' + e.err_msg)

        # trying to receive an init response
        try:
            msg_type, init_res = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to receive init response --> ' + e.err_msg)

        self._debug_payload('Incoming', init_res)

        if msg_type != self.mtp.type_init_res:
            raise SiFT_INIT_Error('Init response expected, but received something else')

        init_res_struct = self.parse_init_res(init_res)

        # verifying the server's signature with the received public key
        try:
            server_pubkey = ECC.import_key(init_res_struct['server_pubkey'])
        except ValueError:
            raise SiFT_INIT_Error('Invalid server public key received')
        if server_pubkey.curve != 'Ed25519' or server_pubkey.has_private():
            raise SiFT_INIT_Error('Server public key is not an Ed25519 public key')
        verifier = eddsa.new(server_pubkey, 'rfc8032')
        try:
            verifier.verify(self.sig_label + init_req + init_res_struct['tbs'],
                            init_res_struct['signature'])
        except ValueError:
            raise SiFT_INIT_Error('Verification of server signature failed')

        # letting the user accept or reject the server key
        if not accept_server_key(self.fingerprint(init_res_struct['server_pubkey'])):
            raise SiFT_INIT_Error('Server public key rejected by user')

        # deriving and installing the MTP key
        z = self.compute_shared_secret(ecdh_key, init_res_struct['server_ecdh_pubkey'])
        key = self.derive_key(z, client_random, init_res_struct['server_random'],
                              init_req, init_res)
        del ecdh_key, z
        self.mtp.set_key(key)

        if self.DEBUG:
            print('Init completed, MTP key installed')
