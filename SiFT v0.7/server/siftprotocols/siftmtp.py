#python3

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class SiFT_MTP_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg
        super().__init__(err_msg)


class SiFT_MTP:
    def __init__(self, peer_socket):

        self.DEBUG = True
        self.version_major = 0
        self.version_minor = 7
        self.msg_hdr_ver = b'\x00\x07'
        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2
        self.size_msg_mac = 12
        self.size_key = 32
        self.msg_types = (
            b'\x00\x00', b'\x00\x10', b'\x01\x00', b'\x01\x10',
            b'\x02\x00', b'\x02\x01', b'\x02\x10', b'\x03\x00',
            b'\x03\x10', b'\x03\x11', b'\x04\x00', b'\x04\x10',
        )
        (
            self.type_login_req, self.type_login_res,
            self.type_command_req, self.type_command_res,
            self.type_upload_req_0, self.type_upload_req_1,
            self.type_upload_res, self.type_dnload_req,
            self.type_dnload_res_0, self.type_dnload_res_1,
            self.type_init_req, self.type_init_res,
        ) = self.msg_types
        # Init messages are sent in cleartext without a mac, and only
        # before the key has been installed.
        self.init_types = (self.type_init_req, self.type_init_res)

        self.peer_socket = peer_socket
        self.key = None  # set by the Init Protocol via set_key()
        self.send_sequence = 0
        self.receive_sequence = 0

    # installs the key derived by the Init Protocol (can be done only once)
    def set_key(self, key):
        if self.key is not None:
            raise SiFT_MTP_Error('MTP key is already installed')
        if not isinstance(key, bytes) or len(key) != self.size_key:
            raise SiFT_MTP_Error('SiFT v0.7 requires a 256-bit AES key')
        self.key = key

    # returns True if a message of the given type is allowed in the current state
    def _type_allowed(self, msg_type):
        if self.key is None:
            return msg_type in self.init_types
        return msg_type in self.msg_types and msg_type not in self.init_types

    def parse_msg_header(self, msg_hdr):
        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error('Invalid message header length')
        return {
            'ver': msg_hdr[0:2],
            'typ': msg_hdr[2:4],
            'len': msg_hdr[4:6],
            'sqn': msg_hdr[6:8],
            'rnd': msg_hdr[8:14],
            'rsv': msg_hdr[14:16],
        }

    def receive_bytes(self, n):
        bytes_received = bytearray()
        while len(bytes_received) < n:
            try:
                chunk = self.peer_socket.recv(n - len(bytes_received))
            except OSError as e:
                raise SiFT_MTP_Error('Unable to receive via peer socket') from e
            if not chunk:
                raise SiFT_MTP_Error('Connection with peer is broken')
            bytes_received.extend(chunk)
        return bytes(bytes_received)

    def _close_and_raise(self, message):
        try:
            self.peer_socket.close()
        except OSError:
            pass
        raise SiFT_MTP_Error(message)

    def receive_msg(self):
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            self._close_and_raise(
                'Unable to receive message header --> ' + e.err_msg
            )

        parsed_msg_hdr = self.parse_msg_header(msg_hdr)
        msg_type = parsed_msg_hdr['typ']
        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            self._close_and_raise('Unsupported version found in message header')
        if msg_type not in self.msg_types:
            self._close_and_raise('Unknown message type found in message header')
        if not self._type_allowed(msg_type):
            self._close_and_raise('Message type not allowed in current state')
        if parsed_msg_hdr['rsv'] != b'\x00\x00':
            self._close_and_raise('Invalid reserved field in message header')

        is_init = msg_type in self.init_types
        msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
        min_len = self.size_msg_hdr + (0 if is_init else self.size_msg_mac)
        if msg_len < min_len:
            self._close_and_raise('Invalid message length in message header')

        sequence = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
        if is_init and sequence != 1:
            self._close_and_raise('Invalid message sequence number')
        if sequence <= self.receive_sequence:
            self._close_and_raise('Invalid message sequence number')

        try:
            msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            self._close_and_raise(
                'Unable to receive message body --> ' + e.err_msg
            )

        if is_init:
            # cleartext payload, protected by the Init Protocol itself
            msg_payload = msg_body
            encrypted_payload = mac = None
        else:
            encrypted_payload = msg_body[:-self.size_msg_mac]
            mac = msg_body[-self.size_msg_mac:]
            nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
            cipher = AES.new(
                self.key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac
            )
            cipher.update(msg_hdr)
            try:
                msg_payload = cipher.decrypt_and_verify(encrypted_payload, mac)
            except ValueError:
                self._close_and_raise('Message authentication failed')

        self.receive_sequence = sequence

        if self.DEBUG:
            print('MTP message received (' + str(msg_len) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            if is_init:
                print('PLD (' + str(len(msg_payload)) + '): ')
                print(msg_payload.hex())
            else:
                print('EPD (' + str(len(encrypted_payload)) + '): ')
                print(encrypted_payload.hex())
                print('MAC (' + str(len(mac)) + '): ' + mac.hex())
            print('------------------------------------------')

        return msg_type, msg_payload

    def send_bytes(self, bytes_to_send):
        try:
            self.peer_socket.sendall(bytes_to_send)
        except OSError as e:
            raise SiFT_MTP_Error('Unable to send via peer socket') from e

    def send_msg(self, msg_type, msg_payload):
        if msg_type not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type')
        if not self._type_allowed(msg_type):
            raise SiFT_MTP_Error('Message type not allowed in current state')
        if not isinstance(msg_payload, bytes):
            raise SiFT_MTP_Error('Message payload must be bytes')
        if self.send_sequence == 0xffff:
            self._close_and_raise('Message sequence number exhausted')

        is_init = msg_type in self.init_types
        sequence = self.send_sequence + 1
        random_value = get_random_bytes(self.size_msg_hdr_rnd)
        msg_size = (
            self.size_msg_hdr + len(msg_payload)
            + (0 if is_init else self.size_msg_mac)
        )
        if msg_size > 0xffff:
            raise SiFT_MTP_Error('Message exceeds maximum MTP length')

        sqn_bytes = sequence.to_bytes(self.size_msg_hdr_sqn, byteorder='big')
        msg_hdr = (
            self.msg_hdr_ver
            + msg_type
            + msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
            + sqn_bytes
            + random_value
            + b'\x00\x00'
        )

        if is_init:
            msg = msg_hdr + msg_payload
        else:
            nonce = sqn_bytes + random_value
            cipher = AES.new(
                self.key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac
            )
            cipher.update(msg_hdr)
            encrypted_payload, mac = cipher.encrypt_and_digest(msg_payload)
            msg = msg_hdr + encrypted_payload + mac

        if self.DEBUG:
            print('MTP message to send (' + str(msg_size) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            if is_init:
                print('PLD (' + str(len(msg_payload)) + '): ')
                print(msg_payload.hex())
            else:
                print('EPD (' + str(len(encrypted_payload)) + '): ')
                print(encrypted_payload.hex())
                print('MAC (' + str(len(mac)) + '): ' + mac.hex())
            print('------------------------------------------')

        try:
            self.send_bytes(msg)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error(
                'Unable to send message to peer --> ' + e.err_msg
            ) from e
        self.send_sequence = sequence
