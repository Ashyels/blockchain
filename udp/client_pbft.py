import json
import os
import sys
import csv
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import ast
import socket

class PBFTClient:

    def __init__(self):
        self.address = ''
        self.mem_temp = self.initiate_mem()
        self.privkey = ''
        self.pubkey = ''
        self.is_sending = False
        self.is_listening = True

    def initiate_mem(self):
        array = []
        return array

    def sign_msg(self, msg, privatekey):
        from Crypto.Signature import PKCS1_v1_5
        from Crypto.Hash import SHA

        hash = SHA.new(msg)
        privatekey_ready = self.import_key(privatekey)
        signer = PKCS1_v1_5.new(privatekey_ready)
        signature = signer.sign(hash)
        return signature

    def encapsulate_msg(self, msg):
        import base64
        return base64.b64encode(msg).decode()

    def send_msg(self, data, UDP_IP, UDP_PORT):
        import requests
        import json
        data = json.dumps(data)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data.encode(), (UDP_IP, UDP_PORT))

    def check_value(self, data):
        required = ['sender_id', 'transaction', 'signature']
        if not all(k in data for k in required):
            return 'Missing values'
        else:
            return 'No Missing values'

    def reveal_msg(self, msg):
        import base64
        return base64.b64decode(msg.encode())

    def decrypt_transaction(self, encrypted_transaction, privkey):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        import ast

        decryptor = PKCS1_OAEP.new(privkey)
        transaction = decryptor.decrypt(ast.literal_eval(str(encrypted_transaction))).decode()

        return transaction

    def authenticate_transaction(self, pubkey, signature, transaction):
        from Crypto.Signature import PKCS1_v1_5
        from Crypto.Hash import SHA

        verifier = PKCS1_v1_5.new(pubkey)
        new_hash = SHA.new(transaction.encode())

        if verifier.verify(new_hash, signature):
            return True
        else:
            return False

    def import_key(self, key):
        from Crypto.PublicKey import RSA
        return RSA.importKey(key)

    def clear_tempstorage(self, tempfile_name):
        with open(tempfile_name, 'w') as tx_tempfile:
            json.dump([], tx_tempfile)
            tx_tempfile.close()
        # print(tempfile_name, 'cleaned up')