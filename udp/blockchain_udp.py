import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request
from database_controller import *
import rsa
import pprint

class Blockchain:
    def __init__(self):
        # print(TRIA)
        self.current_transactions = []
        self.node_status = 'backup'
        self.privatekey = ''
        self.publickey = ''
        self.chain = []
        self.serv_pubkeys = []       # Save servers public key
        self.serv_addrs = []    # Save servers address
        self.database = ''

    def initial_transaction(self, client_total):
        output = []
        for client in range(1, client_total+1):
            receiver = 'U' + str(client)
            tx = {"txid": client, "amount": 1000, "sender": None, "receiver" : receiver}
            output.append(tx)

        self.current_transactions = [
            {
                "input": [],
                "output": output
            }
        ]

    def set_keys(self, port):
        keys = []
        with open('keys/key_' + str(port), 'r') as tx_tempfile:
            keys = json.load(tx_tempfile)
            tx_tempfile.close()
        self.privatekey = keys[0].encode()
        self.publickey = keys[1].encode()
        print('Keys registered')
        # print(self.privatekey, self.publickey)

    def set_database(self, port):
        self.port = port
        self.database = DatabaseController(port)
        self.new_block(previous_hash='1') # Create the genesis block

    def register_node(self, data):
        addresses = data['nodes']
        pubkeys = data['pubkeys']
        if addresses is None:
            print("Error: Please supply a valid list of nodes")
        for index in range(len(addresses)):
            self.serv_pubkeys.append(pubkeys[index].encode())
            parsed_url = urlparse(addresses[index])
            if parsed_url.netloc:
                self.serv_addrs.append(parsed_url.netloc)
            elif parsed_url.path:
                self.serv_addrs.append(parsed_url.path)
            else:
                raise ValueError('Invalid URL')
        print('Registered', len(self.serv_addrs), 'node addresses and', len(self.serv_pubkeys), 'node public keys')
        # print(self.serv_pubkeys)

    def new_block(self, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'data_hash': self.hashData(len(self.chain) + 1, time(), self.current_transactions, previous_hash or self.hash(self.chain[-1])),
            'previous_hash': previous_hash or self.chain[-1]['data_hash'],
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        self.database.insert_data(block)
        return block

    def list_unspent_input(self, sender, receiver, amount):
        account = sender
        outputList = []
        inputTxIDList = []
        outputTxIDList = []
        for block in self.chain:
            for transaction in block['transactions']:
                for tx_input in transaction['input']:
                    if tx_input['receiver'] == account:
                        inputTxIDList.append(tx_input['txid'])
                for tx_output in transaction['output']:
                    if tx_output['receiver'] == account:
                        outputList.append(tx_output)
                        outputTxIDList.append(tx_output['txid'])

        UnspentInputTxIDList = [val for val in outputTxIDList if val not in inputTxIDList]
        UnspentInputList = []
        for tx in outputList:
            for tx_id in UnspentInputTxIDList:
                if tx_id == tx['txid']:
                    UnspentInputList.append(tx)
        return UnspentInputList

    def reveal_msg(self, msg):
        import base64
        return base64.b64decode(msg.encode())

    def encapsulate_msg(self, msg):
        import base64
        msg = base64.b64encode(msg)
        decoded_msg = msg.decode()
        return decoded_msg

    def decrypt_transaction(self, encrypted_transaction):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        import ast

        privatekey_ready = RSA.importKey(self.privatekey)
        decryptor = PKCS1_OAEP.new(privatekey_ready)
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

    def validate_transaction(self, input_list, output_list, sender):
        total_input_amount = 0
        total_output_amount = 0
        validated = False
        for input in input_list:
            total_input_amount = total_input_amount + input['amount']
        for output in output_list:
            total_output_amount = total_output_amount + output['amount']
        if total_input_amount >= total_output_amount:
            selisish = total_input_amount - total_output_amount

            latest_txid = 0
            for output in output_list:
                latest_txid = output['txid']
            new_txid = latest_txid + 1
            if selisish > 0:
                output_list.append({"txid": new_txid, "amount": selisish, "sender": sender, "receiver" : sender})
            validated = True

        return validated, output_list

    def encrypt_msg(self, msg, pubkey):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        pubkey_ready = RSA.importKey(pubkey)
        encryptor = PKCS1_OAEP.new(pubkey_ready)
        encrypted_msg = encryptor.encrypt(msg.encode())        
        return encrypted_msg

    def sign_msg(self, msg):
        from Crypto.Signature import PKCS1_v1_5
        from Crypto.Hash import SHA
        from Crypto.PublicKey import RSA

        hash = SHA.new(msg.encode())
        privatekey_ready = RSA.importKey(self.privatekey)
        signer = PKCS1_v1_5.new(privatekey_ready)
        signature = signer.sign(hash)
        return signature

    def new_transaction(self, transaction):
        latest_txid = 0
        for outputlist in self.chain[len(self.chain)-1]['transactions']:
            for txid in outputlist['output']:
                latest_txid = txid['txid']
        new_txid = latest_txid + 1
        input_list = self.list_unspent_input(transaction['s'], transaction['r'], int(transaction['am']))
        output_list = []
        output_list.append({"txid": new_txid, "amount": int(transaction['am']), "sender": transaction['s'], "receiver" : transaction['r'], "music": transaction['m']})
        validated, output_list = self.validate_transaction(input_list, output_list, transaction['s'])
        if validated:
            self.current_transactions.append(
                {
                    "input": input_list,
                    "output": output_list
                }
            )
        return validated

    def send_msg(self, data, UDP_IP, UDP_PORT):
        import requests
        import json
        import socket

        data = json.dumps(data)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data.encode(), (UDP_IP, int(UDP_PORT)))

    @property
    def last_block(self):
        return self.chain[len(self.chain)-1]

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def hashData(index, timestamp, transactions, previous_hash):
        block = {
            'index': index,
            'timestamp': timestamp,
            'transactions': transactions,
            'previous_hash': previous_hash
        }
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine(self):
        last_block = self.last_block
        previous_hash = self.chain[-1]['data_hash']
        block = self.new_block(previous_hash)

        response = {
            'message': "New Block Forged",
            'index': block['index'],
            'transactions': block['transactions'],
            'previous_hash': block['previous_hash'],
        }
        pprint.pprint(response)

    def check_value(self, data):
        required = ['sender_id', 'transaction', 'signature']
        if not all(k in data for k in required):
            print('Missing values ...')

    def open_msg(self, data):
        client_pubkey = data['client_pubkey']
        sender_address = data['sender_address']
        sender_pubkey = self.import_key(data['sender_id'])
        signature = self.reveal_msg(data['signature'])
        encrypted_transaction = self.reveal_msg(data['transaction'])
        transaction = self.decrypt_transaction(encrypted_transaction)
        return client_pubkey, sender_address, sender_pubkey, signature, transaction

    def execute_transaction(self, transaction):
        transaction = json.loads(transaction)
        done = self.new_transaction(transaction)
        if done:
            self.mine()
        else:
            print('Transaction is invalid')

    def import_key(self, key):
        from Crypto.PublicKey import RSA
        return RSA.importKey(key)

