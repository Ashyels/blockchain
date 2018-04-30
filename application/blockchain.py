import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request

import rsa


# from application.settings import TRIA, IFAN

class Blockchain:
    def __init__(self):
        # print(TRIA)
        self.current_transactions = [
            {
                "input": [],
                "output": [
                    {"txid": 1, "amount": 1000, "sender": None, "receiver" : "USER A"},
                    {"txid": 2, "amount": 1000, "sender": None, "receiver" : "USER B"}
                ]
            }
        ]

        self.privatekey = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDbMq0HKNLEDc3sRBKunmeVikqJdpDzyyL1XzLoqA0cbK0TcnZp\nMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuOxUUiX0g9vLk9qFz7q1/yqwHj\nz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3IwriF8VfrhGdlyvol9WwIDAQAB\nAoGASkjYPq7lDrAm80T2l9ry+8jMDd3yrcxP4pwKorIhD1r9JLQL0Qb3VyPxUI+n\nAAetLO9ERGZx+lgboVdVyr+dNKjnZVeQKnAi2rgEThjsm/t1ozg2WyM+iVFqMYsg\nkqZZMmXIR8YGMT6Qs2K5HBbNOpq6XqV3fwf2eq+gEs0VMrECQQDqa0KZVfQs0P6H\nRCQPAZUQuZYSD0efbnl8TbPPYEsTJ/ELSuRj9Q0TfZdHKRrtl7kOCbTFi9qLYk+4\n3DhgToyPAkEA72CwgkWyeEzvdaW3fuhPtkV2phHO0PgTissiGU0VmyI6b90LtKf2\nmcl7DNimzaEuEgRlgNKfp1qkEsklp0jAdQJBAJ8/OGIEQzlCzPZFMx3CnGpdOPaR\nzL0hBoSMIK+rIbUkuBpMyTSiXzyzX9ZmtTVckclYjKZ6qH9xzOivKdk64z8CQHPj\na5CmDXEQTh22zM8zyOOFXZuoo2ensk5PaYK2Pu+L8p6VdUVQy6JIWLovaRHEJnmy\nhzGGxqROzYAKwZ/rKMECQEjEgMb0ogIol93jfU3JNG3ToU7vP7rIvvMS9Bz0V2C6\nBeIepjSiAkZNFdSsiWXfO1OjyfBuOO313q9T2F5dtVA=\n-----END RSA PRIVATE KEY-----'
        self.publickey = b'-----BEGIN RSA PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbMq0HKNLEDc3sRBKunmeVikqJ\ndpDzyyL1XzLoqA0cbK0TcnZpMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuO\nxUUiX0g9vLk9qFz7q1/yqwHjz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3Iw\nriF8VfrhGdlyvol9WwIDAQAB\n-----END RSA PUBLIC KEY-----'
        self.chain = []
        # self.temp_file = node_identifier + '.son'
        self.servers = []
        self.nodes_ip = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
            self.nodes_ip.append(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
            self.nodes_ip.append(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def register_node_publickey(self, node_ip):
        import requests, json
        response = requests.get(f'http://{node_ip}/nodes/publickey')
        response_data = response.json()
        self.servers.append(response_data['publickey'])

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            print('valid block hash?', block['previous_hash'] != last_block['data_hash'])
            print('valid proof?', self.valid_proof(last_block['proof'], block['proof'], last_block['previous_hash']))
            print('index', current_index)
            # print(block['previous_hash'] != last_block['data_hash'])
            if block['previous_hash'] != last_block['data_hash']:
                return False

            # Check that the Proof of Work is correct
            # if not self.valid_proof(last_block['proof'], block['proof'], last_block['previous_hash']):
            #     return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        current_chain = None

        # We're only looking for chains longer than ours
        current_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            try :
                print(node)
            except:
                print('no node')


            if response.status_code == 200:
                new_length = response.json()['length']
                new_chain = response.json()['chain']
                print(new_length)
                print(current_length)
                # Check if the length is longer and the chain is valid
                print('valid? ', self.valid_chain(new_chain))
                if new_length > current_length and self.valid_chain(new_chain):
                    current_length = new_length
                    current_chain = new_chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if current_chain:
            self.chain = current_chain
            return True

        return False

    # def broadcast_block(self):
    #     neighbours = self.nodes
    #     for node in neighbours:
    #         # print(f'http://{node}/nodes/resolve')
    #         # try:
    #         #     response = requests.get(f'http://{node}/nodes/resolve')
    #         # except:
    #         #     print(response)
    #     return True

    def new_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'data_hash': self.hashData(len(self.chain) + 1, time(), self.current_transactions, previous_hash or self.hash(self.chain[-1])),
            'previous_hash': previous_hash or self.chain[-1]['data_hash'],
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def listUnspentInput(self, sender, receiver, amount):
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
        for input in input_list:
            total_input_amount = total_input_amount + input['amount']
        for output in output_list:
            total_output_amount = total_output_amount + output['amount']
        if total_input_amount > total_output_amount:
            selisish = total_input_amount - total_output_amount

            latest_txid = 0
            for output in output_list:
                latest_txid = output['txid']
            new_txid = latest_txid + 1
            output_list.append({"txid": new_txid, "amount": selisish, "sender": sender, "receiver" : sender})
        return output_list

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

    def multicast_preprepare_msg(self, transaction):
        import base64

        signature = self.sign_msg(transaction)
        encapsulated_signature = self.encapsulate_msg(signature)

        neighbours = self.nodes
        headers = {"Content-Type": "application/json"}
        counter = 0

        for index in range(len(self.nodes_ip)):
            encrypted_transaction = self.encrypt_msg(transaction, self.servers[index])
            encapsulated_transaction = self.encapsulate_msg(encrypted_transaction)
            data={'sender_id': self.publickey.decode(), 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
            print(self.nodes_ip[index])
            response = requests.post(f'http://{self.nodes_ip[index]}/transactions/preprepare', data=json.dumps(data), headers=headers)
            # import socket
            # ip, colon, port = self.nodes_ip[index].partition(':')
            # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # sock.sendto(json.dumps(data).encode(), (ip, int(port)))
            counter = counter + 1

        if counter == len(self.nodes_ip):
            response = 'message has been sent to all nodes'
            print(response)
            print('PREPREPARE DONE')
            return response
        else:
            response = 'there is malicious message'
            print(response)
            return response

    def multicast_prepare_msg(self, transaction):
        import base64
        import time
        # time.sleep(2)

        signature = self.sign_msg(transaction)
        encapsulated_signature = self.encapsulate_msg(signature)

        neighbours = self.nodes
        headers = {"Content-Type": "application/json"}
        counter = 0

        for index in range(len(self.nodes_ip)):
            encrypted_transaction = self.encrypt_msg(transaction, self.servers[index])
            encapsulated_transaction = self.encapsulate_msg(encrypted_transaction)
            data={'sender_id': self.publickey.decode(), 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
            response = requests.post(f'http://{self.nodes_ip[index]}/transactions/prepare', data=json.dumps(data), headers=headers)
            if response.status_code == 201:
                counter = counter + 1
        if counter == len(self.nodes_ip):
            response = 'message has been sent to all nodes'
            print(response)
            print('PREPARE DONE')
            return response
        else:
            response = 'there is malicious message'
            print(response)
            return response

    def multicast_commit_msg(self, transaction):
        import base64
        import time
        # time.sleep(2)

        signature = self.sign_msg(transaction)
        encapsulated_signature = self.encapsulate_msg(signature)

        neighbours = self.nodes
        headers = {"Content-Type": "application/json"}
        counter = 0

        for index in range(len(self.nodes_ip)):
            encrypted_transaction = self.encrypt_msg(transaction, self.servers[index])
            encapsulated_transaction = self.encapsulate_msg(encrypted_transaction)
            data={'sender_id': self.publickey.decode(), 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
            response = requests.post(f'http://{self.nodes_ip[index]}/transactions/commit', data=json.dumps(data), headers=headers)
            if response.status_code == 201:
                counter = counter + 1
        if counter == len(self.nodes_ip):
            response = 'message has been sent to all nodes'
            print(response)
            print('COMMIT DONE')
            return response
        else:
            response = 'there is malicious message'
            print(response)
            return response

    def new_transaction(self, sender, receiver, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param receiver: Address of the receiver
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """

        # get latest txid
        latest_txid = 0
        for outputlist in self.chain[len(self.chain)-1]['transactions']:
            for txid in outputlist['output']:
                latest_txid = txid['txid']
        new_txid = latest_txid + 1

        input_list = self.listUnspentInput(sender, receiver, amount)
        output_list = []
        output_list.append({"txid": new_txid, "amount": amount, "sender": sender, "receiver" : receiver})
        output_list = self.validate_transaction(input_list, output_list, sender)
        self.current_transactions.append(
            {
                "input": input_list,
                "output": output_list
            }
        )

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[len(self.chain)-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
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

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def test(self):        
        # import time
        (pubkey, privkey) = rsa.newkeys(512)
        message = 'Go left at the blue tree'
        encoded_message = message.encode('utf8')
        # time.sleep(5)
        encrypted_message = rsa.encrypt(encoded_message, pubkey)
        decrypted_message = rsa.decrypt(encrypted_message, privkey)
        decoded_message = decrypted_message.decode('utf8')
        print(decoded_message)

        signature = rsa.sign(encoded_message, privkey, 'SHA-1')
        print(encoded_message)
        print(signature)
        print(rsa.verify(encoded_message, signature, pubkey))
