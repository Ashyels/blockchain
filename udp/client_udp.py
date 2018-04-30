import json
import os
import sys
import csv

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import ast

from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('-c', '--client', default=0, type=int, help='client total: 25, 50, 100')
parser.add_argument('-r', '--request', default=0, type=int, help='request type: read-write (1), read-only (2)')
parser.add_argument('-p', '--port', default=0, type=int, help='port')
args = parser.parse_args()
client_total = args.client   
request_type = args.request
port = args.port

import socket

def get_server_info():
    nodes = [
        "127.0.0.1:5000",
        "127.0.0.1:5001",
        "127.0.0.1:5002",
        "127.0.0.1:5003"
    ]

    pubkeys = []
    for index in range(len(nodes)):
        keys = []
        ip, colon, temp_port = nodes[index].partition(':')
        with open('keys/key_' + str(temp_port), 'r') as tx_tempfile:
            keys = json.load(tx_tempfile)
            tx_tempfile.close()
        # print(keys[1].encode())
        pubkeys.append(keys[1].encode())# get pubkey not private key
    return nodes, pubkeys 

def get_dataset(client_address):
    dataset = []
    with open('dataset.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['ip_address'] == client_address:
                data = { 'ad': row['ip_address'], 's': row['sender_id'], 'r': row['receiver_id'], 'am': row['amount'], 'm': row['music_id'] }
                dataset.append(data)
    return dataset
 
def get_total_client():
    clients = []
    with open('dataset.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['ip_address'] not in clients:
                clients.append(row['ip_address'])
    return clients

def sign_msg(msg, privatekey):
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA

    hash = SHA.new(msg)
    privatekey_ready = import_key(privatekey)
    signer = PKCS1_v1_5.new(privatekey_ready)
    signature = signer.sign(hash)
    return signature

def encapsulate_msg(msg):
    import base64
    return base64.b64encode(msg).decode()

def send_msg(data, UDP_IP, UDP_PORT):
    # send the key and the data
    import requests
    import json
    data = json.dumps(data)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data.encode(), (UDP_IP, UDP_PORT))

def send_request_handler(client_address, privkey):
    public_key = privkey.publickey()
    dataset = get_dataset(client_address)
    
    exported_pubkey = public_key.exportKey('PEM')
    decoded_pubkey = exported_pubkey.decode() # ready to send the msg using JSON format

    global json
    for each_data in dataset:
        msg = each_data
        msg = json.dumps(msg)
        msg = msg.encode()
        prim_pubkey = import_key(pubkeys[0])
        encryptor = PKCS1_OAEP.new(prim_pubkey)
        encrypted = encryptor.encrypt(msg)

        encapsulated_transaction = encapsulate_msg(encrypted)
        signature = sign_msg(msg, privkey.exportKey())
        encapsulated_signature = encapsulate_msg(signature)

        ip, colon, port = nodes[0].partition(':')
        UDP_IP = ip
        UDP_PORT = int(port)
        data = {'client_pubkey': decoded_pubkey, 'sender_address': client_address,'sender_id': decoded_pubkey, 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
        data['route'] = 'transaction/request'
        send_msg(data, UDP_IP, UDP_PORT)
        print('message from', client_address, 'has sent')

def get_request_handler(client_address, privkey, reply_tempfile):
    public_key = privkey.publickey()
    ip, colon, port = client_address.partition(':')

    import socket
    UDP_IP = ip
    UDP_PORT = int(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print('client', client_address, 'running', '...')

    def listen(i):
        while True:
            data, addr = sock.recvfrom(1500) # buffer size is 1500 bytes
            data = data.decode()
            data = json.loads(data)
            # print(data)
            threads.append(Thread(target=reply_phase(data, client_address, privkey, reply_tempfile), args=(len(threads),)))
            threads[len(threads)-1].daemon = True
            threads[len(threads)-1].start()

    threads.append(Thread(target=listen, args=(len(threads),)))
    threads[len(threads)-1].daemon = True
    threads[len(threads)-1].start()

def check_value(data):
    required = ['sender_id', 'transaction', 'signature']
    if not all(k in data for k in required):
        return 'Missing values'
    else:
        return 'No Missing values'

def reveal_msg(msg):
    import base64
    return base64.b64decode(msg.encode())

def decrypt_transaction(encrypted_transaction, privkey):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    import ast

    # privatekey_ready = RSA.importKey(privkey)
    decryptor = PKCS1_OAEP.new(privkey)
    transaction = decryptor.decrypt(ast.literal_eval(str(encrypted_transaction))).decode()

    return transaction

def authenticate_transaction(pubkey, signature, transaction):
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA

    verifier = PKCS1_v1_5.new(pubkey)
    new_hash = SHA.new(transaction.encode())

    if verifier.verify(new_hash, signature):
        return True
    else:
        return False

def import_key(key):
    from Crypto.PublicKey import RSA
    return RSA.importKey(key)

def reply_phase(data, client_address, privkey, reply_tempfile):
    check_value(data)
    sender_pubkey = import_key(data['sender_id'])
    signature = reveal_msg(data['signature'])
    encrypted_transaction = reveal_msg(data['transaction'])
    transaction = decrypt_transaction(encrypted_transaction, privkey)

    authenticated = authenticate_transaction(sender_pubkey, signature, transaction)
    if authenticated:
        print(client_address, 'reply', 'message authenticated')
        consisting_transactions = []
        with open(reply_tempfile, 'r') as tx_tempfile:
            consisting_transactions = json.load(tx_tempfile)
            tx_tempfile.close()
        with open(reply_tempfile, 'w') as tx_tempfile:
            consisting_transactions.append(transaction)
            json.dump(consisting_transactions, tx_tempfile)
            tx_tempfile.close()
        total_recv_msg = 4 # len(blockchain.serv_addrs)
        print('prepare', len(consisting_transactions), total_recv_msg)
        if len(consisting_transactions) == total_recv_msg:
            for consisting_transaction in consisting_transactions:
                if consisting_transaction == transaction:
                    clear_tempstorage(reply_tempfile)
                    print(client_address, 'start listening to music ...')
                    break
    else:
        print(client_address, 'reply', 'message not authenticated')

def clear_tempstorage(tempfile_name):
    with open(tempfile_name, 'w') as tx_tempfile:
        consisting_transactions = []
        json.dump([], tx_tempfile)
        tx_tempfile.close()
    print(tempfile_name, 'cleaned up')

def register_node():
    import requests
    import json
    for index in range(len(nodes)):
        data = {}
        data['nodes'] = []
        data['pubkeys'] = []
        data['route'] = 'node/register'
        for index_2 in range(len(nodes)):
            if not nodes[index_2] == nodes[index]:
                data['nodes'].append(nodes[index_2])
                data['pubkeys'].append(pubkeys[index_2].decode())
        ip, colon, port = nodes[index].partition(':')
        send_msg(data, ip, int(port))

def start_client(client_address):
    random_generator = Random.new().read
    privkey = RSA.generate(1024, random_generator)
    ip, colon, port = client_address.partition(':')
    reply_tempfile = 'temp/client/' + port + '_REPLY' + '.temp'
    with open(reply_tempfile, 'w+') as tx_tempfile:
        json.dump([], tx_tempfile)
        tx_tempfile.close()

    threads.append(Thread(target=get_request_handler(client_address, privkey, reply_tempfile), args=(len(threads),)))
    threads[len(threads)-1].daemon = True
    threads[len(threads)-1].start()
    threads.append(Thread(target=send_request_handler(client_address, privkey), args=(len(threads),)))
    threads[len(threads)-1].daemon = True
    threads[len(threads)-1].start()

def keyb_input_handler(i):
    while True:
        input_id = input("")
        if input_id == '0':
            exit()
        elif input_id == '1':
            privkey_1 = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDbMq0HKNLEDc3sRBKunmeVikqJdpDzyyL1XzLoqA0cbK0TcnZp\nMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuOxUUiX0g9vLk9qFz7q1/yqwHj\nz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3IwriF8VfrhGdlyvol9WwIDAQAB\nAoGASkjYPq7lDrAm80T2l9ry+8jMDd3yrcxP4pwKorIhD1r9JLQL0Qb3VyPxUI+n\nAAetLO9ERGZx+lgboVdVyr+dNKjnZVeQKnAi2rgEThjsm/t1ozg2WyM+iVFqMYsg\nkqZZMmXIR8YGMT6Qs2K5HBbNOpq6XqV3fwf2eq+gEs0VMrECQQDqa0KZVfQs0P6H\nRCQPAZUQuZYSD0efbnl8TbPPYEsTJ/ELSuRj9Q0TfZdHKRrtl7kOCbTFi9qLYk+4\n3DhgToyPAkEA72CwgkWyeEzvdaW3fuhPtkV2phHO0PgTissiGU0VmyI6b90LtKf2\nmcl7DNimzaEuEgRlgNKfp1qkEsklp0jAdQJBAJ8/OGIEQzlCzPZFMx3CnGpdOPaR\nzL0hBoSMIK+rIbUkuBpMyTSiXzyzX9ZmtTVckclYjKZ6qH9xzOivKdk64z8CQHPj\na5CmDXEQTh22zM8zyOOFXZuoo2ensk5PaYK2Pu+L8p6VdUVQy6JIWLovaRHEJnmy\nhzGGxqROzYAKwZ/rKMECQEjEgMb0ogIol93jfU3JNG3ToU7vP7rIvvMS9Bz0V2C6\nBeIepjSiAkZNFdSsiWXfO1OjyfBuOO313q9T2F5dtVA=\n-----END RSA PRIVATE KEY-----'
            pubkey_1 = b'-----BEGIN RSA PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbMq0HKNLEDc3sRBKunmeVikqJ\ndpDzyyL1XzLoqA0cbK0TcnZpMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuO\nxUUiX0g9vLk9qFz7q1/yqwHjz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3Iw\nriF8VfrhGdlyvol9WwIDAQAB\n-----END RSA PUBLIC KEY-----'
            privkey_2 = RSA.importKey(privkey_1)
            pubkey_2 = RSA.importKey(pubkey_1)
            exported_pubkey = pubkey_2.exportKey('PEM')
            exported_privkey = privkey_2.exportKey('PEM')
            decoded_pubkey = exported_pubkey.decode() # ready to send the msg using JSON format
            decoded_privkey = exported_privkey.decode() # ready to send the msg using JSON format

            global json
            msg = {'sender': 'USER B', 'receiver': 'USER A', 'amount': 200}
            msg = json.dumps(msg)
            msg = msg.encode()
            prim_pubkey = RSA.importKey(pubkeys[0])
            encryptor = PKCS1_OAEP.new(prim_pubkey)
            encrypted = encryptor.encrypt(msg)

            encapsulated_transaction = encapsulate_msg(encrypted)
            signature = sign_msg(msg, privkey_1)
            encapsulated_signature = encapsulate_msg(signature)

            UDP_IP = "127.0.0.1"
            UDP_PORT = 5000
            data = {'sender_id': decoded_pubkey, 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
            data['route'] = 'transaction/request'
            send_msg(data, UDP_IP, UDP_PORT)

        elif input_id == '2':
            register_node()
        elif input_id == '3':
            data = {}
            data['route'] = 'chain'
            for index in range(len(nodes)):
                ip, colon, port = nodes[index].partition(':')
                send_msg(data, ip, int(port))
        # elif input_id == '4':
        #     get_dataset()

privatekey = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDbMq0HKNLEDc3sRBKunmeVikqJdpDzyyL1XzLoqA0cbK0TcnZp\nMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuOxUUiX0g9vLk9qFz7q1/yqwHj\nz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3IwriF8VfrhGdlyvol9WwIDAQAB\nAoGASkjYPq7lDrAm80T2l9ry+8jMDd3yrcxP4pwKorIhD1r9JLQL0Qb3VyPxUI+n\nAAetLO9ERGZx+lgboVdVyr+dNKjnZVeQKnAi2rgEThjsm/t1ozg2WyM+iVFqMYsg\nkqZZMmXIR8YGMT6Qs2K5HBbNOpq6XqV3fwf2eq+gEs0VMrECQQDqa0KZVfQs0P6H\nRCQPAZUQuZYSD0efbnl8TbPPYEsTJ/ELSuRj9Q0TfZdHKRrtl7kOCbTFi9qLYk+4\n3DhgToyPAkEA72CwgkWyeEzvdaW3fuhPtkV2phHO0PgTissiGU0VmyI6b90LtKf2\nmcl7DNimzaEuEgRlgNKfp1qkEsklp0jAdQJBAJ8/OGIEQzlCzPZFMx3CnGpdOPaR\nzL0hBoSMIK+rIbUkuBpMyTSiXzyzX9ZmtTVckclYjKZ6qH9xzOivKdk64z8CQHPj\na5CmDXEQTh22zM8zyOOFXZuoo2ensk5PaYK2Pu+L8p6VdUVQy6JIWLovaRHEJnmy\nhzGGxqROzYAKwZ/rKMECQEjEgMb0ogIol93jfU3JNG3ToU7vP7rIvvMS9Bz0V2C6\nBeIepjSiAkZNFdSsiWXfO1OjyfBuOO313q9T2F5dtVA=\n-----END RSA PRIVATE KEY-----'
publickey = b'-----BEGIN RSA PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbMq0HKNLEDc3sRBKunmeVikqJ\ndpDzyyL1XzLoqA0cbK0TcnZpMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuO\nxUUiX0g9vLk9qFz7q1/yqwHjz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3Iw\nriF8VfrhGdlyvol9WwIDAQAB\n-----END RSA PUBLIC KEY-----'

nodes, pubkeys = get_server_info()

client_address_dataset = get_total_client()

from threading import Thread
threads = []
threads.append(Thread(target=keyb_input_handler, args=(0,)))
threads[0].daemon = False
threads[0].start()
# register_node()

for thread_index in range(0, len(client_address_dataset)):
    threads.append(Thread(target=start_client(client_address_dataset[thread_index]), args=(len(threads),)))
    threads[len(threads)-1].daemon = True
    threads[len(threads)-1].start()

