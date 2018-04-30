from BlockchainClient import BlockchainClient
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('-c', '--client', default=0, type=int, help='client total: 25, 50, 100')
parser.add_argument('-r', '--request', default=0, type=int, help='request type: read-write (1), read-only (2)')
parser.add_argument('-e', '--exp', default=0, type=int, help='exp')
args = parser.parse_args()
client_total = args.client   
request_type = args.request
exp = args.exp

# BlockchainClient()

def sign_msg(msg, privatekey):
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA

    hash = SHA.new(msg)
    privatekey_ready = RSA.importKey(privatekey)
    signer = PKCS1_v1_5.new(privatekey_ready)
    signature = signer.sign(hash)
    return signature

def encapsulate_msg(msg):
    import base64
    return base64.b64encode(msg).decode()

def send_msg(decoded_pubkey, encapsulated_transaction, encapsulated_signature):
    # send the key and the data
    import requests
    import json
    headers = {"Content-Type": "application/json", 'host': 'example.com'}
    data={'sender_id': decoded_pubkey, 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
    # data={'pubkey': decoded_pubkey, 'data': decoded_msg, 'amount': 1}
    response = requests.post(f'http://127.0.0.1:5000/transactions/new', data=json.dumps(data), headers=headers)
    return response

if exp == 1:
    from Crypto.PublicKey import RSA
    from Crypto import Random
    from Crypto.Cipher import PKCS1_OAEP
    import ast

    privkey_1 = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDbMq0HKNLEDc3sRBKunmeVikqJdpDzyyL1XzLoqA0cbK0TcnZp\nMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuOxUUiX0g9vLk9qFz7q1/yqwHj\nz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3IwriF8VfrhGdlyvol9WwIDAQAB\nAoGASkjYPq7lDrAm80T2l9ry+8jMDd3yrcxP4pwKorIhD1r9JLQL0Qb3VyPxUI+n\nAAetLO9ERGZx+lgboVdVyr+dNKjnZVeQKnAi2rgEThjsm/t1ozg2WyM+iVFqMYsg\nkqZZMmXIR8YGMT6Qs2K5HBbNOpq6XqV3fwf2eq+gEs0VMrECQQDqa0KZVfQs0P6H\nRCQPAZUQuZYSD0efbnl8TbPPYEsTJ/ELSuRj9Q0TfZdHKRrtl7kOCbTFi9qLYk+4\n3DhgToyPAkEA72CwgkWyeEzvdaW3fuhPtkV2phHO0PgTissiGU0VmyI6b90LtKf2\nmcl7DNimzaEuEgRlgNKfp1qkEsklp0jAdQJBAJ8/OGIEQzlCzPZFMx3CnGpdOPaR\nzL0hBoSMIK+rIbUkuBpMyTSiXzyzX9ZmtTVckclYjKZ6qH9xzOivKdk64z8CQHPj\na5CmDXEQTh22zM8zyOOFXZuoo2ensk5PaYK2Pu+L8p6VdUVQy6JIWLovaRHEJnmy\nhzGGxqROzYAKwZ/rKMECQEjEgMb0ogIol93jfU3JNG3ToU7vP7rIvvMS9Bz0V2C6\nBeIepjSiAkZNFdSsiWXfO1OjyfBuOO313q9T2F5dtVA=\n-----END RSA PRIVATE KEY-----'
    pubkey_1 = b'-----BEGIN RSA PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbMq0HKNLEDc3sRBKunmeVikqJ\ndpDzyyL1XzLoqA0cbK0TcnZpMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuO\nxUUiX0g9vLk9qFz7q1/yqwHjz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3Iw\nriF8VfrhGdlyvol9WwIDAQAB\n-----END RSA PUBLIC KEY-----'
    privkey_2 = RSA.importKey(privkey_1)
    pubkey_2 = RSA.importKey(pubkey_1)
    exported_pubkey = pubkey_2.exportKey('PEM')
    exported_privkey = privkey_2.exportKey('PEM')
    decoded_pubkey = exported_pubkey.decode() # ready to send the msg using JSON format
    decoded_privkey = exported_privkey.decode() # ready to send the msg using JSON format

    import json
    msg = {'sender': 'asd', 'receiver': 'asd', 'amount': 1}
    msg = json.dumps(msg)
    msg = msg.encode()
    encryptor = PKCS1_OAEP.new(pubkey_2)
    encrypted = encryptor.encrypt(msg)

    import base64
    encapsulated_transaction = encapsulate_msg(encrypted)
    signature = sign_msg(msg, privkey_1)
    encapsulated_signature = encapsulate_msg(signature)
    response = send_msg(decoded_pubkey, encapsulated_transaction, encapsulated_signature)

elif exp == 2:
    import requests
    import json
    headers = {"Content-Type": "application/json", 'host': 'example.com'}
    data={
        "nodes": [
            "http://127.0.0.1:5001",
            "http://127.0.0.1:5002",
            "http://127.0.0.1:5003"
        ]
    }
    response = requests.post(f'http://127.0.0.1:5000/nodes/register', data=json.dumps(data), headers=headers)
    print(response)

elif exp == 3:
    import requests
    import json
    headers = {"Content-Type": "application/json", 'host': 'example.com'}
    nodes = [
        "http://127.0.0.1:5000",
        "http://127.0.0.1:5001",
        "http://127.0.0.1:5002",
        "http://127.0.0.1:5003"
    ]
    for index in range(len(nodes)):
        response = requests.get(f'{nodes[index]}/nodes/show', headers=headers)
        print(response)

elif exp == 4:
    import requests
    import json
    headers = {"Content-Type": "application/json", 'host': 'example.com'}
    nodes = [
        "http://127.0.0.1:5000",
        "http://127.0.0.1:5001",
        "http://127.0.0.1:5002",
        "http://127.0.0.1:5003"
    ]
    for index in range(len(nodes)):
        data = {}
        data['nodes'] = []
        for ip in nodes:
            if not ip == nodes[index]:
                data['nodes'].append(ip)
        # print(data)
        response = requests.post(f'{nodes[index]}/nodes/register', data=json.dumps(data), headers=headers)
        print(response)
