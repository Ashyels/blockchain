import json, os, sys, csv, ast, socket

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from argparse import ArgumentParser

# if client_type == 'pbft':
#     from client_pbft import *
#     client = PBFTClient()
# elif client_type == 'sbft':
#     from client_sbft import *
#     client = SBFTClient()

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
    tx_dataset = []
    delay_dataset = []
    with open(dataset_name) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['ip_address'] == client_address:
                if request_type == 1:
                    data = {'request_type': 1, 'sender': row['sender_id'], 'receiver': row['receiver_id'], 'amount': row['amount'], 'music': row['music_id'] }
                elif request_type == 2:
                    data = {'request_type': 2, 'sender': row['sender_id'] }
                delay_dataset.append(int(row['delay']))
                tx_dataset.append(data)
    return tx_dataset, delay_dataset
 
def get_total_client():
    clients = []
    with open(dataset_name) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['ip_address'] not in clients:
                clients.append(row['ip_address'])
    return clients

def register_node(nodes):
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
        UDP_IP, COLON, UDP_PORT = nodes[index].partition(':')

        data = json.dumps(data)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data.encode(), (UDP_IP, int(UDP_PORT)))

def start_client(thread_number):
    if client_type == 'pbft':
        client_thread = PBFTClient()
    elif client_type == 'sbft':
        client_thread = SBFTClient()
    # client_thread = client
    client_thread.privkey = RSA.generate(1024, Random.new().read)
    client_thread.pubkey = client_thread.privkey.publickey()
    client_thread.address = client_address_dataset[thread_number-1]
    ip, colon, port = client_thread.address.partition(':')

    print(client_thread.address, 'started ...')

    def get_request_handler_inner(thread_number):
        UDP_IP = ip
        UDP_PORT = int(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((UDP_IP, UDP_PORT))

        def listen(thread_number):
            while client_thread.is_listening:
                data, addr = sock.recvfrom(1500) # buffer size is 1500 bytes
                data = data.decode()
                data = json.loads(data)

                def reply_phase_inner(thread_number):
                    client_thread.check_value(data)
                    sender_pubkey = client_thread.import_key(data['sender_id'])
                    signature = client_thread.reveal_msg(data['signature'])
                    encrypted_transaction = client_thread.reveal_msg(data['transaction'])
                    transaction = client_thread.decrypt_transaction(encrypted_transaction, client_thread.privkey)

                    authenticated = client_thread.authenticate_transaction(sender_pubkey, signature, transaction)
                    if authenticated:
                        # print(client_address, 'reply', 'message authenticated')
                        client_thread.mem_temp.append(transaction)
                        total_recv_msg = len(nodes)
                        # print(client_thread.address,'get', len(client_thread.mem_temp), 'packets')
                        if len(client_thread.mem_temp) == total_recv_msg:
                            for consisting_transaction in client_thread.mem_temp:
                                if consisting_transaction == transaction:
                                    # client_thread.clear_tempstorage(reply_tempfile)
                                    client_thread.mem_temp = []
                                    pure_transaction = json.loads(transaction)
                                    print(pure_transaction)
                                    if request_type == 1:
                                        # print(client_thread.address, 'start listening to music', pure_transaction['music'], '...')
                                        print(client_thread.address, 'start listening to music', '...')
                                    elif request_type == 2:
                                        print(client_thread.address, 'get his account balances:', pure_transaction['balances'])
                                    client_thread.is_sending = False
                                    break
                    else:
                        print(client_thread.address, 'reply', 'message not authenticated')

                reply_phase_inner(thread_number)
                # threads.append(Thread(target=reply_phase_inner, args=(len(threads),)))
                # threads[len(threads)-1].daemon = True
                # threads[len(threads)-1].start()
        listen(thread_number)
        # threads.append(Thread(target=listen, args=(len(threads),)))
        # threads[len(threads)-1].daemon = True
        # threads[len(threads)-1].start()
        # print('i am', client_thread.address, 'get_handler using thread', thread_number)

    def send_request_handler_inner(thread_number):
        global json
        import time

        tx_dataset, delay_dataset = get_dataset(client_thread.address)
        
        exported_pubkey = client_thread.pubkey.exportKey('PEM')
        decoded_pubkey = exported_pubkey.decode() # ready to send the msg using JSON format

        client_latencies = []
        throughput_start_time = time.time()
        lost_packets = 0
        for dataset_index in range(0, len(tx_dataset)):
            # time.sleep(1)
            latency_start_time = time.time()
            time.sleep(delay_dataset[dataset_index])
            pure_msg = tx_dataset[dataset_index]
            msg = json.dumps(pure_msg)
            msg = msg.encode()
            prim_pubkey = client_thread.import_key(pubkeys[0])
            encryptor = PKCS1_OAEP.new(prim_pubkey)
            encrypted = encryptor.encrypt(msg)
            # print('i am', client_thread.address, 'send_handler using thread', thread_number)

            encapsulated_transaction = client_thread.encapsulate_msg(encrypted)
            signature = client_thread.sign_msg(msg, client_thread.privkey.exportKey())
            encapsulated_signature = client_thread.encapsulate_msg(signature)

            ip, colon, port = nodes[0].partition(':')
            UDP_IP = ip
            UDP_PORT = int(port)
            data = {'client_pubkey': decoded_pubkey, 'sender_address': client_thread.address,'sender_id': decoded_pubkey, 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
            data['route'] = 'transaction/request'

            client_thread.send_msg(data, UDP_IP, UDP_PORT)
            client_thread.is_sending = True

            if request_type == 1:
                print(client_thread.address, 'has sent streaming request for music', pure_msg['music'])
            elif request_type == 2:
                print(client_thread.address, 'has sent balance request')

            counter_time = time.time()
            counter_time_2 = time.time()
            while client_thread.is_sending:
                if time.time()-counter_time >= 20:
                    print(client_thread.address, 'has lost the packet!')
                    lost_packets = lost_packets + 1
                    client_thread.mem_temp = []
                    client_thread.send_msg(data, UDP_IP, UDP_PORT)
                    # print(client_thread.address, 'has RESENT streaming request for music', pure_msg['music'])
                    counter_time = time.time()
                    # break
                if time.time()-counter_time_2 >= 1:
                    # print(client_address, 'request still processed ...')
                    counter_time_2 = time.time()
            latency_end_time = time.time()
            client_latencies.append(latency_end_time - latency_start_time)

        throughput_end_time = time.time()
        pure_throughput = throughput_end_time - throughput_start_time
        throughput = len(tx_dataset)/pure_throughput
        latency = sum(client_latencies)/len(client_latencies)
        total_client_data = []
        with open('throughput_latency.csv') as csvfile:
             reader = csv.DictReader(csvfile)
             for row in reader:
                client_data = {'client_address': row['client_address'], 'latency': row['latency'], 'throughput': row['throughput']}
                total_client_data.append(client_data)

        current_client_data = {'client_address': client_thread.address, 'latency': latency, 'throughput': throughput}
        total_client_data.append(current_client_data)

        with open('throughput_latency.csv', 'w+', newline='') as csvfile:
            fieldnames = ['client_address', 'latency', 'throughput']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for client_data in total_client_data:
                writer.writerow(client_data)

        print(client_thread.address, 'DONE.', 'Packet lost =', lost_packets)
        client_thread.is_listening = False

    threads.append(Thread(target=get_request_handler_inner, args=(len(threads),)))
    threads[len(threads)-1].daemon = True
    threads[len(threads)-1].start()
    sender_thread_index = len(threads)
    threads.append(Thread(target=send_request_handler_inner, args=(len(threads),)))
    threads[len(threads)-1].daemon = True
    threads[len(threads)-1].start()
    threads[sender_thread_index].join()


def show_results():
    throughputs = []
    latencies = []
    with open('throughput_latency.csv') as csvfile:
         reader = csv.DictReader(csvfile)
         for row in reader:
            latencies.append(float(row['latency']))
            throughputs.append(float(row['throughput']))
    total_average_latency = sum(latencies)/len(latencies)
    total_average_throughput = sum(throughputs)/len(throughputs)
    print('Total Average Latency:', total_average_latency, 'secs/ op')
    print('Total Average Throughput:', total_average_throughput, 'ops/ sec')

# def keyb_input_handler(thread_number):
#     # print('start keyb input')
#     while are_clients_running:
#         input_id = input("")
#         if input_id == '0':
#             print('PROGRAM CLOSED!')
#             exit()
#         elif input_id == '1':
#             privkey_1 = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDbMq0HKNLEDc3sRBKunmeVikqJdpDzyyL1XzLoqA0cbK0TcnZp\nMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuOxUUiX0g9vLk9qFz7q1/yqwHj\nz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3IwriF8VfrhGdlyvol9WwIDAQAB\nAoGASkjYPq7lDrAm80T2l9ry+8jMDd3yrcxP4pwKorIhD1r9JLQL0Qb3VyPxUI+n\nAAetLO9ERGZx+lgboVdVyr+dNKjnZVeQKnAi2rgEThjsm/t1ozg2WyM+iVFqMYsg\nkqZZMmXIR8YGMT6Qs2K5HBbNOpq6XqV3fwf2eq+gEs0VMrECQQDqa0KZVfQs0P6H\nRCQPAZUQuZYSD0efbnl8TbPPYEsTJ/ELSuRj9Q0TfZdHKRrtl7kOCbTFi9qLYk+4\n3DhgToyPAkEA72CwgkWyeEzvdaW3fuhPtkV2phHO0PgTissiGU0VmyI6b90LtKf2\nmcl7DNimzaEuEgRlgNKfp1qkEsklp0jAdQJBAJ8/OGIEQzlCzPZFMx3CnGpdOPaR\nzL0hBoSMIK+rIbUkuBpMyTSiXzyzX9ZmtTVckclYjKZ6qH9xzOivKdk64z8CQHPj\na5CmDXEQTh22zM8zyOOFXZuoo2ensk5PaYK2Pu+L8p6VdUVQy6JIWLovaRHEJnmy\nhzGGxqROzYAKwZ/rKMECQEjEgMb0ogIol93jfU3JNG3ToU7vP7rIvvMS9Bz0V2C6\nBeIepjSiAkZNFdSsiWXfO1OjyfBuOO313q9T2F5dtVA=\n-----END RSA PRIVATE KEY-----'
#             pubkey_1 = b'-----BEGIN RSA PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbMq0HKNLEDc3sRBKunmeVikqJ\ndpDzyyL1XzLoqA0cbK0TcnZpMsoO1nD2xFuPw6l3oB1dgodUDRIRI6cKabgWBeuO\nxUUiX0g9vLk9qFz7q1/yqwHjz47sMElZdnPb0NgLbRQhaMpICWsmAizxnFjNB3Iw\nriF8VfrhGdlyvol9WwIDAQAB\n-----END RSA PUBLIC KEY-----'
#             privkey_2 = RSA.importKey(privkey_1)
#             pubkey_2 = RSA.importKey(pubkey_1)
#             exported_pubkey = pubkey_2.exportKey('PEM')
#             exported_privkey = privkey_2.exportKey('PEM')
#             decoded_pubkey = exported_pubkey.decode() # ready to send the msg using JSON format
#             decoded_privkey = exported_privkey.decode() # ready to send the msg using JSON format

#             global json
#             msg = {'sender': 'USER B', 'receiver': 'USER A', 'amount': 200}
#             msg = json.dumps(msg)
#             msg = msg.encode()
#             prim_pubkey = RSA.importKey(pubkeys[0])
#             encryptor = PKCS1_OAEP.new(prim_pubkey)
#             encrypted = encryptor.encrypt(msg)

#             encapsulated_transaction = client.encapsulate_msg(encrypted)
#             signature = client.sign_msg(msg, privkey_1)
#             encapsulated_signature = client.encapsulate_msg(signature)

#             UDP_IP = "127.0.0.1"
#             UDP_PORT = 5000
#             data = {'sender_id': decoded_pubkey, 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
#             data['route'] = 'transaction/request'
#             client.send_msg(data, UDP_IP, UDP_PORT)
#         elif input_id == '2':
#             register_node()
#         elif input_id == '3':
#             data = {}
#             data['route'] = 'chain'
#             for index in range(len(nodes)):
#                 UDP_IP, COLON, UDP_PORT = nodes[index].partition(':')
#                 data = json.dumps(data)
#                 sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#                 sock.sendto(data.encode(), (UDP_IP, int(UDP_PORT)))
#         elif input_id == '4':
#             show_results()

# ======================================================================

parser = ArgumentParser() # inpurt: "py client_udp.py -r 1 -t pbft"
parser.add_argument('-r', '--request', default=0, type=int, help='request type: read-write (1), read-only (2)')
parser.add_argument('-t', '--type', default='pbft', type=str, help='Client Type')
parser.add_argument('-c', '--client', default=10, type=int, help='Total Client')
args = parser.parse_args()
request_type = args.request
client_type = args.type
client_total = args.client

if request_type == 1:
    dataset_name = 'dataset_rw_' + str(client_total) + '.csv'
elif request_type == 2:
    dataset_name = 'dataset_ro_' + str(client_total) + '.csv'

if client_type == 'pbft':
    from client_pbft import *
elif client_type == 'sbft':
    from client_sbft import *

nodes, pubkeys = get_server_info()
client_address_dataset = get_total_client()

is_register = input("wanna register the server nodes? [y/n] ")
if is_register == 'y':
    register_node(nodes)


print(len(client_address_dataset), 'clients in', client_type, 'consensus running using request', request_type)

with open('throughput_latency.csv', 'w+', newline='') as csvfile:
    fieldnames = ['client_address', 'latency', 'throughput']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

from threading import Thread
threads = []
# threads.append(Thread(target=keyb_input_handler, args=(0,)))
# are_clients_running = True
# threads[0].daemon = False
# threads[0].start()

last_thread = len(threads)
thread_index_dataset = []
for thread_index in range(0, len(client_address_dataset)):
    next_thread =  last_thread + thread_index
    thread_index_dataset.append(next_thread)
    threads.append(Thread(target=start_client, args=(next_thread,)))
    threads[next_thread].daemon = True

for thread_index in thread_index_dataset:
    threads[thread_index].start()

for thread_index in thread_index_dataset:
    threads[thread_index].join()

print('Experiment Done!')
show_results()
# print('Experiment Done! Give input \'4\' to get the result!')