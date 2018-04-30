### Module: Client for Blockchain Application
### Author: Ifan (141524011) on 25/4/2018

import requests, json, time, rsa
from threading import Thread
from random import randint

class BlockchainClient:
    def __init__(self):
        self.throughput_total = []
        self.latency_total = []

        client_total = 10
        client = []
        for i in range(client_total):
            client.append(Thread(target=self.transaction, args=(i,)))
        for i in range(client_total):
            client[i].start()
        for i in range(client_total):
            client[i].join()

        latency_total_average = sum(self.latency_total)/len(self.latency_total)
        throughput_total_average = sum(self.throughput_total)/len(self.throughput_total)
        print('latency total average:', latency_total_average, 'secs/ op')
        print('throughput total average:', throughput_total_average, 'ops/ sec')

    ### Method: Transaction activity by each client
    ### Author: Ifan (141524011) on 25/4/2018
    def transaction(self, i):
        # (pubkey, privkey) = rsa.newkeys(32)
        # message = 'Go left at the blue tree'
        # encoded_message = message.encode('utf8')
        # encrypted_message = rsa.encrypt(encoded_message, pubkey)
        # decrypted_message = rsa.decrypt(encrypted_message, privkey)
        # decoded_message = decrypted_message.decode('utf8')
        # signature = rsa.sign(encoded_message, privkey, 'SHA-1')
        # rsa.verify(encoded_message, signature, pubkey)

        start = time.time()
        total_operation = 0
        throughputs = []
        latencies = []
        for j in range(10):
            delay = randint(0,3)
            headers = {"Content-Type": "application/json", 'host': 'example.com'}
            data={'sender': 'sender', 'receiver': 'receiver', 'amount': 1}
            t0 = time.time()
            response = requests.post(f'http://127.0.0.1:5000/transactions/new', data=json.dumps(data), headers=headers)
            t1 = time.time()
            latencies.append(t1-t0)
            total_operation = total_operation + 1
            time.sleep(delay)
            if (time.time()-start) >= 1:
                start = time.time()
                throughputs.append(total_operation)
                total_operation = 0
        
        throughput_average = sum(throughputs)/len(throughputs)
        latency_average = sum(latencies)/len(latencies)
        self.throughput_total.append(throughput_average)
        self.latency_total.append(latency_average)