from blockchain_udp import *

blockchain = Blockchain()

class PBFTConsensus():
    def __init__(self):
        self.prepare_tempfile = ''
        self.commit_tempfile = ''

    def set_tempfile(self, filename):
        self.prepare_tempfile = 'temp/' + filename + '_PREPARE' +'.temp'
        self.commit_tempfile = 'temp/' + filename +  '_COMMIT' + '.temp'
        with open(self.prepare_tempfile, 'w+') as tx_tempfile:
            json.dump([], tx_tempfile)
            tx_tempfile.close()
        with open(self.commit_tempfile, 'w+') as tx_tempfile:
            json.dump([], tx_tempfile)
            tx_tempfile.close()


    def commit_phase(self, data):
        blockchain.check_value(data)
        client_pubkey, sender_address, sender_pubkey, signature, transaction = blockchain.open_msg(data)
        authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
        if authenticated:
            print('commit', 'message authenticated')
            consisting_transactions = []
            with open(self.commit_tempfile, 'r') as tx_tempfile:
                consisting_transactions = json.load(tx_tempfile)
                tx_tempfile.close()
            with open(self.commit_tempfile, 'w') as tx_tempfile:
                consisting_transactions.append(transaction)
                json.dump(consisting_transactions, tx_tempfile)
                tx_tempfile.close()
            print('commit', len(consisting_transactions), len(blockchain.serv_addrs))
            if len(consisting_transactions) == len(blockchain.serv_addrs):
                for consisting_transaction in consisting_transactions:
                    if consisting_transaction == transaction:
                        blockchain.execute_transaction(transaction)
                        self.clear_tempstorage(self.commit_tempfile)
                        print('multicast reply msg')
                        response = self.multicast_reply_msg(sender_address, transaction, client_pubkey)
                        break
        else:
            print('message not authenticated')
            
    def prepare_phase(self, data):
        blockchain.check_value(data)
        client_pubkey, sender_address, sender_pubkey, signature, transaction = blockchain.open_msg(data)
        authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
        if authenticated:
            print('prepare', 'message authenticated')
            consisting_transactions = []
            with open(self.prepare_tempfile, 'r') as tx_tempfile:
                consisting_transactions = json.load(tx_tempfile)
                tx_tempfile.close()
            with open(self.prepare_tempfile, 'w') as tx_tempfile:
                consisting_transactions.append(transaction)
                json.dump(consisting_transactions, tx_tempfile)
                tx_tempfile.close()
            if blockchain.node_status == 'primary':
                total_recv_msg = len(blockchain.serv_addrs)
            else:
                total_recv_msg = len(blockchain.serv_addrs)-1
            print('prepare', len(consisting_transactions), total_recv_msg)
            if len(consisting_transactions) == total_recv_msg:
                for consisting_transaction in consisting_transactions:
                    if consisting_transaction == transaction:
                        self.clear_tempstorage(self.prepare_tempfile)
                        print('multicast commit msg')
                        response = self.multicast_commit_msg(sender_address, transaction, client_pubkey)
                        break
        else:
            print('message not authenticated')

    def preprepare_phase(self, data):
        blockchain.check_value(data)
        client_pubkey, sender_address, sender_pubkey, signature, transaction = blockchain.open_msg(data)
        authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
        if authenticated:
            print('preprepare', 'message authenticated')
            print('multicast prepare msg')
            response = self.multicast_prepare_msg(sender_address, transaction, client_pubkey)
        else:
            print('message not authenticated')

    def request_phase(self, data):
        blockchain.check_value(data)
        # print(data)
        client_pubkey, sender_address, sender_pubkey, signature, transaction = blockchain.open_msg(data)
        authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
        if authenticated:
            print('request', 'message authenticated')
            print('multicast preprepare msg')
            response = self.multicast_preprepare_msg(sender_address, transaction, client_pubkey)
        else:
            print('message not authenticated')

    def multicast_preprepare_msg(self, sender_address, transaction, client_pubkey):
        print(blockchain.serv_addrs)
        import base64
        signature = blockchain.sign_msg(transaction)
        encapsulated_signature = blockchain.encapsulate_msg(signature)
        for index in range(len(blockchain.serv_addrs)):
            encrypted_transaction = blockchain.encrypt_msg(transaction, blockchain.serv_pubkeys[index])
            encapsulated_transaction = blockchain.encapsulate_msg(encrypted_transaction)
            data={'client_pubkey': client_pubkey, 'sender_address': sender_address,'sender_id': blockchain.publickey.decode(), 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
            data['route'] = 'transaction/preprepare'
            ip, colon, port = blockchain.serv_addrs[index].partition(':')
            blockchain.send_msg(data, ip, int(port))
        print('PREPREPARE DONE')

    def multicast_prepare_msg(self, sender_address, transaction, client_pubkey):
        import base64
        signature = blockchain.sign_msg(transaction)
        encapsulated_signature = blockchain.encapsulate_msg(signature)
        for index in range(len(blockchain.serv_addrs)):
            encrypted_transaction = blockchain.encrypt_msg(transaction, blockchain.serv_pubkeys[index])
            encapsulated_transaction = blockchain.encapsulate_msg(encrypted_transaction)
            data={'client_pubkey': client_pubkey, 'sender_address': sender_address,'sender_id': blockchain.publickey.decode(), 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
            data['route'] = 'transaction/prepare'
            ip, colon, port = blockchain.serv_addrs[index].partition(':')
            blockchain.send_msg(data, ip, int(port))
        print('PREPARE DONE')

    def multicast_commit_msg(self, sender_address, transaction, client_pubkey):
        import base64
        signature = blockchain.sign_msg(transaction)
        encapsulated_signature = blockchain.encapsulate_msg(signature)
        for index in range(len(blockchain.serv_addrs)):
            encrypted_transaction = blockchain.encrypt_msg(transaction, blockchain.serv_pubkeys[index])
            encapsulated_transaction = blockchain.encapsulate_msg(encrypted_transaction)
            data={'client_pubkey': client_pubkey, 'sender_address': sender_address,'sender_id': blockchain.publickey.decode(), 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
            data['route'] = 'transaction/commit'
            ip, colon, port = blockchain.serv_addrs[index].partition(':')
            blockchain.send_msg(data, ip, int(port))
        print('COMMIT DONE')

    def multicast_reply_msg(self, sender_address, transaction, client_pubkey):
        import base64
        signature = blockchain.sign_msg(transaction)
        encapsulated_signature = blockchain.encapsulate_msg(signature)

        # client_pubkey = client_pubkey.exportKey('PEM')
        encrypted_transaction = blockchain.encrypt_msg(transaction, client_pubkey)
        encapsulated_transaction = blockchain.encapsulate_msg(encrypted_transaction)
        data={'client_pubkey': client_pubkey, 'sender_address': sender_address,'sender_id': blockchain.publickey.decode(), 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
        data['route'] = 'transaction/reply'
        ip, colon, port = sender_address.partition(':')
        blockchain.send_msg(data, ip, int(port))
        print('REPLY DONE')


    def clear_tempstorage(self, tempfile_name):
        with open(tempfile_name, 'w') as tx_tempfile:
            consisting_transactions = []
            json.dump([], tx_tempfile)
            tx_tempfile.close()
        print(tempfile_name, 'cleaned up')