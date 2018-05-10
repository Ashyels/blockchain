from blockchain_udp import *

blockchain = Blockchain()

class SBFTConsensus():
    def __init__(self):
        self.temp = self.initiate_temp()

    def initiate_temp(self):
        array = []
        return array

    def preprepare_phase(self, data):
        blockchain.check_value(data)
        client_pubkey, sender_address, sender_pubkey, signature, transaction = blockchain.open_msg(data)
        authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
        if authenticated:
            # print('preprepare', 'message authenticated')
            # print('multicast prepare msg')
            blockchain.execute_transaction(transaction)
            response = self.multicast_reply_msg(sender_address, transaction, client_pubkey)
        else:
            print('message not authenticated')

    def request_phase(self, data):
        blockchain.check_value(data)
        client_pubkey, sender_address, sender_pubkey, signature, transaction = blockchain.open_msg(data)
        authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
        if authenticated:
            # print('request', 'message authenticated')
            # print('multicast preprepare msg')
            response = self.multicast_preprepare_msg(sender_address, transaction, client_pubkey)
            blockchain.execute_transaction(transaction)
            response = self.multicast_reply_msg(sender_address, transaction, client_pubkey)
        else:
            print('message not authenticated')

    def multicast_preprepare_msg(self, sender_address, transaction, client_pubkey):
        # print(blockchain.serv_addrs)
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

    def multicast_reply_msg(self, sender_address, transaction, client_pubkey):
        import base64
        signature = blockchain.sign_msg(transaction)
        encapsulated_signature = blockchain.encapsulate_msg(signature)
        encrypted_transaction = blockchain.encrypt_msg(transaction, client_pubkey)
        encapsulated_transaction = blockchain.encapsulate_msg(encrypted_transaction)

        data={'client_pubkey': client_pubkey, 'sender_address': sender_address,'sender_id': blockchain.publickey.decode(), 'transaction': encapsulated_transaction, 'signature': encapsulated_signature}
        data['route'] = 'transaction/reply'
        ip, colon, port = sender_address.partition(':')
        blockchain.send_msg(data, ip, int(port))
        print('REPLY DONE')

    # def clear_tempstorage(self, tempfile_name):
    #     with open(tempfile_name, 'w') as tx_tempfile:
    #         consisting_transactions = []
    #         json.dump([], tx_tempfile)
    #         tx_tempfile.close()
        # print(tempfile_name, 'cleaned up')