from application import *
# from application.blockchain import *

@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    # blockchain.new_transaction(
    #     sender="0",
    #     receiver=node_identifier,
    #     amount=1,
    # )

    # Forge the new Block by adding it to the chain
    # previous_hash = blockchain.hash(last_block)
    previous_hash = blockchain.chain[-1]['data_hash']
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }

    # print(blockchain.broadcast_block())
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # blockchain.test()

    # Check that the required fields are in the POST'ed data
    required = ['sender_id', 'transaction', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    from Crypto.PublicKey import RSA
    sender_pubkey = RSA.importKey(values['sender_id'])
    signature = blockchain.reveal_msg(values['signature'])
    encrypted_transaction = blockchain.reveal_msg(values['transaction'])
    transaction = blockchain.decrypt_transaction(encrypted_transaction)
    print(transaction)
    # index = blockchain.new_transaction(transaction['sender_id'], transaction['receiver_id'], transaction['amount'])

    authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
    if authenticated:
        print('message authenticated')
        def return_response(i):
            print('response')
        def multicast_message(i):
            print('THREAD 222')
            response = blockchain.multicast_preprepare_msg(transaction)
        from threading import Thread
        threads = []
        threads.append(Thread(target=return_response, args=(0,)))
        threads.append(Thread(target=multicast_message, args=(1,)))
        threads[0].start()
        threads[1].start()
        response = {'message': f'Transaction will be added to Block index'}
        return jsonify(response), 201
        # threads[0].join()
        # threads[1].join()
    else:
        print('message not authenticated')
        response = {'message': f'transaction not verified'}
        return jsonify(response), 201

@app.route('/transactions/preprepare', methods=['POST'])
def preprepare_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender_id', 'transaction', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    from Crypto.PublicKey import RSA
    sender_pubkey = RSA.importKey(values['sender_id'])
    signature = blockchain.reveal_msg(values['signature'])
    encrypted_transaction = blockchain.reveal_msg(values['transaction'])
    transaction = blockchain.decrypt_transaction(encrypted_transaction)
    print(transaction)
    # index = blockchain.new_transaction(transaction['sender_id'], transaction['receiver_id'], transaction['amount'])

    authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
    if authenticated:
        def return_response(i):
            print('response')
        def multicast_message(i):
            print('THREAD 222')
            response = blockchain.multicast_prepare_msg(transaction)
        print('message authenticated')
        from threading import Thread
        threads = []
        threads.append(Thread(target=return_response, args=(0,)))
        threads.append(Thread(target=multicast_message, args=(1,)))
        threads[0].start()
        threads[1].start()
        response = {'message': f'Transaction will be added to Block index'}
        return jsonify(response), 201
        # threads[0].join()
        # threads[1].join()

    else:
        print('message not authenticated')
        response = {'message': f'transaction not verified'}
        return jsonify(response), 201

    # send transaction to other nodes
    # print(blockchain.multicast_message(values['sender'], values['receiver'], values['amount']))

    # Create a new Transaction
    # index = blockchain.new_transaction(values['sender'], values['receiver'], values['amount'])

    response = {'message': f'Transaction will be added to Block'}
    return jsonify(response), 201

@app.route('/transactions/prepare', methods=['POST'])
def prepare_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender_id', 'transaction', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    from Crypto.PublicKey import RSA
    sender_pubkey = RSA.importKey(values['sender_id'])
    signature = blockchain.reveal_msg(values['signature'])
    encrypted_transaction = blockchain.reveal_msg(values['transaction'])
    transaction = blockchain.decrypt_transaction(encrypted_transaction)
    print(transaction)
    # index = blockchain.new_transaction(transaction['sender_id'], transaction['receiver_id'], transaction['amount'])

    authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
    if authenticated:
        print('message authenticated')
        def return_response(i):
            print('response')
        def multicast_message(i):
            isVerified = False
            try:
                with open('temp/' + node_identifier + '.son', 'r') as fh:
                    consisting_transactions = json.load(fh)
                    print(consisting_transactions)
                    for consisting_transaction in consisting_transactions:
                        print(consisting_transaction)
                        if consisting_transaction == transaction:
                            response = blockchain.multicast_commit_msg(transaction)
                            isVerified = True
                            print('isVerified',isVerified)
                if not isVerified:
                    with open('temp/' + node_identifier + '.son', 'w') as fh:
                        data 
                        json.dump(transaction, fh)
                        print('isVerified',isVerified)
            except:
                with open('temp/' + node_identifier + '.son', 'w+') as fh:
                    array = []
                    array.append(transaction)
                    json.dump(array, fh)
                    print('isVerified',isVerified)
                    
        from threading import Thread
        threads = []
        threads.append(Thread(target=return_response, args=(0,)))
        threads.append(Thread(target=multicast_message, args=(1,)))
        threads[0].start()
        threads[1].start()
        response = {'message': f'Transaction will be added to Block index'}
        return jsonify(response), 201
    else:
        print('message not authenticated')
        response = {'message': f'transaction not verified'}
        return jsonify(response), 201

    # send transaction to other nodes
    # print(blockchain.multicast_message(values['sender'], values['receiver'], values['amount']))

    # Create a new Transaction
    # index = blockchain.new_transaction(values['sender'], values['receiver'], values['amount'])

    response = {'message': f'Transaction will be added to Block'}
    return jsonify(response), 201

@app.route('/transactions/commit', methods=['POST'])
def commit_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender_id', 'transaction', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    from Crypto.PublicKey import RSA
    sender_pubkey = RSA.importKey(values['sender_id'])
    signature = blockchain.reveal_msg(values['signature'])
    encrypted_transaction = blockchain.reveal_msg(values['transaction'])
    transaction = blockchain.decrypt_transaction(encrypted_transaction)
    print(transaction)
    # index = blockchain.new_transaction(transaction['sender_id'], transaction['receiver_id'], transaction['amount'])

    authenticated = blockchain.authenticate_transaction(sender_pubkey, signature, transaction)
    if authenticated:
        print('message authenticated')
        # send transaction to other nodes
        # encrypted_transaction = blockchain.encrypt_msg(transaction.encode(), blockchain.publickey)
        # response = blockchain.send_reply_msg(transaction)
        response = {'message': f'Transaction will be added to Block index'}
        return jsonify(response), 201
    else:
        print('message not authenticated')
        response = {'message': f'transaction not verified'}
        return jsonify(response), 201

    # send transaction to other nodes
    # print(blockchain.multicast_message(values['sender'], values['receiver'], values['amount']))

    # Create a new Transaction
    # index = blockchain.new_transaction(values['sender'], values['receiver'], values['amount'])

    response = {'message': f'Transaction will be added to Block'}
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/nodes/show', methods=['GET'])
def nodes_info():
    for index in range(len(blockchain.nodes)):
        print('node', blockchain.nodes_ip[index])
        print('server', blockchain.servers[index])

    response = { 'message': 'OK' }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    for node in blockchain.nodes:
        blockchain.register_node_publickey(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/publickey', methods=['GET'])
def get_node_publickey():
    response = {
        'publickey': blockchain.publickey.decode()
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200



import cgi
import os

@app.route('/test', methods=['POST'])
def test():
    # response = {
    #     'message': 'Our chain was replaced',
    #     'new_chain': 'chain'
    # }

    # print("Content-type: text/html")
    # print("")
    # print(cgi.escape(os.environ["REMOTE_ADDR"]))

    # print(self.client_address[0])
    print(request.get_json())
    response = request.get_json()
    return response['sender'], 200 

