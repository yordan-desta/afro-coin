from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS # Cross origin reference, for inter client connection and session managment

from wallet import Wallet
from blockchain import Blockchain
from block import Block

app = Flask(__name__)
CORS(app)


@app.route('/', methods = ['GET'])
def get_ui():
    return send_from_directory('ui', 'node.html')

@app.route('/network', methods = ['GET'])
def get_network_ui():
    return send_from_directory('ui', 'network.html')

@app.route('/wallet', methods= ['POST'])
def create_keys():
    wallet.create_keys()
    if wallet.save_keys():
        global blockchain
        blockchain = Blockchain(wallet.public_key, port)
        response = {
            'public_key' : wallet.public_key,
            'private_key' : wallet.private_key,
            'funds' : blockchain.get_balance()
        }
        return jsonify(response), 201
    else:
        response = {
            'message' : 'saving wallet failed'
        }
        return jsonify(response), 500

@app.route('/wallet', methods = ['GET'])
def load_keys():
    if wallet.load_keys():
        global blockchain
        blockchain = Blockchain(wallet.public_key, port)
        response = {
            'public_key' : wallet.public_key,
            'private_key' : wallet.private_key,
            'message': 'fetching funds successful',
            'funds' : blockchain.get_balance()
        }
        return jsonify(response), 200
    else:
        response = {
            "message" : 'loading wallet failed'
        }
        return jsonify(response), 500

@app.route('/balance', methods = ['GET'])
def get_balance():
    balance = blockchain.get_balance()
    if balance != None:
        reponse = {
            'public_key' : wallet.public_key,
            'private_key' : wallet.private_key,
            'funds' : balance
        }

        return jsonify(reponse), 201

    else:
        response = {
            'message': 'Loading balance failed',
            'wallet_setup' : wallet != None
        }
        return jsonify(response), 500

@app.route('/transaction', methods=['POST'])
def add_transaction():
    if wallet.public_key == None:
        response = {
            'messege' : 'No wallet setup'
        }
        return jsonify(response), 400

    values = request.get_json()
    if not values:
        response = {
            'message' : 'No data found'
        }
        return jsonify(response), 400

    required_fields = ['recipient', 'amount']
    if not all(field in values for field in required_fields):
        response = {
            'message' : 'Required data is missing'
        }
        return jsonify(response), 400

    recipient = values['recipient']
    amount = values['amount']
    signature = wallet.sign_transaction(wallet.public_key, recipient, amount)
    success = blockchain.add_transaction(recipient, wallet.public_key, signature, amount)
    
    if success:
        response = {
            'message' : 'Creating transaction succeeded',
            'transaction' : {
                'sender' : wallet.public_key,
                'recipient' : recipient,
                'amount' : amount,
                'signature': signature
            },
            'funds' : blockchain.get_balance()
        }

        return jsonify(response), 201
    
    else:
        response = {
            'message' : 'Creating transaction failed'
        }
        return jsonify(response), 500

@app.route('/transactions', methods=['GET'])
def get_open_transaction():
    transactions = blockchain.get_open_transaction()
    dict_transactions = [tx.__dict__ for tx in transactions]
    return jsonify(dict_transactions), 200

@app.route('/broadcast-transaction', methods = ['POST'])
def broadcast_transaction():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found'}
        return jsonify(response), 400
    required = ['sender', 'recipient', 'amount', 'signature']

    if not all(key in values for key in required):
        response = {'message': 'Some data missing'}
        return jsonify(response), 400
    success = blockchain.add_transaction(values['recipient'], values['sender'], values['signature'], values['amount'], is_receiving=True)
    if success:
            response = {
                'message' : 'Creating transaction succeeded',
                'transaction' : {
                    'sender' : values['sender'],
                    'recipient' : values['recipient'],
                    'amount' : values['amount'],
                    'signature': values['signature']
                }
            }

            return jsonify(response), 201 
    else:
        response = {
            'message' : 'Creating transaction failed'
        }
        return jsonify(response), 500    


@app.route('/mine', methods = ['POST'])
def mine():
    if blockchain.resolve_conflicts:
        response = {'message' : 'Resolve conflicts first, block not mined'}
        return jsonify(response), 409

    block = blockchain.mine_block()
    if block != None:
        dict_block = block.__dict__.copy()
        dict_block['transactions'] = [tx.__dict__ for tx in dict_block['transactions']]
        response = {
            'message' : 'Adding block succeeded',
            'block' : dict_block,
            'funds' : blockchain.get_balance()
        }
        return jsonify(response), 201
    else:
        response = {
            'message' : 'Adding block failed',
            'wallet_setup' : wallet.public_key != None
        }
        return jsonify(response), 500

@app.route('/broadcast-block', methods=['POST'])
def broadcast_block():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found'}
        return jsonify(response), 400
    if 'block' not in values:
        response = {'message': 'No block found'}
        return jsonify(response), 400
    block = values['block']
    if block['index'] == blockchain.chain[-1].index + 1:
        if blockchain.add_block(values['block']):
            response = {'message' : 'Added block'}
            return jsonify(response), 200
        else:
            response = {'message' : 'Adding block failed'}
            return jsonify(response), 409

    elif block['index'] > blockchain.chain[-1].index:
        response = {'message': 'Blockchain seems to be different from local nodes'}
        blockchain.resolve_conflicts = True
        return jsonify(response), 409 #invalid data sent error code

    else:
        response = {'message': 'Blockchain seems to be shorter, block not added'}
        return jsonify(response), 409 #invalid data sent error code

@app.route('/chain', methods = ['GET'])
def get_chain():
    chain_snapshot = blockchain.chain
    #serializable_chain = [Block(bl_el.index, bl_el.previous_hash, [tx.__dict__ for tx in bl_el.transactions], bl_el.proof, bl_el.timestamp) for bl_el in chain_snapshot]
    #dict_chain = [block.__dict__ for block in serializable_chain]
    dict_chain = [block.__dict__.copy() for block in [Block(bl_el.index, bl_el.previous_hash, [tx.__dict__ for tx in bl_el.transactions], bl_el.proof, bl_el.timestamp) for bl_el in chain_snapshot]]
    return jsonify(dict_chain), 200

@app.route('/node', methods = ['POST'])
def add_node():
    values = request.get_json()
    if not values:
        response = {
            'message' : 'No data attached'
        }
        return jsonify(response), 400
    if 'node' not in values:
        response = {
            'message' : 'No node attached'
        }
    node = values['node']
    blockchain.add_peer_nodes(node)
    response = {
        'message' : 'Added node successfully',
        'all_nodes' : blockchain.get_peer_nodes()
    }
    return jsonify(response), 201

@app.route('/resolve-conflicts', methods = ['POST'])
def resolve_conflicts():
    replaced = blockchain.resolve()
    if replaced:
        response = {'message' : 'chain was replaced'}
    else:
        response = {'message' : 'chain was not replaced'}
    return jsonify(response), 200

@app.route('/node/<node_url>', methods = ['DELETE'])
def remove_node(node_url):
    if node_url == '' or node_url == None:
        response = {
            'message' : 'No node found'
        }
        return jsonify(response), 400
    else:
        blockchain.remove_peer_node(node_url)
        response = {
            'message': 'Node removed',
            'all_nodes' : blockchain.get_peer_nodes()
        }
        return jsonify(response), 200

@app.route('/nodes', methods = ['GET'])
def get_nodes():
    nodes = blockchain.get_peer_nodes()
    response = {
        'nodes': nodes
    }
    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default = 5000)
    args = parser.parse_args()
    #print(args.port)
    port = args.port
    wallet = Wallet(port)
    blockchain = Blockchain(wallet.public_key, port)
    app.run(host='0.0.0.0', port=port)