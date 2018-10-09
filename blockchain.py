import json
from functools import reduce
import requests

from block import Block
from utility.hash_util import hash_block
from transaction import Transaction
from utility.verification import Verification
from wallet import Wallet

MINING_REWARD = 10


class Blockchain:
    def __init__(self, public_key, node_id):
        # Our starting block for our blockchain
        genesis_block = Block(0, '', [], 100, 0)
        # Initializing our blockchain list
        self.chain = [genesis_block]
        # Unhandled transactions
        self.__open_transactions = []
        self.public_key = public_key
        self.node_id = node_id
        self.resolve_conflicts = False
        self.__peer_nodes = set()

        self.load_data()

    @property
    def chain(self):
        return self.__chain[:]

    @chain.setter
    def chain(self, val):
        self.__chain = val

    def get_open_transaction(self):
        return self.__open_transactions[:]

    def load_data(self):
        try:
            with open('blockchain-{}.txt'.format(self.node_id), mode='r') as f:
                file_content = f.readlines()
                blockchain = json.loads(file_content[0][:-1])
                updated_blockchain = []

                for block in blockchain:
                    converted_tx = [
                        Transaction(tx['sender'], tx['recipient'],
                                    tx['signature'], tx['amount'])
                        for tx in block['transactions']
                    ]
                    updated_block = Block(block['index'],
                                          block['previous_hash'], converted_tx,
                                          block['proof'], block['timestamp'])
                    updated_blockchain.append(updated_block)

                self.chain = updated_blockchain
                open_transactions = json.loads(file_content[1][:-1])
                updated_transactions = []
                for tx in open_transactions:
                    updated_transaction = Transaction(
                        tx['sender'], tx['recipient'], tx['signature'],
                        tx['amount'])
                    updated_transactions.append(updated_transaction)
                self.__open_transactions = updated_transactions

                self.__peer_nodes = set(json.loads(file_content[2]))
                # file_content= pickle.loads(f.read())
                # global blockchain, open_transactions
                # blockchain = file_content['chain'](
                # open_transactions = file_content['ot']
        except (IOError, IndexError):
            pass
        finally:
            pass  #print("Always reached")

    def save_data(self):
        try:
            with open('blockchain-{}.txt'.format(self.node_id), mode='w') as f:
                savable_chain = [
                    bl.__dict__ for bl in [
                        Block(bl_el.index, bl_el.previous_hash,
                              [tx.__dict__ for tx in bl_el.transactions],
                              bl_el.proof, bl_el.timestamp)
                        for bl_el in self.__chain
                    ]
                ]
                f.write(json.dumps(savable_chain))
                f.write('\n')
                savable_transaction = [
                    tx.__dict__ for tx in self.__open_transactions
                ]
                f.write(json.dumps(savable_transaction))
                f.write('\n')
                f.write(json.dumps(list(self.__peer_nodes)))
                # saved_data = {
                #     'chain' : blockchain,
                #     'ot' : open_transactions
                # }
                # f.write(pickle.dumps(saved_data))
        except IOError:
            print("Couldn't persist the data!")

    def proof_of_work(self):
        last_block = self.__chain[-1]
        last_hash = hash_block(last_block)
        proof = 0
        while not Verification.valid_proof(self.__open_transactions, last_hash,
                                           proof):
            proof += 1
        return proof

    def get_balance(self, sender = None):

        if sender == None:
            if self.public_key == None:
                return None               
            participant = self.public_key
        else:
            participant = sender

        tx_sender = [[
            tx.amount for tx in block.transactions if tx.sender == participant
        ] for block in self.__chain]

        open_sender_tx = [
            tx.amount for tx in self.__open_transactions
            if tx.sender == participant
        ]
        tx_sender.append(open_sender_tx)
        amount_sent = reduce(
            lambda tx_sum, tx_amt: tx_sum + sum(tx_amt) if len(tx_amt) > 0 else tx_sum + 0,
            tx_sender, 0)

        tx_recipient = [[
            tx.amount for tx in block.transactions
            if tx.recipient == participant
        ] for block in self.__chain]
        amount_recieved = reduce(
            lambda tx_sum, tx_amt: tx_sum + sum(tx_amt) if len(tx_amt) > 0 else tx_sum + 0,
            tx_recipient, 0)

        return amount_recieved - amount_sent

    def get_last_blockchain_value(self):
        return self.__chain[-1]

    def add_transaction(self, recipient, sender, signature, amount=1.0, is_receiving = False):
        """
        Append a new value as well as the last blockchain value to the blockchain

        Arguments:
            :sender: The sender of coins
            :recipient: The recipient of coins
            :amount: The amount of coins sent with the transaction (default = 1.0)
        """
        if self.public_key == None:
            return False

        transaction = Transaction(sender, recipient, signature, amount)

        if Verification.verify_transaction(transaction, self.get_balance):
            self.__open_transactions.append(transaction)
            self.save_data()
            if not is_receiving:
                for node in self.__peer_nodes:
                    url = 'http://{}/broadcast-transaction'.format(node)
                    try:
                        response = requests.post(url, json= {'sender': sender, 'recipient' : recipient, 'amount' : amount, 'signature' : signature})
                        if response.status_code == 400 or response.status_code == 500:
                            print('Transaction declined, needs resolving')
                            return False
                    except requests.exceptions.ConnectionError:
                        continue

            return True
        return False

    def mine_block(self):
        """ add transaction to blockchain"""
        if self.public_key == None:
            return None
            
        last_block = self.__chain[-1]
        hashed_block = hash_block(last_block)
        proof = self.proof_of_work()
        reward_transaction = Transaction('MINING', self.public_key, '',
                                         MINING_REWARD)
        copied_transaction = self.__open_transactions[:]
        
        for tx in copied_transaction:
            if not Wallet.verify_transaction(transaction = tx):
                return None

        copied_transaction.append(reward_transaction)
        block = Block(
            len(self.__chain), hashed_block, copied_transaction, proof)

        self.__chain.append(block)
        self.__open_transactions = []
        self.save_data()

        for node in self.__peer_nodes:
            url = 'http://{}/broadcast-block'.format(node)
            converted_block = block.__dict__.copy()
            #print(converted_block['transactions'])
            converted_block['transactions'] = [tx.__dict__ for tx in converted_block['transactions']]
            #print(converted_block['transactions'])
            try:
                response = requests.post(url, json={'block' : converted_block})
                if response.status_code == 400 or response.status_code == 500:
                            print('Block declined, needs resolving')
                if response.status_code == 409:
                    self.resolve_conflicts = True
            except requests.exceptions.ConnectionError:
                continue
        return block

    def add_block(self, block):
        transactions = [Transaction(tx['sender'], tx['recipient'], tx['signature'],tx['amount']) for tx in block['transactions']]
        proof_is_valid = Verification.valid_proof(transactions[:-1], block['previous_hash'], block['proof'])
        hashes_match = hash_block(self.chain[-1]) == block['previous_hash']
        if not proof_is_valid or not hashes_match:
            print('failed to validate', proof_is_valid, hashes_match)
            return False
        print('validated before adding')
        converted_block = Block(block['index'], block['previous_hash'], transactions, block['proof'], block['timestamp'])
        self.__chain.append(converted_block)
        stored_transaction = self.__open_transactions[:]
        for in_tx in transactions:
            for op_tx in stored_transaction:
                if in_tx.sender == op_tx.sender and in_tx.recipient == op_tx.recipient and in_tx.amount == op_tx.amount:
                    try:
                        self.__open_transactions.remove(op_tx)
                    except ValueError:
                        print('Value already removed')
                    finally:
                        break
        self.save_data()
        return True

    def resolve(self):
        winner_chain = self.chain
        replace = False
        for node in self.__peer_nodes:
            url = 'http://{}/chain'.format(node)
            try:
                response = requests.get(url)
                node_chain = response.json()                
                node_chain = [self.get_block_object_from_json(block) for block in node_chain]
                node_chain_len = len(node_chain)
                local_chain_len = len(self.chain)
                if node_chain_len > local_chain_len and Verification.verify_chain(node_chain):
                    winner_chain = node_chain
                    replace = True
            except requests.exceptions.ConnectionError:
                continue
        self.resolve_conflicts = False
        self.chain = winner_chain
        if replace:
            self.__open_transactions = []
        self.save_data()
        return replace
        
    def get_block_object_from_json(self, block):
        transactions = [self.get_tx_object_from_json(tx) for tx in block['transactions']]
        converted_block = Block(block['index'], block['previous_hash'], transactions, block['proof'], block['timestamp'])
        return converted_block
        
    def get_tx_object_from_json(self, tx):
        return Transaction(tx['sender'], tx['recipient'], tx['signature'],tx['amount'])

    def add_peer_nodes(self, node):
        """ Add a new node to peer node network

        Arguments:
            :node : The node url which should be added
        """
        self.__peer_nodes.add(node)
        self.save_data()

    def remove_peer_node(self, node):
        """ Remove an existing peer node from network

        Arguments:
            :node : The node url which should be added
        """
        self.__peer_nodes.discard(node)
        self.save_data()
    
    def get_peer_nodes(self):
        """Returns a list of connected peer nodes"""
        return list(self.__peer_nodes)

