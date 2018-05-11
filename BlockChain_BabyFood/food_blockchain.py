import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import random
import string
from model import AccountDetails, Base, LicenceIds, UPCNumbers
from sqlalchemy import create_engine
from argparse import ArgumentParser
from merkle import gen_merkle_tree_hash
from datetime import datetime

import requests
from flask import Flask, jsonify, request, redirect, render_template

class Blockchain:
    def __init__(self):
        self.reg_txn = []
        self.chain = []
        self.nodes = set()
        self.Id_roles = {}
        
        # Create the genesis block
        #Removed proof
        self.new_block(previous_hash='1',proof=100,genesis=True)
        

    
    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain):


        last_block = chain[1]
        current_index = 2

        while current_index < len(chain):
            block = chain[current_index]

            # Check that the hash of the block is correct
            if (block['previous_hash']) != (self.hash_merkle(last_block['Product_Details/Transactions'])):
                return False

  
            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'],block['previous_hash']):
                return False

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
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)
        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get('http://'+node+'/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            print("Chain replaced")
            self.chain = new_chain
            return True

        return False



    def new_block(self, previous_hash, proof,genesis):
        """
        Create a new Block in the Blockchain
        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        if (genesis == True):
            block = {
                'index': len(self.chain) + 1,
                'Product_Details/Transactions': self.reg_txn,
                'proof': proof,
                'previous_hash': previous_hash or self.hash(self.chain[-1]),
            }
        else:
            block = {
            'index': len(self.chain) + 1,
            'timestamp': datetime.now(),
            'Product_Details/Transactions': self.reg_txn,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'Reward Points': 100,
            'Reward Receipent': node_identifier
            }
            

        # Reset the current list of transactions
        self.reg_txn = []

        self.chain.append(block)
        return block

    def registration(self, values):
        validation = self.validate_registration( values['UPC'], values['OwnerID'], values['itemno'])
        session = session_factory()
        OwnerDetails = session.query(AccountDetails).get(values['OwnerID'])
        if(validation == 'True'):
            self.reg_txn.append({
            'UPC': values['UPC'],
            'ItemNo': values['itemno'],
            'Owner Name': OwnerDetails.name,
            'OwnerID': values['OwnerID'],
            'Product Name': values['Name'],
            'Description': values['Description'],
            'Item Weight' : values['weight'],
            'Cost' : values['Cost'],
            'Expiry Date' : values['Expiry Date']
            })
            if(len(self.reg_txn) == 2):
                self.mine(self.reg_txn)
                self.broadcast()
                return self.last_block['index']
            else:
                return "Tx will be mined"
        else:
            return validation

    def transferOwner(self, values):
        
        validation = self.validate_transfer( values['UPC'], values['OwnerID'], values['ReceiverID'], values['itemno'])
        session = session_factory()
        OwnerDetails = session.query(AccountDetails).get(values['OwnerID'])
        ReceiverDetails = session.query(AccountDetails).get(values['ReceiverID'])

        if(validation == "True"):
            self.reg_txn.append({
            'UPC': values['UPC'],
            'ItemNo': values['itemno'],
            'Owner ID': values['OwnerID'],
            'Owner Name': OwnerDetails.name,
            'Receiver ID': values['ReceiverID'],
            'Receiver Name': ReceiverDetails.name
            })
            if(len(self.reg_txn) == 2):
                self.mine(self.reg_txn)
                self.broadcast()
                return self.last_block['index']
            else:
                return "Tx will be mined"
        else:
            return validation

    def broadcast(self):
        headers = {'content-type': 'application/json'}
        for node in blockchain.nodes:
            response = requests.post("http://"+node+"/broadcast", data=json.dumps(blockchain.chain[-1]),headers=headers)
    
    @staticmethod
    def mine(txn_list):
    
        last_block = blockchain.last_block
        last_proof = last_block['proof']
        proof = blockchain.proof_of_work(last_block)

        # Forge the new Block by adding it to the chain
        #previous_hash = blockchain.hash(last_block)
        if(len(last_block['Product_Details/Transactions']) >=1 ):
            previous_hash = blockchain.hash_merkle(last_block['Product_Details/Transactions'])
        else:
            previous_hash = blockchain.hash(last_block) 
        block = blockchain.new_block(previous_hash, proof, False)

        response = {
        'message': "New Block Forged",
        'index': block['index'],
        'Product_Details/Transactions': block['Product_Details/Transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        }

    def validate_registration(self,UPC, ownerID, itemno):

        session = session_factory()
        details = session.query(AccountDetails).filter(AccountDetails.id == ownerID).first()
        UPC_DB = session.query(UPCNumbers).filter(UPCNumbers.id == UPC).first()

        if details is not None:
            if UPC_DB is not None:
                if details.role == 'Manufacturer':
                    chain = blockchain.chain
                    if(len(chain)>1):
                        for i in range(1, len(chain)):
                            tx_list = (chain[i])['Product_Details/Transactions']
                            for j in range(0, len(tx_list)):
                                tx_existing =  tx_list[j]
                                upc_existing = (tx_list[j])['UPC']
                                item_existing = (tx_list[j])['ItemNo']
                                if(upc_existing == UPC):
                                    if(item_existing == itemno):
                                        response = "Cannot Register. Item {} already registered by {}".format(itemno,tx_existing['OwnerID'])
                                        return response
                                    else:
                                        return 'True'
                                else:
                                    return 'True'
                    else:
                        if(len(self.reg_txn)>0):
                            for i in range(0, len(self.reg_txn)):
                                upc_existing = (self.reg_txn[i])['UPC']
                                ownerid_existing = (self.reg_txn[i])['OwnerID']
                                itemno_existing = (self.reg_txn[i])['ItemNo']
                                if (upc_existing == UPC):
                                    if(itemno_existing == itemno):
                                        response = "Cannot Register. Item {} already registered by {}".format(itemno,ownerid_existing)
                                        return response
                                    else:
                                        return 'True'
                                else:
                                    return 'True'
                        else:
                            return 'True'

                else:
                    response = "Cannot Register. User {} is not having manufacturing privieges".format(ownerID)
                    return response
            else:
                response = 'Cannot Register. {} is not valid Universal Product Code'.format(UPC)
                return response
        else:
            response = "Cannot Register. {} is not enrolled.Please enroll prior to registration".format(ownerID)
            return response

    def validate_transfer(self, upc, ownerID, receiverID, itemno):

        session = session_factory()
        if(ownerID == receiverID):
            return "Cannot Transfer Ownership. Owner and Receiver cannot be same"

        
        UPC = session.query(UPCNumbers).filter(UPCNumbers.id == upc).first()
        ownerinfo = session.query(AccountDetails).filter(AccountDetails.id == ownerID).first()
        receiverinfo = session.query(UPCNumbers).filter(AccountDetails.id == receiverID).first()
        if UPC is None or ownerinfo is None or receiverinfo is None :
            return "Details Incorrect. Please enter valid information"
        else:
            chain = blockchain.chain
            if(len(chain)>1):
                for i in range(1, len(chain)):
                    tx_list = (chain[i])['Product_Details/Transactions']
                    for j in range(0, len(tx_list)):
                        upc_existing = ( tx_list[j])['UPC']
                        item_existing = (tx_list[j])['ItemNo']
                        if(upc_existing == upc):
                            if(str(item_existing)== itemno): 
                                return "True"
            if(len(self.reg_txn)>0):
                for i in range(0, len(self.reg_txn)):
                    upc_existing = (self.reg_txn[i])['UPC']
                    item_existing = (self.reg_txn[i])['ItemNo']
                    if (str(upc_existing) == str(upc)):
                        if(str(item_existing)== itemno):
                            return 'True'      
                response ="Cannot Transfer Ownership. Item {} is not registered".format(itemno)
                return response                    
            else:
                if(len(chain)<2):
                    response ="Cannot Transfer Ownership. Item {} is not registered".format(itemno)
                    return response 

    def enrollment(self, values):
        
        id = ''.join(random.choice(string.hexdigits) for _ in range(15))
        
        session = session_factory()
        session.execute('pragma foreign_keys=on')

        if( values['Role'] == 'Manufacturer'):
            licenceid =  values['Manufacturer_Licence_Id']
        else:
            licenceid = ""

        account_entry = AccountDetails(id, values['Name'], values['Role'],licenceid)
        session.add(account_entry)
        session.commit()
        return id

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
    def hash_merkle(txn_list):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        """
        encoded_list = []
        for txn in txn_list:
            encoded_list.append(json.dumps(txn, sort_keys=True).encode())
        root_hash = gen_merkle_tree_hash(encoded_list)
        return root_hash
    @property
    def last_block(self):
        return self.chain[-1]
    
    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']

        if(len(last_block['Product_Details/Transactions']) >=1 ):
            previous_hash = blockchain.hash_merkle(last_block['Product_Details/Transactions'])
        else:
            previous_hash = blockchain.hash(last_block) 

        proof = 0
        while self.valid_proof(last_proof, proof, previous_hash) is False:
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

        guess = '{}{}{}'.format(last_proof,proof, last_hash).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

engine=create_engine('sqlite:///project.db')
Base.metadata.create_all(engine)
# Instantiate the Node
app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')

def session_factory():
    from sqlalchemy.orm import sessionmaker
    DBSession=sessionmaker(bind=engine)
    return DBSession()

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/register', methods=['POST'])
def register():
    
    values = request.form
    # Check that the required fields are in the POST'ed data
    required = ['UPC', 'Name', 'Description', 'Cost', 'Expiry Date', 'OwnerID', 'itemno']
    if not all(k in values for k in required):
        response = {'message': 'Missing Values'}
        return jsonify(response),400

    # Create a new Transaction
    index = blockchain.registration(values)

    if(isinstance(index, int)):
        response = {'message': 'Product is registered and a new Block {} is mined'.format(index)}
        return jsonify(response),201
    else:
        if( index == 'Tx will be mined'):
            response = {'message': 'Product will be registered in next mined Block'}
            return jsonify(response),201
        else:
            response = {'message': '{}'.format(index)}
            #500
            return jsonify(response),500

@app.route('/transfer', methods=['POST'])
def transfer():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['UPC', 'itemno', 'OwnerID', 'ReceiverID']
    if not all(k in values for k in required):
        response = {'message': 'Missing Values'}
        return jsonify(response),400

    # Create a new Transaction
    index = blockchain.transferOwner(values)

    if(isinstance(index, int)):
        response = {'message': 'Product is registered and a new Block {} is mined'.format(index)}
        return jsonify(response),201
    else:
        if( index == 'Tx will be mined'):
            response = {'message': 'Product will be registered in next mined Block'}
            return jsonify(response),201
        else:
            response = {'message': '{}'.format(index)}
            #500
            return jsonify(response),500

@app.route('/broadcast', methods=['POST'])
def append_block():
    values = request.get_json()
    blockchain.chain.append(values)
    return "Block successully appended",201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response),200


@app.route('/enroll', methods=['POST'])
def enrollment():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['Name', 'Role']
    if not all(k in values for k in required):
        return 'Missing values', 400

    
    if(values['Role'] == 'Manufacturer'):
        session = session_factory()
        licenceid = session.query(LicenceIds).filter(LicenceIds.id == values['Manufacturer_Licence_Id']).first()

        if licenceid is None:
            response = {'message': 'The licence ID {} provided is not valid. Cannot assign manufacturer role'.format(values['Manufacturer_Licence_Id'])}
            return jsonify(response), 403
    # Create a new enrollment
    index = blockchain.enrollment(values)
    response = {'message': 'ID assigned for you is {}'.format(index)}
    return jsonify(response), 201

@app.route('/query', methods=['GET'])
def query_chain():
    upc = request.args.get('upc')
    itemno = request.args.get('itemno')
    chain = blockchain.chain
    response_list = []
    for i in range(1, len(chain)):
        tx_list = ( ( ( chain[i] )['Product_Details/Transactions'] ))
        for tx in tx_list:
            if(tx['UPC'] == upc):
                if(tx['ItemNo'] == itemno):
                    response_list.append(tx)
            
    return jsonify(response_list),200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values['nodes']
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    print("Replacement Status", replaced)

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

if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
