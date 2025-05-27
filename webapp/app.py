from flask import Flask, jsonify, request, render_template, redirect, url_for
from mscnet_blockchain import MSCNetBlockchain, Block
from wallet import Wallet
import time

app = Flask(__name__)

# Initialize blockchain and a temporary wallet to sign blocks
blockchain = MSCNetBlockchain()
wallet = Wallet()

@app.route('/')
def index():
    chain = blockchain.chain
    return render_template('index.html', chain=chain)

@app.route('/chain')
def get_chain():
    chain_data = [block.__dict__ for block in blockchain.chain]
    return jsonify(chain_data)

@app.route('/add_block', methods=['POST'])
def add_block():
    data = request.form.get('data')
    impact = float(request.form.get('impact', 0))
    reputation = float(request.form.get('reputation', 1.0))
    consistency = float(request.form.get('consistency', 0))

    block_data = {
        'agent_id': 'webapp',
        'action': data,
        'content': data,
        'details': {},
        'agent_public_key': wallet.get_public_key()
    }
    synth_proof = {'Ψ': reputation, 'Φ': impact, 'Ω': consistency}
    last_block = blockchain.get_latest_block()
    new_block = Block(last_block.index + 1, time.time(), block_data, synth_proof, last_block.hash)
    new_block.sign_block(wallet.private_key)
    blockchain.add_block(block_data, synth_proof, new_block.agent_signature)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
