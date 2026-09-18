"""Regression tests for the P0 fixes in the modular node."""

import asyncio
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from msc_network import BlockchainConfig, MSCBlockchainV3
from msc_network.consensus.vrf import VRF
from msc_network.consensus.hybrid_consensus import HybridConsensus
from msc_network.core.data_structures import Account
from msc_network.core.merkle_trie import MerklePatriciaTrie
from msc_network.core.transaction import Transaction
from msc_network.utils import rlp_decode, rlp_encode
from msc_network_main import MSCNetworkV3


class P0RegressionTests(unittest.TestCase):
    def test_rlp_and_persistent_authenticated_state(self):
        self.assertEqual(rlp_decode(rlp_encode([0, b"cat", [1, 2]])),
                         [b"", b"cat", [b"\x01", b"\x02"]])
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state")
            trie = MerklePatriciaTrie(path)
            trie.put(b"a", b"one")
            trie.put(b"b", b"two")
            root = trie.root_hash
            proof = trie.get_proof(b"a")
            self.assertTrue(trie.verify_proof(b"a", b"one", proof))
            self.assertFalse(trie.verify_proof(b"a", b"tampered", proof))
            reopened = MerklePatriciaTrie(path)
            self.assertEqual(reopened.root_hash, root)
            self.assertEqual(reopened.get(b"b"), b"two")

    def test_transaction_signature_and_vrf_are_verifiable(self):
        key = ec.generate_private_key(ec.SECP256K1())
        tx = Transaction(0, BlockchainConfig.MIN_GAS_PRICE, 21000,
                         "0x" + "1" * 40, 1)
        tx.sign(key)
        public_key = key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )[1:]
        expected_sender = "0x" + hashlib.sha256(public_key).digest()[-20:].hex()
        self.assertEqual(tx.sender(), expected_sender)

        vrf = VRF(b"a" * 32)
        output, proof = vrf.generate_proof(b"block-seed")
        self.assertTrue(VRF.verify_proof(b"block-seed", output, proof, vrf.public_key))
        self.assertFalse(VRF.verify_proof(b"block-seed", b"x" * 32, proof, vrf.public_key))
        self.assertFalse(VRF.verify_proof(b"block-seed", output, proof, VRF(b"b" * 32).public_key))

    def test_hybrid_consensus_uses_verifiable_vrf(self):
        consensus = HybridConsensus()
        address = "0x" + "4" * 40
        consensus.register_validator(address, 1_000_000, b"c" * 32)
        self.assertEqual(consensus.select_block_producer(10, b"parent"), address)

    def test_mining_commits_state_and_consumes_pool(self):
        with tempfile.TemporaryDirectory() as directory:
            BlockchainConfig.STATE_DB_PATH = str(Path(directory) / "state")
            chain = MSCBlockchainV3()
            key = ec.generate_private_key(ec.SECP256K1())
            sender_key = key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )[1:]
            sender = "0x" + hashlib.sha256(sender_key).digest()[-20:].hex()
            recipient = "0x" + "2" * 40
            miner = "0x" + "3" * 40
            chain._save_account(Account(sender, balance=10**18))
            tx = Transaction(0, BlockchainConfig.MIN_GAS_PRICE, 21000, recipient, 1000)
            tx.sign(key)
            self.assertTrue(asyncio.run(chain.add_transaction(tx)))
            self.assertFalse(asyncio.run(chain.add_transaction(tx)))
            block = asyncio.run(chain.mine_block(miner))
            self.assertTrue(block.verify_pow())
            self.assertEqual(block.header.transactions_root, block.calculate_transactions_root())
            self.assertEqual(len(chain.pending_transactions), 0)
            self.assertEqual(chain.get_balance(recipient), 1000)
            self.assertEqual(chain.get_nonce(sender), 1)

    def test_node_start_is_bounded_and_stop_cancels_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            BlockchainConfig.STATE_DB_PATH = str(Path(directory) / "state")
            node = MSCNetworkV3()
            asyncio.run(asyncio.wait_for(node.start(), timeout=1))
            self.assertTrue(node.is_running)
            asyncio.run(node.stop())
            self.assertFalse(node.is_running)
            self.assertEqual(node._background_tasks, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
