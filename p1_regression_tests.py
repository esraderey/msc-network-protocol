"""Regresiones de seguridad y validación para los P1 del camino modular."""

import asyncio
import base64
import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct

from msc_network.defi.dex import DEXProtocol
from msc_network.defi.lending import LendingProtocol
from msc_network.defi.oracle import OracleSystem
from msc_network.governance.governance_system import GovernanceSystem, ProposalStatus
from msc_network.governance.staking_system import StakingSystem, ValidatorStatus
from msc_network.network.discovery import DiscoveryProtocol
from msc_network.network.p2p_manager import P2PNetworkManager
from msc_network.virtual_machine.vm import MSCVirtualMachine, SecureInternalChannel
from msc_network.core.merkle_trie import MerklePatriciaTrie
from msc_network.utils import sha3_256
from wallet import Keystore, MultiSigWallet, TransactionData


class FixedOracle:
    def __init__(self, prices):
        self.prices = prices

    def get_price(self, asset):
        return self.prices.get(asset)


class P1RegressionTests(unittest.TestCase):
    def test_defi_and_oracle_reject_invalid_inputs(self):
        dex = DEXProtocol("factory")
        pair = dex.create_pair("MSC", "USD")
        pool = dex.get_pair("MSC", "USD")
        with self.assertRaises(ValueError):
            pool.add_liquidity(Decimal("-1"), Decimal("1"))
        pool.add_liquidity(Decimal("100"), Decimal("100"))
        amount_out = pool.swap(Decimal("1"), "MSC")
        self.assertGreater(amount_out, Decimal("0"))
        with self.assertRaises(ValueError):
            pool.swap(Decimal("1"), "UNKNOWN")
        self.assertEqual(pair, dex.create_pair("USD", "MSC"))

        lending = LendingProtocol()
        lending.create_market("MSC", Decimal("0.8"))
        lending.create_market("USD", Decimal("0.8"))
        with self.assertRaises(ValueError):
            lending.supply("alice", "MSC", Decimal("-1"))
        with self.assertRaises(ValueError):
            lending.supply("alice", "MISSING", Decimal("1"))
        lending.oracle = FixedOracle({"MSC": Decimal("2"), "USD": Decimal("1")})
        lending.supply("alice", "MSC", Decimal("100"))
        lending.supply("liquidity", "USD", Decimal("1000"))
        lending.borrow("alice", "USD", Decimal("160"))
        with self.assertRaises(ValueError):
            lending.borrow("alice", "USD", Decimal("1"))

        async def check_oracle():
            oracle = OracleSystem()
            with self.assertRaises(ValueError):
                await oracle.add_price_feed("MSC", "http://example.com/feed")
            with self.assertRaises(ValueError):
                await oracle.add_price_feed("MSC", "https://127.0.0.1/feed")

        asyncio.run(check_oracle())

    def test_governance_and_staking_enforce_power_and_amounts(self):
        governance = GovernanceSystem("MSC_TOKEN")
        governance.set_voting_power("alice", Decimal("100"))
        proposal_id = governance.create_proposal("alice", "Test", "Test", [])
        governance.update_proposal_status(proposal_id, 0)
        with self.assertRaises(ValueError):
            governance.vote(proposal_id, "alice", True, Decimal("101"))
        governance.vote(proposal_id, "alice", True, Decimal("100"))
        governance.update_proposal_status(proposal_id, governance.voting_period)
        self.assertEqual(governance.get_proposal(proposal_id).status, ProposalStatus.SUCCEEDED)
        governance.execute_proposal(proposal_id)

        staking = StakingSystem(object())
        staking.register_validator("validator", Decimal("0.1"), Decimal("1"))
        with self.assertRaises(ValueError):
            staking.delegate("alice", "validator", Decimal("0"))
        staking.delegate("validator", "validator", Decimal("1000000000000000000000"))
        self.assertEqual(staking.get_validator_info("validator").status, ValidatorStatus.ACTIVE)
        staking.undelegate("validator", "validator", Decimal("1000000000000000000000"))
        self.assertEqual(staking.get_validator_info("validator").status, ValidatorStatus.INACTIVE)

    def test_keystore_is_authenticated_and_multisig_checks_signer(self):
        with tempfile.TemporaryDirectory() as directory:
            keystore = Keystore(Path(directory))
            private_key = bytes.fromhex("11" * 32)
            encrypted = keystore.encrypt_key(private_key, "correct horse")
            decrypted = keystore.decrypt_key(encrypted, "correct horse")
            self.assertEqual(decrypted.to_string(), private_key)
            ciphertext = bytearray(base64.b64decode(encrypted["crypto"]["ciphertext"]))
            ciphertext[0] ^= 1
            encrypted["crypto"]["ciphertext"] = base64.b64encode(ciphertext).decode()
            with self.assertRaises(Exception):
                keystore.decrypt_key(encrypted, "correct horse")

        account = Account.create()
        wallet = MultiSigWallet(1, [account.address])
        tx_data = TransactionData("MSC" + "1" * 40, "MSC" + "2" * 40, Decimal("1"))
        transaction = wallet.create_transaction(tx_data)
        payload = json.dumps(asdict_for_test(tx_data), sort_keys=True,
                             separators=(",", ":"), default=str)
        signature = account.sign_message(encode_defunct(text=payload)).signature.hex()
        self.assertTrue(wallet.sign_transaction(transaction.tx_id, account.address, "0x" + signature))

    def test_vm_and_network_do_not_fabricate_state(self):
        with tempfile.TemporaryDirectory() as directory:
            trie = MerklePatriciaTrie(str(Path(directory) / "state"))
            vm = MSCVirtualMachine(trie)
            vm.context = {"address": "0x" + "1" * 40, "code": b"\x5b"}
            vm.gas_remaining = 40000
            vm.memory[:2] = b"\x60\x00"
            vm.stack = [2, 0, 2]
            vm.op_create()
            created = trie.get(next(key for key in trie.data if key.startswith(b"contract:")))
            self.assertEqual(created, b"`\x00")

        manager = P2PNetworkManager("1" * 40, ("127.0.0.1", 0))
        manager.add_bootstrap_node(("127.0.0.1", 1))
        self.assertEqual(manager.discover_peers(), [])
        self.assertFalse(manager.connect_to_peer("2" * 40, ("127.0.0.1", 1)))

        async def check_discovery():
            discovery = DiscoveryProtocol("1" * 40, ("127.0.0.1", 0))
            with self.assertRaises(NotImplementedError):
                await discovery._query_stun_server("stun.example:19302")

        asyncio.run(check_discovery())

    def test_p2p_listener_accepts_real_peer_handshake(self):
        async def check_listener():
            first = P2PNetworkManager("1" * 40, ("127.0.0.1", 0))
            second = P2PNetworkManager("2" * 40, ("127.0.0.1", 0))
            try:
                await first.start()
                await second.start()
                connected = await asyncio.to_thread(
                    second.connect_to_peer, first.node_id, first.listen_address
                )
                self.assertTrue(connected)
                response = await asyncio.to_thread(
                    second._exchange, first.listen_address,
                    {"type": "ping", "node_id": second.node_id}, True
                )
                self.assertEqual(response["type"], "pong")
                self.assertIn(first.node_id, second.connected_peers)
                self.assertIn(second.node_id, first.connected_peers)
            finally:
                await second.stop()
                await first.stop()

        asyncio.run(check_listener())

    def test_vm_stack_memory_revert_and_encrypted_internal_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            trie = MerklePatriciaTrie(str(Path(directory) / "state"))
            vm = MSCVirtualMachine(trie)
            address = "0x" + "1" * 40
            code = bytes.fromhex("6000602a526000516080fd")
            result = vm.execute(code, 100000, {"address": address})
            self.assertFalse(result["success"])
            self.assertTrue(result["reverted"])
            self.assertEqual(vm.contract_storage[address], {})

            code_envelope = vm.encrypt_code(b"\x60\x2a\x00", b"k" * 32, address)
            encrypted_result = vm.execute_encrypted(
                code_envelope, b"k" * 32, 1000, {"address": address}
            )
            self.assertTrue(encrypted_result["success"])
            with self.assertRaises(ValueError):
                vm.execute_encrypted(code_envelope, b"x" * 32, 1000, {"address": address})

            channel = SecureInternalChannel(b"s" * 32)
            sender = address
            recipient = "0x" + "2" * 40
            vm.context = {"address": sender, "secure_channel": channel}
            vm.gas_remaining = 100000
            vm.memory.extend(b"secret")

            def secure_handler(envelope, gas):
                payload = channel.decrypt(envelope, recipient, sender)
                return channel.encrypt(recipient, sender, payload.upper())

            vm.context["secure_call_handler"] = secure_handler
            vm.stack = [6, 0, 6, 0, 0, int(recipient, 16), 10000]
            vm.op_secure_call()
            self.assertEqual(vm.memory[:6], b"SECRET")
            self.assertEqual(vm.stack[-1], 1)

    def test_vm_extended_opcode_surface(self):
        with tempfile.TemporaryDirectory() as directory:
            trie = MerklePatriciaTrie(str(Path(directory) / "state"))
            address = "0x" + "1" * 40

            def run(code, **context):
                vm = MSCVirtualMachine(trie)
                result = vm.execute(code, 200000, {
                    "address": address,
                    "calldata": b"\x01\x02\x03",
                    "gas_price": 7,
                    "block_number": 9,
                    "timestamp": 10,
                    "chain_id": 1337,
                    **context,
                })
                self.assertTrue(result["success"], result)
                return vm, result

            vm, _ = run(bytes.fromhex("6008600305600160041b00"))
            self.assertEqual(vm.stack, [2, 16])

            vm, _ = run(bytes.fromhex("60003500"))
            self.assertEqual(vm.stack[-1], int.from_bytes(b"\x01\x02\x03".ljust(32, b"\x00"), "big"))

            vm, _ = run(bytes.fromhex("6003600160003760005100"))
            self.assertEqual(vm.stack[-1] >> (29 * 8), 0x020300)

            vm, result = run(bytes.fromhex("6000602a5260006020a000"))
            self.assertEqual(len(result["logs"]), 1)
            self.assertEqual(result["logs"][0]["data"][-1], 0x2a)

            vm, _ = run(bytes.fromhex("3d600060003e00"))
            self.assertEqual(vm.stack, [])

            self.assertEqual(
                vm.compiler.compile("PUSH1 1\nPUSH1 2\nSDIV\nSTOP"),
                bytes.fromhex("600160020500"),
            )

    def test_vm_modern_opcodes_handlers_and_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            trie = MerklePatriciaTrie(str(Path(directory) / "state"))
            address = "0x" + "1" * 40

            def run(code, **context):
                vm = MSCVirtualMachine(trie)
                result = vm.execute(code, 200000, {
                    "address": address,
                    **context,
                })
                return vm, result

            vm, result = run(bytes.fromhex("6001602a5d60015c00"))
            self.assertTrue(result["success"], result)
            self.assertEqual(vm.stack, [42])

            vm, result = run(bytes.fromhex("6000602a536001600060015e00"))
            self.assertTrue(result["success"], result)
            self.assertEqual(bytes(vm.memory[:2]), b"**")

            vm, result = run(
                bytes.fromhex("60003f00"),
                external_code_handler=lambda _address: b"\x60\x00",
            )
            self.assertTrue(result["success"], result)
            self.assertEqual(vm.stack, [int.from_bytes(sha3_256(b"\x60\x00"), "big")])

            vm, result = run(
                bytes.fromhex("6000494a00"),
                blob_hashes=[b"h" * 32],
                blob_base_fee=7,
            )
            self.assertTrue(result["success"], result)
            self.assertEqual(vm.stack, [int.from_bytes(b"h" * 32, "big"), 7])

            def static_call_handler(_address, _value, _payload, _gas):
                trie.put(b"static-side-effect", b"must-rollback")
                return True, b"ok"

            vm, result = run(
                bytes.fromhex("60026000600060006007612710fa00"),
                call_handler=static_call_handler,
            )
            self.assertTrue(result["success"], result)
            self.assertEqual(vm.stack, [1])
            self.assertEqual(bytes(vm.memory[:2]), b"ok")
            self.assertIsNone(trie.get(b"static-side-effect"))

            delegate_vm, delegate_result = run(
                bytes.fromhex("60026000600060006007612710f400"),
                call_handler=lambda _address, _value, _payload, _gas: (True, b"dg"),
            )
            self.assertTrue(delegate_result["success"], delegate_result)
            self.assertEqual(delegate_vm.stack, [1])
            self.assertEqual(bytes(delegate_vm.memory[:2]), b"dg")

            def failed_call_handler(_address, _value, _payload, _gas):
                trie.put(b"external-side-effect", b"must-rollback")
                return False, b""

            vm, result = run(
                bytes.fromhex("600060006000600060006007612710f100"),
                call_handler=failed_call_handler,
            )
            self.assertTrue(result["success"], result)
            self.assertEqual(vm.stack, [0])
            self.assertIsNone(trie.get(b"external-side-effect"))

            vm = MSCVirtualMachine(trie)
            vm.context = {"address": address, "code": b"\x00"}
            vm.gas_remaining = 200000
            vm.memory.extend(b"\x00")
            vm.stack = [0, 0, 1, 1]
            vm.op_create2()
            created = next(key for key in trie.data if key.startswith(b"contract:"))
            self.assertEqual(trie.get(created), b"\x00")

            result = run(bytes.fromhex("63010000005f5200"))[1]
            self.assertFalse(result["success"])
            self.assertIn("Memory access out of bounds", result["error"])

            source = "\n".join([
                "PUSH1 1", "PUSH1 2", "EXTCODEHASH", "BLOBHASH",
                "TLOAD", "TSTORE", "MCOPY", "DELEGATECALL",
                "CREATE2", "STATICCALL", "STOP",
            ])
            bytecode = vm.compiler.compile(source)
            decompiled = vm.compiler.decompile(bytecode)
            for mnemonic in ("EXTCODEHASH", "BLOBHASH", "TLOAD", "TSTORE",
                              "MCOPY", "DELEGATECALL", "CREATE2", "STATICCALL"):
                self.assertIn(mnemonic, decompiled)

            jump_code = vm.compiler.compile("\n".join([
                "PUSH1 1", "JUMP target", "PUSH1 9",
                "LABEL target", "JUMPDEST", "STOP",
            ]))
            jump_vm, jump_result = run(jump_code)
            self.assertTrue(jump_result["success"], jump_result)
            self.assertEqual(jump_vm.stack, [1])

            _, invalid_jump_result = run(bytes.fromhex("605b60015600"))
            self.assertFalse(invalid_jump_result["success"])
            self.assertIn("Invalid jump destination", invalid_jump_result["error"])


def asdict_for_test(tx_data):
    return {
        "from_address": tx_data.from_address,
        "to_address": tx_data.to_address,
        "value": tx_data.value,
        "gas_limit": tx_data.gas_limit,
        "gas_price": tx_data.gas_price,
        "nonce": tx_data.nonce,
        "data": tx_data.data,
        "chain_id": tx_data.chain_id,
    }


if __name__ == "__main__":
    unittest.main(verbosity=2)
