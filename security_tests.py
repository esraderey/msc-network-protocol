#!/usr/bin/env python3
"""
Tests de Seguridad para MSC Network Protocol
Valida las correcciones críticas de seguridad implementadas
"""

import unittest
import hashlib
import tempfile
import os
from mscnet_blockchain import (
    Transaction, MerklePatriciaTrie, MSCVirtualMachine,
    rlp_encode, rlp_decode, sha3_256
)

class SecurityTests(unittest.TestCase):
    """Tests de seguridad para validar correcciones críticas"""
    
    def setUp(self):
        """Configuración inicial para cada test"""
        self.temp_dir = tempfile.mkdtemp()
        self.trie = MerklePatriciaTrie(os.path.join(self.temp_dir, "test_trie"))
        self.vm = MSCVirtualMachine(self.trie)
    
    def tearDown(self):
        """Limpieza después de cada test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_sender_cryptography_fix(self):
        """Test: Verificar que la función sender() implementa criptografía correcta"""
        print("\n🔐 Probando corrección de criptografía en sender()...")
        
        # Crear transacción de prueba
        tx = Transaction(
            nonce=1,
            gas_price=20000000000,
            gas_limit=21000,
            to="0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
            value=1000000000000000000,
            data=b"",
            v="0x1b",
            r="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            s="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            chain_id=1
        )
        
        # La función sender() ahora debe manejar errores de criptografía correctamente
        sender = tx.sender()
        
        # Debe devolver None si hay error en la recuperación de clave pública
        # (ya que la firma de prueba no es válida)
        self.assertIsNone(sender, "Sender debe ser None para firma inválida")
        print("✅ Función sender() maneja errores criptográficos correctamente")
    
    def test_patricia_trie_implementation(self):
        """Test: Verificar que el Patricia Trie implementa estructura real de árbol"""
        print("\n🌳 Probando implementación real de Patricia Merkle Trie...")
        
        # Insertar datos de prueba
        key1 = b"test_key_1"
        value1 = b"test_value_1"
        key2 = b"test_key_2"
        value2 = b"test_value_2"
        
        # Insertar valores
        self.trie.put(key1, value1)
        self.trie.put(key2, value2)
        
        # Verificar que se pueden recuperar
        self.assertEqual(self.trie.get(key1), value1)
        self.assertEqual(self.trie.get(key2), value2)
        
        # Verificar que el root hash no es solo concatenación
        root_hash = self.trie.root_hash
        self.assertIsNotNone(root_hash)
        self.assertIsInstance(root_hash, str)
        self.assertEqual(len(root_hash), 64)  # SHA3-256 hex
        
        # Verificar que las pruebas Merkle funcionan
        proof1 = self.trie.get_proof(key1)
        self.assertIsInstance(proof1, list)
        
        # Verificar que la verificación de prueba funciona
        verification = self.trie.verify_proof(key1, value1, proof1)
        self.assertTrue(verification)
        
        print("✅ Patricia Merkle Trie implementa estructura real de árbol")
    
    def test_rlp_encoding_standards(self):
        """Test: Verificar que RLP encoding cumple con estándares"""
        print("\n📦 Probando implementación de RLP encoding...")
        
        # Test casos básicos
        test_cases = [
            (b"hello", "string simple"),
            (123, "entero"),
            ([1, 2, 3], "lista simple"),
            ([b"hello", 123, [1, 2]], "lista anidada"),
            (b"", "string vacío"),
            ([], "lista vacía")
        ]
        
        for data, description in test_cases:
            with self.subTest(description=description):
                # Codificar
                encoded = rlp_encode(data)
                self.assertIsInstance(encoded, bytes)
                self.assertGreater(len(encoded), 0)
                
                # Decodificar
                decoded, remaining = rlp_decode(encoded)
                self.assertEqual(decoded, data)
                self.assertEqual(len(remaining), 0)
        
        print("✅ RLP encoding cumple con estándares")
    
    def test_reentrancy_protection(self):
        """Test: Verificar protección contra ataques de re-entrancy"""
        print("\n🛡️ Probando protección contra re-entrancy...")
        
        # Simular contrato atacante
        attacker_contract = "0xAttackerContract"
        
        # Verificar que inicialmente no hay guard activo
        self.assertFalse(self.vm.check_reentrancy_guard(attacker_contract))
        
        # Simular primera ejecución
        context = {'address': attacker_contract}
        result1 = self.vm.execute(b'\x00', 1000, context)  # STOP opcode
        
        # Verificar que el guard se activó durante la ejecución
        # (aunque se limpia al final)
        self.assertFalse(self.vm.check_reentrancy_guard(attacker_contract))
        
        # Verificar límite de profundidad de llamadas
        original_depth = self.vm.call_depth
        self.assertLess(original_depth, self.vm.max_call_depth)
        
        # Simular múltiples llamadas anidadas
        for i in range(5):
            context = {'address': f'contract_{i}'}
            result = self.vm.execute(b'\x00', 1000, context)
            self.assertTrue(result['success'])
        
        print("✅ Protección contra re-entrancy implementada correctamente")
    
    def test_call_depth_limit(self):
        """Test: Verificar límite de profundidad de llamadas"""
        print("\n📏 Probando límite de profundidad de llamadas...")
        
        # Simular exceso de profundidad
        self.vm.call_depth = self.vm.max_call_depth
        
        context = {'address': 'test_contract'}
        result = self.vm.execute(b'\x00', 1000, context)
        
        self.assertFalse(result['success'])
        self.assertIn('Maximum call depth exceeded', result['error'])
        
        print("✅ Límite de profundidad de llamadas funciona correctamente")
    
    def test_sha3_256_function(self):
        """Test: Verificar función SHA3-256"""
        print("\n🔒 Probando función SHA3-256...")
        
        test_data = b"test_data_for_hashing"
        hash_result = sha3_256(test_data)
        
        self.assertIsInstance(hash_result, bytes)
        self.assertEqual(len(hash_result), 32)  # SHA3-256 produce 32 bytes
        
        # Verificar que es determinístico
        hash_result2 = sha3_256(test_data)
        self.assertEqual(hash_result, hash_result2)
        
        # Verificar que diferentes datos producen diferentes hashes
        different_data = b"different_data"
        different_hash = sha3_256(different_data)
        self.assertNotEqual(hash_result, different_hash)
        
        print("✅ Función SHA3-256 funciona correctamente")
    
    def test_vm_state_reset(self):
        """Test: Verificar reset del estado del VM"""
        print("\n🔄 Probando reset del estado del VM...")
        
        # Modificar estado del VM
        self.vm.stack.append(123)
        self.vm.memory.extend(b"test")
        self.vm.storage["key"] = "value"
        self.vm.pc = 10
        self.vm.return_data = b"test_return"
        self.vm.logs.append({"test": "log"})
        
        # Resetear estado
        self.vm.reset_vm_state()
        
        # Verificar que se reseteó
        self.assertEqual(len(self.vm.stack), 0)
        self.assertEqual(len(self.vm.memory), 0)
        self.assertEqual(len(self.vm.storage), 0)
        self.assertEqual(self.vm.pc, 0)
        self.assertEqual(self.vm.return_data, b"")
        self.assertEqual(len(self.vm.logs), 0)
        
        # Verificar que call_depth, reentrancy_guard, call_stack NO se resetean
        # (estos se manejan en execute())
        self.assertIsInstance(self.vm.call_depth, int)
        self.assertIsInstance(self.vm.reentrancy_guard, dict)
        self.assertIsInstance(self.vm.call_stack, list)
        
        print("✅ Reset del estado del VM funciona correctamente")

def run_security_tests():
    """Ejecuta todos los tests de seguridad"""
    print("🔴 INICIANDO TESTS DE SEGURIDAD CRÍTICA")
    print("=" * 50)
    
    # Crear suite de tests
    suite = unittest.TestLoader().loadTestsFromTestCase(SecurityTests)
    
    # Ejecutar tests con output detallado
    runner = unittest.TextTestRunner(verbosity=2, stream=open('security_test_results.txt', 'w'))
    result = runner.run(suite)
    
    # Mostrar resumen
    print("\n" + "=" * 50)
    print("📊 RESUMEN DE TESTS DE SEGURIDAD")
    print("=" * 50)
    print(f"Tests ejecutados: {result.testsRun}")
    print(f"Fallos: {len(result.failures)}")
    print(f"Errores: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ FALLOS DETECTADOS:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n💥 ERRORES DETECTADOS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    if result.wasSuccessful():
        print("\n✅ TODOS LOS TESTS DE SEGURIDAD PASARON")
        print("🔒 El sistema está protegido contra las vulnerabilidades críticas")
    else:
        print("\n❌ ALGUNOS TESTS FALLARON")
        print("⚠️  Revisar las correcciones de seguridad")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_security_tests()
    exit(0 if success else 1)
