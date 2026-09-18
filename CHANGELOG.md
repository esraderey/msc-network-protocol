# Changelog

## [Unreleased] — 2026-09-18

### Corregido

- P0: codificación RLP canónica, estado autenticado persistente, hashes de bloque completos, validación PoW, firmas ECDSA/recuperación, VRF verificable y transición de estado durante minería.
- P1: validaciones de DEX, lending, oracle, staking y gobernanza; se eliminaron acciones de gobernanza arbitrarias.
- P1: keystore con AES-256-GCM autenticado y exportación de claves condicionada a contraseña; multisig verifica criptográficamente el firmante.
- P1: VM con límites de memoria, destinos de salto válidos, `CREATE` determinista y `CALL`/`SELFDESTRUCT` explícitos mediante handlers.
- VM: añadidos `PUSH0..PUSH32`, `DUP1..DUP16`, `SWAP1..SWAP16`, aritmética modular, memoria expandible con coste de gas, `MSTORE8`, `MSIZE`, `REVERT` y `INVALID`.
- VM: ampliados opcodes signed/bitwise (`SDIV`, `SMOD`, `EXP`, `SIGNEXTEND`, `SLT`, `SGT`, `BYTE`, `SHL`, `SHR`, `SAR`), calldata/código, retorno de datos, entorno de bloque y `LOG0..LOG4`; el compilador y decompilador reconocen esta superficie.
- VM: ejecución transaccional con rollback de trie/storage ante errores o `REVERT`, bytecode cifrado autenticado con AES-GCM y `SECURE_CALL` para comunicación interna cifrada con protección contra replay.
- VM modular: añadidos `EXTCODEHASH`, `BLOBHASH`, `BLOBBASEFEE`, `TLOAD`, `TSTORE`, `MCOPY`, `DELEGATECALL`, `CREATE2` y `STATICCALL`; los handlers externos reciben un presupuesto de gas validado y los fallos revierten sus cambios de estado.
- Compilador/decompilador modular: los saltos con operandos se normalizan como `PUSHn` más salto, las etiquetas usan offsets absolutos y los inmediatos fuera de rango se rechazan sin truncamiento.
- P1: listener TCP real en la red modular, handshake `hello`, respuestas `ping/pong`, consulta de bloques y recepción de transacciones mediante JSON-lines; se eliminaron peers, bloques, pings y conexiones simuladas.
- Dependencias opcionales del wallet: las funciones estándar y multisig no requieren `bip32`; las HD muestran un error explícito si falta ese paquete.
- Monolito legado: RLP tipado para `int`, `None`, strings y diccionarios; trie con resolución correcta de hojas/extensiones, snapshots, rollback y verificación estructural de proofs.

### Pruebas

- `python p0_regression_tests.py`: 5 pruebas correctas.
- `python p1_regression_tests.py`: 8 pruebas correctas.
- `python -m unittest p1_regression_tests.P1RegressionTests.test_vm_modern_opcodes_handlers_and_limits -v`: correcto.
- `python -m unittest p1_regression_tests.P1RegressionTests.test_vm_extended_opcode_surface -v`: correcto.
- `python -X utf8 security_tests.py`: 7 pruebas correctas.
- `python -X utf8 architecture_tests.py`: 10 pruebas correctas.
- `python -m compileall -q .`: correcto.
- `git diff --check`: correcto.

### Limitaciones conocidas

- El entrypoint modular es `msc_network_main.py`. `mscnet_blockchain.py` es un monolito legado separado y no comparte automáticamente estas correcciones.
- La VM implementa un subconjunto de opcodes; no debe describirse como una EVM completa.
- `0xf2` es la extensión MSC `SECURE_CALL`, por lo que `CALLCODE` no se expone en esa misma ranura; la compatibilidad EVM completa no es un objetivo de esta VM personalizada.
- La minería modular verificada aplica transferencias, consume el pool y acredita fees; todavía no existe un subsistema separado de minería de uso ni ejecución completa de contratos dentro del bloque.
- El transporte P2P modular tiene listener y mensajes JSON-lines, pero todavía requiere autenticación criptográfica de identidad y un protocolo completo de sincronización/validación de bloques para producción.
