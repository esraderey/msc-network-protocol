# Esquema de Especificación Formal - MSC Ledger Protocol

Este documento describe el diseño inicial y los componentes clave propuestos para el protocolo MSC Ledger, basado en los principios del Marco de Síntesis Colectiva (MSC) y destinado a ejecutarse inicialmente sobre Arbitrum.

## 1. Estructuras de Datos On-Chain (Conceptuales)

Se propone almacenar la información esencial del grafo directamente on-chain para verificación y procesamiento por la STF. El contenido completo residiría off-chain (ej. IPFS), referenciado por su hash.

### 1.1. Nodo (KnowledgeComponent - V')

Podría almacenarse en un mapeo principal, ej: `mapping(uint256 => NodeData) public nodes;`

```solidity
// Estructura conceptual en estilo Solidity
struct NodeData {
    uint256 id;             // ID único del nodo
    bytes32 contentHash;    // Hash del contenido almacenado off-chain (ej. IPFS CID v1 en base32 -> bytes32)
    uint256 state;          // Estado/Confianza (sj), ej: entero representando valor con 18 decimales (0 a 1 * 10**18)
    bytes32[] keywordsHash; // Hashes keccak256 de keywords indexables (alternativa a string[])
    uint256 creationTimestamp; // Marca de tiempo de creación (block.timestamp)
    address creator;        // Dirección del creador
    uint256 lastUpdateTimestamp; // Marca de tiempo de la última actualización de estado
    // Almacenamiento de conexiones TBD (aquí o por separado)
}
Notas sobre Nodo:

Usar uint256 para IDs, timestamps, estado escalado.
state escalado (ej. 10^18) permite aritmética de precisión fija on-chain.
contentHash permite verificación de integridad del contenido off-chain.
El manejo eficiente de keywordsHash on-chain requiere diseño cuidadoso (coste de gas).
1.2. Arista (SynthesisRelationship - E')
Podrían almacenarse en mapeos separados/anidados para eficiencia en lectura/escritura, ej: mapping(uint256 => mapping(uint256 => EdgeData)) public edges; (sourceId -> targetId -> Data).

Solidity

// Estructura conceptual en estilo Solidity
struct EdgeData {
    // IDs source/target implícitos si se usa mapeo anidado.
    int256 utility;         // Utilidad (uij), ej: entero con signo escalado a 18 decimales.
    uint256 creationTimestamp;
    address creator;
    uint256 lastUpdateTimestamp; // Última evaluación de utilidad
}
Notas sobre Arista:

utility escalado permite valores positivos y negativos.
El diseño exacto del almacenamiento (mapeos vs. listas) impacta el coste de gas de las operaciones del grafo.
2. Tipos de Transacciones MSC Principales
Estas son las operaciones fundamentales que los usuarios/agentes enviarían a la red.

proposeNode(bytes32 _contentHash, bytes32[] calldata _keywordsHash, uint256 _initialState)

Crea un nuevo nodo V' con el contenido (off-chain) referenciado por _contentHash.
Asigna keywords iniciales (hashes) y un estado inicial (limitado).
Registra al msg.sender como creador.
proposeEdge(uint256 _sourceId, uint256 _targetId, int256 _initialUtility)

Crea una nueva arista E' entre dos nodos existentes.
Asigna una utilidad inicial (limitada).
Registra al msg.sender como creador.
evaluateNode(uint256 _nodeId, bytes calldata _evaluationData)

Inicia un proceso (potencialmente complejo) para re-evaluar el estado sj del nodo _nodeId.
_evaluationData podría contener evidencia, referencias a otros nodos, o parámetros para la lógica de evaluación. La STF interpreta esto.
evaluateEdge(uint256 _sourceId, uint256 _targetId, bytes calldata _evaluationData)

Similar a evaluateNode, pero para re-evaluar la utilidad uij de una arista existente.
combineNodes(uint256 _nodeA_Id, uint256 _nodeB_Id, bytes calldata _combinationParams)

Inicia un proceso para intentar crear nuevas conexiones o incluso nodos basados en la combinación/compatibilidad de A y B. La STF interpreta los _combinationParams.
refuteNode(uint256 _nodeId, bytes calldata _refutationData)

Inicia un proceso para marcar un nodo como obsoleto o incorrecto, afectando negativamente su estado sj.
(Otras Potenciales): addKeywordToNode, updateNodeContentHash, delegateEvaluation, etc.

3. Descripción de Alto Nivel de la Función de Transición de Estado (STF)
La STF define cómo cada transacción MSC modifica el estado del grafo on-chain.

Para proposeNode:

Validar inputs (ej. ¿_initialState dentro de límites?).
Verificar que contentHash no esté ya asociado a otro nodo (opcional).
Asignar nuevo nodeId.
Crear y almacenar la nueva NodeData en el mapeo nodes.
Emitir evento NodeProposed.
Calcular y cobrar gas.
Para proposeEdge:

Validar inputs (ej. ¿existen _sourceId, _targetId? ¿son diferentes? ¿_initialUtility en límites?).
Verificar que la arista no exista ya.
Crear y almacenar la nueva EdgeData en el mapeo edges.
Emitir evento EdgeProposed.
Calcular y cobrar gas.
Para evaluateNode (Esquema Complejo):

Validar inputs y permisos del msg.sender.
Leer estado actual del _nodeId.
Leer estado/utilidad de nodos/aristas vecinas relevantes (puede requerir múltiples lecturas SLOAD, potencialmente costoso o requerir índices/cachés).
Ejecutar Lógica de Evaluación: Esta es la parte más compleja.
Opción Simplificada: Lógica muy básica on-chain (ej. promedio ponderado simple, como en la simulación). -> Gas predecible pero limitada.
Opción Híbrida/Oráculo: La transacción on-chain registra la solicitud. Un proceso off-chain (ejecutado por validadores o un servicio descentralizado) realiza el cálculo complejo (considerando decay, keywords, inconsistencias, etc.) y envía el resultado de vuelta en una transacción posterior o mediante un mecanismo de oráculo. -> Más potente pero más compleja arquitectónicamente.
Calcular el nuevo state (sj).
Validar que el nuevo state esté en rango [0, 1 * 10**18].
Actualizar NodeData en el mapeo nodes (escritura SSTORE).
Actualizar lastUpdateTimestamp.
Emitir evento NodeEvaluated.
Calcular y cobrar gas (potencialmente alto o variable si la lógica es compleja).
(Lógica similar para evaluateEdge, combineNodes, refuteNode, adaptando las lecturas, cómputo y escrituras correspondientes).

4. Interacción Estado On-Chain / Almacenamiento Off-Chain
On-Chain: Se almacena la estructura del grafo (quién conecta con quién), los estados de confianza/calidad (sj), las utilidades de las relaciones (uij), los hashes de contenido, y metadatos esenciales (timestamps, creadores). Esto es lo verificable y sobre lo que opera la STF.
Off-Chain (ej. IPFS): Se almacena el contenido completo de cada KnowledgeComponent (texto, datos, código, imágenes, etc.). Inmutable gracias al direccionamiento por contenido.
Flujo:
Un agente propone un nodo on-chain con el contentHash del contenido previamente subido a IPFS.
Otros agentes/usuarios pueden leer el contentHash on-chain.
Usan el contentHash para recuperar el contenido completo desde la red IPFS (usando un gateway IPFS o un cliente local).
Realizan su evaluación/análisis off-chain basándose en el contenido completo.
Envían una transacción evaluateNode on-chain con el resultado o la evidencia necesaria para que la STF (o el proceso híbrido) actualice el estado sj on-chain.
5. Requisitos Iniciales para Nodos Validadores
Los nodos que validan transacciones y participan en el consenso (PoS + Ψ) necesitarán cumplir requisitos mínimos (a definir con más detalle):

Stake $SYNTH: Una cantidad mínima significativa para incentivar el comportamiento honesto (sujeta a slashing).
Reputación Ψ (Futuro): Potencialmente, un umbral mínimo de reputación on-chain para poder ser elegido como validador.
Hardware:
CPU: Suficiente para ejecutar la STF (que incluye lógica MSC) eficientemente. (TBD)
RAM: Suficiente para mantener en memoria partes relevantes del estado del grafo/shard. (TBD)
Almacenamiento: Espacio para almacenar el estado de la blockchain (creciente). SSD recomendado. (TBD)
Ancho de Banda: Conexión de red fiable y rápida para sincronización P2P. (TBD)
Software: Cliente MSC Ledger, conexión a red IPFS (opcionalmente, nodo IPFS propio), software de nodo de la L2 subyacente (Arbitrum).