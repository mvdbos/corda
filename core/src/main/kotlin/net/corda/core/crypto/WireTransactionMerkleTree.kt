package net.corda.core.crypto

import net.corda.core.contracts.ComponentGroupEnum
import net.corda.core.contracts.PrivacySalt
import net.corda.core.transactions.ComponentGroup
import net.corda.core.transactions.WireTransaction
import net.corda.core.utilities.OpaqueBytes
import java.nio.ByteBuffer

interface TransactionMerkleTree {
    val root: SecureHash

    /**
     * The full Merkle tree for a transaction.
     * Each transaction component group has its own sub Merkle tree.
     * All of the roots of these trees are used as leaves in the top level Merkle tree.
     *
     * Note that ordering of elements inside a [ComponentGroup] matters when computing the Merkle root.
     * On the other hand, insertion group ordering does not affect the top level Merkle tree construction, as it is
     * actually an ordered Merkle tree, where its leaves are ordered based on the group ordinal in [ComponentGroupEnum].
     * If any of the groups is an empty list or a null object, then [SecureHash.allOnesHash] is used as its hash.
     * Also, [privacySalt] is not a Merkle tree leaf, because it is already "inherently" included via the component nonces.
     */
    val tree: MerkleTree
}

class WireTransactionMerkleTree(wtx: WireTransaction, val componentGroupLeafDigestService: DigestService, val nodeDigestService: DigestService) : TransactionMerkleTree {
    private val componentGroups: List<ComponentGroup> = wtx.componentGroups
    private val privacySalt: PrivacySalt = wtx.privacySalt

    constructor(wtx: WireTransaction) : this(wtx, DefaultDigestServiceFactory.getService(Algorithm.SHA256d()))
    constructor(wtx: WireTransaction, digestService: DigestService) : this(wtx, digestService, digestService)

    override val root: SecureHash get() = tree.hash

    override val tree: MerkleTree by lazy { MerkleTree.getMerkleTree(groupHashes, nodeDigestService) }

    /**
     * For each component group: the root hashes of the sub Merkle tree for that component group
     *
     * If a group's Merkle root is allOnesHash, it is a flag that denotes this group is empty (if list) or null (if single object)
     * in the wire transaction.
     */
    internal val groupHashes: List<SecureHash> by lazy {
        val listOfLeaves = mutableListOf<SecureHash>()
        // Even if empty and not used, we should at least send oneHashes for each known
        // or received but unknown (thus, bigger than known ordinal) component groups.
        for (i in 0..componentGroups.map { it.groupIndex }.max()!!) {
            val root = groupsMerkleRoots[i] ?: nodeDigestService.allOnesHash
            listOfLeaves.add(root)
        }
        listOfLeaves
    }

    /**
     * Calculate the hashes of the existing component groups, that are used to build the transaction's Merkle tree.
     * Each group has its own sub Merkle tree and the hash of the root of this sub tree works as a leaf of the top
     * level Merkle tree. The root of the latter is the transaction identifier.
     *
     * The tree structure is helpful for preserving privacy, please
     * see the user-guide section "Transaction tear-offs" to learn more about this topic.
     */
    internal val groupsMerkleRoots: Map<Int, SecureHash> by lazy {
        availableComponentHashes.map { Pair(it.key, MerkleTree.getMerkleTree(it.value, nodeDigestService = nodeDigestService, leafDigestService = componentGroupLeafDigestService).hash) }
                .toMap()
    }

    /**
     * Calculate nonces for every transaction component, including new fields (due to backwards compatibility support) we cannot process.
     * Nonce are computed in the following way:
     * nonce1 = H(salt || path_for_1st_component)
     * nonce2 = H(salt || path_for_2nd_component)
     * etc.
     * Thus, all of the nonces are "independent" in the sense that knowing one or some of them, you can learn
     * nothing about the rest.
     */
    internal val availableComponentNonces: Map<Int, List<SecureHash>> by lazy {
        componentGroups.map {
            Pair(
                    it.groupIndex,
                    it.components.mapIndexed { componentIndex, component -> componentNonce(component, privacySalt, it.groupIndex, componentIndex) }
            )
        }.toMap()
    }

    /**
     * Calculate hashes for every transaction component. These will be used to build the full Merkle tree.
     * The root of the tree is the transaction identifier. The tree structure is helpful for privacy, please
     * see the user-guide section "Transaction tear-offs" to learn more about this topic.
     */
    internal val availableComponentHashes: Map<Int, List<SecureHash>> by lazy {
        componentGroups.map {
            Pair(
                    it.groupIndex,
                    it.components.mapIndexed { componentIndex, component -> componentHash(availableComponentNonces[it.groupIndex]!![componentIndex], component) }
            )
        }.toMap()
    }

    /**
     * Compute the hash of each serialised component so as to be used as Merkle tree leaf. The resultant output (leaf) is
     * calculated using the SHA256d algorithm, thus SHA256(SHA256(nonce || serializedComponent)), where nonce is computed
     * from [computeNonce].
     *
     * TODO: Why is the nonce hashed again? Because this function is only used for the nonce. Can't change it now, for the normal tx id, because compatibily, but we may not need to do it for our additional merkle tree.
     */
    private fun componentNonce(opaqueBytes: OpaqueBytes, privacySalt: PrivacySalt, componentGroupIndex: Int, internalIndex: Int): SecureHash =
            componentHash(computeNonce(privacySalt, componentGroupIndex, internalIndex), opaqueBytes)

    /** Return the SHA256(SHA256(nonce || serializedComponent)). */
    private fun componentHash(nonce: SecureHash, opaqueBytes: OpaqueBytes): SecureHash = componentGroupLeafDigestService.hash(nonce.bytes + opaqueBytes.bytes, true)

    /**
     * Method to compute a nonce based on privacySalt, component group index and component internal index.
     * SHA256d (double SHA256) is used to prevent length extension attacks.
     * @param privacySalt a [PrivacySalt].
     * @param groupIndex the fixed index (ordinal) of this component group.
     * @param internalIndex the internal index of this object in its corresponding components list.
     * @return SHA256(SHA256(privacySalt || groupIndex || internalIndex))
     */
    private fun computeNonce(privacySalt: PrivacySalt, groupIndex: Int, internalIndex: Int) = componentGroupLeafDigestService.hash(privacySalt.bytes + ByteBuffer.allocate(8)
            .putInt(groupIndex).putInt(internalIndex).array(), true)
}