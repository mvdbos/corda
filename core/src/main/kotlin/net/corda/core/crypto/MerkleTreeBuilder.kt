package net.corda.core.crypto

import net.corda.core.contracts.ComponentGroupEnum
import net.corda.core.contracts.PrivacySalt
import net.corda.core.transactions.ComponentGroup
import net.corda.core.transactions.WireTransaction
import net.corda.core.utilities.OpaqueBytes
import java.nio.ByteBuffer

class MerkleTreeBuilder(wtx: WireTransaction, private val componentGroupLeafDigestService: DigestService, private val nodeDigestService: DigestService) {
    private val componentGroups: List<ComponentGroup> = wtx.componentGroups
    private val privacySalt: PrivacySalt = wtx.privacySalt

    constructor(wtx: WireTransaction): this(wtx, DefaultDigestServiceFactory.getService(Algorithm.SHA256()))
    constructor(wtx: WireTransaction, digestService: DigestService): this(wtx, digestService, digestService)

    /**
     * Builds whole Merkle tree for a transaction.
     * Each transaction component group has its own sub Merkle tree.
     * All of the roots of these trees are used as leaves in the top level Merkle tree.
     *
     * Note that ordering of elements inside a [ComponentGroup] matters when computing the Merkle root.
     * On the other hand, insertion group ordering does not affect the top level Merkle tree construction, as it is
     * actually an ordered Merkle tree, where its leaves are ordered based on the group ordinal in [ComponentGroupEnum].
     * If any of the groups is an empty list or a null object, then [SecureHash.allOnesHash] is used as its hash.
     * Also, [privacySalt] is not a Merkle tree leaf, because it is already "inherently" included via the component nonces.
     */
    fun build(): MerkleTree {
        return MerkleTree.getMerkleTree(groupHashes, nodeDigestService)
    }

    /**
     * The leaves (group hashes) of the top level Merkle tree.
     * If a group's Merkle root is allOnesHash, it is a flag that denotes this group is empty (if list) or null (if single object)
     * in the wire transaction.
     */
    private val groupHashes: List<SecureHash> by lazy {
        val listOfLeaves = mutableListOf<SecureHash>()
        // Even if empty and not used, we should at least send oneHashes for each known
        // or received but unknown (thus, bigger than known ordinal) component groups.
        for (i in 0..componentGroups.map { it.groupIndex }.max()!!) {
            val root = componentGroupsMerkleTrees[i] ?: nodeDigestService.allOnesHash
            listOfLeaves.add(root)
        }
        listOfLeaves
    }

    /**
     * Calculate the hashes of the existing component groups, that are used to build the transaction's Merkle tree.
     * Each group has its own sub Merkle tree and the hash of the root of this sub tree works as a leaf of the top
     * level Merkle tree. The root of the latter is the transaction identifier.
     */
    private val componentGroupsMerkleTrees: Map<Int, SecureHash> by lazy {
        // TODO: switch this over to Pedersen Hashes
        componentHashesPerComponentGroup.map { Pair(it.key, MerkleTree.getMerkleTree(it.value, nodeDigestService, componentGroupLeafDigestService).hash) }.toMap()
    }

    /**
     * Calculate hashes for every transaction component. These will be used to build the full Merkle tree.
     * The root of the tree is the transaction identifier. The tree structure is helpful for privacy, please
     * see the user-guide section "Transaction tear-offs" to learn more about this topic.
     */
    private val componentHashesPerComponentGroup: Map<Int, List<SecureHash>> by lazy {
        componentGroups.map { group ->
            Pair(
                    group.groupIndex,
                    group.components.mapIndexed { componentIndex, component ->
                        componentHash(componentNonce(component, privacySalt, group.groupIndex, componentIndex), component)
                    })
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