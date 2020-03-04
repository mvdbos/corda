package net.corda.core.crypto

import net.corda.core.contracts.ComponentGroupEnum
import net.corda.core.contracts.PrivacySalt
import net.corda.core.transactions.ComponentGroup

class MerkleTreeBuilder(componentGroups: List<ComponentGroup>, privacySalt: PrivacySalt, digestService: DigestService) {
        /**
         * Builds whole Merkle tree for a transaction.
         * Briefly, each component group has its own sub Merkle tree and all of the roots of these trees are used as leaves
         * in a top level Merkle tree.
         * Note that ordering of elements inside a [ComponentGroup] matters when computing the Merkle root.
         * On the other hand, insertion group ordering does not affect the top level Merkle tree construction, as it is
         * actually an ordered Merkle tree, where its leaves are ordered based on the group ordinal in [ComponentGroupEnum].
         * If any of the groups is an empty list or a null object, then [SecureHash.allOnesHash] is used as its hash.
         * Also, [privacySalt] is not a Merkle tree leaf, because it is already "inherently" included via the component nonces.
         */
        fun getMerkleTreeForComponentGroups(componentGroups: List<ComponentGroup>, digestService: DigestService): MerkleTree {
            return MerkleTree.getMerkleTree(groupHashes)
        }

    /**
     * The leaves (group hashes) of the top level Merkle tree.
     * If a group's Merkle root is allOnesHash, it is a flag that denotes this group is empty (if list) or null (if single object)
     * in the wire transaction.
     */
    internal val groupHashes: List<SecureHash> by lazy {
        val listOfLeaves = mutableListOf<SecureHash>()
        // Even if empty and not used, we should at least send oneHashes for each known
        // or received but unknown (thus, bigger than known ordinal) component groups.
        for (i in 0..componentGroups.map { it.groupIndex }.max()!!) {
            val root = groupsMerkleRoots[i] ?: SecureHash.allOnesHash
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
        availableComponentHashes.map { Pair(it.key, MerkleTree.getMerkleTree(it.value).hash) }.toMap()
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
        componentGroups.map { Pair(it.groupIndex, it.components.mapIndexed { internalIndex, internalIt -> componentHash(internalIt, privacySalt, it.groupIndex, internalIndex) }) }.toMap()
    }

    /**
     * Calculate hashes for every transaction component. These will be used to build the full Merkle tree.
     * The root of the tree is the transaction identifier. The tree structure is helpful for privacy, please
     * see the user-guide section "Transaction tear-offs" to learn more about this topic.
     */
    internal val availableComponentHashes: Map<Int, List<SecureHash>> by lazy {
        componentGroups.map { Pair(it.groupIndex, it.components.mapIndexed { internalIndex, internalIt -> componentHash(availableComponentNonces[it.groupIndex]!![internalIndex], internalIt) }) }.toMap()
    }

}