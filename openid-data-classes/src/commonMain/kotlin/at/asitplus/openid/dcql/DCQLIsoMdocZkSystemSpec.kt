package at.asitplus.openid.dcql

import at.asitplus.iso.ZkSystemSpec
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Proposed DCQL ZK System Specification for OpenID4VP requests targeting ISO mDoc zero-knowledge proofs
 * See: https://google.github.io/longfellow-zk/docs/protocols/
 */
@Serializable
data class DCQLIsoMdocZkSystemSpec (
    @SerialName(PROP_ID)
    val id: String,

    @SerialName(PROP_SYSTEM)
    val system: String,

    @SerialName(PROP_CIRCUIT_HASH)
    val circuitHash: String,

    @SerialName(PROP_NUM_ATTRIBUTES)
    val numAttributes: Long,

    @SerialName(PROP_VERSION)
    val version: Long,

    @SerialName(PROP_BLOCK_ENC_HASH)
    val blockEncHash: Long? = null,

    @SerialName(PROP_BLOCK_ENC_SIG)
    val blockEncSig: Long? = null,
) {
    fun toZkSystemSpec() = ZkSystemSpec(
        id = id,
        system = system,
        params = buildMap {
            put(PROP_CIRCUIT_HASH, circuitHash)
            put(PROP_NUM_ATTRIBUTES, numAttributes)
            put(PROP_VERSION, version)

            blockEncHash?.let{ put(PROP_BLOCK_ENC_HASH, it) }
            blockEncSig?.let{ put(PROP_BLOCK_ENC_SIG, it) }
        }
    )

    companion object {
        const val PROP_ID = "id"
        const val PROP_SYSTEM = "system"
        const val PROP_CIRCUIT_HASH = "circuit_hash"
        const val PROP_NUM_ATTRIBUTES = "num_attributes"
        const val PROP_VERSION = "version"
        const val PROP_BLOCK_ENC_HASH = "block_enc_hash"
        const val PROP_BLOCK_ENC_SIG = "block_enc_sig"
    }
}