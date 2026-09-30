package at.asitplus.csc.datamodel.basic

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import io.ktor.util.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient


/**
 * CSC Data Model 1.0.0 section 7.4: REQUIRED
 * Structured hash containing a digest and its algorithm OID.
 *
 * CSC Data Model Bindings 1.0.0 section 6.2.1 uses an SRI string for `qesRequest.checksum`; ETSI TS 119 432 Annex A
 * uses this structured object.
 */
@Serializable
data class Hash(
    /**
     * CSC Data Model 1.0.0 section 7.4: REQUIRED
     * Digest value, encoded as Base64.
     */
    @SerialName("value")
    @Serializable(with = ByteArrayBase64Serializer::class)
    val value: ByteArray,
    /**
     * CSC Data Model 1.0.0 section 7.4: REQUIRED
     * Object identifier of the digest algorithm.
     */
    @SerialName("algorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val algorithmOid: ObjectIdentifier,
) {
    @Transient
    val digest: Digest? = Digest.entries.find { it.oid == algorithmOid }

    init {
        require(value.isNotEmpty()) { "value must not be empty" }
    }

    fun toDigestOrNull(): Digest? = digest

    override fun equals(other: Any?): Boolean =
        this === other || other is Hash && value.contentEquals(other.value) && algorithmOid == other.algorithmOid

    override fun hashCode(): Int = 31 * value.contentHashCode() + algorithmOid.hashCode()
}
