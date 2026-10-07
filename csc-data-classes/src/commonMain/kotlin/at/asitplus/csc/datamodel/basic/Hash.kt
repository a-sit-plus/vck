package at.asitplus.csc.datamodel.basic

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.ObjectIdentifierStringSerializer
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import io.ktor.util.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient


/**
 * CSC Data Model 1.0.0 section 7.4: REQUIRED
 * Structured hash containing a Base64-encoded digest and its algorithm OID. Its JSON form is an object, for example
 * `{"value":"BwgJ","algorithmOID":"2.16.840.1.101.3.4.2.1"}`.
 *
 * CSC Data Model Bindings 1.0.0 section 6.2.1 uses an SRI string for `qesRequest.checksum`;
 * ETSI TS 119 432 Annex A uses the structured object.
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
    val digest: Digest = WellKnownDigest.entries.first { it.oid == algorithmOid }

    init {
        require(value.isNotEmpty()) { "value must not be empty" }
    }

    override fun equals(other: Any?): Boolean =
        this === other || other is Hash && value.contentEquals(other.value) && algorithmOid == other.algorithmOid

    override fun hashCode(): Int = 31 * value.contentHashCode() + algorithmOid.hashCode()
}
