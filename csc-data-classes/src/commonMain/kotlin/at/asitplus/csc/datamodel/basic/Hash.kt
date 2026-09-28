package at.asitplus.csc.datamodel.basic

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** A Base64-encoded digest and the OID of the algorithm used to create it. */
@Serializable
data class Hash(
    @SerialName("value")
    @Serializable(with = ByteArrayBase64Serializer::class)
    val value: ByteArray,
    @SerialName("algorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val algorithmOid: ObjectIdentifier,
) {
    init {
        require(value.isNotEmpty()) { "value must not be empty" }
    }

    fun toDigestOrNull(): Digest? = Digest.entries.firstOrNull { it.oid == algorithmOid }

    override fun equals(other: Any?): Boolean =
        this === other || other is Hash && value.contentEquals(other.value) && algorithmOid == other.algorithmOid

    override fun hashCode(): Int = 31 * value.contentHashCode() + algorithmOid.hashCode()
}