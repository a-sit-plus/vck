package at.asitplus.csc.bindings

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer


/**
 * CSC Data Model Bindings 1.0.0 section 6.2.2: CONDITIONAL
 * Return the representation required by the signature format when no responseURI is specified; omit both fields
 * when the response is sent to responseURI.
 */
@Serializable
data class QesResponse(
    /**
     * CSC Data Model Bindings 1.0.0 section 6.2.2: CONDITIONAL
     * Required when signatures are embedded in the document and no responseURI is specified; otherwise omit.
     */
    @SerialName("documentWithSignature")
    @Serializable(with = Base64ByteArrayListSerializer::class)
    val documentWithSignature: List<ByteArray>? = null,
    /**
     * CSC Data Model Bindings 1.0.0 section 6.2.2: CONDITIONAL
     * Required for detached or enveloping signatures when no responseURI is specified; otherwise omit.
     */
    @SerialName("signatureObject")
    @Serializable(with = Base64ByteArrayListSerializer::class)
    val signatureObject: List<ByteArray>? = null,
) {
    override fun equals(other: Any?): Boolean = other is QesResponse &&
            documentWithSignature.byteListsEqual(other.documentWithSignature) &&
            signatureObject.byteListsEqual(other.signatureObject)

    override fun hashCode(): Int = 31 * (documentWithSignature?.fold(1) { a, b -> 31 * a + b.contentHashCode() } ?: 0) +
            (signatureObject?.fold(1) { a, b -> 31 * a + b.contentHashCode() } ?: 0)
}

private fun List<ByteArray>?.byteListsEqual(other: List<ByteArray>?): Boolean = when {
    this === other -> true
    this == null || other == null || size != other.size -> false
    else -> indices.all { this[it].contentEquals(other[it]) }
}

private object Base64ByteArrayListSerializer :
    KSerializer<List<ByteArray>> by ListSerializer(ByteArrayBase64Serializer)
