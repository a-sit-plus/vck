@file:UseSerializers(UrlSerializer::class)

package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.vckCborSerializer
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/**
 * Implements "Transaction Data entries as defined in D3.1: UC Specification WP3"
 * leveraging upcoming changes to OpenID4VP `https://github.com/openid/OpenID4VP/pull/197`
 */
interface TransactionDataEntry {
    val type: String
}
@Serializable
data class QesAuthorization(
    val signatureQualifier: String? = null,
    val credentialId: String? = null,
    val documentDigest: List<DocumentDigestEntry>,
    val processID: String? = null,
) : TransactionDataEntry {
    override val type: String = "qes_authorization"
    /**
     * Summary for the conditionally required parameters (informational)
     * If in each of the following bullet points one of the mentioned parameters is
     * present, the other must be present:
     *  “hash” and “hashAlgorithmOID”
     *  “documentLocation_uri” and “documentLocation_method”
     *  “dtbsr” and “dtbsrHashAlgorithmOID”
     * In each of the following bullet points at least one of the mentioned
     * parameters must be present:
     *  “signatureQualifier” or “credentialID”
     *  “hash” or “dtbsr”
     * If “document_access_mode” is “OTP”, “oneTimePassword” must be
     * present.
     */
    @Serializable
    data class DocumentDigestEntry(
        val label: String,
        val hash: String? = null, // base64 encoded octet representatoin using "hashAlgorithmOID"
        val hashAlgorithmOid: String? = null, // REQUIRED if hash is present
        val documentLocationUri: Url? = null, // If set hash is REQUIRED
        val documentLocationMethod: DocumentLocationMethod? = null, // MUST NOT be present if documentLocationUri is null
        val dtbsr: String? = null, // contains data to be signed, either hash or this MUST be present, both MAY be present
        val dtbsrHashAlgorithmOid: String? = null, //REQUIRED if dtbsr present, if dtbsr not present MUST NOT be present
    )

    @Serializable
    data class DocumentLocationMethod(
        val documentAccessMode: String,
        val oneTimePassword: String? = null, //REQUIRED if documentAccessMode == OTP
    )
}

@Serializable
data class QCertCreationAcceptance(
    val qcTermsConditionsUri: String,
    val qcHash: String,
    val qcHashAlgorithmOID: String,
) : TransactionDataEntry {
    override val type: String = "qcert_creation_acceptance"
}


/**
 * According to "Transaction Data entries as defined in D3.1: UC Specification WP3" the encoding
 * is JSON and every entry is serialized to a base64 encoded string
 */
object TransactionDataEntrySerializer : KSerializer<TransactionDataEntry> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("TransactionDataEntrySerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: TransactionDataEntry) {
        val jsonString = vckJsonSerializer.encodeToString(PolymorphicSerializer(TransactionDataEntry::class), value)
        val base64String = jsonString.encodeBase64()
        encoder.encodeString(base64String)
    }

    override fun deserialize(decoder: Decoder): TransactionDataEntry {
        val base64String = decoder.decodeString()
        val jsonString = base64String.decodeBase64String()
        return vckJsonSerializer.decodeFromString(PolymorphicSerializer(TransactionDataEntry::class), jsonString)
    }
}

object UrlSerializer : KSerializer<Url> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("UrlSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Url = Url(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: Url) {
        encoder.encodeString(value.toString())
    }

}