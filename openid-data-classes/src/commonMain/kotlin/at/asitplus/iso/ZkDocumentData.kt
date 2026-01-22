package at.asitplus.iso

import kotlinx.serialization.Contextual
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborLabel
import kotlin.time.Instant

@Serializable
data class ZkDocumentData (
    @SerialName("docType")
    val docType: String,
    @SerialName("zkSystemId")
    val zkSystemId: String,
    @SerialName("timestamp")
    val timestamp: Instant,
    @SerialName("issuerSigned")
    @Serializable(with = NamespacedZkSignedListSerializer::class)
    val issuerSigned: Map<String, @Contextual ZkSignedList>? = null,
    @SerialName("deviceSigned")
    @Serializable(with = NamespacedZkSignedListSerializer::class)
    val deviceSigned: Map<String, @Contextual ZkSignedList>? = null,
    /**
     * This header parameter contains an ordered array of X.509 certificates. The certificates are to be ordered
     * starting with the certificate containing the end-entity key followed by the certificate that signed it, and so
     * on. There is no requirement for the entire chain to be present in the element if there is reason to believe that
     * the relying party already has, or can locate, the missing certificates. This means that the relying party is
     * still required to do path building but that a candidate path is proposed in this header parameter.
     *
     * This header parameter allows for a single X.509 certificate or a chain of X.509 certificates to be carried in
     * the message.
     *
     * See [RFC9360](https://www.rfc-editor.org/rfc/rfc9360.html)
     */
    @CborLabel(33)
    @SerialName("msoX5chain")
    @ByteString
    val certificateChain: List<ByteArray>? = null,
)