package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

@Serializable
data class DocRequestInfo(
    @SerialName("issuerIdentifiers")
    @ByteString
    val issuerIdentifiers: List<ByteArray>? = null,
    @SerialName("uniqueDocSetRequired")
    val uniqueDocSetRequired: Boolean? = null,
    @SerialName("maximumResponseSize")
    val maximumResponseSize: UInt? = null,
    @SerialName("zkRequest")
    val zkRequest: ZkRequest? = null,
    @SerialName("docResponseEncryption")
    val docResponseEncryption: EncryptionParameters? = null,
    // TODO: Implement alternativeDataElements
)
