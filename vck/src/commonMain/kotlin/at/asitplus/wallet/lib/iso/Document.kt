package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class Document(
    @SerialName("docType")
    val docType: String, // this is relevant for deserializing the elementValue of IssuerSignedItem
    @SerialName("issuerSigned")
    val issuerSigned: IssuerSigned,
    @SerialName("deviceSigned")
    val deviceSigned: DeviceSigned,
    @SerialName("errors")
    val errors: Map<String, Map<String, Int>>? = null,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Document) return false

        if (docType != other.docType) return false
        if (issuerSigned != other.issuerSigned) return false
        if (deviceSigned != other.deviceSigned) return false
        if (errors != other.errors) return false

        return true
    }

    override fun hashCode(): Int {
        var result = docType.hashCode()
        result = 31 * result + issuerSigned.hashCode()
        result = 31 * result + deviceSigned.hashCode()
        result = 31 * result + (errors?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<Document>(it)
        }.wrap()
    }
}