package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.*

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class IssuerSigned private constructor(
    @SerialName("nameSpaces")
    @Serializable(with = NamespacedIssuerSignedListSerializer::class)
    val namespaces: Map<String, @Contextual IssuerSignedList>? = null,
    @SerialName("issuerAuth")
    val issuerAuth: CoseSigned,
) {

    constructor(
        namespacedItems: Map<String, List<IssuerSignedItem>>,
        issuerAuth: CoseSigned,
        tag: Byte? = null
    ) : this(
        issuerAuth = issuerAuth,
        namespaces = namespacedItems.map { (ns, value) ->
            ns to IssuerSignedList(
                value.map { item ->
                    ByteStringWrapper(
                        item,
                        item.serialize(ns).let { tag?.let { tg -> it.wrapInCborTag(tg) } ?: it })
                })
        }.toMap()
    )

    fun getIssuerAuthPayloadAsMso() = issuerAuth.payload?.stripCborTag(24)
        ?.let { vckCborSerializer.decodeFromByteArray(ByteStringWrapperMobileSecurityObjectSerializer, it).value }

    fun serialize() = vckCborSerializer.encodeToByteArray(this)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IssuerSigned) return false

        if (issuerAuth != other.issuerAuth) return false
        if (namespaces != other.namespaces) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuerAuth.hashCode()
        result = 31 * result + (namespaces?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<IssuerSigned>(it)
        }.wrap()
    }
}