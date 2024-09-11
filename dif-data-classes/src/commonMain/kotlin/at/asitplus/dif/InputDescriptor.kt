@file:UseSerializers(InputDescriptorSerializer::class)

package at.asitplus.dif

import at.asitplus.dif.rqes.Serializer.Base64URLTransactionDataSerializer
import at.asitplus.dif.rqes.CollectionEntries.TransactionData
import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

@Serializable(with = InputDescriptorSerializer::class)
sealed interface InputDescriptor {
    val id: String
    val group: String?
    val name: String?
    val purpose: String?
    val format: FormatHolder?
    val constraints: Constraint?
}

/**
 * Data class for
 * [DIF Presentation Exchange v2.1.1](https://identity.foundation/presentation-exchange/spec/v2.1.1/#term:presentation-definition)
 */
@Serializable
data class DifInputDescriptor(
    @SerialName("id")
    override val id: String,
    @SerialName("group")
    override val group: String? = null,
    @SerialName("name")
    override val name: String? = null,
    @SerialName("purpose")
    override val purpose: String? = null,
    @SerialName("format")
    override val format: FormatHolder? = null,
    @SerialName("constraints")
    override val constraints: Constraint? = null,
) : InputDescriptor {
    constructor(name: String, constraints: Constraint? = null) : this(
        id = uuid4().toString(),
        name = name,
        constraints = constraints,
    )
}

@Serializable
data class QesInputDescriptor(
    @SerialName("id")
    override val id: String,
    @SerialName("group")
    override val group: String? = null,
    @SerialName("name")
    override val name: String? = null,
    @SerialName("purpose")
    override val purpose: String? = null,
    @SerialName("format")
    override val format: FormatHolder? = null,
    @SerialName("constraints")
    override val constraints: Constraint? = null,
    @SerialName("transaction_data")
    val transactionData: List<@Serializable(Base64URLTransactionDataSerializer::class) TransactionData>,
) : InputDescriptor


object InputDescriptorSerializer : JsonContentPolymorphicSerializer<InputDescriptor>(InputDescriptor::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "transaction_data" in element.jsonObject -> QesInputDescriptor.serializer()
        else -> DifInputDescriptor.serializer()
    }
}