package at.asitplus.dif

import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject


object InputDescriptorSerializer : JsonContentPolymorphicSerializer<InputDescriptor>(InputDescriptor::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "transaction_data" in element.jsonObject -> QesInputDescriptor.serializer()
        else -> DifInputDescriptor.serializer()
    }
}