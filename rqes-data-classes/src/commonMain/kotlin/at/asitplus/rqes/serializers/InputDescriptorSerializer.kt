package at.asitplus.rqes.serializers

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptor
import at.asitplus.rqes.QesInputDescriptor
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object InputDescriptorSerializer : JsonContentPolymorphicSerializer<InputDescriptor>(InputDescriptor::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        "transaction_data" in element.jsonObject -> QesInputDescriptor.serializer()
        else -> DifInputDescriptor.serializer()
    }
}