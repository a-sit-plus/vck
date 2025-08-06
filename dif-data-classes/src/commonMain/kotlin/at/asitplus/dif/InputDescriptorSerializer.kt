package at.asitplus.dif

import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement

object InputDescriptorSerializer : JsonContentPolymorphicSerializer<InputDescriptor>(InputDescriptor::class) {
    override fun selectDeserializer(element: JsonElement) = DifInputDescriptor.serializer()
}