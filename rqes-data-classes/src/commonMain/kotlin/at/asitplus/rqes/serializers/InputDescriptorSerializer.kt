package at.asitplus.rqes.serializers

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptor
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement

//TODO check if removeable
object InputDescriptorSerializer : JsonContentPolymorphicSerializer<InputDescriptor>(InputDescriptor::class) {
    override fun selectDeserializer(element: JsonElement) = DifInputDescriptor.serializer()
}