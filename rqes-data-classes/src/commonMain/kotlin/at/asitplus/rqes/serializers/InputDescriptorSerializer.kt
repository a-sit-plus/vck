package at.asitplus.rqes.serializers

import at.asitplus.rqes.InputDescriptor
import at.asitplus.rqes.QesInputDescriptor
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement

@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.dif.InputDescriptorSerializer"))
object InputDescriptorSerializer : JsonContentPolymorphicSerializer<InputDescriptor>(InputDescriptor::class) {
    override fun selectDeserializer(element: JsonElement) = QesInputDescriptor.serializer()
}