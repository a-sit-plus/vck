package at.asitplus.dif

import kotlinx.serialization.Serializable

@Serializable(with = InputDescriptorSerializer::class)
sealed class InputDescriptorInterface {
    abstract val id: String
    abstract val group: String?
    abstract val name: String?
    abstract val purpose: String?
    abstract val format: FormatHolder?
    abstract val constraints: Constraint?
}
