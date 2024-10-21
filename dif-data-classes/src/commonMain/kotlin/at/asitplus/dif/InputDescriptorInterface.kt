package at.asitplus.dif

import kotlinx.serialization.Serializable

//@Serializable(with = InputDescriptorSerializer::class)
interface InputDescriptorInterface {
    val id: String
    val group: String?
    val name: String?
    val purpose: String?
    val format: FormatHolder?
    val constraints: Constraint?
}
