package at.asitplus.dif

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

/**
 * Class describing
 * [DIF Presentation Exchange v2.1.1](https://identity.foundation/presentation-exchange/spec/v2.1.1/#term:presentation-definition)
 *
 * Uses open serialization in order to avoid type-discriminator in serialization
 */
@JsonClassDiscriminator("")
@Serializable(with = InputDescriptorSerializer::class)
sealed class InputDescriptor {
    abstract val id: String
    @Deprecated("To be replaced with groups, see #267")
    abstract val group: String?
    abstract val name: String?
    abstract val purpose: String?
    abstract val format: FormatHolder?
    abstract val constraints: Constraint?
}
