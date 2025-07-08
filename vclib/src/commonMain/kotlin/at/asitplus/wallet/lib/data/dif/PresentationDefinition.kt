package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.data.jsonSerializer
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class PresentationDefinition(
    @SerialName("id")
    val id: String,
    @SerialName("name")
    val name: String? = null,
    @SerialName("purpose")
    val purpose: String? = null,
    @SerialName("input_descriptors")
    val inputDescriptors: Array<InputDescriptor>,
    @SerialName("format")
    val formats: FormatHolder? = null,
    @SerialName("submission_requirements")
    val submissionRequirements: Array<SubmissionRequirement>? = null,
) {
    constructor(
        inputDescriptors: Array<InputDescriptor>,
        formats: FormatHolder
    ) : this(id =@OptIn(ExperimentalUuidApi::class) Uuid.random().toString(), inputDescriptors = inputDescriptors, formats = formats)

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PresentationDefinition

        if (id != other.id) return false
        if (name != other.name) return false
        if (purpose != other.purpose) return false
        if (!inputDescriptors.contentEquals(other.inputDescriptors)) return false
        if (formats != other.formats) return false
        if (submissionRequirements != null) {
            if (other.submissionRequirements == null) return false
            if (!submissionRequirements.contentEquals(other.submissionRequirements)) return false
        } else if (other.submissionRequirements != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (purpose?.hashCode() ?: 0)
        result = 31 * result + inputDescriptors.contentHashCode()
        result = 31 * result + (formats?.hashCode() ?: 0)
        result = 31 * result + (submissionRequirements?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<PresentationDefinition>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

