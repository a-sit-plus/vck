package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.data.vckJsonSerializer
import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
// TODO into data classes
@Serializable
data class PresentationDefinition(
    @SerialName("id")
    val id: String? = null,
    @SerialName("name")
    val name: String? = null,
    @SerialName("purpose")
    val purpose: String? = null,
    @SerialName("input_descriptors")
    val inputDescriptors: Collection<InputDescriptor>,
    @SerialName("format")
    val formats: FormatHolder? = null,
    @SerialName("submission_requirements")
    val submissionRequirements: Collection<SubmissionRequirement>? = null,
) {
    constructor(
        inputDescriptors: Collection<InputDescriptor>,
        formats: FormatHolder
    ) : this(id = uuid4().toString(), inputDescriptors = inputDescriptors, formats = formats)

    fun serialize() = vckJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            vckJsonSerializer.decodeFromString<PresentationDefinition>(it)
        }.wrap()
    }
}

