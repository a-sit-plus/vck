package at.asitplus.wallet.lib.data

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
sealed interface SingleClaimReference

@JvmInline
@Serializable(with = JsonClaimReference.Serializer::class)
value class JsonClaimReference(
    val normalizedJsonPath: NormalizedJsonPath,
) : SingleClaimReference {

    /**
     * Serializes as an object holding [normalizedJsonPath]. [NormalizedJsonPath] is a list, and serializing it inline
     * as a [SingleClaimReference] would put the class discriminator into that list, which is not valid JSON.
     */
    object Serializer : KSerializer<JsonClaimReference> by TransformingSerializerTemplate(
        parent = Surrogate.serializer(),
        encodeAs = { Surrogate(it.normalizedJsonPath) },
        decodeAs = { JsonClaimReference(it.normalizedJsonPath) },
        serialName = "at.asitplus.wallet.lib.data.JsonClaimReference",
    )

    @Serializable
    internal class Surrogate(val normalizedJsonPath: NormalizedJsonPath)
}

@Serializable
data class MdocClaimReference(
    val namespace: String,
    val claimName: String,
) : SingleClaimReference
