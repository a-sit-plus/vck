package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlin.jvm.JvmInline

@Serializable
sealed interface SingleClaimReference

@JvmInline
@Serializable(with = JsonClaimReference.Serializer::class)
value class JsonClaimReference(
    val path: DCQLClaimsPathPointer,
) : SingleClaimReference {

    /** Keeps the existing object and member name when serialized as a [SingleClaimReference]. */
    object Serializer : KSerializer<JsonClaimReference> by TransformingSerializerTemplate(
        parent = Surrogate.serializer(),
        encodeAs = { Surrogate(it.path) },
        decodeAs = { JsonClaimReference(it.path) },
        serialName = "at.asitplus.wallet.lib.data.JsonClaimReference",
    )

    @Serializable
    internal class Surrogate(@SerialName("normalizedJsonPath") val path: DCQLClaimsPathPointer)
}

/**
 * A data element of an ISO mdoc, requested and presented as a name space with a data element identifier
 * (ISO/IEC 18013-5:2021, 8.3.2.1.2.1).
 */
@Serializable
data class MdocClaimReference(
    val namespace: String,
    val claimName: String,
) : SingleClaimReference {

    /**
     * Serializes the reference as the two-element array `[namespace, claimName]`, the form that
     * [at.asitplus.wallet.lib.agent.DeviceRequestCredentialDisclosure.disclosedAttributes] keeps from its earlier
     * representation as a JSONPath of two names.
     */
    object ArraySerializer : KSerializer<MdocClaimReference> by TransformingSerializerTemplate(
        parent = ListSerializer(String.serializer()),
        encodeAs = { listOf(it.namespace, it.claimName) },
        decodeAs = {
            require(it.size == 2) { "An mdoc data element has a name space and a data element identifier: $it" }
            MdocClaimReference(it[0], it[1])
        },
        serialName = "at.asitplus.wallet.lib.data.MdocClaimReference.Array",
    )
}
