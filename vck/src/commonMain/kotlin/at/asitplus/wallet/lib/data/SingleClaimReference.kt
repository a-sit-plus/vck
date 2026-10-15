package at.asitplus.wallet.lib.data

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
sealed interface SingleClaimReference

@JvmInline
@Serializable(with = JsonClaimReference.Serializer::class)
value class JsonClaimReference(
    val path: DCQLClaimsPathPointer,
) : SingleClaimReference {

    /** A concrete path, retained for callers that do not select array wildcards. */
    constructor(normalizedJsonPath: NormalizedJsonPath) : this(
        DCQLClaimsPathPointer(normalizedJsonPath.map { segment ->
            when (segment) {
                is NormalizedJsonPathSegment.NameSegment -> DCQLClaimsPathPointerSegment.NameSegment(segment.memberName)
                is NormalizedJsonPathSegment.IndexSegment -> DCQLClaimsPathPointerSegment.IndexSegment(segment.index)
            }
        }.toNonEmptyList())
    )

    /** A concrete path; throws if [path] selects all elements of an array. */
    @Deprecated("Use path, which also supports array wildcards", ReplaceWith("path"))
    val normalizedJsonPath: NormalizedJsonPath
        get() = NormalizedJsonPath(path.map { segment ->
            when (segment) {
                is DCQLClaimsPathPointerSegment.NameSegment -> NormalizedJsonPathSegment.NameSegment(segment.name)
                is DCQLClaimsPathPointerSegment.IndexSegment -> NormalizedJsonPathSegment.IndexSegment(segment.index)
                DCQLClaimsPathPointerSegment.NullSegment -> error("An array wildcard is not a concrete path")
            }
        })

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

@Serializable
data class MdocClaimReference(
    val namespace: String,
    val claimName: String,
) : SingleClaimReference
