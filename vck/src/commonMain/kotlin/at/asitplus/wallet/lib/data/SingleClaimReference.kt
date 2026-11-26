package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer

/**
 * One claim of a credential, in the form its credential format addresses claims with: a claims path pointer into a
 * JSON-based credential ([JsonClaimReference], OpenID4VP 1.0, 7.1), or a name space with a data element identifier of
 * an ISO mdoc ([MdocClaimReference], ISO/IEC 18013-5:2021, 8.3.2.1.2.1).
 *
 * Used for the claims a verifier requests, in the [at.asitplus.wallet.lib.ClaimSelection] of a
 * [at.asitplus.wallet.lib.RequestedCredential], and for the claims of a received request that WRPRC authorization
 * checks against the claims the relying party registered
 * ([at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest.getAttributes],
 * reported with its result in `RequestCredentialAttributesValidity`). Serializable as part of such results, with the
 * concrete type as discriminator.
 */
@Serializable
sealed interface SingleClaimReference

/**
 * A claim of a JSON-based credential (SD-JWT VC or VC-JWT), selected by the claims path pointer [path]
 * (OpenID4VP 1.0, 7.1).
 */
@Serializable(with = JsonClaimReference.Serializer::class)
data class JsonClaimReference(
    val path: DCQLClaimsPathPointer,
) : SingleClaimReference {

    /** The claim at the path of [name] and [names], e.g. `JsonClaimReference("address", "street_address")`. */
    constructor(name: String, vararg names: String) : this(DCQLClaimsPathPointer(name, *names))

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

    /** The data element [claimName] in the [IsoMdocCredentialScheme.isoNamespace] of [scheme]. */
    constructor(scheme: IsoMdocCredentialScheme, claimName: String) : this(
        namespace = scheme.isoNamespace,
        claimName = claimName,
    )

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
