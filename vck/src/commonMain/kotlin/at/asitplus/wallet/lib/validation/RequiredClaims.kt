package at.asitplus.wallet.lib.validation

import at.asitplus.catchingUnwrapped
import at.asitplus.openid.OpenId4VciClaimsPathPointer
import at.asitplus.openid.OpenId4VciClaimsPathPointerSegmentIndex
import at.asitplus.openid.OpenId4VciClaimsPathPointerSegmentString
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.isoQualifiedClaimDescriptions
import at.asitplus.wallet.lib.data.toCredentialScheme
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject

/**
 * A claim a credential type requires, i.e. one its metadata describe as `mandatory`, which "MUST be included in the
 * credential by the Issuer" (draft-ietf-oauth-sd-jwt-vc-19, 5.6.3): the credential has to contain [path], unless it
 * does not contain [condition], the closest ancestor of [path] that the metadata describe as optional, e.g. `address`
 * for a mandatory `address.country`. The draft defines no rule for such nested claims, so this one is VC-K's: an
 * optional claim that is absent does not require its parts.
 */
data class RequiredClaim(
    val path: OpenId4VciClaimsPathPointer,
    val condition: OpenId4VciClaimsPathPointer? = null,
)

/** The [claims] the credential type [credentialIdentifier] requires, and the [source] of its metadata, if known. */
data class RequiredClaims(
    val credentialIdentifier: String,
    val claims: List<RequiredClaim>,
    /** Names the metadata the claims come from, e.g. the URL of a type metadata document, `null` if defined in code. */
    val source: String? = null,
)

/**
 * The claims of the credential type [credentialIdentifier] that this scheme describes as `mandatory`, each with the
 * closest ancestor described as optional as its [RequiredClaim.condition]. For [ISO_MDOC], paths are qualified with
 * the ISO namespace, see [isoQualifiedClaimDescriptions].
 */
fun CredentialScheme.requiredClaims(
    credentialIdentifier: String,
    representation: CredentialRepresentation,
    source: String? = null,
): RequiredClaims {
    val isIsoCredential = representation == ISO_MDOC && this is IsoMdocCredentialScheme
    val descriptions = if (isIsoCredential) isoQualifiedClaimDescriptions else claimDescriptions
    val optional = descriptions.filter { it.mandatory != true }.map { it.path }
    val claims = descriptions.filter { it.mandatory == true }.map { description ->
        RequiredClaim(
            path = description.path,
            condition = optional.filter { it.isProperPrefixOf(description.path) }.maxByOrNull { it.size },
        )
    }
    return RequiredClaims(credentialIdentifier, claims, source)
}

/**
 * Resolves the claims a credential type requires, by the identifier signed into the credential, see
 * [CredentialValidator]. Returns `null` if no metadata of that type are known, which blocks the check: a type without
 * metadata is not a type without required claims. A registered scheme supplies metadata even when its claim
 * descriptions are empty or all optional; in either case it declares no mandatory claims.
 */
fun interface RequiredClaimsResolver {
    suspend fun resolve(credentialIdentifier: String, representation: CredentialRepresentation): RequiredClaims?

    /**
     * Resolves through the [CredentialMetadataRegistry][at.asitplus.wallet.lib.data.CredentialMetadataRegistry]s of
     * [AttributeIndex] first, naming the document the metadata were loaded from as source, then through the schemes
     * registered in code. Matches identifiers exactly, unlike [AttributeIndex.resolveIsoDoctype], and never falls back
     * to a scheme without metadata. Registered schemes with empty or entirely optional claim descriptions declare
     * no mandatory claims, so the check passes for them.
     */
    object Default : RequiredClaimsResolver {
        override suspend fun resolve(
            credentialIdentifier: String,
            representation: CredentialRepresentation,
        ): RequiredClaims? {
            AttributeIndex.credentialMetadataRegistrySet.firstNotNullOfOrNull {
                it.findEntry(credentialIdentifier, representation)
            }?.let {
                return it.toCredentialScheme().requiredClaims(credentialIdentifier, representation, it.loadedFrom)
            }
            return AttributeIndex.schemeSet
                .firstOrNull { it.identifies(credentialIdentifier, representation) }
                ?.requiredClaims(credentialIdentifier, representation)
        }

        private fun CredentialScheme.identifies(identifier: String, representation: CredentialRepresentation) =
            when (representation) {
                PLAIN_JWT -> (this as? VcJwtCredentialScheme)?.vcType == identifier
                SD_JWT -> (this as? SdJwtCredentialScheme)?.sdJwtType == identifier
                ISO_MDOC -> (this as? IsoMdocCredentialScheme)?.isoDocType == identifier
            }
    }
}

/**
 * Whether [claims] contain every claim the type [identifier] requires under [policy]: not applicable if the policy
 * skips it, blocked unless every disclosed item passed (claims of an invalid disclosure must not count), the type is
 * unambiguous, and this resolver knows its metadata, otherwise failed with the paths of the missing claims.
 */
internal suspend fun RequiredClaimsResolver.check(
    policy: RequiredClaimsPolicy,
    identifier: String?,
    representation: CredentialRepresentation,
    disclosedItems: List<DisclosedItemValidation>,
    claims: () -> JsonObject,
): RequiredClaimsValidation {
    if (policy == RequiredClaimsPolicy.Skip) return RequiredClaimsValidation(NotApplicable, identifier)
    if (disclosedItems.any { it.parsing != Passed || it.digest != Passed || it.structure != Passed })
        return RequiredClaimsValidation(
            Blocked(IllegalStateException("The claims of a credential with invalid disclosed items are not evaluated")),
            identifier,
        )
    if (identifier == null)
        return RequiredClaimsValidation(Blocked(IllegalArgumentException("The credential type is ambiguous")))
    val required = catchingUnwrapped { resolve(identifier, representation) }
        .getOrElse { return RequiredClaimsValidation(Blocked(it), identifier) }
        ?: return RequiredClaimsValidation(
            Blocked(IllegalArgumentException("No metadata describe the claims of $identifier")),
            identifier,
        )
    val json = claims()
    val missing = required.claims.filterNot { it.isSatisfiedBy(json) }.map { it.path }
    val outcome = if (missing.isEmpty()) Passed else Failed(MissingRequiredClaimException(missing))
    return RequiredClaimsValidation(outcome, identifier, required.source, missing)
}

/**
 * Keep array branches separate: every selected element must contain the mandatory descendant unless its optional
 * ancestor is absent in that same branch. Querying only existing leaves would lose branches with missing claims.
 * An empty array has no elements whose descendants need checking; requiring an element needs an indexed path.
 * A JSON null value, like a missing property, does not count as an included claim.
 */
private fun RequiredClaim.isSatisfiedBy(json: JsonElement): Boolean {
    fun visit(node: JsonElement?, depth: Int): Boolean {
        if (node == null || node == JsonNull) return condition?.let { depth <= it.size } == true
        if (depth == path.size) return true
        return when (val segment = path[depth]) {
            null -> (node as? JsonArray)?.all { visit(it, depth + 1) } == true
            is OpenId4VciClaimsPathPointerSegmentString ->
                node is JsonObject && visit(node[segment.string], depth + 1)

            is OpenId4VciClaimsPathPointerSegmentIndex ->
                node is JsonArray && visit(node.getOrNull(segment.uint.toInt()), depth + 1)
        }
    }
    return visit(json, 0)
}

private fun OpenId4VciClaimsPathPointer.isProperPrefixOf(other: OpenId4VciClaimsPathPointer) =
    size < other.size && other.subList(0, size) == this
