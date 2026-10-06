package at.asitplus.wallet.lib.validation

import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.etsi.LoTEFilterService
import at.asitplus.wallet.lib.etsi.LoteProfile
import at.asitplus.wallet.lib.etsi.TrustAnchorProvider

/** What trust anchors of a credential type are used for. */
enum class TrustPurpose {
    /** Authorize the issuer of a credential. */
    ISSUANCE,

    /** Authorize the signer of a status list token a credential references. */
    STATUS,
}

/**
 * Trust anchors of one trust source for one [TrustPurpose].
 */
data class CredentialTrustAnchorSet(
    /** Names the trust source in reports, e.g. the URL of a trust list. Never the certificates themselves. */
    val source: String,
    val certificates: Set<X509Certificate>,
)

/**
 * Trust anchors per credential type, selected by the identifier signed into the credential, i.e. the SD-JWT `vct`,
 * the mdoc `docType`, or a VC type. Each attestation type is trusted through its own trust source [TS11-4.3.1]: a
 * provider listed for one type is not authorized for another [TS2-2.5].
 *
 * Use [CredentialTrustScopes] for explicitly configured types, or [asCredentialTrustAnchors] to adapt a
 * [TrustAnchorProvider].
 */
fun interface CredentialTrustAnchors {
    /**
     * Anchors for the signed [credentialIdentifier] and [purpose], or `null` if no trust source covers that type.
     * May throw if the trust source is unavailable, e.g. a trust list can not be loaded.
     */
    suspend fun resolve(credentialIdentifier: String, purpose: TrustPurpose): CredentialTrustAnchorSet?

    companion object
}

/**
 * The trust source of one attestation type, covering its signed identifiers in every format, e.g. `urn:eudi:pid:1`
 * and `eu.europa.ec.eudi.pid.1`.
 *
 * Issuance and status anchors are separate [LoTE-SvcType]: if the trust framework of the type lets the issuer sign
 * its own status lists, pass the same source for [status] explicitly.
 */
data class CredentialTrustScope(
    /** Matched exactly and case-sensitively; list national extensions, e.g. of a PID `vct`, explicitly. */
    val credentialIdentifiers: Set<String>,
    /** Names the trust source in reports, e.g. the URL of a trust list. */
    val source: String,
    /** Anchors of the issuers of this type. */
    val issuance: TrustedCertificates,
    /** Anchors of the signers of status list tokens of this type. */
    val status: TrustedCertificates,
) {
    init {
        require(credentialIdentifiers.isNotEmpty()) { "A trust scope covers at least one credential identifier" }
    }
}

/**
 * Trust anchors from a fixed set of [scopes], one per attestation type.
 *
 * An identifier is resolved by exact match only: there is no fallback to another scope and no prefix matching, so a
 * type no scope covers has no anchors, and anchors of one type never authorize another. Every identifier may occur
 * in one scope only; to combine several trust sources for one type, combine them in that scope's
 * [TrustedCertificates].
 */
class CredentialTrustScopes(scopes: List<CredentialTrustScope>) : CredentialTrustAnchors {

    constructor(vararg scopes: CredentialTrustScope) : this(scopes.toList())

    private val scopeByIdentifier: Map<String, CredentialTrustScope> = buildMap {
        scopes.forEach { scope ->
            scope.credentialIdentifiers.forEach { identifier ->
                val previous = put(identifier, scope)
                require(previous == null) {
                    "Credential identifier $identifier is covered by both ${previous?.source} and ${scope.source}"
                }
            }
        }
    }

    override suspend fun resolve(credentialIdentifier: String, purpose: TrustPurpose): CredentialTrustAnchorSet? =
        scopeByIdentifier[credentialIdentifier]?.let { scope ->
            val anchors = when (purpose) {
                TrustPurpose.ISSUANCE -> scope.issuance
                TrustPurpose.STATUS -> scope.status
            }
            CredentialTrustAnchorSet(scope.source, anchors())
        }
}

/**
 * A [CredentialTrustScope] from the verified [lists] of [profile], e.g. the PID providers list: their issuance
 * services authorize issuers, their revocation services the signers of status list tokens [LoTE-SvcType].
 *
 * VC-K does not verify the signature of a list: [lists] has to return lists the application has verified.
 */
fun LoTEFilterService.credentialTrustScope(
    credentialIdentifiers: Set<String>,
    profile: LoteProfile,
    source: String,
    lists: suspend () -> Collection<ListOfTrustedEntities>,
) = CredentialTrustScope(
    credentialIdentifiers = credentialIdentifiers,
    source = source,
    issuance = TrustedCertificates {
        lists().flatMap { extractIssuanceCertificates(it, profile) }.mapNotNull { it.certificate }.toSet()
    },
    status = TrustedCertificates {
        lists().flatMap { extractRevocationCertificates(it, profile) }.mapNotNull { it.certificate }.toSet()
    },
)

/**
 * Adapts this provider through its overloads taking a credential identifier, reporting the anchors as [source].
 * A provider can not tell an uncovered type from a covered type without anchors, so no anchors mean the type is not
 * covered.
 *
 * The overloads taking a [LoteProfile], e.g. for WRPAC or wallet providers, serve trust in other artifacts.
 */
fun TrustAnchorProvider.asCredentialTrustAnchors(
    source: String
) = CredentialTrustAnchors { identifier, purpose ->
    val anchors = when (purpose) {
        TrustPurpose.ISSUANCE -> issuanceAnchors(identifier)
        TrustPurpose.STATUS -> revocationAnchors(identifier)
    }
    anchors.takeIf { it.isNotEmpty() }
        ?.let { CredentialTrustAnchorSet(source, it.toSet()) }
}

/**
 * The same anchors for every credential type, which does **not** separate trust per type. Only for the
 * compatibility policy behind the deprecated `trustedIssuers` of `HolderAgent` and `VerifierAgent`.
 */
internal fun CredentialTrustAnchors.Companion.sameForAllTypes(
    issuance: TrustedCertificates,
    status: TrustedCertificates?,
    source: String,
) = CredentialTrustAnchors { _, purpose ->
    when (purpose) {
        TrustPurpose.ISSUANCE -> CredentialTrustAnchorSet(source, issuance())
        TrustPurpose.STATUS -> status?.let { CredentialTrustAnchorSet(source, it()) }
    }
}

/*
 * References
 *
 * | Tag           | Source                                                                                      |
 * |---------------|---------------------------------------------------------------------------------------------|
 * | TS11-4.3.1    | EUDI TS11, 4.3.1 SchemaMeta main class and 4.3.3 TrustAuthority sub-class                   |
 * |               | (eudi-doc-standards-and-technical-specifications ee91a294): trustedAuthorities per type     |
 * | TS2-2.5       | EUDI TS2, 2.5 PIDProvider, citing CIR (EU) 2024/2980 Annex II 3.(h): the certificates of    |
 * |               | the PID providers list verify PID                                                           |
 * | LoTE-SvcType  | ETSI TS 119 602 V1.1.1, Annex D Table D.3, Annex E Table E.3, Annex F Table F.3, Annex H    |
 * |               | Table H.3: separate Issuance and Revocation service types per list                          |
 */
