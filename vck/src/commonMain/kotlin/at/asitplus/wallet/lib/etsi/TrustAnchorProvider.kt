package at.asitplus.wallet.lib.etsi

import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.signum.indispensable.pki.X509Certificate

interface TrustAnchorProvider {
    /** Issuer anchors for a credential type (vct / doctype), e.g. "urn:eudi:pid:1". */
    suspend fun issuanceAnchors(credentialIdentifier: String): List<X509Certificate>



    /** Issuer anchors for a fixed list type, e.g. LoteProfile.WRPAC. */
    suspend fun issuanceAnchors(profile: LoteProfile): List<X509Certificate>



    /** Status list signer anchors for a credential type, JWT and CWT alike (PID -> PID revocation only). */
    suspend fun revocationAnchors(credentialIdentifier: String): List<X509Certificate>



    /** Status list signer anchors for a fixed list type, e.g. LoteProfile.WRPAC. */
    suspend fun revocationAnchors(profile: LoteProfile): List<X509Certificate>
}



class LoTETrustAnchorProvider(
    /** Every list the app has fetched and verified, from whichever stages it enabled. */
    private val trustLists: suspend () -> Collection<ListOfTrustedEntities>,
    /** Lists for a credential type. Default: prefix mapping. */
    private val trustListsFor: suspend (credentialIdentifier: String) -> Collection<ListOfTrustedEntities> = { id ->
        val profile = LoteProfile.fromSchemeIdentifier(id)
        trustLists().filter { LoTEFilterService().profileOf(it) == profile }
    },
    private val additionalAnchors: List<X509Certificate> = emptyList(),
    private val filter: LoTEFilterService = LoTEFilterService(),
) : TrustAnchorProvider {



    override suspend fun issuanceAnchors(credentialIdentifier: String) =
        trustListsFor(credentialIdentifier).flatMap { filter.extractIssuanceCertificates(it) }.anchors()



    override suspend fun issuanceAnchors(profile: LoteProfile) =
        trustLists().flatMap { filter.extractIssuanceCertificates(it, profile) }.anchors()



    override suspend fun revocationAnchors(credentialIdentifier: String) =
        trustListsFor(credentialIdentifier).flatMap { filter.extractRevocationCertificates(it) }.anchors()



    override suspend fun revocationAnchors(profile: LoteProfile) =
        trustLists().flatMap { filter.extractRevocationCertificates(it, profile) }.anchors()



    private fun List<TrustedCertificate>.anchors() = additionalAnchors + mapNotNull { it.certificate }
}