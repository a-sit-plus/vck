package at.asitplus.wallet.lib.agent

import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolver
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverNoop
import at.asitplus.wallet.lib.agent.validation.TokenStatusValidator
import at.asitplus.wallet.lib.agent.validation.invoke
import at.asitplus.wallet.lib.agent.validation.toTokenStatusValidator
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class Validator(
    /** Clients may use [TokenStatusResolverImpl]. */
    private val tokenStatusResolver: TokenStatusResolver = TokenStatusResolverNoop,
    private val acceptedTokenStatuses: Set<TokenStatus> = setOf(TokenStatus.Valid),
    private val tokenStatusValidator: TokenStatusValidator =
        tokenStatusResolver.toTokenStatusValidator(acceptedTokenStatuses),
    private val credentialTimelinessValidator: CredentialTimelinessValidator = CredentialTimelinessValidator(),
) {
    /**
     * Checks both the timeliness and the token status of the passed credentials
     */
    suspend fun checkCredentialFreshness(storeEntry: SubjectCredentialStore.StoreEntry) = when (storeEntry) {
        is SubjectCredentialStore.StoreEntry.Iso -> checkCredentialFreshness(storeEntry.issuerSigned)
        is SubjectCredentialStore.StoreEntry.SdJwt -> checkCredentialFreshness(storeEntry.sdJwt)
        is SubjectCredentialStore.StoreEntry.Vc -> checkCredentialFreshness(storeEntry.vc)
    }

    suspend fun checkCredentialFreshness(issuerSigned: IssuerSigned) = CredentialFreshnessSummary.Mdoc(
        tokenStatusValidationResult = checkRevocationStatus(issuerSigned),
        timelinessValidationSummary = credentialTimelinessValidator(issuerSigned)
    )

    suspend fun checkCredentialFreshness(sdJwt: VerifiableCredentialSdJwt) = CredentialFreshnessSummary.SdJwt(
        tokenStatusValidationResult = checkRevocationStatus(sdJwt),
        timelinessValidationSummary = credentialTimelinessValidator(sdJwt)
    )

    suspend fun checkCredentialFreshness(vcJws: VerifiableCredentialJws) = CredentialFreshnessSummary.VcJws(
        tokenStatusValidationResult = checkRevocationStatus(vcJws),
        timelinessValidationSummary = credentialTimelinessValidator(vcJws)
    )

    internal fun checkCredentialTimeliness(vcJws: VerifiableCredentialJws) = credentialTimelinessValidator(vcJws)

    /**
     * Checks the revocation state of the passed credential.
     */
    internal suspend fun checkRevocationStatus(storeEntry: SubjectCredentialStore.StoreEntry) =
        tokenStatusValidator(storeEntry)

    internal suspend fun checkRevocationStatus(issuerSigned: IssuerSigned) = tokenStatusValidator(issuerSigned)
    internal suspend fun checkRevocationStatus(sdJwt: VerifiableCredentialSdJwt) = tokenStatusValidator(sdJwt)
    internal suspend fun checkRevocationStatus(vcJws: VerifiableCredentialJws) = tokenStatusValidator(vcJws)

}
