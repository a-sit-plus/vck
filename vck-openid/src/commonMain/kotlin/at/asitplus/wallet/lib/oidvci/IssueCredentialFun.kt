package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.Issuer.IssuedCredential

fun interface IssueCredentialFun {

    /**
     * Wraps the credential-to-be-issued in [credential] into a single instance of [IssuedCredential],
     * according to the representation, i.e. it essentially signs the credential with the issuer key.
     */
    suspend operator fun invoke(credential: CredentialToBeIssued): KmmResult<IssuedCredential>

}

class IssueCredential(val issuer: Issuer) : IssueCredentialFun {
    override suspend fun invoke(
        credential: CredentialToBeIssued,
    ): KmmResult<IssuedCredential> = issuer.issueCredential(credential)
}