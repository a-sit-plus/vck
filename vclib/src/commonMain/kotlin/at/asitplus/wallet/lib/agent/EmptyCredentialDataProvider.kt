package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult

object EmptyCredentialDataProvider : IssuerCredentialDataProvider {

    override fun getClaim(subjectId: String, attributeName: String)
        : KmmResult<IssuerCredentialDataProvider.CredentialToBeIssued> = KmmResult.failure(NullPointerException())

    override fun getCredential(subjectId: String, attributeType: String)
        : KmmResult<IssuerCredentialDataProvider.CredentialToBeIssued> = KmmResult.failure(NullPointerException())

}