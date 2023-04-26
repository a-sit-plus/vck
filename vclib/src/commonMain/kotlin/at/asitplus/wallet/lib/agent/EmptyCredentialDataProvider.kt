package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult

object EmptyCredentialDataProvider : IssuerCredentialDataProvider {

    override fun getClaim(subjectId: String, attributeName: String)
            : KmmResult<IssuerCredentialDataProvider.CredentialToBeIssued> =
        KmmResult.failure(NotImplementedError())

    override fun getCredential(subjectId: String, attributeType: String)
            : KmmResult<IssuerCredentialDataProvider.CredentialToBeIssued> =
        KmmResult.failure(NotImplementedError())

    override fun getCredentialWithType(subjectId: String, attributeTypes: Collection<String>)
            : KmmResult<List<IssuerCredentialDataProvider.CredentialToBeIssued>> =
        KmmResult.failure(NotImplementedError())
}