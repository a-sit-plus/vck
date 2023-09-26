package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.CryptoPublicKey

object EmptyCredentialDataProvider : IssuerCredentialDataProvider {

    override fun getCredentialWithType(
        subjectId: String,
        subjectPublicKey: CryptoPublicKey?,
        attributeTypes: Collection<String>
    ): KmmResult<List<CredentialToBeIssued>> =
        KmmResult.failure(NotImplementedError())

}