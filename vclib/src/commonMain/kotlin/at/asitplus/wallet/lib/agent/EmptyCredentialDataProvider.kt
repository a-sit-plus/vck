package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex

object EmptyCredentialDataProvider : IssuerCredentialDataProvider {

    override fun getCredentialWithType(
        subjectId: String,
        subjectPublicKey: CryptoPublicKey?,
        attributeTypes: Collection<String>,
        representation: ConstantIndex.CredentialRepresentation
    ): KmmResult<List<CredentialToBeIssued>> =
        KmmResult.failure(NotImplementedError())

}