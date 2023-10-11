package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.cose.CoseKey

object EmptyCredentialDataProvider : IssuerCredentialDataProvider {

    override fun getCredentialWithType(
        subjectId: String,
        subjectPublicKey: CoseKey?,
        attributeTypes: Collection<String>
    ): KmmResult<List<CredentialToBeIssued>> =
        KmmResult.failure(NotImplementedError())

}