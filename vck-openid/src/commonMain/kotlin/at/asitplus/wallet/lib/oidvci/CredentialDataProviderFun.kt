package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme


fun interface CredentialDataProviderFun {
    /**
     * Gets called with the user authorized in [userInfo],
     * a resolved [credentialScheme],
     * the holder key in [subjectPublicKey],
     * and the requested credential's representation in [representation].
     */
    suspend operator fun invoke(
        userInfo: OidcUserInfoExtended,
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
    ): KmmResult<CredentialToBeIssued>
}

class CredentialIssuerDataProviderAdapter(
    val credentialDataProvider: CredentialIssuerDataProvider,
) : CredentialDataProviderFun {
    override suspend fun invoke(
        userInfo: OidcUserInfoExtended,
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
    ): KmmResult<CredentialToBeIssued> =
        credentialDataProvider.getCredential(userInfo, subjectPublicKey, credentialScheme, representation, null)

}
