package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme

/**
 * Provides the actual data of the user as a credential that shall be issued
 */
fun interface CredentialDataProviderFun {
    /**
     * Gets called with the user authorized, a resolved credential scheme, the holder key,
     * and the requested representation, see [CredentialDataProviderInput].
     */
    suspend operator fun invoke(
        input: CredentialDataProviderInput,
    ): KmmResult<CredentialToBeIssued>
}

data class CredentialDataProviderInput(
    val userInfo: OidcUserInfoExtended,
    val subjectPublicKey: CryptoPublicKey,
    val credentialScheme: CredentialScheme,
    val credentialRepresentation: ConstantIndex.CredentialRepresentation,
)

class CredentialIssuerDataProviderAdapter(
    val credentialDataProvider: CredentialIssuerDataProvider,
) : CredentialDataProviderFun {
    override suspend fun invoke(
        input: CredentialDataProviderInput,
    ): KmmResult<CredentialToBeIssued> =
        credentialDataProvider.getCredential(
            input.userInfo,
            input.subjectPublicKey,
            input.credentialScheme,
            input.credentialRepresentation,
            null
        )

}
