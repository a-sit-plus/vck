package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

/**
 * Adapter implementation to convert [userInfo] obtained from an [OAuth2AuthorizationServer]
 * into credentials needed by [IssuerCredentialDataProvider].
 */
class OAuth2IssuerCredentialDataProvider(
    private val userInfo: OidcUserInfoExtended,
    private val clock: Clock = Clock.System
) : IssuerCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    override fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?
    ): KmmResult<CredentialToBeIssued> = catching {
        val expiration = clock.now() + defaultLifetime
        // TODO Extend list of default OIDC claims
        if (credentialScheme != ConstantIndex.AtomicAttribute2023)
            throw NotImplementedError()
        val subjectId = subjectPublicKey.didEncoded
        val claims = listOfNotNull(
            // TODO Extend list of default OIDC claims
            userInfo.userInfo.givenName?.let { optionalClaim(claimNames, "given_name", it) },
            userInfo.userInfo.familyName?.let { optionalClaim(claimNames, "family_name", it) },
            optionalClaim(claimNames, "subject", userInfo.userInfo.subject),
        )
        when (representation) {
            ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialToBeIssued.VcSd(
                claims = claims,
                expiration = expiration,
                scheme = credentialScheme,
                subjectPublicKey = subjectPublicKey,
            )

            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                subject = AtomicAttribute2023(subjectId, "given_name", userInfo.userInfo.givenName ?: "no value"),
                expiration = expiration,
                scheme = credentialScheme,
                subjectPublicKey = subjectPublicKey,
            )

            ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialToBeIssued.Iso(
                issuerSignedItems = claims.mapIndexed { index, claim ->
                    issuerSignedItem(claim.name, claim.value, index.toUInt())
                },
                expiration = expiration,
                scheme = credentialScheme,
                subjectPublicKey = subjectPublicKey,
            )
        }
    }

    private fun Collection<String>?.isNullOrContains(s: String) =
        this == null || contains(s)

    private fun optionalClaim(claimNames: Collection<String>?, name: String, value: Any) =
        if (claimNames.isNullOrContains(name)) ClaimToBeIssued(name, value) else null

    private fun issuerSignedItem(name: String, value: Any, digestId: UInt) =
        IssuerSignedItem(
            digestId = digestId,
            random = Random.nextBytes(16),
            elementIdentifier = name,
            elementValue = value
        )
}
