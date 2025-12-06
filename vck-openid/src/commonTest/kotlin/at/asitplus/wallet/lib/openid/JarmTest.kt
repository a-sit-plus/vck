package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull

val JarmTest by testSuite {
    withFixtureGenerator(suspend {
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val holderAgent = HolderAgent(holderKeyMaterial).also {
            it.storeCredential(
                IssuerAgent(
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ).issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        AtomicAttribute2023,
                        SD_JWT
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
        }
        object {

            val verifierKeyMaterial = EphemeralKeyWithoutCert()
            val clientId = "https://example.com/rp/${uuid4()}"

            val holderOid4vp = OpenId4VpHolder(
                holder = holderAgent,
                randomSource = RandomSource.Default,
            )
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(clientId)
            )
        }
    }) - {

        /**
         * Incorrect behaviour arises when the [RelyingPartyMetadata.jsonWebKeySet] cannot be retrieved.
         */
        "DirectPostJwt must either be signed or encrypted" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(
                            AtomicAttribute2023,
                            SD_JWT,
                            setOf(AtomicAttribute2023.CLAIM_GIVEN_NAME)
                        )
                    ),
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = "https://example.com/${uuid4()}"
                )
            ).shouldNotBeNull()

            val invalidReq = authnRequest.copy(
                clientMetadata = authnRequest.clientMetadata?.copy(
                    jsonWebKeySet = null,
                    jsonWebKeySetUrl = null,
                )
            )

            shouldThrow<OAuth2Exception.InvalidRequest> {
                it.holderOid4vp.createAuthnResponse(vckJsonSerializer.encodeToString(invalidReq)).getOrThrow()
            }
        }
    }
}