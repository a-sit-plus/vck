package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.openid.formUrlEncode
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStorePlainJwt
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

val JarmTest by matrixSuite {
    fixture {
        runBlocking {
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val issuerAgent = IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val holderAgent = HolderAgent(holderKeyMaterial).also {
                issueAndStorePlainJwt(it, holderKeyMaterial, issuerAgent)
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
                val requestFactory = OpenId4VpRequestFactory(
                    clientIdScheme = ClientIdScheme.RedirectUri(clientId),
                    ephemeralEncryptionKeyService = EphemeralEncryptionKeyService(),
                    decryptionKeyMaterial = null,
                    signAuthnRequest = SignJwt(
                        verifierKeyMaterial,
                        JwsHeaderClientIdScheme(ClientIdScheme.RedirectUri(clientId))
                    ),
                    nonceService = DefaultNonceService(),
                    supportedAlgorithms = setOf(SignatureAlgorithm.ECDSAwithSHA256),
                    stateToAuthnRequestStore = DefaultMapStore(),
                    supportedJweEncryptionAlgorithms = JweEncryption.entries.toSet(),
                )
            }
        }
    } - {

        /**
         * Incorrect behaviour arises when the [RelyingPartyMetadata.jsonWebKeySet] cannot be retrieved.
         */
        "DirectPostJwt must either be signed or encrypted" {
            val authnRequest = it.requestFactory.createPlainAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(
                            credentialScheme = AtomicAttribute2023,
                            representation = SD_JWT,
                            attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME))
                        )
                    ).toDCQLRequest(),
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
                it.holderOid4vp.createAuthnResponse(joseCompliantSerializer.encodeToString(invalidReq)).getOrThrow()
            }
        }

        /**
         * OpenID4VC HAIP: *"Verifiers MUST supply ephemeral encryption public keys specific to each Authorization
         * Request passed via client metadata as specified in Section 8.3 of OpenID4VP"*.
         */
        "every request carries its own ephemeral encryption key" {
            val first = it.requestFactory.createPlainAuthnRequest(directPostJwtOptions()).encryptionKey()
            val second = it.requestFactory.createPlainAuthnRequest(directPostJwtOptions()).encryptionKey()

            first.publicKeyUse shouldBe "enc"
            first.algorithm shouldBe JweAlgorithm.ECDH_ES
            first.keyId.shouldNotBeNull() shouldNotBe second.keyId.shouldNotBeNull()
            first.shouldNotBe(second)
        }

        "a response is validated by another instance sharing the ephemeral key store" {
            // deployments running in a cluster do not receive the response on the instance that created the
            // request, so the ephemeral encryption key has to be synchronized along with the request itself
            val nonceService = DefaultNonceService()
            val stateToAuthnRequestStore = DefaultMapStore<String, AuthenticationRequestParameters>()
            val ephemeralEncryptionKeyService = EphemeralEncryptionKeyService()
            val newInstance = {
                OpenId4VpVerifier(
                    keyMaterial = it.verifierKeyMaterial,
                    clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                    nonceService = nonceService,
                    stateToAuthnRequestStore = stateToAuthnRequestStore,
                    ephemeralEncryptionKeyService = ephemeralEncryptionKeyService,
                )
            }

            val authnRequest = newInstance().createAuthnRequest(
                requestOptions = directPostJwtOptions(),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()

            newInstance().validateAuthnResponse(authnResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
        }
    }
}

/** Asks for the plain JWT credential the fixture's holder actually holds, so that the flow can complete. */
private fun directPostJwtOptions() = OpenId4VpRequestOptions(
    presentationRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(AtomicAttribute2023)
    ).toDCQLRequest(),
    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
    responseUrl = "https://example.com/${uuid4()}",
)

/** The key the wallet is supposed to encrypt its response to, i.e. the one from this request's client metadata. */
private fun AuthenticationRequestParameters.encryptionKey(): JsonWebKey =
    clientMetadata.shouldNotBeNull().jsonWebKeySet.shouldNotBeNull().keys.getEncryptionTargetKey().shouldNotBeNull()
