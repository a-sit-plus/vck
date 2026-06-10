package at.asitplus.wallet.lib.openid

import at.asitplus.testballoon.matrix.*
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtScheme
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

@Suppress("unused")
val OpenId4VpSdJwtProtocolTest by matrixSuite {

    fixture({ kotlinx.coroutines.runBlocking {
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
                    )
                        .getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
            it.storeCredential(
                IssuerAgent(
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ).issueCredential(
                    DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidSdJwtScheme, SD_JWT)
                        .getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
        }
        object {

            val verifierKeyMaterial = EphemeralKeyWithoutCert()
            val clientId = "https://example.com/rp/${uuid4()}"
            val walletUrl = "https://example.com/wallet/${uuid4()}"

            val holderOid4vp = OpenId4VpHolder(
                holder = holderAgent,
                randomSource = RandomSource.Default,
            )
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(clientId)
            )
        }
    } }) - {

        "Selective Disclosure with custom credential" {
            val requestedClaim = AtomicAttribute2023.CLAIM_GIVEN_NAME
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        setOf(
                            RequestOptionsCredential(AtomicAttribute2023, SD_JWT, setOf(requestedClaim))
                        )
                    ).toDCQLRequest(),
                ),
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            authnRequest shouldContain requestedClaim

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values
                .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    verifiableCredentialSdJwt.shouldNotBeNull()
                    reconstructedJsonObject[requestedClaim].shouldNotBeNull()
                }
        }

        "Selective Disclosure with EU PID credential" {
            val requestedClaims = setOf(
                EuPidSdJwtScheme.SdJwtAttributes.FAMILY_NAME,
                EuPidSdJwtScheme.SdJwtAttributes.GIVEN_NAME,
                EuPidSdJwtScheme.SdJwtAttributes.FAMILY_NAME_BIRTH,
                EuPidSdJwtScheme.SdJwtAttributes.GIVEN_NAME_BIRTH,
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(EuPidSdJwtScheme, SD_JWT, requestedClaims)
                        )
                    ).toDCQLRequest(),
                ),
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values
                .shouldBeSingleton().first()
                .shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    verifiableCredentialSdJwt.shouldNotBeNull()
                    requestedClaims.forEach {
                        it.shouldBeIn(reconstructedJsonObject.keys)
                        reconstructedJsonObject[it].shouldNotBeNull()
                    }
                }

        }
    }
}
