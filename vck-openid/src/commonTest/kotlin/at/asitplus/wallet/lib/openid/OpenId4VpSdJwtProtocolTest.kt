package at.asitplus.wallet.lib.openid

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.eupid.EuPidScheme
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
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

val OpenId4VpSdJwtProtocolTest by testSuite {

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
                    )
                        .getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
            it.storeCredential(
                IssuerAgent(
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ).issueCredential(
                    DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidScheme, SD_JWT)
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
    }) - {

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
                .allValidationResults.values
                .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    verifiableCredentialSdJwt.shouldNotBeNull()
                    reconstructedJsonObject[requestedClaim].shouldNotBeNull()
                }
        }

        "Selective Disclosure with EU PID credential with mapped claim names" {
            val requestedClaims = setOf(
                EuPidScheme.SdJwtAttributes.FAMILY_NAME,
                EuPidScheme.SdJwtAttributes.GIVEN_NAME,
                EuPidScheme.SdJwtAttributes.FAMILY_NAME_BIRTH, // "birth_family_name" instead of "family_name_birth"
                EuPidScheme.SdJwtAttributes.GIVEN_NAME_BIRTH, // "birth_given_name" instead of "given_name_birth"
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(EuPidScheme, SD_JWT, requestedClaims)
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
                .allValidationResults.values
                .shouldBeSingleton().first()
                .shouldBeSingleton().first().getOrThrow().shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    verifiableCredentialSdJwt.shouldNotBeNull()
                    requestedClaims.forEach {
                        it.shouldBeIn(reconstructed.keys)
                        reconstructed[it].shouldNotBeNull()
                    }
                }

        }
    }
}
