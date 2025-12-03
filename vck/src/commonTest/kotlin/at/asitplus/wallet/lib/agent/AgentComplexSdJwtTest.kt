package at.asitplus.wallet.lib.agent

import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.PresentationExchangeRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes


val AgentComplexSdJwtTest by testSuite {

    withFixtureGenerator {
        object {
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val holderCredentialStore = InMemorySubjectCredentialStore()
            val issuer = IssuerAgent(
                issuerCredentialStore = issuerCredentialStore,
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val holder = HolderAgent(holderKeyMaterial, holderCredentialStore)
            val verifierId = "urn:${uuid4()}"
            val verifier = VerifierAgent(identifier = verifierId)
            val challenge = uuid4().toString()
        }
    } - {

        "with flat address" {
            listOf(
                ClaimToBeIssued(
                    CLAIM_ADDRESS, listOf(
                        ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna", selectivelyDisclosable = false),
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT", selectivelyDisclosable = false)
                    )
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$['$CLAIM_ADDRESS']['$CLAIM_ADDRESS_REGION']",
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )

            val vp = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 1 // for address only
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        "with claims in address selectively disclosable, but address not" {
            listOf(
                ClaimToBeIssued(
                    CLAIM_ADDRESS, listOf(
                        ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna"),
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT")
                    ), selectivelyDisclosable = false
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$['$CLAIM_ADDRESS']['$CLAIM_ADDRESS_REGION']",
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )

            val vp = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 2 // for region, country
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        "with claims in address recursively selectively disclosable" {
            listOf(
                ClaimToBeIssued(
                    CLAIM_ADDRESS,
                    listOf(
                        ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna"),
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT"),
                    ),
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$['$CLAIM_ADDRESS']['$CLAIM_ADDRESS_REGION']",
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )

            val vp = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 3 // for address, region, country
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        "with claims in address selectively disclosable, getting all inner disclosures" {
            listOf(
                ClaimToBeIssued(
                    CLAIM_ADDRESS,
                    listOf(
                        ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna"),
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT")
                    ),
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames("$.$CLAIM_ADDRESS")

            val vp = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 3 // for address, region, country
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        "with claims in address in dot-notation" {
            listOf(
                ClaimToBeIssued("$CLAIM_ADDRESS.$CLAIM_ADDRESS_REGION", "Vienna"),
                ClaimToBeIssued("$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY", "AT"),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_REGION",
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )

            val vp = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 3 // for address, region, country
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        "simple walk-through success" {
            listOf(
                ClaimToBeIssued(CLAIM_GIVEN_NAME, "Susanne"),
                ClaimToBeIssued(CLAIM_FAMILY_NAME, "Meier"),
                ClaimToBeIssued(CLAIM_ALWAYS_VISIBLE, "anything", selectivelyDisclosable = false),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$['$CLAIM_GIVEN_NAME']",
                "$['$CLAIM_FAMILY_NAME']",
                "$.$CLAIM_ALWAYS_VISIBLE"
            )

            val vp = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 2 // claim_given_name, claim_family_name
                    reconstructedJsonObject[CLAIM_GIVEN_NAME]
                        ?.jsonPrimitive?.content shouldBe "Susanne"
                    reconstructedJsonObject[CLAIM_FAMILY_NAME]
                        ?.jsonPrimitive?.content shouldBe "Meier"
                    reconstructedJsonObject[CLAIM_ALWAYS_VISIBLE]
                        ?.jsonPrimitive?.content shouldBe "anything"
                }
        }
    }
}

private fun nonsenseClaim(): ClaimToBeIssued = ClaimToBeIssued(uuid4().toString(), uuid4().toString())

private suspend fun issueAndStoreCredential(
    holder: Holder,
    issuer: Issuer,
    claims: List<ClaimToBeIssued>,
    holderKeyMaterial: KeyMaterial,
) {
    holder.storeCredential(
        issuer.issueCredential(
            CredentialToBeIssued.VcSd(
                claims = claims,
                expiration = Clock.System.now() + 1.minutes,
                scheme = AtomicAttribute2023,
                subjectPublicKey = holderKeyMaterial.publicKey,
                userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                sdAlgorithm = supportedSdAlgorithms.random(),
            )
        ).getOrThrow().toStoreCredentialInput()
    )
}


private const val CLAIM_ALWAYS_VISIBLE = "alwaysVisible"
private const val CLAIM_ADDRESS = "address"
private const val CLAIM_ADDRESS_REGION = "region"
private const val CLAIM_ADDRESS_COUNTRY = "country"