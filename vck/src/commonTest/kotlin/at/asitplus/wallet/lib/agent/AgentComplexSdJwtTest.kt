package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.dcql.*
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.PresentationExchangeRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Duration.Companion.minutes


class AgentComplexSdJwtTest : FreeSpec({

    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var challenge: String
    lateinit var verifierId: String

    beforeEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent(issuerCredentialStore = issuerCredentialStore)
        holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        holder = HolderAgent(holderKeyMaterial, holderCredentialStore)
        verifierId = "urn:${uuid4()}"
        verifier = VerifierAgent(identifier = verifierId)
        challenge = uuid4().toString()
    }

    "when using presentation exchange" - {
        "with flat address" {
            listOf(
                ClaimToBeIssued(
                    CLAIM_ADDRESS, listOf(
                        ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna", selectivelyDisclosable = false),
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT", selectivelyDisclosable = false)
                    )
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$['$CLAIM_ADDRESS']['$CLAIM_ADDRESS_REGION']",
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )

            val vp = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$['$CLAIM_ADDRESS']['$CLAIM_ADDRESS_REGION']",
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )

            val vp = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$['$CLAIM_ADDRESS']['$CLAIM_ADDRESS_REGION']",
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )

            val vp = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames("$.$CLAIM_ADDRESS")

            val vp = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_REGION",
                "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )

            val vp = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val presentationRequest = PresentationExchangeRequest.forAttributeNames(
                "$['$CLAIM_GIVEN_NAME']",
                "$['$CLAIM_FAMILY_NAME']",
                "$.$CLAIM_ALWAYS_VISIBLE"
            )

            val vp = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentationRequest = presentationRequest
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
                .presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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

    "when using DCQL" - {
        "with flat address" {
            listOf(
                ClaimToBeIssued(
                    CLAIM_ADDRESS, listOf(
                        ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna", selectivelyDisclosable = false),
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT", selectivelyDisclosable = false)
                    )
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_REGION,
                ),
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_COUNTRY,
                ),
            )

            val vp = createPresentation(holder, challenge, dcqlQuery, verifierId)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_REGION,
                ),
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_COUNTRY,
                ),
            )

            val vp = createPresentation(holder, challenge, dcqlQuery, verifierId)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT")
                    ),
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_REGION,
                ),
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_COUNTRY,
                ),
            )

            val vp = createPresentation(holder, challenge, dcqlQuery, verifierId)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 3 // for address, region, country
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        "with claims in address recursively selectively disclosable, getting inner disclosures" {
            listOf(
                ClaimToBeIssued(
                    CLAIM_ADDRESS,
                    listOf(
                        ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna"),
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT")
                    ),
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(CLAIM_ADDRESS)))

            val vp = createPresentation(holder, challenge, dcqlQuery, verifierId)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_REGION,
                ),
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_COUNTRY,
                ),
            )

            val vp = createPresentation(holder, challenge, dcqlQuery, verifierId)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
            ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                ),
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_FAMILY_NAME),
                ),
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ALWAYS_VISIBLE),
                ),
            )

            val vp = createPresentation(holder, challenge, dcqlQuery, verifierId)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
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
})

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
            )
        ).getOrThrow().toStoreCredentialInput()
    )
}

private fun buildDCQLQuery(vararg claimsQueries: DCQLJsonClaimsQuery) = DCQLQuery(
    credentials = DCQLCredentialQueryList(
        DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier(uuid4().toString()),
            format = CredentialFormatEnum.DC_SD_JWT,
            claims = DCQLClaimsQueryList(claimsQueries.toList().toNonEmptyList()),
        )
    )
)

private suspend fun createPresentation(
    holder: Holder,
    challenge: String,
    dcqlQuery: DCQLQuery,
    verifierId: String,
) = holder.createDefaultPresentation(
    request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
    credentialPresentationRequest = DCQLRequest(dcqlQuery),
).getOrThrow().let {
    it as PresentationResponseParameters.DCQLParameters
}.verifiablePresentations.values.firstOrNull()


private const val CLAIM_ALWAYS_VISIBLE = "alwaysVisible"
private const val CLAIM_ADDRESS = "address"
private const val CLAIM_ADDRESS_REGION = "region"
private const val CLAIM_ADDRESS_COUNTRY = "country"