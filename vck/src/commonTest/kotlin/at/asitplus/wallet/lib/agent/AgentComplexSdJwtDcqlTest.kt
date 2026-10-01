package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import com.benasher44.uuid.uuid4
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

val AgentComplexSdJwtDcqlTest by matrixSuite {

    fixture {
        object {
            val issuer = IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val holder = HolderAgent(holderKeyMaterial)
            val verifierId = "urn:${uuid4()}"
            val verifier = NonceChallengeVerifier(
                verifierId = verifierId,
                verifier = VerifierAgent(identifier = verifierId),
            )
        }
    } - {

        test("with flat address") {
            listOf(
                ClaimToBeIssued(
                    CLAIM_ADDRESS, listOf(
                        ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna", selectivelyDisclosable = false),
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT", selectivelyDisclosable = false)
                    )
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_REGION,
                ),
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_COUNTRY,
                ),
            )

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 1 // for address only
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        test("with claims in address selectively disclosable, but address not") {
            listOf(
                ClaimToBeIssued(
                    CLAIM_ADDRESS, listOf(
                        ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna"),
                        ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT")
                    ), selectivelyDisclosable = false
                ),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_REGION,
                ),
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_COUNTRY,
                ),
            )

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 2 // for region, country

                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        test("with claims in address recursively selectively disclosable") {
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

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_REGION,
                ),
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_ADDRESS) + CLAIM_ADDRESS_COUNTRY,
                ),
            )

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 3 // for address, region, country
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        test("with claims in address recursively selectively disclosable, getting inner disclosures") {
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

            val dcqlQuery = buildDCQLQuery(DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(CLAIM_ADDRESS)))

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 3 // for address, region, country
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
                        ?.jsonPrimitive?.content shouldBe "Vienna"
                    reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
                        ?.jsonPrimitive?.content shouldBe "AT"
                }
        }

        test("claim name with dot is stored flat, NOT nested") {
            val dotClaimName = "$CLAIM_ADDRESS.$CLAIM_ADDRESS_REGION"
            listOf(
                ClaimToBeIssued(dotClaimName, "Vienna"),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(dotClaimName)),
            )

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 1
                    reconstructedJsonObject[CLAIM_ADDRESS] shouldBe null
                    reconstructedJsonObject[dotClaimName]?.jsonPrimitive?.content shouldBe "Vienna"
                }
        }

        test("simple walk-through success") {
            listOf(
                ClaimToBeIssued(AtomicAttribute2023.CLAIM_GIVEN_NAME, "Susanne"),
                ClaimToBeIssued(AtomicAttribute2023.CLAIM_FAMILY_NAME, "Meier"),
                ClaimToBeIssued(CLAIM_ALWAYS_VISIBLE, "anything", selectivelyDisclosable = false),
                nonsenseClaim()
            ).apply { issueAndStoreCredential(it.holder, it.issuer, this, it.holderKeyMaterial) }

            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_GIVEN_NAME)),
                DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_FAMILY_NAME)),
                DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(CLAIM_ALWAYS_VISIBLE)),
            )

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    disclosures.size shouldBe 2 // claim_given_name, claim_family_name
                    reconstructedJsonObject[AtomicAttribute2023.CLAIM_GIVEN_NAME]
                        ?.jsonPrimitive?.content shouldBe "Susanne"
                    reconstructedJsonObject[AtomicAttribute2023.CLAIM_FAMILY_NAME]
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

private fun buildDCQLQuery(vararg claimsQueries: DCQLJsonClaimsQuery) = DCQLQuery(
    credentials = DCQLCredentialQueryList(
        DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier(uuid4().toString()),
            format = CredentialFormatEnum.DC_SD_JWT,
            claims = DCQLClaimsQueryList(claimsQueries.toList().toNonEmptyList()),
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(listOf(AtomicAttribute2023.sdJwtType))
        )
    )
)

private suspend fun createPresentation(
    holder: Holder,
    request: PresentationRequestParameters,
    dcqlQuery: DCQLQuery,
) = holder.createDefaultPresentation(
    request = request,
    credentialPresentationRequest = DCQLRequest(dcqlQuery),
).getOrThrow().let {
    it as PresentationResponseParameters.DCQLParameters
}.verifiablePresentations.values.firstOrNull()?.first()

private const val CLAIM_ALWAYS_VISIBLE = "alwaysVisible"
private const val CLAIM_ADDRESS = "address"
private const val CLAIM_ADDRESS_REGION = "region"
private const val CLAIM_ADDRESS_COUNTRY = "country"