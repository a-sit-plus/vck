package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLExpectedClaimValue
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderModifierFun
import at.asitplus.wallet.lib.jws.SignJwtExt
import at.asitplus.wallet.lib.jws.SignJwtExtFun
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.ValidatedCredential
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

/**
 * Selecting single elements of an array claim, whose elements are selectively disclosable (RFC 9901, 4.2.2), with
 * claims path pointers containing an index or `null` (OpenID4VP 1.0, 7.1).
 *
 * Indices and `null` address the array as issued, i.e. counting elements that are not disclosed
 * (draft-ietf-oauth-sd-jwt-vc-19, 5.6), while decoy digests (RFC 9901, 4.2.5) are no elements of the credential.
 */
val AgentSdJwtArrayElementDcqlTest by matrixSuite {

    fixture {
        object {
            val issuerKeyMaterial = EphemeralKeyWithoutCert()
            val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val holder = HolderAgent(holderKeyMaterial)
            val verifierId = "urn:${uuid4()}"
            val verifier = NonceChallengeVerifier(verifierId = verifierId)

            fun issuer(signIssuedSdJwt: SignJwtExtFun<JsonObject> = SignJwtExt(issuerKeyMaterial, JwsHeaderCertOrJwk())) =
                IssuerAgent(
                    keyMaterial = issuerKeyMaterial,
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default,
                    signIssuedSdJwt = signIssuedSdJwt,
                )

            /** The accepted [presentation] answering [request]. */
            suspend fun validate(presentation: CreatePresentationResult, request: PresentationRequestParameters) =
                CredentialValidator().validatePresentation(
                    presentation = presentation,
                    context = verifier.consumeChallenge(request.nonce).context(audience = verifierId),
                ).shouldBeSingleton().first().acceptedOrThrow()
                    .shouldBeInstanceOf<ValidatedPresentation.SdJwt>()
        }
    } - {

        test("element selected by value with null segment is disclosed alone, and satisfies the query") {
            issueAndStoreNationalities(it.holder, it.issuer(), it.holderKeyMaterial, nationalitySd = true)
            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_NATIONALITIES) + null,
                    values = listOf(DCQLExpectedClaimValue.StringValue("DE")),
                )
            )

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val presentation = it.validate(vp, request)
            presentation.credential.disclosedNationalities() shouldBe listOf("DE")
            dcqlQuery.checkSubmissionRequirements(presentation).getOrThrow()
        }

        test("element selected by index is disclosed alone, and satisfies the query") {
            issueAndStoreNationalities(it.holder, it.issuer(), it.holderKeyMaterial, nationalitySd = true)
            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(CLAIM_NATIONALITIES) + 1u)
            )

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val presentation = it.validate(vp, request)
            presentation.credential.disclosedNationalities() shouldBe listOf("DE")
            // The index addresses the array as issued, where "DE" is at index 1, not the processed payload of the
            // presentation, where the withheld element "AT" has been removed (RFC 9901, 7.1 step 3.d)
            dcqlQuery.checkSubmissionRequirements(presentation).getOrThrow()
        }

        test("element selected by value with null segment is disclosed alone, with a decoy digest in the array") {
            // nationalities: [{"...": <decoy>}, {"...": <AT>}, {"...": <DE>}], so the array as issued is ["AT", "DE"]
            val issuer = it.issuer(SignWithLeadingArrayDecoy(it.issuerKeyMaterial, CLAIM_NATIONALITIES))
            issueAndStoreNationalities(it.holder, issuer, it.holderKeyMaterial, nationalitySd = false)
            val dcqlQuery = buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_NATIONALITIES) + null,
                    values = listOf(DCQLExpectedClaimValue.StringValue("DE")),
                )
            )

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.validate(vp, request).credential.disclosedNationalities() shouldBe listOf("DE")
        }

        test("index into an array without element digests is checked at its position") {
            issueAndStoreNationalities(
                it.holder, it.issuer(), it.holderKeyMaterial, nationalitySd = true, elementsSd = false
            )
            val dcqlQuery = buildDCQLQuery(nationalityAt(1u, "DE"))

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val presentation = it.validate(vp, request)
            presentation.credential.disclosedNationalities() shouldBe listOf("AT", "DE")
            dcqlQuery.checkSubmissionRequirements(presentation).getOrThrow()
            // Every element is in the presentation, so positions are known: "AT" is at index 0
            buildDCQLQuery(nationalityAt(0u, "DE")).checkSubmissionRequirements(presentation).isFailure shouldBe true
        }

        test("index into an array with element digests matches any disclosed element") {
            issueAndStoreNationalities(it.holder, it.issuer(), it.holderKeyMaterial, nationalitySd = true)
            val dcqlQuery = buildDCQLQuery(nationalityAt(1u, "DE"))

            val request = it.verifier.createPresentationRequest()
            val vp = createPresentation(it.holder, request, dcqlQuery)
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val presentation = it.validate(vp, request)
            presentation.credential.disclosedNationalities() shouldBe listOf("DE")
            // The withheld "AT" may as well be a decoy (RFC 9901, 4.2.5), so the position of "DE" can not be determined
            buildDCQLQuery(nationalityAt(0u, "DE")).checkSubmissionRequirements(presentation).getOrThrow()
        }
    }
}

private fun nationalityAt(index: UInt, value: String) = DCQLJsonClaimsQuery(
    path = DCQLClaimsPathPointer(CLAIM_NATIONALITIES) + index,
    values = listOf(DCQLExpectedClaimValue.StringValue(value)),
)

/**
 * Signs SD-JWTs like [SignJwtExt], but puts a decoy digest (RFC 9901, 4.2.5) in front of the elements of the array
 * claim [claimName] of the issuer-signed payload.
 */
private class SignWithLeadingArrayDecoy(
    keyMaterial: KeyMaterial,
    private val claimName: String,
) : SignJwtExtFun<JsonObject> {
    private val delegate = SignJwtExt<JsonObject>(keyMaterial, JwsHeaderCertOrJwk())

    override suspend fun invoke(
        type: String?,
        payload: JsonObject,
        serializer: SerializationStrategy<JsonObject>,
        additionalHeaderModifier: JwsHeaderModifierFun,
    ): KmmResult<JwsCompactTyped<JsonObject>> {
        val decoy = buildJsonObject {
            put("...", JsonPrimitive(Random.nextBytes(32).encodeToString(Base64UrlStrict)))
        }
        val elements = payload.getValue(claimName).jsonArray
        val modified = JsonObject(payload + (claimName to JsonArray(listOf(decoy) + elements)))
        return delegate(type, modified, serializer, additionalHeaderModifier)
    }
}

/**
 * Issues `nationalities: ["AT", "DE"]`, the array itself selectively disclosable if [nationalitySd] and its elements if
 * [elementsSd], like the EU PID of the issuing backend by default.
 */
private suspend fun issueAndStoreNationalities(
    holder: Holder,
    issuer: Issuer,
    holderKeyMaterial: KeyMaterial,
    nationalitySd: Boolean,
    elementsSd: Boolean = true,
) {
    holder.storeCredential(
        issuer.issueCredential(
            CredentialToBeIssued.VcSd(
                claims = listOf(
                    ClaimToBeIssued(
                        CLAIM_NATIONALITIES,
                        listOf("AT", "DE").map { ClaimToBeIssuedArrayElement(it, elementsSd) },
                        selectivelyDisclosable = nationalitySd,
                    ),
                    ClaimToBeIssued(AtomicAttribute2023.CLAIM_GIVEN_NAME, "Susanne"),
                ),
                expiration = Clock.System.now() + 1.minutes,
                scheme = AtomicAttribute2023,
                subjectPublicKey = holderKeyMaterial.publicKey,
                userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
            )
        ).getOrThrow().toStoreCredentialInput()
    ).getOrThrow()
}

private fun ValidatedCredential.SdJwtVc.disclosedNationalities() =
    decoded.reconstructedJsonObject[CLAIM_NATIONALITIES]?.jsonArray?.map { it.jsonPrimitive.content }

private fun DCQLQuery.checkSubmissionRequirements(presentation: ValidatedPresentation) =
    DCQLQueryAdapter(this).checkAcceptedSubmissions(mapOf(credentials.single().id to listOf(presentation)))

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

private const val CLAIM_NATIONALITIES = "nationalities"
