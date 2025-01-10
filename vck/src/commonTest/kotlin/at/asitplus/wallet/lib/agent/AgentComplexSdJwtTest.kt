package at.asitplus.wallet.lib.agent

import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.jws.SdJwtSigned
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock
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
        issuer = IssuerAgent(EphemeralKeyWithoutCert(), issuerCredentialStore)
        holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        holder = HolderAgent(holderKeyMaterial, holderCredentialStore)
        verifierId = "urn:${uuid4()}"
        verifier = VerifierAgent(identifier = verifierId)
        challenge = uuid4().toString()
    }

    "with flat address" {
        listOf(
            ClaimToBeIssued(
                CLAIM_ADDRESS, listOf(
                    ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna", selectivelyDisclosable = false),
                    ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT", selectivelyDisclosable = false)
                )
            ),
        ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

        val presentationDefinition = buildPresentationDefinition(
            "$['$CLAIM_ADDRESS']['$CLAIM_ADDRESS_REGION']",
            "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY",
        )

        val vp = createPresentation(holder, challenge, presentationDefinition, verifierId)
            .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

        val verified = verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

        verified.disclosures.size shouldBe 1 // for address only

        verified.reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
            ?.jsonPrimitive?.content shouldBe "Vienna"
        verified.reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
            ?.jsonPrimitive?.content shouldBe "AT"
    }

    "with claims in address selectively disclosable, but address not" {
        listOf(
            ClaimToBeIssued(
                CLAIM_ADDRESS, listOf(
                    ClaimToBeIssued(CLAIM_ADDRESS_REGION, "Vienna"),
                    ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, "AT")
                ), selectivelyDisclosable = false
            ),
        ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

        val presentationDefinition = buildPresentationDefinition(
            "$['$CLAIM_ADDRESS']['$CLAIM_ADDRESS_REGION']",
            "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY",
        )

        val vp = createPresentation(holder, challenge, presentationDefinition, verifierId)
            .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

        val verified = verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

        verified.disclosures.size shouldBe 2 // for region, country

        verified.reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
            ?.jsonPrimitive?.content shouldBe "Vienna"
        verified.reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
            ?.jsonPrimitive?.content shouldBe "AT"
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
        ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

        val presentationDefinition = buildPresentationDefinition(
            "$['$CLAIM_ADDRESS']['$CLAIM_ADDRESS_REGION']",
            "$.$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY",
        )

        val vp = createPresentation(holder, challenge, presentationDefinition, verifierId)
            .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

        val verified = verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

        verified.disclosures.size shouldBe 3 // for address, region, country

        verified.reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_REGION)
            ?.jsonPrimitive?.content shouldBe "Vienna"
        verified.reconstructedJsonObject[CLAIM_ADDRESS]?.jsonObject?.get(CLAIM_ADDRESS_COUNTRY)
            ?.jsonPrimitive?.content shouldBe "AT"
    }

    "simple walk-through success" {
        listOf(
            ClaimToBeIssued(CLAIM_GIVEN_NAME, "Susanne"),
            ClaimToBeIssued(CLAIM_FAMILY_NAME, "Meier"),
            ClaimToBeIssued(CLAIM_ALWAYS_VISIBLE, "anything", selectivelyDisclosable = false)
        ).apply { issueAndStoreCredential(holder, issuer, this, holderKeyMaterial) }

        val presentationDefinition = buildPresentationDefinition(
            "$['$CLAIM_GIVEN_NAME']",
            "$['$CLAIM_FAMILY_NAME']",
            "$.$CLAIM_ALWAYS_VISIBLE"
        )

        val vp = createPresentation(holder, challenge, presentationDefinition, verifierId)
            .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

        val verified = verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

        verified.disclosures.size shouldBe 2 // claim_given_name, claim_family_name

        verified.reconstructedJsonObject[CLAIM_GIVEN_NAME]
            ?.jsonPrimitive?.content shouldBe "Susanne"
        verified.reconstructedJsonObject[CLAIM_FAMILY_NAME]
            ?.jsonPrimitive?.content shouldBe "Meier"
        verified.reconstructedJsonObject[CLAIM_ALWAYS_VISIBLE]
            ?.jsonPrimitive?.content shouldBe "anything"
    }

})

private suspend fun issueAndStoreCredential(
    holder: Holder,
    issuer: Issuer,
    claims: List<ClaimToBeIssued>,
    holderKeyMaterial: KeyMaterial
) {
    holder.storeCredential(
        issuer.issueCredential(
            CredentialToBeIssued.VcSd(
                claims = claims,
                expiration = Clock.System.now() + 1.minutes,
                scheme = AtomicAttribute2023,
                subjectPublicKey = holderKeyMaterial.publicKey,
            )
        ).getOrThrow().toStoreCredentialInput()
    )
}

private fun buildPresentationDefinition(vararg attributeName: String) = PresentationDefinition(
    id = uuid4().toString(),
    inputDescriptors = listOf(
        DifInputDescriptor(
            id = uuid4().toString(),
            constraints = Constraint(
                fields = attributeName.map { ConstraintField(path = listOf(it)) }
            )
        )
    )
)

private suspend fun createPresentation(
    holder: Holder,
    challenge: String,
    presentationDefinition: PresentationDefinition,
    verifierId: String
) = holder.createPresentation(
    request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
    presentationDefinition = presentationDefinition
).getOrThrow().presentationResults.firstOrNull()


private const val CLAIM_ALWAYS_VISIBLE = "alwaysVisible"
private const val CLAIM_ADDRESS = "address"
private const val CLAIM_ADDRESS_REGION = "region"
private const val CLAIM_ADDRESS_COUNTRY = "country"