package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
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

    beforeEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent(EphemeralKeyWithoutCert(), issuerCredentialStore)
        holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        holder = HolderAgent(holderKeyMaterial, holderCredentialStore)
        verifier = VerifierAgent()
        challenge = uuid4().toString()
    }

    "simple walk-through success" {
        holder.storeCredential(
            issuer.issueCredential(
                getCredential(holderKeyMaterial.publicKey, AtomicAttribute2023, SD_JWT).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = verifier.keyMaterial.identifier,
            presentationDefinition = buildPresentationDefinition(
                "$['$CLAIM_GIVEN_NAME']",
                "$['$CLAIM_FAMILY_NAME']",
                "$['address']['region']",
                "$.address.country",
            )
        ).getOrThrow()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()

        val verified = verifier.verifyPresentation(vp.sdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

        verified.reconstructedJsonObject[CLAIM_GIVEN_NAME]
            ?.jsonPrimitive?.content shouldBe "Susanne"
        verified.reconstructedJsonObject[CLAIM_FAMILY_NAME]
            ?.jsonPrimitive?.content shouldBe "Meier"
        verified.reconstructedJsonObject["address"]?.jsonObject?.get("region")
            ?.jsonPrimitive?.content shouldBe "Vienna"
        verified.reconstructedJsonObject["address"]?.jsonObject?.get("country")
            ?.jsonPrimitive?.content shouldBe "AT"
        verified.isRevoked shouldBe false
    }

})

private fun getCredential(
    subjectPublicKey: CryptoPublicKey,
    credentialScheme: ConstantIndex.CredentialScheme,
    representation: ConstantIndex.CredentialRepresentation,
): KmmResult<CredentialToBeIssued> = catching {
    val claims = listOf(
        ClaimToBeIssued(CLAIM_GIVEN_NAME, "Susanne"),
        ClaimToBeIssued(CLAIM_FAMILY_NAME, "Meier"),
        ClaimToBeIssued(
            "address", listOf(
                ClaimToBeIssued("region", "Vienna"),
                ClaimToBeIssued("country", "AT")
            )
        )
    )
    when (representation) {
        ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialToBeIssued.VcSd(
            claims = claims,
            expiration = Clock.System.now() + 1.minutes,
            scheme = credentialScheme,
            subjectPublicKey = subjectPublicKey,
        )

        else -> throw IllegalArgumentException(representation.toString())
    }
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
