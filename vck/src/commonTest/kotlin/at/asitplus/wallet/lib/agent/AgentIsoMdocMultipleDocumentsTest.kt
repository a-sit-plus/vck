package at.asitplus.wallet.lib.agent

import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.PresentationExchangeRequest
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.engine.runBlocking
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlinx.serialization.builtins.ByteArraySerializer

val AgentIsoMdocMultipleDocumentsTest by testSuite {

    withFixtureGenerator {
        object {
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val holderCredentialStore = InMemorySubjectCredentialStore()
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                issuerCredentialStore = issuerCredentialStore,
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val validator = ValidatorMdoc(
                validator = Validator(tokenStatusResolver = randomCwtOrJwtResolver(statusListIssuer))
            )
            val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val holder = HolderAgent(
                holderKeyMaterial,
                holderCredentialStore,
                validatorMdoc = validator,
            ).also {
                runBlocking {
                    it.storeCredential(
                        issuer.issueCredential(
                            DummyCredentialDataProvider.getCredentialForClaim(
                                holderKeyMaterial.publicKey,
                                AtomicAttribute2023,
                                ConstantIndex.CredentialRepresentation.ISO_MDOC,
                                ClaimToBeIssued(CLAIM_GIVEN_NAME, "Susanne"),
                            ).getOrThrow()
                        ).getOrThrow().toStoreCredentialInput()
                    ).getOrThrow()
                    it.storeCredential(
                        issuer.issueCredential(
                            DummyCredentialDataProvider.getCredentialForClaim(
                                holderKeyMaterial.publicKey,
                                AtomicAttribute2025,
                                ConstantIndex.CredentialRepresentation.ISO_MDOC,
                                ClaimToBeIssued(CLAIM_FAMILY_NAME, "Meier"),
                            ).getOrThrow()
                        ).getOrThrow().toStoreCredentialInput()
                    ).getOrThrow()
                }
            }
            val verifierId = "urn:${uuid4()}"
            val verifier = VerifierAgent(
                identifier = verifierId,
                validatorMdoc = validator,
            )
            val challenge = uuid4().toString()
            val signer = SignCose<ByteArray>(keyMaterial = holderKeyMaterial)
        }
    } - {

        test("presex: multiple credentials should be multiple device responses for remote presentation") {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId,
                    calcIsoDeviceSignaturePlain = simpleSigner(it.signer),
                    returnOneDeviceResponse = false
                ),
                credentialPresentation = PresentationExchangePresentation(
                    PresentationExchangeRequest(
                        PresentationDefinition(
                            listOf(
                                inputDescriptor(AtomicAttribute2023, CLAIM_GIVEN_NAME),
                                inputDescriptor(AtomicAttribute2025, CLAIM_FAMILY_NAME),
                            )
                        ),
                    )
                )
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            presentationParameters.presentationResults.shouldHaveSize(2).forEach { result ->
                result.shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()
                it.verifier.verifyPresentationIsoMdoc(result.deviceResponse, documentVerifier())
                    .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>().apply {
                        documents.shouldBeSingleton().forEach {
                            it.freshnessSummary.tokenStatusValidationResult
                                .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                        }
                    }
            }
            val validItems = presentationParameters.presentationResults
                .filterIsInstance<CreatePresentationResult.DeviceResponse>()
                .map { resp -> it.verifier.verifyPresentationIsoMdoc(resp.deviceResponse, documentVerifier()) }
                .flatMap { it.shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>().documents }
                .flatMap { it.validItems }
            validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_GIVEN_NAME }
                .shouldNotBeNull().elementValue shouldBe "Susanne"
            validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_FAMILY_NAME }
                .shouldNotBeNull().elementValue shouldBe "Meier"
        }

        test("presex: multiple credentials should be one device response for local presentation") {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId,
                    calcIsoDeviceSignaturePlain = simpleSigner(it.signer),
                    returnOneDeviceResponse = true
                ),
                credentialPresentation = PresentationExchangePresentation(
                    PresentationExchangeRequest(
                        PresentationDefinition(
                            listOf(
                                inputDescriptor(AtomicAttribute2023, CLAIM_GIVEN_NAME),
                                inputDescriptor(AtomicAttribute2025, CLAIM_FAMILY_NAME),
                            )
                        ),
                    )
                ),
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            presentationParameters.presentationResults
                .shouldBeSingleton().firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>().let { result ->
                    it.verifier.verifyPresentationIsoMdoc(result.deviceResponse, documentVerifier())
                        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>().apply {
                            documents.shouldHaveSize(2).forEach {
                                it.freshnessSummary.tokenStatusValidationResult
                                    .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                            }
                        }
                }

            val validItems = presentationParameters.presentationResults
                .filterIsInstance<CreatePresentationResult.DeviceResponse>()
                .map { resp -> it.verifier.verifyPresentationIsoMdoc(resp.deviceResponse, documentVerifier()) }
                .flatMap { it.shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>().documents }
                .flatMap { it.validItems }
            validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_GIVEN_NAME }
                .shouldNotBeNull().elementValue shouldBe "Susanne"
            validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_FAMILY_NAME }
                .shouldNotBeNull().elementValue shouldBe "Meier"
        }
    }
}

private fun inputDescriptor(
    scheme: ConstantIndex.CredentialScheme,
    claim: String
) = DifInputDescriptor(
    id = scheme.isoDocType!!,
    constraints = Constraint(
        fields = setOf(
            ConstraintField(
                path = path(scheme, claim)
            )
        )
    )
)

private fun path(scheme: ConstantIndex.CredentialScheme, claimName: String): List<String> = listOf(
    NormalizedJsonPath(
        NameSegment(scheme.isoNamespace!!),
        NameSegment(claimName),
    ).toString()
)

private fun simpleSigner(
    signer: SignCose<ByteArray>
): suspend (IsoDeviceSignatureInput) -> CoseSigned<ByteArray>? = { input ->
    signer(
        protectedHeader = null,
        unprotectedHeader = null,
        payload = input.docType.encodeToByteArray(),
        serializer = ByteArraySerializer()
    ).getOrThrow()
}

// No OpenID4VP, no need to verify the device signature
private fun documentVerifier(): suspend (MobileSecurityObject, Document) -> Boolean = { _, _ -> true }


object AtomicAttribute2025 : ConstantIndex.CredentialScheme {
    const val CLAIM_GIVEN_NAME = "given_name"
    const val CLAIM_FAMILY_NAME = "family_name"
    const val CLAIM_DATE_OF_BIRTH = "date_of_birth"
    const val CLAIM_PORTRAIT = "portrait"
    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/AtomicAttribute2025.json"
    override val vcType: String = "AtomicAttribute2025"
    override val sdJwtType: String = "AtomicAttribute2025"
    override val isoNamespace: String = "at.a-sit.wallet.atomic-attribute-2025"
    override val isoDocType: String = "at.a-sit.wallet.atomic-attribute-2025.iso"
    override val claimNames: Collection<String> = listOf(
        CLAIM_GIVEN_NAME,
        CLAIM_FAMILY_NAME,
        CLAIM_DATE_OF_BIRTH,
        CLAIM_PORTRAIT
    )
}
