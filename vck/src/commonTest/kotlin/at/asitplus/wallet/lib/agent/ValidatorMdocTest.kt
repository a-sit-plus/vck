package at.asitplus.wallet.lib.agent

import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueIsoMdoc
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.comparables.shouldNotBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

val ValidatorMdocTest by matrixSuite {
    fixture {
        object {
            val issuerKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val validator = ValidatorMdoc(
                validator = Validator(
                    tokenStatusResolver = randomCwtOrJwtResolver(statusListIssuer)
                )
            )
            val issuer = IssuerAgent(
                keyMaterial = issuerKeyMaterial,
                issuerCredentialStore = issuerCredentialStore,
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val verifierKeyMaterial = EphemeralKeyWithoutCert()
        }
    } - {
        test("freshly issued credentials are valid") {
            val credential = issueIsoMdoc(it.issuer, it.verifierKeyMaterial)
                .shouldBeInstanceOf<Issuer.IssuedCredential.Iso>().apply {
                    // Assert the issuanceOffset in IssuerAgent
                    issuerSigned.issuerAuth.payload.shouldNotBeNull().apply {
                        validityInfo.validFrom shouldBeLessThan Clock.System.now().minus(1.minutes)
                        validityInfo.validFrom shouldNotBeGreaterThan Clock.System.now()
                    }
                }

            it.validator.verifyIsoCred(credential.issuerSigned).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessIso>()
        }

        test("tampered issuer signed items are marked as invalid items") {
            val credential = issueIsoMdoc(it.issuer, it.verifierKeyMaterial)
                .shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            val issuerNamespaces = credential.issuerSigned.namespaces.shouldNotBeNull()
            val namespace = issuerNamespaces.keys.first()
            val targetItem = issuerNamespaces.values.flatMap { it.entries }.map { it.value }
                .first { it.elementValue is String }
            val tamperedItem = IssuerSignedItem(
                digestId = targetItem.digestId,
                random = targetItem.random,
                elementIdentifier = targetItem.elementIdentifier,
                elementValue = (targetItem.elementValue as String) + "-TAMPERED-BY-ATTACKER",
            )
            val tamperedItems = issuerNamespaces.values.flatMap { it.entries }.map { it.value } + tamperedItem
            val tampered = IssuerSigned.fromIssuerSignedItems(
                namespacedItems = mapOf(namespace to tamperedItems),
                issuerAuth = credential.issuerSigned.issuerAuth
            )
            val document = Document(
                docType = ConstantIndex.AtomicAttribute2023.isoDocType,
                issuerSigned = tampered,
                deviceSigned = DeviceSigned(
                    namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf())),
                    deviceAuth = DeviceAuth(
                        deviceSignature = null
                    )
                )
            )

            shouldThrowAny {
                it.validator.verifyDocument(document) { _, _ -> true }
            }
        }

        test("revoked credentials are not valid") {
            val credential = issueIsoMdoc(it.issuer, it.verifierKeyMaterial)
                .shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            val value = it.validator.verifyIsoCred(credential.issuerSigned).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessIso>()

            it.issuerCredentialStore.setStatus(
                timePeriod = FixedTimePeriodProvider.timePeriod,
                index = credential.issuerSigned.issuerAuth.payload.shouldNotBeNull()
                    .status.shouldBeInstanceOf<StatusListInfo>().index,
                status = TokenStatus.Invalid,
            ) shouldBe true

            it.validator.checkRevocationStatus(value.issuerSigned)
                .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
        }

        test("document errors are preserved in parsed output") {
            val credential = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ISO_MDOC,
                ).getOrThrow().shouldBeInstanceOf<CredentialToBeIssued.Iso>()
                    .copy(digest = Digest.SHA384)
            ).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            val documentErrors = mapOf(
                ConstantIndex.AtomicAttribute2023.isoNamespace to mapOf(
                    ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME to 42,
                ),
            )

            val document = Document(
                docType = ConstantIndex.AtomicAttribute2023.isoDocType,
                issuerSigned = credential.issuerSigned,
                deviceSigned = DeviceSigned(
                    namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf())),
                    deviceAuth = DeviceAuth(),
                ),
                errors = documentErrors,
            )

            it.validator.verifyDocument(document) { _, _ -> true }.apply {
                mso.digest shouldBe Digest.SHA384
                mso.valueDigests.values.single().entries.all { it.value.size == 48 } shouldBe true
                validItems.size shouldBe 4
                documentErrors shouldBe documentErrors
            }
        }
    }
}
