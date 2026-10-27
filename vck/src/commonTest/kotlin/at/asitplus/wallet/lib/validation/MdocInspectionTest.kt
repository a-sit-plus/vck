package at.asitplus.wallet.lib.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import at.asitplus.wallet.mdl.MDL_NAMESPACE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.ISSUING_COUNTRY
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.ISSUING_JURISDICTION
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private fun country(code: String) = AttributeTypeAndValue.Country(Asn1String.Printable(code))

private fun state(name: String) = AttributeTypeAndValue.Other(ObjectIdentifier("2.5.4.8"), Asn1String.UTF8(name))

private val noLeeway = TimeScope(Clock.System.now(), Duration.ZERO)

/** An mdoc of [scheme] issued with [documentSigner], whose MSO is signed [issuanceOffset] before now. */
private suspend fun issueMdoc(
    documentSigner: KeyMaterial,
    issuanceOffset: Duration = (-3).minutes,
): IssuerSigned {
    val issuer = IssuerAgent(
        keyMaterial = documentSigner,
        issuerCredentialStore = InMemoryIssuerCredentialStore(),
        issuanceOffset = issuanceOffset,
        identifier = "https://issuer.example.com/".toUri(),
    )
    val credential = DummyCredentialDataProvider
        .getCredential(EphemeralKeyWithoutCert().publicKey, scheme, CredentialRepresentation.ISO_MDOC).getOrThrow()
    return (issuer.issueCredential(credential).getOrThrow() as Issuer.IssuedCredential.Iso).issuerSigned
}

/** Validates [issuerSigned] with [anchors] as the issuers of [scheme], neither requiring nor resolving a status. */
private suspend fun validate(issuerSigned: IssuerSigned, anchors: Set<X509Certificate>) = CredentialValidator(
    trustAnchors = CredentialTrustScopes(
        CredentialTrustScope(
            credentialIdentifiers = setOf(scheme.isoDocType),
            source = "test IACAs",
            issuance = { anchors },
            status = { anchors },
        )
    ),
).validate(
    input = CredentialValidationInput.IsoMdoc(
        coseCompliantSerializer.encodeToByteArray(IssuerSigned.serializer(), issuerSigned)
    ),
    policy = strictPolicy.copy(status = StatusPolicy.Skip),
)

private val CredentialValidationResult.checks get() = report.checks.shouldBeInstanceOf<CredentialChecks>()

private fun MobileSecurityObject.withValidity(
    signed: Instant = validityInfo.signed,
    validFrom: Instant = validityInfo.validFrom,
    validUntil: Instant = validityInfo.validUntil,
) = copy(validityInfo = validityInfo.copy(signed = signed, validFrom = validFrom, validUntil = validUntil))

/** [issuerSigned] with the mDL elements [items] in its namespace, for the issuing authority check only. */
private fun mdlItems(issuerSigned: IssuerSigned, vararg items: Pair<String, String>) =
    IssuerSigned.fromIssuerSignedItems(
        namespacedItems = mapOf(MDL_NAMESPACE to items.mapIndexed { index, (identifier, value) ->
            IssuerSignedItem(index.toUInt(), Random.nextBytes(16), identifier, value)
        }),
        issuerAuth = issuerSigned.issuerAuth,
    )

val MdocInspectionTest by matrixSuite {

    "validityInfo" - {
        "is consistent if validFrom is not before signed and validUntil after validFrom" {
            val mso = issueMdoc(TestCertificateAuthority().issue()).issuerAuth.payload.shouldNotBeNull()
            val signed = mso.validityInfo.signed

            mso.validityIsConsistent() shouldBe Passed
            mso.withValidity(validFrom = signed - 1.seconds).validityIsConsistent().shouldBeInstanceOf<Failed>()
            mso.withValidity(validFrom = signed, validUntil = signed).validityIsConsistent()
                .shouldBeInstanceOf<Failed>()
        }

        "was signed within the validity of the document signer certificate, with the leeway" {
            val documentSigner = TestCertificateAuthority().issue().getCertificate().shouldNotBeNull()
            val notBefore = documentSigner.tbsCertificate.validFrom.instant
            val notAfter = documentSigner.tbsCertificate.validUntil.instant
            val mso = issueMdoc(TestCertificateAuthority().issue()).issuerAuth.payload.shouldNotBeNull()
            val leeway = TimeScope(Clock.System.now(), 5.minutes)

            listOf(notBefore, notAfter).forEach {
                mso.withValidity(signed = it).isSignedWithinValidityOf(documentSigner, noLeeway) shouldBe Passed
            }
            listOf(notBefore - 1.seconds, notAfter + 1.seconds).forEach {
                mso.withValidity(signed = it).isSignedWithinValidityOf(documentSigner, noLeeway)
                    .shouldBeInstanceOf<Failed>()
                mso.withValidity(signed = it).isSignedWithinValidityOf(documentSigner, leeway) shouldBe Passed
            }
        }

        "expires within the document signer certificate" {
            val documentSigner = TestCertificateAuthority().issue().getCertificate().shouldNotBeNull()
            val notAfter = documentSigner.tbsCertificate.validUntil.instant
            val mso = issueMdoc(TestCertificateAuthority().issue()).issuerAuth.payload.shouldNotBeNull()

            mso.withValidity(validUntil = notAfter).expiresWithin(documentSigner) shouldBe Passed
            mso.withValidity(validUntil = notAfter + 1.seconds).expiresWithin(documentSigner)
                .shouldBeInstanceOf<Failed>()
        }
    }

    "an mdoc signed long before its document signer certificate is valid fails its semantics, but not trust" {
        val iaca = TestCertificateAuthority()
        val documentSigner = iaca.issue(validFrom = Clock.System.now() - 1.minutes)
        val result = validate(issueMdoc(documentSigner, issuanceOffset = (-30).minutes), setOf(iaca.certificate))

        result.report.decision shouldBe REJECTED
        result.checks.semantics.shouldBeInstanceOf<Failed>()
        result.checks.issuerTrust.outcome shouldBe Passed
    }

    "an mdoc valid until after its document signer certificate expires is only reported" {
        val iaca = TestCertificateAuthority()
        val result = validate(issueMdoc(iaca.issue(validity = 30.seconds)), setOf(iaca.certificate))

        result.report.decision shouldBe ACCEPTED
        result.checks.expiryWithinCertificate.shouldBeInstanceOf<Failed>()
        result.report.namedChecks.single { it.name == "expiryWithinCertificate" }.satisfied shouldBe true

        validate(issueMdoc(iaca.issue(validity = 1.days)), setOf(iaca.certificate))
            .checks.expiryWithinCertificate shouldBe Passed
    }

    "the country and state or province of an IACA and of the document signer it issued" - {
        listOf(
            Triple("are the same", listOf(country("AT"), state("Wien")), listOf(country("AT"), state("Wien"))),
            Triple("are the same country, the IACA without a state", listOf(country("AT")),
                listOf(country("AT"), state("Wien"))),
            Triple("are both absent", listOf(), listOf()),
        ).asData(nameFn = { (name, _, _) -> "pass if they $name" }) test { (_, iacaAttributes, signerAttributes) ->
            val iaca = TestCertificateAuthority(attributes = iacaAttributes)
            val result = validate(
                issueMdoc(iaca.issue(subjectAttributes = signerAttributes)),
                setOf(iaca.certificate),
            )

            result.report.decision shouldBe ACCEPTED
            result.checks.issuerTrust.outcome shouldBe Passed
        }

        listOf(
            Triple("another country", listOf(country("AT")), listOf(country("DE"))),
            Triple("no country", listOf(country("AT")), listOf()),
            Triple("another state", listOf(country("AT"), state("Wien")), listOf(country("AT"), state("Tirol"))),
        ).asData(nameFn = { (name, _, _) -> "fail trust for $name" }) test { (_, iacaAttributes, signerAttributes) ->
            val iaca = TestCertificateAuthority(attributes = iacaAttributes)
            val result = validate(
                issueMdoc(iaca.issue(subjectAttributes = signerAttributes)),
                setOf(iaca.certificate),
            )

            result.report.decision shouldBe REJECTED
            result.checks.issuerTrust.outcome.shouldBeInstanceOf<Failed>()
        }

        "are not compared for a document signer listed as an anchor itself" {
            val documentSigner = TestCertificateAuthority(attributes = listOf(country("AT")))
                .issue(subjectAttributes = listOf(country("DE")))

            validate(issueMdoc(documentSigner), setOf(documentSigner.getCertificate().shouldNotBeNull()))
                .checks.issuerTrust.outcome shouldBe Passed
        }
    }

    "the issuing authority of an mDL" - {
        "is compared with the document signer if disclosed" {
            val signer = TestCertificateAuthority().issue(subjectAttributes = listOf(country("AT"), state("Wien")))
                .getCertificate().shouldNotBeNull()
            val issuerSigned = issueMdoc(TestCertificateAuthority().issue())

            mdlItems(issuerSigned, ISSUING_COUNTRY to "AT", ISSUING_JURISDICTION to "Wien")
                .issuingAuthorityAgreesWith(MDL_DOCTYPE, signer) shouldBe Passed
            mdlItems(issuerSigned).issuingAuthorityAgreesWith(MDL_DOCTYPE, signer) shouldBe Passed
            mdlItems(issuerSigned, ISSUING_COUNTRY to "DE")
                .issuingAuthorityAgreesWith(MDL_DOCTYPE, signer).shouldBeInstanceOf<Failed>()
            mdlItems(issuerSigned, ISSUING_COUNTRY to "AT", ISSUING_JURISDICTION to "Tirol")
                .issuingAuthorityAgreesWith(MDL_DOCTYPE, signer).shouldBeInstanceOf<Failed>()
        }

        "is only compared with a state or province the document signer has, and only for mDLs" {
            val signer = TestCertificateAuthority().issue(subjectAttributes = listOf(country("AT")))
                .getCertificate().shouldNotBeNull()
            val issuerSigned = issueMdoc(TestCertificateAuthority().issue())

            mdlItems(issuerSigned, ISSUING_COUNTRY to "AT", ISSUING_JURISDICTION to "Wien")
                .issuingAuthorityAgreesWith(MDL_DOCTYPE, signer) shouldBe Passed
            mdlItems(issuerSigned, ISSUING_COUNTRY to "DE")
                .issuingAuthorityAgreesWith(scheme.isoDocType, signer) shouldBe Passed
        }

        "is not compared with a document signer without country, which violates its profile" {
            val signer = TestCertificateAuthority().issue().getCertificate().shouldNotBeNull()
            val issuerSigned = issueMdoc(TestCertificateAuthority().issue())

            mdlItems(issuerSigned, ISSUING_COUNTRY to "AT")
                .issuingAuthorityAgreesWith(MDL_DOCTYPE, signer) shouldBe Passed
        }
    }

    "other formats do not report the expiry within their certificate" {
        val issuance = issuance()
        val result = issuance.validator().validate(
            issuance.issue(CredentialRepresentation.SD_JWT).input(),
            strictPolicy.copy(status = StatusPolicy.Skip),
        )

        result.checks.expiryWithinCertificate shouldBe NotApplicable
    }
}
