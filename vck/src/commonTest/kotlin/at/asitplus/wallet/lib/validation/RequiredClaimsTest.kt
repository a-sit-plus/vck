package at.asitplus.wallet.lib.validation

import at.asitplus.openid.ClaimDescription
import at.asitplus.openid.OpenId4VciClaimsPathPointer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.LibraryInitializer
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.ExtractedIsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.StaticCredentialMetadataRegistry
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformation
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationList
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPath
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPathSegmentName
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDefinition
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocument
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocumentRegistry
import at.asitplus.wallet.sdjwt.SdJwtVcType
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private val requireMandatory = strictPolicy.copy(requiredClaims = RequiredClaimsPolicy.RequireMandatory)

/** A claim every issued credential of [representation] contains, see `DummyCredentialDataProvider`. */
private fun presentClaim(representation: CredentialRepresentation) = when (representation) {
    PLAIN_JWT -> "name"
    SD_JWT, ISO_MDOC -> "given_name"
}

private fun mandatory(vararg path: String) = ClaimDescription(OpenId4VciClaimsPathPointer(path.toList()), true)
private fun optional(vararg path: String) = ClaimDescription(OpenId4VciClaimsPathPointer(path.toList()), false)

/** Requires the claims [descriptions] describe, for every type, qualified with the ISO namespace for mdocs. */
private fun requiring(vararg descriptions: ClaimDescription) = RequiredClaimsResolver { identifier, representation ->
    ExtractedIsoMdocCredentialScheme(
        isoDocType = scheme.isoDocType,
        isoNamespace = scheme.isoNamespace,
        claimDescriptions = descriptions.toSet(),
    ).requiredClaims(identifier, representation, source = "test metadata")
}

private fun Issuance.validator(resolver: RequiredClaimsResolver) = CredentialValidator(
    trustAnchors = trustAnchors,
    statusValidator = StatusValidator(statusTokens),
    requiredClaimsResolver = resolver,
)

private suspend fun Issuance.validate(
    representation: CredentialRepresentation,
    resolver: RequiredClaimsResolver,
    policy: ValidationPolicy = requireMandatory,
) = validator(resolver).validate(
    input = issue(representation).input(),
    policy = policy.copy(holderBinding = HolderBindingPolicy.RequireExpectedKey),
    context = context(),
)

private val CredentialValidationResult.claims
    get() = report.checks.shouldBeInstanceOf<CredentialChecks>().requiredClaims

val RequiredClaimsTest by matrixSuite {

    "every format" - {
        listOf(PLAIN_JWT, SD_JWT, ISO_MDOC).asData(nameFn = { "$it" }) - { representation ->

            "required claims are not checked unless the policy requires them" {
                val result = issuance().validate(representation, requiring(mandatory("missing")), strictPolicy)

                result.report.decision shouldBe ACCEPTED
                result.claims.outcome shouldBe NotApplicable
                result.report.namedChecks.single { it.name == "requiredClaims" }.requirement shouldBe
                        Requirement.OPTIONAL
            }

            "a credential containing every mandatory claim passes" {
                val resolver = requiring(mandatory(presentClaim(representation)), optional("missing"))
                val result = issuance().validate(representation, resolver)

                result.report.decision shouldBe ACCEPTED
                result.claims.outcome shouldBe Passed
                result.claims.source shouldBe "test metadata"
                result.claims.credentialIdentifier.shouldNotBeNull()
                result.claims.missing.shouldBeEmpty()
            }

            "a credential missing a mandatory claim fails with its path, and its status is resolved" {
                val resolver = requiring(mandatory(presentClaim(representation)), mandatory("missing"))
                val result = issuance().validate(representation, resolver)

                result.report.decision shouldBe REJECTED
                result.credential.shouldBeNull()
                result.unacceptedCredential.shouldNotBeNull()
                val expected = OpenId4VciClaimsPathPointer(
                    listOfNotNull(scheme.isoNamespace.takeIf { representation == ISO_MDOC }, "missing")
                )
                result.claims.missing shouldContainExactly listOf(expected)
                result.claims.outcome.shouldBeInstanceOf<Failed>().throwable
                    .shouldBeInstanceOf<MissingRequiredClaimException>().missing shouldContainExactly listOf(expected)
                result.report.namedChecks.single { it.name == "requiredClaims" }.claims shouldBe result.claims
                result.report.checks.shouldBeInstanceOf<CredentialChecks>()
                    .status.mechanisms.single().observed shouldBe TokenStatus.Valid
            }

            "without metadata of the type, the check is blocked" {
                val result = issuance().validate(representation, RequiredClaimsResolver { _, _ -> null })

                result.report.decision shouldBe REJECTED
                result.claims.outcome.shouldBeInstanceOf<Blocked>()
                result.unacceptedCredential.shouldNotBeNull()
            }

            "a failing resolver blocks the check with its cause" {
                val cause = IllegalStateException("offline")
                val result = issuance().validate(representation, RequiredClaimsResolver { _, _ -> throw cause })

                result.claims.outcome.shouldBeInstanceOf<Blocked>().cause shouldBe cause
            }

            "a mandatory claim of an absent optional claim is not required" {
                val resolver = requiring(optional("address"), mandatory("address", "country"))
                val result = issuance().validate(representation, resolver)

                result.report.decision shouldBe ACCEPTED
                result.claims.outcome shouldBe Passed
            }
        }
    }

    "a mandatory claim of an absent mandatory claim is missing too" {
        val resolver = requiring(mandatory("address"), mandatory("address", "country"))
        val result = issuance().validate(SD_JWT, resolver)

        result.claims.missing shouldContainExactly listOf(
            OpenId4VciClaimsPathPointer("address"),
            OpenId4VciClaimsPathPointer("address", "country"),
        )
    }

    "the default resolver selects the mandatory claims of registered metadata, naming their document" {
        val vct = SdJwtVcType("urn:test:required-claims:${uuid4()}")
        val loadedFrom = "https://metadata.example.test/${uuid4()}/sd-jwt.json"
        LibraryInitializer.registerCredentialMetadataRegistry(
            StaticCredentialMetadataRegistry(
                documentRegistry = SdJwtTypeMetadataDocumentRegistry(
                    vct to SdJwtTypeMetadataDocument(
                        originalBytes = ByteArray(0),
                        definition = SdJwtTypeMetadataDefinition(
                            vct = vct,
                            claims = SdJwtTypeMetadataClaimInformationList(
                                listOf(
                                    claimInformation("family_name", mandatory = true),
                                    claimInformation("email", mandatory = null),
                                )
                            ),
                        ),
                    )
                ),
                documentUrls = mapOf(vct to loadedFrom),
            )
        )

        RequiredClaimsResolver.Default.resolve(vct.string, SD_JWT).shouldNotBeNull().apply {
            credentialIdentifier shouldBe vct.string
            source shouldBe loadedFrom
            claims shouldContainExactly listOf(RequiredClaim(OpenId4VciClaimsPathPointer("family_name")))
        }
        RequiredClaimsResolver.Default.resolve("urn:test:unknown:${uuid4()}", SD_JWT).shouldBeNull()
    }
}

private fun claimInformation(name: String, mandatory: Boolean?) = SdJwtTypeMetadataClaimInformation(
    path = SdJwtTypeMetadataClaimInformationPath(listOf(SdJwtTypeMetadataClaimInformationPathSegmentName(name))),
    isMandatory = mandatory,
)
