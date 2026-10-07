package at.asitplus.wallet.lib.validation

import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.selfSignedKey
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.Identifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.IdentifierInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.extensions.toStatusList
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

private const val PID_VCT = "urn:eudi:pid:1"
private const val STATUS_LIST_URI = "https://issuer.example.com/status/1"
private const val IDENTIFIER_LIST_URI = "https://issuer.example.com/identifiers/1"
private val leeway = 5.minutes

/** Two bits per status, least significant first: index 0 valid, index 1 invalid, index 2 suspended. */
private val statusList = StatusListView(byteArrayOf(0b0010_0100), TokenStatusBitSize.TWO)
    .toStatusList(DefaultZlibService(), statusListAggregationUrl = null)

private val revokedIdentifier = byteArrayOf(7)

private val identifierList = IdentifierList(mapOf(Identifier(revokedIdentifier) to IdentifierInfo()))

private fun payload(
    revocationList: RevocationList = statusList,
    subject: String = STATUS_LIST_URI,
    expiration: Instant? = Clock.System.now() + 1.hours,
) = StatusListTokenPayload(
    subject = UniformResourceIdentifier(subject),
    issuedAt = Clock.System.now(),
    expirationTime = expiration,
    timeToLive = PositiveDuration(1.hours),
    revocationList = revocationList,
)

private suspend fun jwt(
    signer: KeyMaterial,
    payload: StatusListTokenPayload = payload(),
    type: String = MediaTypes.STATUSLIST_JWT,
    resolvedAt: Instant? = Clock.System.now(),
): StatusListToken = StatusListJwt(
    SignJwt<StatusListTokenPayload>(signer, JwsHeaderCertOrJwk())(type, payload, StatusListTokenPayload.serializer())
        .getOrThrow(),
    resolvedAt,
)

private suspend fun cwt(
    signer: KeyMaterial,
    payload: StatusListTokenPayload,
    type: String,
): StatusListToken = StatusListCwt(
    SignCose<ByteArray>(signer, unprotectedHeaderModifier = CoseHeaderCertificate()).invoke(
        CoseHeader(type = type), null, coseCompliantSerializer.encodeToByteArray(payload), ByteArraySerializer()
    ).getOrThrow(),
    resolvedAt = Clock.System.now(),
)

private fun resolver(vararg tokens: Pair<String, StatusListToken>) = StatusListTokenResolver { uri ->
    tokens.toMap()[uri.string] ?: throw IllegalStateException("Not found: $uri")
}

private fun statusAt(index: Int) = TokenStatusInfo(
    statusList = StatusListInfo(index = index.toULong(), uri = UniformResourceIdentifier(STATUS_LIST_URI))
)

private fun TestCertificateAuthority.pidStatusAnchors() = StatusSignerAnchors.OfCredentialType(
    anchors = CredentialTrustScopes(
        CredentialTrustScope(setOf(PID_VCT), "PID", issuance = { emptySet() }, status = { setOf(certificate) })
    ),
    credentialIdentifier = PID_VCT,
)

private suspend fun StatusValidator.check(
    status: TokenStatusInfo?,
    anchors: StatusSignerAnchors,
    policy: StatusPolicy = requireClaim,
) = validate(status, anchors, policy, leeway, Clock.System.now())

private data class TimeCase(val name: String, val expiration: Instant, val resolvedAt: Instant)

private fun StatusValidation.single() = mechanisms.shouldHaveSize(1).single()

private fun ValidationReport.tokenChecks() = checks.shouldBeInstanceOf<StatusListTokenChecks>()

val StatusValidatorTest by matrixSuite {

    "status list" - {
        "a valid status from an authorized signer passes" {
            val revocation = TestCertificateAuthority()
            val validator = StatusValidator(resolver(STATUS_LIST_URI to jwt(revocation.issue())))

            val status = validator.check(statusAt(0), revocation.pidStatusAnchors())
            status.claim shouldBe Passed
            status.agreement shouldBe Passed
            status.single().outcome shouldBe Passed
            status.single().observed shouldBe TokenStatus.Valid
            status.single().token.decision shouldBe ValidationDecision.ACCEPTED
            status.single().token.tokenChecks().signerTrust shouldBe TrustValidation(Passed, PID_VCT, "PID")
        }

        "a revoked status fails with the status, which is kept as observed" {
            val revocation = TestCertificateAuthority()
            val validator = StatusValidator(resolver(STATUS_LIST_URI to jwt(revocation.issue())))

            val mechanism = validator.check(statusAt(1), revocation.pidStatusAnchors()).single()
            mechanism.outcome.shouldBeInstanceOf<Failed>()
                .throwable.shouldBeInstanceOf<TokenStatusException>().status shouldBe TokenStatus.Invalid
            mechanism.observed shouldBe TokenStatus.Invalid
        }

        "a status the policy accepts passes" {
            val revocation = TestCertificateAuthority()
            val validator = StatusValidator(resolver(STATUS_LIST_URI to jwt(revocation.issue())))
            val policy = StatusPolicy.RequireClaim(
                TrustPolicy.RequireAuthorizedSigner,
                accepted = setOf(TokenStatus.Valid, TokenStatus.Suspended),
            )

            validator.check(statusAt(2), revocation.pidStatusAnchors(), policy).single().let {
                it.outcome shouldBe Passed
                it.observed shouldBe TokenStatus.Suspended
            }
        }

        "an index out of bounds blocks, as no statement about the status can be made" {
            val revocation = TestCertificateAuthority()
            val validator = StatusValidator(resolver(STATUS_LIST_URI to jwt(revocation.issue())))

            val mechanism = validator.check(statusAt(1000), revocation.pidStatusAnchors()).single()
            mechanism.token.decision shouldBe ValidationDecision.ACCEPTED
            mechanism.outcome.shouldBeInstanceOf<Blocked>().cause.shouldBeInstanceOf<IndexOutOfBoundsException>()
        }
    }

    "status claim" - {
        "without a claim, it is not applicable or failed, as the policy requires" {
            val anchors = TestCertificateAuthority().pidStatusAnchors()
            val validator = StatusValidator(resolver())

            validator.check(null, anchors, StatusPolicy.Skip).claim shouldBe NotApplicable
            validator.check(null, anchors, ifPresent).claim shouldBe NotApplicable
            validator.check(null, anchors, requireClaim).claim.shouldBeInstanceOf<Failed>()
        }

        "a skipped status resolves nothing" {
            val anchors = TestCertificateAuthority().pidStatusAnchors()
            val status = StatusValidator(resolver()).check(statusAt(0), anchors, StatusPolicy.Skip)

            status.claim shouldBe NotApplicable
            status.mechanisms.shouldBeEmpty()
        }
    }

    "status list token" - {
        "without a resolver it is blocked" {
            val mechanism = StatusValidator().check(statusAt(0), TestCertificateAuthority().pidStatusAnchors()).single()

            mechanism.token.tokenChecks().retrieval.shouldBeInstanceOf<Blocked>()
            mechanism.outcome.shouldBeInstanceOf<Blocked>()
            mechanism.observed.shouldBeNull()
        }

        "an unavailable token blocks with the cause of its retrieval" {
            val unavailable = IllegalStateException("unavailable")
            val validator = StatusValidator(statusListTokenResolver = { throw unavailable })

            val mechanism = validator.check(statusAt(0), TestCertificateAuthority().pidStatusAnchors()).single()
            mechanism.token.tokenChecks().retrieval shouldBe Blocked(unavailable)
            mechanism.outcome shouldBe Blocked(unavailable)
        }

        "a wrong media type fails parsing" {
            val revocation = TestCertificateAuthority()
            val token = jwt(revocation.issue(), type = MediaTypes.Application.STATUSLIST_JWT)
            val mechanism = StatusValidator(resolver(STATUS_LIST_URI to token))
                .check(statusAt(0), revocation.pidStatusAnchors()).single()

            mechanism.token.tokenChecks().parsing.shouldBeInstanceOf<Failed>()
            mechanism.outcome.shouldBeInstanceOf<Blocked>()
        }

        "a subject other than the referenced URI fails" {
            val revocation = TestCertificateAuthority()
            val token = jwt(revocation.issue(), payload(subject = "https://issuer.example.com/status/2"))
            val mechanism = StatusValidator(resolver(STATUS_LIST_URI to token))
                .check(statusAt(0), revocation.pidStatusAnchors()).single()

            mechanism.token.tokenChecks().subject.shouldBeInstanceOf<Failed>()
            mechanism.outcome.shouldBeInstanceOf<Blocked>()
        }

        "an invalid signature fails, and blocks every check relying on the claims" {
            val revocation = TestCertificateAuthority()
            val signed = jwt(revocation.issue()) as StatusListJwt
            val parts = signed.value.jws.toString().split(".")
            val other = jwt(revocation.issue(), payload(subject = "https://x.example.com")) as StatusListJwt
            val otherPayload = other.value.jws.toString().split(".")[1]
            val forged = JwsCompact("${parts[0]}.$otherPayload.${parts[2]}")
            val tampered = signed.copy(value = JwsCompactTyped(forged, signed.value.payload))
            val checks = StatusValidator(resolver(STATUS_LIST_URI to tampered))
                .check(statusAt(0), revocation.pidStatusAnchors()).single().token.tokenChecks()

            checks.signature.shouldBeInstanceOf<Failed>()
            checks.signerTrust.outcome.shouldBeInstanceOf<Blocked>()
            checks.subject.shouldBeInstanceOf<Blocked>()
            checks.timeliness.shouldBeInstanceOf<Blocked>()
        }

        "time" - {
            listOf(
                TimeCase("an expired token fails", Clock.System.now() - 1.hours, Clock.System.now()),
                TimeCase(
                    "a token whose ttl elapsed since it was resolved fails",
                    expiration = Clock.System.now() + 1.hours,
                    resolvedAt = Clock.System.now() - 2.hours,
                ),
            ).asData(nameFn = { it.name }) test { case ->
                val revocation = TestCertificateAuthority()
                val token =
                    jwt(revocation.issue(), payload(expiration = case.expiration), resolvedAt = case.resolvedAt)
                val mechanism = StatusValidator(resolver(STATUS_LIST_URI to token))
                    .check(statusAt(0), revocation.pidStatusAnchors()).single()

                mechanism.token.tokenChecks().timeliness.shouldBeInstanceOf<Failed>()
                    .throwable.shouldBeInstanceOf<TimelinessException>()
                mechanism.outcome.shouldBeInstanceOf<Blocked>()
            }

            "an expiry within the leeway passes" {
                val revocation = TestCertificateAuthority()
                val token = jwt(revocation.issue(), payload(expiration = Clock.System.now() - 1.minutes))

                StatusValidator(resolver(STATUS_LIST_URI to token))
                    .check(statusAt(0), revocation.pidStatusAnchors()).single().outcome shouldBe Passed
            }
        }

        "signer trust" - {
            "a signer of another authority is not authorized, unless the policy only requires integrity" {
                val revocation = TestCertificateAuthority()
                val validator = StatusValidator(resolver(STATUS_LIST_URI to jwt(TestCertificateAuthority().issue())))

                validator.check(statusAt(0), revocation.pidStatusAnchors()).single().let {
                    it.token.tokenChecks().signerTrust.outcome.shouldBeInstanceOf<Failed>()
                    it.outcome.shouldBeInstanceOf<Blocked>()
                }
                val integrityOnly = StatusPolicy.RequireClaim(TrustPolicy.IntegrityOnly)
                validator.check(statusAt(0), revocation.pidStatusAnchors(), integrityOnly)
                    .single().outcome shouldBe Passed
            }

            "a directly listed signer is not authorized" {
                val signer = selfSignedKey()
                val listed = signer.getCertificate()!!
                val anchors = StatusSignerAnchors.OfCredentialType(
                    CredentialTrustScopes(
                        CredentialTrustScope(setOf(PID_VCT), "PID", { emptySet() }, status = { setOf(listed) })
                    ),
                    PID_VCT,
                )

                StatusValidator(resolver(STATUS_LIST_URI to jwt(signer))).check(statusAt(0), anchors).single()
                    .token.tokenChecks().signerTrust.outcome.shouldBeInstanceOf<Failed>()
            }

            "an ambiguous credential type can not select anchors" {
                val revocation = TestCertificateAuthority()
                val anchors = revocation.pidStatusAnchors().copy(credentialIdentifier = null)

                StatusValidator(resolver(STATUS_LIST_URI to jwt(revocation.issue()))).check(statusAt(0), anchors)
                    .single().token.tokenChecks().signerTrust.outcome.shouldBeInstanceOf<Blocked>()
            }

            "anchors of an artifact kind are reported with their source" {
                val walletProviders = TestCertificateAuthority()
                val validator = StatusValidator(resolver(STATUS_LIST_URI to jwt(walletProviders.issue())))

                val anchors = TrustedCertificates { setOf(walletProviders.certificate) }
                validator.check(statusAt(0), StatusSignerAnchors.OfArtifactKind(anchors, "wallet providers"))
                    .single().token.tokenChecks().signerTrust shouldBe TrustValidation(Passed, null, "wallet providers")
                validator.check(statusAt(0), StatusSignerAnchors.OfArtifactKind(null, "wallet providers"))
                    .single().token.tokenChecks().signerTrust.outcome.shouldBeInstanceOf<Blocked>()
            }
        }
    }

    "status list and identifier list" - {
        suspend fun bothMechanisms(identifier: ByteArray): StatusValidation {
            val revocation = TestCertificateAuthority()
            val signer = revocation.issue()
            val validator = StatusValidator(
                resolver(
                    STATUS_LIST_URI to cwt(signer, payload(), MediaTypes.Application.STATUSLIST_CWT),
                    IDENTIFIER_LIST_URI to cwt(
                        signer,
                        payload(identifierList, subject = IDENTIFIER_LIST_URI),
                        MediaTypes.Application.IDENTIFIERLIST_CWT,
                    ),
                )
            )
            val status = TokenStatusInfo(
                statusList = StatusListInfo(index = 0u, uri = UniformResourceIdentifier(STATUS_LIST_URI)),
                identifierList = IdentifierListInfo(
                    identifier = identifier,
                    uri = UniformResourceIdentifier(IDENTIFIER_LIST_URI),
                ),
            )
            return validator.check(status, revocation.pidStatusAnchors())
        }

        "agreeing mechanisms pass, both evaluated" {
            val status = bothMechanisms(identifier = byteArrayOf(1))

            status.mechanisms.map { it.outcome } shouldBe listOf(Passed, Passed)
            status.agreement shouldBe Passed
        }

        "conflicting mechanisms fail agreement, keeping both findings" {
            val status = bothMechanisms(identifier = revokedIdentifier)

            status.mechanisms.map { it.observed } shouldBe listOf(TokenStatus.Valid, TokenStatus.Invalid)
            status.agreement.shouldBeInstanceOf<Failed>()
        }
    }
}
