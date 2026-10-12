package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.josef.ClientStatus
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.extensions.toStatusList
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationPoPJwt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.ClientAttestationChecks
import at.asitplus.wallet.lib.validation.ClientAttestationValidator
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.ValidationReport
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

val ClientAttestationValidationTest by matrixSuite {

    "an attestation of a trusted wallet provider is reported as accepted, with the authenticated client" {
        val walletProvider = WalletProvider()
        val service = walletProvider.service()

        service.validate(walletProvider.request(service), CLIENT_ID, null, strictPolicy).apply {
            report.decision shouldBe ACCEPTED
            report.attestationChecks().apply {
                signature shouldBe CheckOutcome.Passed
                trust.outcome shouldBe CheckOutcome.Passed
                clientId shouldBe CheckOutcome.Passed
                challenge shouldBe CheckOutcome.Passed
            }
            client.shouldNotBeNull().clientId shouldBe CLIENT_ID
        }
    }

    "without wallet provider anchors, attestations are rejected" {
        val walletProvider = WalletProvider()
        val service = AttestationBasedClientAuthenticationService(issuerIdentifier = AUTHORIZATION_SERVER)

        service.validate(walletProvider.request(service), CLIENT_ID, null, strictPolicy).apply {
            report.decision shouldBe REJECTED
            report.attestationChecks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
            client.shouldBeNull()
        }
        shouldThrow<OAuth2Exception.InvalidClient> {
            service.authenticateClient(walletProvider.request(service), CLIENT_ID, null).getOrThrow()
        }.description.shouldNotBeNull() shouldContain "not verified"
    }

    "a forged attestation with a self-signed certificate and its own jwk is rejected" {
        val walletProvider = WalletProvider()
        val service = walletProvider.service()
        val forger = EphemeralKeyWithSelfSignedCert()
        val forged = walletProvider.attestation(SignJwt(forger, JwsHeaderCertOrJwk()))

        service.validate(walletProvider.request(service, forged), CLIENT_ID, null, strictPolicy)
            .report.decision shouldBe REJECTED
        shouldThrow<OAuth2Exception.InvalidClient> {
            service.authenticateClient(walletProvider.request(service, forged), CLIENT_ID, null).getOrThrow()
        }
    }

    "an attestation without iat is accepted, as iat is optional" {
        val walletProvider = WalletProvider()
        val service = walletProvider.service()
        val attestation = walletProvider.signAttestation(walletProvider.payload().copy(issuedAt = null))

        service.authenticateClient(walletProvider.request(service, attestation), CLIENT_ID, null).getOrThrow()
    }

    "an attestation whose client_status is no longer maintained needs to be refreshed" {
        val walletProvider = WalletProvider()
        val service = walletProvider.service()
        val payload = walletProvider.payload()
        val attestation = walletProvider.signAttestation(
            payload.copy(clientStatus = payload.clientStatus!!.copy(expiration = Clock.System.now() - 1.days))
        )

        service.validate(walletProvider.request(service, attestation), CLIENT_ID, null, strictPolicy)
            .report.attestationChecks().timeliness.shouldBeInstanceOf<CheckOutcome.Failed>()
        shouldThrow<OAuth2Exception.UseFreshAttestation> {
            service.authenticateClient(walletProvider.request(service, attestation), CLIENT_ID, null).getOrThrow()
        }
    }

    "an attestation of a revoked wallet instance is rejected, if the status can be resolved" {
        val walletProvider = WalletProvider()
        val revoking = walletProvider.service(
            statusListTokenResolver = { buildStatusListToken(revokedIndex = CLIENT_STATUS_INDEX) },
        )
        val notRevoking = walletProvider.service(
            statusListTokenResolver = { buildStatusListToken(revokedIndex = CLIENT_STATUS_INDEX + 1) },
        )

        shouldThrow<OAuth2Exception.InvalidClient> {
            revoking.authenticateClient(walletProvider.request(revoking), CLIENT_ID, null).getOrThrow()
        }.description shouldBe "client_status invalid"
        notRevoking.authenticateClient(walletProvider.request(notRevoking), CLIENT_ID, null).getOrThrow()
    }

    "the challenge of a rejected attestation is not consumed" {
        val walletProvider = WalletProvider()
        val nonceService = DefaultNonceService()
        val service = walletProvider.service(nonceService = nonceService)
        val untrusting = AttestationBasedClientAuthenticationService(
            issuerIdentifier = AUTHORIZATION_SERVER,
            nonceService = nonceService,
        )
        val challenge = service.getAttestationChallenge()
        val request = walletProvider.request(challenge = challenge)

        untrusting.validate(request, CLIENT_ID, null, strictPolicy).report.decision shouldBe REJECTED
        service.validate(request, CLIENT_ID, null, strictPolicy).report.decision shouldBe ACCEPTED
        // now it is consumed
        shouldThrow<OAuth2Exception.UseAttestationChallenge> {
            service.authenticateClient(request, CLIENT_ID, null).getOrThrow()
        }
    }

    "a PoP without aud is rejected, also without the identifier of the server" {
        val walletProvider = WalletProvider()
        val service = walletProvider.service(issuerIdentifier = null)
        val pop = walletProvider.signPop(
            JsonWebToken(
                jwtId = "jti",
                issuedAt = Clock.System.now().truncateToSeconds(),
                challenge = service.getAttestationChallenge(),
            )
        )
        val request = RequestInfo(
            url = "https://example.com/",
            method = HttpMethod.Post,
            clientAttestation = walletProvider.attestation(),
            clientAttestationPop = pop,
        )

        service.validate(request, CLIENT_ID, null, strictPolicy).report.attestationChecks()
            .parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "with DPoP, the time and challenge of the proof are checks of the DPoP proof" {
        val walletProvider = WalletProvider()
        val service = walletProvider.service(popMethods = setOf(ClientAttestationPopMethod.DpopCombined))
        val request = RequestInfo(
            url = "https://example.com/",
            method = HttpMethod.Post,
            clientAttestation = walletProvider.attestation(),
        )

        service.validate(request, CLIENT_ID, walletProvider.clientKey.jsonWebKey, strictPolicy).apply {
            report.decision shouldBe ACCEPTED
            report.attestationChecks().apply {
                popSignature shouldBe CheckOutcome.Passed
                popTime shouldBe CheckOutcome.NotApplicable
                challenge shouldBe CheckOutcome.NotApplicable
            }
        }
        service.validate(request, CLIENT_ID, EphemeralKeyWithoutCert().jsonWebKey, strictPolicy).report
            .attestationChecks().popSignature.shouldBeInstanceOf<CheckOutcome.Failed>()
    }
}

private const val AUTHORIZATION_SERVER = "https://wallet.a-sit.at/authorization-server"
private const val CLIENT_ID = "https://wallet.example.org"

/** Index of the client status of the attestations built here, see [WalletProvider.payload]. */
private const val CLIENT_STATUS_INDEX = 3
private const val STATUS_LIST_URI = "https://example.org/status/wallet-instance"

private val strictPolicy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = StatusPolicy.Skip,
    timeLeeway = 5.minutes,
    requireTimeliness = true,
)

private fun ValidationReport.attestationChecks() = checks.shouldBeInstanceOf<ClientAttestationChecks>()

/** A wallet provider signing client attestations with a certificate issued by its CA, for a [clientKey]. */
private class WalletProvider private constructor(
    val authority: TestCertificateAuthority,
    keyMaterial: KeyMaterial,
) {
    val clientKey = EphemeralKeyWithoutCert()
    private val signJwt = SignJwt<JsonWebToken>(keyMaterial, JwsHeaderCertOrJwk())

    fun service(
        statusListTokenResolver: StatusListTokenResolver? = null,
        nonceService: DefaultNonceService = DefaultNonceService(),
        issuerIdentifier: String? = AUTHORIZATION_SERVER,
        popMethods: Set<ClientAttestationPopMethod> = setOf(ClientAttestationPopMethod.AttestationPopJwt),
    ) = AttestationBasedClientAuthenticationService(
        acceptedPopMethods = popMethods,
        clientAttestationValidator = ClientAttestationValidator(
            walletProviderAnchors = { setOf(authority.certificate) },
            statusValidator = StatusValidator(statusListTokenResolver),
        ),
        issuerIdentifier = issuerIdentifier,
        nonceService = nonceService,
    )

    suspend fun attestation(signJwt: SignJwt<JsonWebToken> = this.signJwt) = BuildClientAttestationJwt(
        signJwt = signJwt,
        clientId = CLIENT_ID,
        clientKey = clientKey.jsonWebKey,
        clientStatus = clientStatus(),
    )

    /** The payload of [attestation], to build variants of it. */
    suspend fun payload() = attestation().payload

    suspend fun signAttestation(payload: JsonWebToken) = signJwt(
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_JWT,
        payload = payload,
        serializer = JsonWebToken.serializer(),
    ).getOrThrow()

    suspend fun signPop(payload: JsonWebToken) = SignJwt<JsonWebToken>(clientKey, JwsHeaderNone())(
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT,
        payload = payload,
        serializer = JsonWebToken.serializer(),
    ).getOrThrow()

    /** A request with [attestation] and a PoP for a fresh challenge of [service]. */
    suspend fun request(
        service: AttestationBasedClientAuthenticationService,
        attestation: JwsCompactTyped<JsonWebToken>? = null,
    ) = request(service.getAttestationChallenge(), attestation)

    suspend fun request(
        challenge: String,
        attestation: JwsCompactTyped<JsonWebToken>? = null,
    ) = RequestInfo(
        url = "https://example.com/",
        method = HttpMethod.Post,
        clientAttestation = attestation ?: attestation(),
        clientAttestationPop = BuildClientAttestationPoPJwt(
            signJwt = SignJwt(clientKey, JwsHeaderNone()),
            audience = AUTHORIZATION_SERVER,
            nonce = challenge,
            randomSource = RandomSource.Default,
        ),
    )

    private fun clientStatus() = ClientStatus(
        status = buildJsonObject {
            putJsonObject("status_list") {
                put("idx", CLIENT_STATUS_INDEX)
                put("uri", STATUS_LIST_URI)
            }
        },
        expiration = Clock.System.now().truncateToSeconds() + 31.days,
    )

    companion object {
        suspend operator fun invoke(): WalletProvider {
            val authority = TestCertificateAuthority()
            return WalletProvider(authority, authority.issue())
        }
    }
}

/** Status list token with only [revokedIndex] set to [TokenStatus.Invalid]. */
private suspend fun buildStatusListToken(revokedIndex: Int) = StatusListJwt(
    value = SignJwt<StatusListTokenPayload>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())(
        type = MediaTypes.STATUSLIST_JWT,
        payload = StatusListTokenPayload(
            subject = UniformResourceIdentifier(STATUS_LIST_URI),
            issuedAt = Clock.System.now(),
            revocationList = StatusListView.fromTokenStatuses(
                tokenStatuses = List(revokedIndex + 1) {
                    if (it == revokedIndex) TokenStatus.Invalid else TokenStatus.Valid
                },
                statusBitSize = TokenStatusBitSize.ONE,
            ).toStatusList(DefaultZlibService(), null),
        ),
        serializer = StatusListTokenPayload.serializer(),
    ).getOrThrow(),
    resolvedAt = Clock.System.now(),
)
