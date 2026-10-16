package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.PreRegisteredClients
import at.asitplus.wallet.lib.validation.RelyingPartyChecks
import at.asitplus.wallet.lib.validation.RelyingPartyTrustAnchors
import at.asitplus.wallet.lib.validation.RelyingPartyValidator
import at.asitplus.wallet.lib.validation.RequestObjectChecks
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TimelinessException
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.ValidationReport
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

val OpenId4VpRequestValidationReportTest by matrixSuite {

    "a request signed with a certificate of a trusted relying party is accepted" {
        val relyingParty = relyingParty()
        val holder = OpenId4VpHolder(relyingPartyValidator = relyingParty.validator)

        holder.startAuthorizationResponsePreparation(relyingParty.request(), strictPolicy).getOrThrow()
            .validationReport.decision shouldBe ACCEPTED
    }

    "without trust in relying parties, the request is rejected, but can still be answered" {
        val relyingParty = relyingParty()
        val holder = OpenId4VpHolder()

        holder.startAuthorizationResponsePreparation(relyingParty.request(), strictPolicy).getOrThrow().apply {
            validationReport.decision shouldBe REJECTED
            validationReport.requestChecks().apply {
                signature shouldBe CheckOutcome.Passed
                clientId shouldBe CheckOutcome.Passed
                trust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
            }
            preparationState.request.parameters.clientId.shouldNotBeNull()
        }
        // The legacy method does not evaluate trust without relyingPartyTrust, as before
        holder.startAuthorizationResponsePreparation(relyingParty.request()).getOrThrow()
    }

    "an expired request object is rejected if timeliness is required" {
        val relyingParty = relyingParty()
        val holder = OpenId4VpHolder(relyingPartyValidator = relyingParty.validator)
        val expired = relyingParty.request(claims = expiredClaims())

        holder.startAuthorizationResponsePreparation(expired, strictPolicy).getOrThrow().validationReport.apply {
            decision shouldBe REJECTED
            requestChecks().timeliness.shouldBeInstanceOf<CheckOutcome.Failed>()
                .throwable.shouldBeInstanceOf<TimelinessException>()
        }
        // The legacy method has never checked exp
        holder.startAuthorizationResponsePreparation(relyingParty.request(claims = expiredClaims())).getOrThrow()
    }

    "an unknown wallet_nonce is rejected" {
        val relyingParty = relyingParty()
        val holder = OpenId4VpHolder(relyingPartyValidator = relyingParty.validator)
        val request = relyingParty.request(claims = mapOf("wallet_nonce" to "unknown"))

        holder.startAuthorizationResponsePreparation(request, strictPolicy).getOrThrow().validationReport.apply {
            decision shouldBe REJECTED
            requestChecks().walletNonce.shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "a request carrying a registration certificate that can not be validated is rejected" {
        val relyingParty = relyingParty()
        val holder = OpenId4VpHolder(relyingPartyValidator = relyingParty.validator)
        val request = relyingParty.request(
            claims = mapOf("verifier_info" to """[{"format":"registration_cert","data":"not-a-jws"}]""")
        )

        holder.startAuthorizationResponsePreparation(request, strictPolicy).getOrThrow().validationReport.apply {
            decision shouldBe REJECTED
            requestChecks().signature shouldBe CheckOutcome.Passed
            children.single().checks.shouldBeInstanceOf<RelyingPartyChecks>().requestData
                .shouldBeInstanceOf<CheckOutcome.Failed>()
        }
        // The legacy method has never validated registration certificates
        holder.startAuthorizationResponsePreparation(relyingParty.request(claims = mapOf("verifier_info" to
                """[{"format":"registration_cert","data":"not-a-jws"}]"""))).getOrThrow()
    }

    "a pre-registered client is trusted with the keys registered for it" {
        val relyingParty = relyingParty()
        val clients = PreRegisteredClients {
            if (it == "known-verifier") setOf(relyingParty.keyMaterial.publicKey) else null
        }
        val trust = RelyingPartyTrustAnchors(preRegisteredClients = clients)
        val holder = OpenId4VpHolder(relyingPartyValidator = RelyingPartyValidator(trust = trust))

        holder.startAuthorizationResponsePreparation(
            relyingParty.request(claims = mapOf("client_id" to "known-verifier")),
            strictPolicy,
        ).getOrThrow().validationReport.decision shouldBe ACCEPTED
        holder.startAuthorizationResponsePreparation(
            relyingParty.request(claims = mapOf("client_id" to "unknown-verifier")),
            strictPolicy,
        ).getOrThrow().validationReport.requestChecks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "a client identifier prefix this library does not evaluate is trusted with the keys its source establishes" {
        val relyingParty = relyingParty()
        suspend fun request() = relyingParty.request(claims = mapOf("client_id" to "did:example:verifier"))
        fun holder(keys: Set<CryptoPublicKey>) = OpenId4VpHolder(
            relyingPartyValidator = RelyingPartyValidator(
                trust = RelyingPartyTrustAnchors(clientIdentifierPrefixes = { keys })
            )
        )

        holder(setOf(relyingParty.keyMaterial.publicKey))
            .startAuthorizationResponsePreparation(request(), strictPolicy).getOrThrow().validationReport.decision shouldBe ACCEPTED
        holder(setOf(EphemeralKeyWithoutCert().publicKey)).startAuthorizationResponsePreparation(request(), strictPolicy)
            .getOrThrow().validationReport.requestChecks().signature.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "with trust configured the deprecated way, a request is accepted" {
        val relyingParty = relyingParty()
        @Suppress("DEPRECATION")
        val holder = OpenId4VpHolder(relyingPartyTrust = relyingParty.trust)

        holder.startAuthorizationResponsePreparation(relyingParty.request(), strictPolicy).getOrThrow()
            .validationReport.decision shouldBe ACCEPTED
    }
}

private val strictPolicy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = StatusPolicy.Skip,
    timeLeeway = 5.minutes,
    requireTimeliness = true,
)

private fun expiredClaims() = mapOf("exp" to Clock.System.now().epochSeconds - 3600)

private fun ValidationReport.requestChecks() =
    checks.shouldBeInstanceOf<RequestObjectChecks>()

private suspend fun relyingParty(): RelyingParty {
    val keyMaterial = EphemeralKeyWithSelfSignedCert()
    return RelyingParty(keyMaterial, keyMaterial.getCertificate().shouldNotBeNull())
}

/** A relying party with a self-signed certificate, using the client identifier prefix `x509_hash`. */
private class RelyingParty(val keyMaterial: KeyMaterial, certificate: X509Certificate) {
    val verifier = OpenId4VpVerifier(
        keyMaterial = keyMaterial,
        clientIdScheme = ClientIdScheme.CertificateHash(listOf(certificate), "https://example.com/redirect"),
    )
    val certificates = TrustedCertificates { setOf(certificate) }
    val trust = setOf(RelyingPartyTrust.Certificates(certificates))
    val validator = RelyingPartyValidator(trust = RelyingPartyTrustAnchors(accessCertificates = certificates))

    suspend fun requestParameters(): AuthenticationRequestParameters {
        val requestUrl = "https://example.com/request"
        val created = verifier.createAuthnRequest(
            OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = AtomicAttribute2023,
                        representation = SD_JWT,
                        attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                    ),
                ).toDCQLRequest(),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = "https://example.com/response",
            ),
            CreationOptions.SignedRequestByReference("haip://", requestUrl),
        ).getOrThrow()
        return JwsCompactTyped<AuthenticationRequestParameters>(created.loadRequestObject!!(null).getOrThrow()).payload
    }

    /** A request object of this relying party, signed with its certificate in `x5c`, with additional [claims]. */
    suspend fun request(claims: Map<String, Any> = emptyMap()): RequestParametersFrom<AuthenticationRequestParameters> {
        val parameters = requestParameters()
        val payload = JsonObject(
            joseCompliantSerializer.encodeToJsonElement(AuthenticationRequestParameters.serializer(), parameters)
                .jsonObject + claims.mapValues { (_, value) ->
                when (value) {
                    is Number -> JsonPrimitive(value)
                    is String if value.startsWith("[") -> Json.parseToJsonElement(value)
                    else -> JsonPrimitive(value.toString())
                }
            }
        )
        val signed = SignJwt<JsonObject>(keyMaterial, JwsHeaderCertOrJwk())(
            JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
            payload,
            JsonObject.serializer(),
        ).getOrThrow()
        return RequestParametersFrom.Jws(
            jws = JwsCompact(signed.toString()),
            parameters = joseCompliantSerializer
                .decodeFromJsonElement(AuthenticationRequestParameters.serializer(), payload),
        )
    }
}
