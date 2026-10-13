package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier.ChallengeSession
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.PresentationChecks
import at.asitplus.wallet.lib.validation.PresentationContext
import at.asitplus.wallet.lib.validation.PresentationValidationInput
import at.asitplus.wallet.lib.validation.PresentationValidationResult
import at.asitplus.wallet.lib.validation.ProtocolResponseChecks
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.ValidationReport
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration.Companion.seconds

/**
 * Validates the `vp_token` of an OpenID4VP authentication response, independently of the transport
 * that delivered it: URL/QR (see [OpenId4VpVerifier]) or the W3C Digital Credentials API (see [DcApiVerifier]).
 * The only transport-specific step, calculation of the ISO session transcript, is delegated to
 * the injected [SessionTranscriptCalculator].
 *
 * Every presentation is validated once with [credentialValidator]; the legacy [VpTokenValidationResultDCQL] is
 * projected from these validations, see [legacyPresentationResult].
 */
internal class VpTokenValidator(
    /** Calculates the ISO session transcript for the transport the response was received over. */
    private val createSessionTranscript: SessionTranscriptCalculator,
    /** Long-lived decryption key, when the request did not convey the key itself (it was distributed out-of-band). */
    private val decryptionKeyMaterial: KeyMaterial?,
    /** Validates every presentation for [VpTokenValidation.report]. */
    private val credentialValidator: CredentialValidator,
    /**
     * The policy every presentation is validated under with [credentialValidator]: whether issuers and status list
     * signers have to be authorized, whether the status is checked, and whether credentials have to be valid at the
     * time of validation. The holder proof is always checked against the request, see [PresentationContext].
     */
    private val presentationPolicy: ValidationPolicy,
) {

    /**
     * Extract and verifies verifiable presentations, according to format defined in
     * [OpenID for VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
     * as referenced by [OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
     *
     * [origin] is the calling origin from the W3C Digital Credentials API, or `null` for URL/QR transport.
     * [expectedOrigin] is whether the transport checked the origin against the request's `expected_origins`.
     *
     * [session] is the consumed challenge of [authnRequest], which all presentations of the response answer.
     */
    @Throws(CancellationException::class)
    suspend fun validateVpToken(
        authnRequest: AuthenticationRequestParameters,
        responseParameters: ResponseParametersFrom,
        origin: String?,
        expectedOrigin: CheckOutcome,
        session: ChallengeSession,
    ): VpTokenValidation {
        val vpToken = catching { parse(authnRequest, responseParameters, origin) }.getOrElse {
            return VpTokenValidation(
                result = KmmResult.failure(it),
                report = credentialValidator.reportResponse(
                    checks = responseChecks(
                        parsing = CheckOutcome.Failed(it),
                        responseParameters = responseParameters,
                        expectedOrigin = expectedOrigin,
                        requestState = CheckOutcome.Passed,
                        submissionRequirements = CheckOutcome.Blocked(),
                    ),
                    presentations = emptyList(),
                )
            )
        }
        val recipientKey = if (responseParameters.hasBeenEncrypted) {
            authnRequest.clientMetadata?.jsonWebKeySet?.keys?.getEncryptionTargetKey()
                ?: decryptionKeyMaterial?.jsonWebKey
        } else null
        val responseUrl = authnRequest.responseUrl ?: authnRequest.redirectUrlExtracted
        val validated = vpToken.presentations.mapValues { (credentialQueryId, relatedPresentations) ->
            val credentialQuery = vpToken.query.credentialQuery(credentialQueryId)!!
            val context = session.context(
                audience = vpToken.audience,
                transactionData = authnRequest.transactionData,
                requireHolderBinding = credentialQuery.requireCryptographicHolderBinding != false,
            )
            relatedPresentations.map {
                ValidatedEntry(
                    compact = catching { it.extractContent() }.getOrNull().orEmpty(),
                    validations = validatePresentation(credentialQuery.format, it, context) { challenge ->
                        createSessionTranscript(
                            clientId = authnRequest.clientId,
                            nonce = challenge,
                            responseUrl = responseUrl,
                            clientIdRequired = responseParameters.clientIdRequired,
                            origin = origin,
                            recipientKey = recipientKey,
                        )
                    },
                )
            }
        }
        val presentationValidations = validated.mapValues { (_, entries) -> entries.flatMap { it.validations } }
        val submissionRequirements = DCQLQueryAdapter(vpToken.query).checkAcceptedSubmissions(
            presentationValidations.mapValues { (_, validations) -> validations.mapNotNull { it.presentation } }
        )
        val reports = presentationValidations.values.flatten().map { it.report }
        val result = catching {
            VpTokenValidationResultDCQL(
                credentialQueryResponseValidations = validated.mapValues { (_, entries) ->
                    entries.map { legacyPresentationResult(it.compact, it.validations) }
                },
                submissionRequirementsValidationResult = submissionRequirements,
                presentationValidations = presentationValidations,
            )
        }
        return VpTokenValidation(
            result = result,
            report = credentialValidator.reportResponse(
                checks = responseChecks(
                    parsing = CheckOutcome.Passed,
                    responseParameters = responseParameters,
                    expectedOrigin = expectedOrigin,
                    requestState = reports.requestState(),
                    submissionRequirements = submissionRequirements
                        .fold(onSuccess = { CheckOutcome.Passed }, onFailure = { CheckOutcome.Failed(it) }),
                ),
                presentations = reports,
            ),
            presentationValidations = presentationValidations,
        )
    }

    /** One presentation of the `vp_token`, as transported, and its validations, see [validatePresentation]. */
    private class ValidatedEntry(
        val compact: String,
        val validations: List<PresentationValidationResult>,
    )

    /** The `vp_token` of a response, by the credential queries of the request's DCQL query. */
    private class ParsedVpToken(
        val query: DCQLQuery,
        val presentations: Map<DCQLCredentialQueryIdentifier, List<JsonElement>>,
        /** The audience of holder proofs: the client identifier, or the origin over the Digital Credentials API. */
        val audience: String,
    )

    @Throws(IllegalArgumentException::class)
    private fun parse(
        authnRequest: AuthenticationRequestParameters,
        responseParameters: ResponseParametersFrom,
        origin: String?,
    ): ParsedVpToken {
        val vpToken = responseParameters.parameters.vpToken
            ?: throw IllegalArgumentException("vp_token not present in ${responseParameters.parameters}")
        // We do not support mapping "scope" in request to DCQL queries
        val query = authnRequest.dcqlQuery
            ?: throw IllegalArgumentException("DCQL Query not present in $authnRequest")
        val presentations = vpToken.jsonObject.mapKeys {
            DCQLCredentialQueryIdentifier(it.key)
        }.mapValues { (credentialQueryId, relatedPresentations) ->
            query.credentialQuery(credentialQueryId)
                ?: throw IllegalArgumentException("Unknown credential query identifier.")
            relatedPresentations.jsonArray.toList()
        }
        // Over the DC API, holder proofs are bound to the calling Origin, otherwise to client_id (OpenID4VP 1.0, A.4)
        val audience = origin?.let { "origin:$it" } ?: authnRequest.clientId
            ?: throw IllegalArgumentException("Request has no client_id to bind presentations to")
        return ParsedVpToken(query, presentations, audience)
    }

    private fun responseChecks(
        parsing: CheckOutcome,
        responseParameters: ResponseParametersFrom,
        expectedOrigin: CheckOutcome,
        requestState: CheckOutcome,
        submissionRequirements: CheckOutcome,
    ) = ProtocolResponseChecks(
        parsing = parsing,
        // A response without the encryption its request requires is not processed at all
        encryption = if (responseParameters.hasBeenEncrypted) CheckOutcome.Passed else CheckOutcome.NotApplicable,
        expectedOrigin = expectedOrigin,
        requestState = requestState,
        submissionRequirements = submissionRequirements,
    )

    /**
     * The response answers the request it has been correlated with, unless a presentation in it does not contain the
     * nonce of that request, which rejects the whole response (OpenID4VP 1.0, 14.1.2).
     */
    private fun List<ValidationReport>.requestState(): CheckOutcome =
        map { (it.checks as PresentationChecks).challenge }.firstOrNull { it is CheckOutcome.Failed }
            ?: CheckOutcome.Passed

    /**
     * Validates one presentation of the `vp_token` with [credentialValidator], in the format of its credential query:
     * an mdoc `DeviceResponse` yields one presentation per document.
     */
    private suspend fun validatePresentation(
        credentialFormat: CredentialFormatEnum,
        relatedPresentation: JsonElement,
        context: PresentationContext,
        createSessionTranscript: (challenge: String) -> SessionTranscript,
    ): List<PresentationValidationResult> = catching {
        when (credentialFormat) {
            CredentialFormatEnum.DC_SD_JWT -> listOf(
                PresentationValidationInput.SdJwt(relatedPresentation.extractContent())
                    .let { credentialValidator.validate(it, context, presentationPolicy) }
            )

            CredentialFormatEnum.JWT_VC -> listOf(
                relatedPresentation.extractContent().let {
                    if (context.requireHolderBinding) PresentationValidationInput.VpJwt(it)
                    else PresentationValidationInput.VcJwt(it)
                }.let { credentialValidator.validate(it, context, presentationPolicy) }
            )

            // ZK proofs are not verified, the documents are validated like plain mdocs
            CredentialFormatEnum.MSO_MDOC,
            CredentialFormatEnum.MSO_MDOC_ZK -> {
                val deviceResponse = relatedPresentation.extractContent().decodeToByteArray(Base64UrlStrict)
                    .let { coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(it) }
                val documents = deviceResponse.documents
                require(!documents.isNullOrEmpty()) { "The device response contains no documents" }
                val mdocContext = context.copy(sessionTranscript = createSessionTranscript(context.challenge))
                documents.map {
                    credentialValidator.validate(
                        PresentationValidationInput.MdocDocument(it),
                        mdocContext,
                        presentationPolicy,
                    )
                }
            }

            else -> throw IllegalArgumentException("Unsupported format: $credentialFormat")
        }
    }.getOrElse { listOf(credentialValidator.rejectUndecodable(it)) }

    private fun DCQLQuery.credentialQuery(id: DCQLCredentialQueryIdentifier): DCQLCredentialQuery? =
        credentials.associateBy { it.id }[id]

    // To be reconsidered when supporting [DCQLCredentialQueryInstance.multiple]
    private fun JsonElement.extractContent(): String = when (this) {
        is JsonArray -> first().extractContent()
        is JsonObject -> toString()
        is JsonPrimitive -> content
        JsonNull -> throw IllegalArgumentException("Can't extract string from JsonNull")
    }
}

/**
 * The validation of a `vp_token`: the [result] of the legacy verifier, and the [report] of the response, which every
 * presentation of it is validated for with a [CredentialValidator].
 */
internal class VpTokenValidation(
    val result: KmmResult<VpTokenValidationResult>,
    val report: ValidationReport,
    val presentationValidations: Map<DCQLCredentialQueryIdentifier, List<PresentationValidationResult>> = emptyMap(),
)

/**
 * The policy [OpenId4VpVerifier] and [DcApiVerifier] validate presentations under by default, the strictest one:
 * issuers and status list signers have to be authorized by the trust anchors of the credential validator, a status
 * is checked if the credential advertises one, and credentials have to be valid at the time of validation.
 */
internal val defaultPresentationPolicy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = StatusPolicy.ValidateIfPresent(signerTrust = TrustPolicy.RequireAuthorizedSigner),
    timeLeeway = 300.seconds,
    requireTimeliness = true,
)
