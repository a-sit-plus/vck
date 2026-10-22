package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.openid.digest
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.agent.matchesIdentifier
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.deviceAuthenticationBytes
import at.asitplus.wallet.lib.verifyDeviceMac
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlin.time.Instant

/**
 * Completes the validation of a credential in a presentation: trust, status, and its report.
 */
internal fun interface CredentialValidationCompletion {
    suspend operator fun invoke(
        evaluation: FormatEvaluation,
        holderBinding: HolderBindingPolicy,
    ): CredentialValidationResult
}

/**
 * What the validation of a presentation found: the holder's proof, the results of its credentials, and the validated
 * presentation, if all of its credentials are accepted.
 */
internal class PresentationEvaluation(
    val checks: PresentationChecks,
    val credentials: List<CredentialValidationResult> = emptyList(),
    val presentation: ValidatedPresentation? = null,
) {
    constructor(
        checks: PresentationChecks,
        credential: CredentialValidationResult,
        presentation: ValidatedPresentation? = null
    ) : this(checks, listOf(credential), presentation)
}

private fun notApplicable(parsing: CheckOutcome = Passed) = PresentationChecks(
    parsing = parsing,
    signature = NotApplicable,
    proofTime = NotApplicable,
    challenge = NotApplicable,
    audience = NotApplicable,
    presentationBinding = NotApplicable,
)

/** The checks of a presentation whose [parsing] did not pass, which blocks every other check. */
internal fun blockedPresentationChecks(parsing: CheckOutcome) = PresentationChecks(
    parsing = parsing,
    signature = Blocked(),
    proofTime = Blocked(),
    challenge = Blocked(),
    audience = Blocked(),
    presentationBinding = Blocked(),
)

/** A blank [expected] value, e.g. of [PresentationContext.forMdoc], is never answered. */
private fun equalOrFailed(actual: String?, expected: String, claim: String): CheckOutcome = when {
    expected.isBlank() -> Failed(IllegalArgumentException("The request has no $claim to answer"))
    actual == expected -> Passed
    else -> Failed(IllegalArgumentException("The $claim is not the expected one"))
}

/**
 * Validates an SD-JWT presentation: the SD-JWT as a credential (RFC 9901, 7.1), and, if the request requires holder
 * binding, its key binding JWT (RFC 9901, 7.3 step 5). Whether key binding is checked never depends on whether a
 * key binding JWT was supplied (RFC 9901, 7.3 step 1), so a supplied one is not checked if binding is not required,
 * and not returned either. Transaction data requires holder binding (OpenID4VP 1.0, B.3.3).
 */
internal suspend fun evaluateSdJwtPresentation(
    input: PresentationValidationInput.SdJwt,
    context: PresentationContext,
    signatureCheck: SignatureCheck,
    timeScope: TimeScope,
    complete: CredentialValidationCompletion,
): PresentationEvaluation {
    if (!input.compact.contains("~")) {
        val failure = IllegalArgumentException("Invalid format for an SD-JWT, contains no ~")
        return PresentationEvaluation(blockedPresentationChecks(Failed(failure)))
    }
    // The SD-JWT without the key binding JWT is the input of sd_hash (RFC 9901, 4.3.1)
    val sdJwt = input.compact.substringBeforeLast("~") + "~"
    val keyBindingJwt = input.compact.substringAfterLast("~")
    val evaluation = evaluateSdJwtVc(
        input = CredentialValidationInput.SdJwtVc(sdJwt),
        signatureCheck = signatureCheck,
        holderBinding = HolderBindingPolicy.None,
        context = CredentialValidationContext(),
        timeScope = timeScope,
    )
    val credential = complete(evaluation, HolderBindingPolicy.None)
    val validated = credential.credential as? ValidatedCredential.SdJwtVc
    val bindingRequired = context.requireHolderBinding || !context.transactionData.isNullOrEmpty()
    if (!bindingRequired) {
        val presentation = validated?.let { ValidatedPresentation.SdJwt(it, keyBinding = null) }
        return PresentationEvaluation(notApplicable(), credential, presentation)
    }
    val keyBinding = catching {
        require(keyBindingJwt.isNotEmpty()) { "The request requires a key binding JWT" }
        JwsCompactTyped<KeyBindingJws>(keyBindingJwt).also {
            val type = it.jws.jwsHeader.type
            // RFC 9901, 4.3 and 7.3 step 5.d
            require(type.equals(JwsContentTypeConstants.KB_JWT, ignoreCase = true)) {
                "Invalid type of key binding JWT: $type"
            }
            requireNotNull(it.payload.issuedAt) { "The key binding JWT has no iat" }
        }
    }.getOrElse {
        return PresentationEvaluation(blockedPresentationChecks(Failed(it)), credential)
    }
    val issuerSigned = (evaluation as? FormatEvaluation.Evaluated)?.credential as? ValidatedCredential.SdJwtVc
    // The key binding JWT is verified with the key the issuer bound the credential to (RFC 9901, 7.3 step 5.a),
    // never with a key it asserts itself; that key is only authoritative once the issuer signature verified.
    val signature = when {
        issuerSigned == null -> Blocked(IllegalStateException("The issuer signature of the SD-JWT did not verify"))
        else -> issuerSigned.credential.confirmationClaim?.jsonWebKey?.toCryptoPublicKey()?.getOrNull()
            ?.let { signatureCheck.verify(keyBinding.jws, key = it).outcome }
            ?: Failed(IllegalArgumentException("The SD-JWT has no cnf key to verify the key binding JWT with"))
    }
    val claims = keyBinding.payload.takeIf { signature == Passed }
    val checks = PresentationChecks(
        parsing = Passed,
        signature = signature,
        proofTime = claims?.let { proofTime(it.issuedAt, it.issuedAt, timeScope) } ?: Blocked(),
        challenge = claims?.let { equalOrFailed(it.challenge, context.challenge, "nonce") } ?: Blocked(),
        audience = claims?.let { equalOrFailed(it.audience, context.audience, "aud") } ?: Blocked(),
        presentationBinding = claims?.let {
            presentationBinding(it, sdJwt, issuerSigned?.credential?.selectiveDisclosureAlgorithm, context)
        } ?: Blocked(),
    )
    val presentation = validated?.let { ValidatedPresentation.SdJwt(it, keyBinding = claims) }
    return PresentationEvaluation(checks, credential, presentation)
}

/**
 * The creation time of a holder proof has to be within the window of the leeway around the time of validation
 * (RFC 9901, 7.3 step 5.e): issued not after [latest], and not expiring before [earliest]. Never relaxed by
 * `requireTimeliness`, as it protects against replay.
 */
private fun proofTime(latest: Instant?, earliest: Instant?, timeScope: TimeScope): CheckOutcome = with(timeScope) {
    when {
        latest != null && latest.isTooLate() ->
            Failed(TimelinessException("The holder proof is from the future", now, notBefore = latest, notAfter = null))

        earliest != null && earliest.isTooEarly() ->
            Failed(TimelinessException("The holder proof is too old", now, notBefore = null, notAfter = earliest))

        else -> Passed
    }
}

/**
 * `sd_hash` over the SD-JWT with the hash function of `_sd_alg` (RFC 9901, 4.3.1, 7.3 step 5.g), and, if the request
 * contains transaction data, `transaction_data_hashes` over each of them in order (OpenID4VP 1.0, B.3.3.1).
 */
private fun presentationBinding(
    keyBinding: KeyBindingJws,
    sdJwt: String,
    sdAlgorithm: String?,
    context: PresentationContext,
): CheckOutcome = catching {
    val sdHash = sdJwtDigest(sdAlgorithm).digest(sdJwt.encodeToByteArray())
    require(keyBinding.sdHash.contentEquals(sdHash)) { "The sd_hash does not match the SD-JWT" }
    context.transactionData?.takeIf { it.isNotEmpty() }?.let { transactionData ->
        val hashes = requireNotNull(keyBinding.transactionDataHashes) { "The key binding JWT has no transaction data" }
        val expected = transactionData.map { it.digest(keyBinding.transactionDataHashesAlgorithm) }
        require(hashes.size == expected.size && hashes.zip(expected).all { it.first.contentEquals(it.second) }) {
            "The transaction data hashes do not match the transaction data"
        }
    }
}.toOutcome()

/**
 * Validates a VP-JWT (W3C VC Data Model 1.1, *JWT encoding*): signed by the holder, whose key `iss` identifies,
 * `jti` is the presentation `id`, `nonce` and `aud` answer the request, and `exp` and `nbf` hold if present. Its
 * credentials have to be bound to the key that signed it.
 */
internal suspend fun evaluateVpJwtPresentation(
    input: PresentationValidationInput.VpJwt,
    context: PresentationContext,
    signatureCheck: SignatureCheck,
    timeScope: TimeScope,
    complete: CredentialValidationCompletion,
): PresentationEvaluation {
    val vpJws = catching {
        JwsCompactTyped<VerifiablePresentationJws>(input.compact).also {
            require(it.payload.vp.type == VcDataModelConstants.VERIFIABLE_PRESENTATION) {
                "Not a verifiable presentation"
            }
            require(it.payload.jwtId == it.payload.vp.id) { "The jti is not the id of the presentation" }
            require(it.payload.vp.verifiableCredential.isNotEmpty()) { "The presentation contains no credential" }
        }
    }.getOrElse {
        return PresentationEvaluation(blockedPresentationChecks(Failed(it)))
    }
    val payload = vpJws.payload
    val verification = signatureCheck.verify(vpJws.jws)
    val holderKey = verification.key?.takeIf { it.matchesIdentifier(payload.issuer) }
    val signature = when {
        verification.outcome != Passed -> verification.outcome
        holderKey == null -> Failed(IllegalArgumentException("The iss of the presentation does not identify its key"))
        else -> Passed
    }
    val credentials = payload.vp.verifiableCredential.map { vc ->
        val holderBinding = HolderBindingPolicy.RequireExpectedKey
        val evaluation = evaluateVcJwt(
            input = CredentialValidationInput.VcJwt(vc),
            signatureCheck = signatureCheck,
            holderBinding = holderBinding,
            context = CredentialValidationContext(expectedHolderKey = holderKey),
            timeScope = timeScope,
        )
        complete(evaluation, holderBinding)
    }
    val claims = vpJws.jws.getPayload<JsonObject>().getOrNull()?.takeIf { signature == Passed }
    val checks = PresentationChecks(
        parsing = Passed,
        signature = signature,
        proofTime = claims?.let { proofTime(it.instant("nbf"), it.instant("exp"), timeScope) } ?: Blocked(),
        challenge = claims?.let { equalOrFailed(payload.challenge, context.challenge, "nonce") } ?: Blocked(),
        audience = claims?.let { equalOrFailed(payload.audience, context.audience, "aud") } ?: Blocked(),
        presentationBinding = NotApplicable,
    )
    val validated = credentials.map { it.credential as? ValidatedCredential.VcJwt }
    val presentation = validated.takeIf { list -> list.all { it != null } }
        ?.let { ValidatedPresentation.VpJwt(payload, it.filterNotNull()) }
    return PresentationEvaluation(checks, credentials, presentation)
}

private fun JsonObject.instant(claim: String): Instant? =
    get(claim)?.jsonPrimitive?.longOrNull?.let { Instant.fromEpochSeconds(it) }

/**
 * Validates a VC-JWT presented without a VP, which proves no holder binding: rejected if the request requires one
 * (DCQL `require_cryptographic_holder_binding`, OpenID4VP 1.0, 6.1).
 */
internal suspend fun evaluateVcJwtPresentation(
    input: PresentationValidationInput.VcJwt,
    context: PresentationContext,
    signatureCheck: SignatureCheck,
    timeScope: TimeScope,
    complete: CredentialValidationCompletion,
): PresentationEvaluation {
    val evaluation = evaluateVcJwt(
        input = CredentialValidationInput.VcJwt(input.compact),
        signatureCheck = signatureCheck,
        holderBinding = HolderBindingPolicy.None,
        context = CredentialValidationContext(),
        timeScope = timeScope,
    )
    val credential = complete(evaluation, HolderBindingPolicy.None)
    val checks = if (context.requireHolderBinding) notApplicable().copy(
        signature = Failed(IllegalArgumentException("The request requires holder binding, no presentation proves it"))
    ) else notApplicable()
    val validated = credential.credential as? ValidatedCredential.VcJwt
    return PresentationEvaluation(checks, credential, validated?.let { ValidatedPresentation.VcJwt(it) })
}

/**
 * Validates an mdoc `Document`: its `IssuerSigned` as a credential of the document's `docType`, and its device
 * authentication over `DeviceAuthenticationBytes` with the device key the MSO binds, which is only authoritative once
 * the issuer signature verified: either its device signature (ISO/IEC 18013-5:2021, 9.1.3.6), or its device MAC
 * with the reader's ephemeral key [PresentationContext.eReaderKey] (9.1.3.5). The session transcript binds the
 * request, so nonce and audience are not applicable.
 */
internal suspend fun evaluateMdocPresentation(
    input: PresentationValidationInput.MdocDocument,
    context: PresentationContext,
    signatureCheck: SignatureCheck,
    timeScope: TimeScope,
    complete: CredentialValidationCompletion,
): PresentationEvaluation {
    val document = input.document
    val evaluation = evaluateIssuerSigned(
        issuerSigned = document.issuerSigned,
        signatureCheck = signatureCheck,
        holderBinding = HolderBindingPolicy.None,
        context = CredentialValidationContext(expectedCredentialIdentifier = document.docType),
        timeScope = timeScope,
    )
    val credential = complete(evaluation, HolderBindingPolicy.None)
    val issuerSigned = (evaluation as? FormatEvaluation.Evaluated)?.credential as? ValidatedCredential.IsoMdoc
    val deviceKey: CryptoPublicKey? =
        issuerSigned?.issuerSigned?.issuerAuth?.payload?.deviceKeyInfo?.deviceKey?.toCryptoPublicKey()?.getOrNull()
    val deviceSignature = document.deviceSigned.deviceAuth.deviceSignature
    val deviceMac = document.deviceSigned.deviceAuth.deviceMac
    val transcript = context.sessionTranscript
    val eReaderKey = context.eReaderKey
    val signature = when {
        transcript == null -> Blocked(IllegalStateException("No session transcript to verify the device authentication"))
        deviceKey == null -> Blocked(IllegalStateException("The issuer signature of the MSO did not verify"))
        deviceSignature != null && deviceMac != null ->
            Failed(IllegalArgumentException("The document has both a device signature and a device MAC"))

        deviceSignature != null -> signatureCheck.verify(
            cose = deviceSignature,
            detachedPayload = document.deviceAuthenticationBytes(transcript),
            key = deviceKey,
        ).outcome

        deviceMac == null -> Failed(IllegalArgumentException("The document has neither a device signature nor a MAC"))
        eReaderKey == null ->
            Blocked(IllegalStateException("No ephemeral reader key to verify the device MAC of the document"))

        else -> document.verifyDeviceMac(deviceMac, deviceKey, eReaderKey, transcript)
            .fold(onSuccess = { Passed }, onFailure = { Failed(it) })
    }
    val validated = credential.credential as? ValidatedCredential.IsoMdoc
    return PresentationEvaluation(
        checks = notApplicable().copy(signature = signature),
        credential = credential,
        presentation = validated?.let { ValidatedPresentation.MdocDocument(document, it) },
    )
}
