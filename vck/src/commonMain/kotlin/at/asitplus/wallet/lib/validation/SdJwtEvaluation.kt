package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidator
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlinx.serialization.json.JsonObject

/**
 * Registered claims of an SD-JWT VC that must not be selectively disclosed (draft-ietf-oauth-sd-jwt-vc-19, 2.2.2.3),
 * so they are read from the issuer-signed payload.
 */
private val notDisclosable = setOf("iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status")

/**
 * Evaluates an issued SD-JWT VC: parses it strictly, verifies the issuer signature, processes every supplied
 * disclosure (see [processDisclosures]), and checks holder binding by `cnf` and time. Trust anchors are selected by
 * `vct`.
 */
internal suspend fun evaluateSdJwtVc(
    input: CredentialValidationInput.SdJwtVc,
    signatureCheck: SignatureCheck,
    holderBinding: HolderBindingPolicy,
    context: CredentialValidationContext,
    timeScope: TimeScope,
): FormatEvaluation {
    val parsed = catching { parseIssued(input.compact) }.getOrElse {
        return FormatEvaluation.WithoutPrerequisites(Failed(it), issuerSignature = Passed)
    }
    val signature = signatureCheck.verify(parsed.jws)
    if (signature.outcome != Passed)
        return FormatEvaluation.WithoutPrerequisites(Passed, signature.outcome)
    val processed =
        processDisclosures(parsed.sdJwtSigned.rawDisclosures, parsed.signedPayload, parsed.digest, notDisclosable)
    val vct = parsed.credential.verifiableCredentialType
    return FormatEvaluation.Evaluated(
        credentialIdentifier = vct,
        certificateChain = signature.certificateChain,
        semantics = semanticsOf(
            expectedIdentifier(context.expectedCredentialIdentifier, listOf(vct)),
            // A digest occurring more than once rejects the SD-JWT (RFC 9901, 7.1 step 4)
            if (processed.duplicateDigest)
                Failed(IllegalArgumentException("A digest occurs more than once"))
            else Passed,
        ),
        disclosedItems = processed.items,
        holderBinding = holderBinding.check(context.expectedHolderKey) { key ->
            parsed.credential.confirmationClaim?.jsonWebKey?.toCryptoPublicKey()?.getOrNull() == key
        },
        timeliness = SdJwtTimelinessValidator()(parsed.credential, timeScope).let { details ->
            CredentialTimelinessValidationSummary.SdJwt(details).toValidation(
                evaluatedAt = timeScope.now,
                notYetValid = listOf(details.jwsNotYetValidError),
                expired = listOf(details.jwsExpiredError),
            )
        },
        status = parsed.credential.statusElement?.let { TokenStatusInfo.from(it) },
        credential = ValidatedCredential.SdJwtVc(
            sdJwtSigned = parsed.sdJwtSigned,
            credential = parsed.credential,
            reconstructedJsonObject = processed.payload,
            disclosures = processed.disclosures,
        ),
    )
}

private data class ParsedSdJwt(
    val sdJwtSigned: SdJwtSigned,
    val signedPayload: JsonObject,
    val credential: VerifiableCredentialSdJwt,
    val digest: Digest,
) {
    val jws: JwsCompact get() = sdJwtSigned.jws
}

/**
 * Parses an issued SD-JWT, `<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~` (RFC 9901, 4), without
 * normalizing it: an issued credential carries no key binding JWT, so it ends with `~`.
 */
private fun parseIssued(compact: String): ParsedSdJwt {
    val parts = compact.split("~")
    require(parts.size >= 2) { "An SD-JWT consists of the issuer-signed JWT and disclosures, separated by ~" }
    require(parts.last().isEmpty()) { "An issued SD-JWT ends with ~, it carries no key binding JWT" }
    val disclosures = parts.subList(1, parts.size - 1)
    require(disclosures.none { it.isEmpty() }) { "An SD-JWT contains no empty disclosure" }
    val jws = JwsCompact(parts.first())
    val type = jws.jwsHeader.type
    // The legacy vc+sd-jwt is rejected (draft-ietf-oauth-sd-jwt-vc-19, 2.2.1: "typ value MUST use dc+sd-jwt")
    require(type.equals(JwsContentTypeConstants.SD_JWT, ignoreCase = true)) { "Invalid type of SD-JWT VC: $type" }
    val signedPayload = jws.getPayload<JsonObject>().getOrThrow()
    val credential = jws.getPayload<VerifiableCredentialSdJwt>().getOrThrow()
    // A hash algorithm that is not understood rejects the SD-JWT (RFC 9901, 7.1 step 2.d), SHA-256 by default (4.1.1)
    val digest = when (val algorithm = credential.selectiveDisclosureAlgorithm?.lowercase()) {
        null, SdJwtConstants.SHA_256 -> Digest.SHA256
        SdJwtConstants.SHA_384 -> Digest.SHA384
        SdJwtConstants.SHA_512 -> Digest.SHA512
        else -> throw IllegalArgumentException("Unsupported hash algorithm $algorithm")
    }
    return ParsedSdJwt(SdJwtSigned.issued(jws, disclosures), signedPayload, credential, digest)
}
