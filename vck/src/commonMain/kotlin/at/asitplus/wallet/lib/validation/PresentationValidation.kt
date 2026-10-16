package at.asitplus.wallet.lib.validation

import at.asitplus.iso.Document
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import kotlin.jvm.JvmOverloads

/**
 * One presentation, as received, together with its explicitly declared format.
 */
sealed interface PresentationValidationInput {

    /** A W3C VP as JWT, in JWS compact serialization, containing VC-JWTs. */
    data class VpJwt(val compact: String) : PresentationValidationInput

    /**
     * A VC-JWT presented without a VP, i.e. without holder proof, for DCQL
     * `require_cryptographic_holder_binding: false`.
     */
    data class VcJwt(val compact: String) : PresentationValidationInput

    /** An SD-JWT VC with the disclosures the holder selected, and a key binding JWT if holder binding is proven. */
    data class SdJwt(val compact: String) : PresentationValidationInput

    /**
     * One mdoc `Document` of a `DeviceResponse`, which the protocol layer decoded. The encoded issuer-signed items
     * are preserved by their `ByteStringWrapper`, so digests are checked over the bytes that were received.
     */
    data class MdocDocument(val document: Document) : PresentationValidationInput
}

/**
 * What the request expects of the holder's proof. Create it from the challenge session of the request, so that the
 * challenge is always the one that has been consumed.
 */
data class PresentationContext @JvmOverloads constructor(
    val challenge: String,
    /** The OpenID4VP client identifier, or `origin:<origin>` over the Digital Credentials API. */
    val audience: String,
    /** The transport-specific session transcript, required for mdoc device authentication. */
    val sessionTranscript: SessionTranscript? = null,
    val transactionData: List<TransactionDataBase64Url>? = null,
    /** Whether the request requires a holder proof, i.e. DCQL `require_cryptographic_holder_binding`. */
    val requireHolderBinding: Boolean = true,
)

/**
 * A presentation that passed every required check, with the credentials it contains.
 */
sealed interface ValidatedPresentation {
    data class VpJwt(
        val presentation: VerifiablePresentationJws,
        val credentials: List<ValidatedCredential.VcJwt>,
    ) : ValidatedPresentation

    data class VcJwt(
        val credential: ValidatedCredential.VcJwt
    ) : ValidatedPresentation

    data class SdJwt(
        val credential: ValidatedCredential.SdJwtVc,
        /** Present if the holder proved possession of the bound key. */
        val keyBinding: KeyBindingJws?,
    ) : ValidatedPresentation

    data class MdocDocument(
        val document: Document,
        val credential: ValidatedCredential.IsoMdoc,
    ) : ValidatedPresentation
}

/**
 * The [report] of validating a presentation, and the [presentation] if it has been accepted.
 * [presentation] is present if and only if the report is accepted.
 */
data class PresentationValidationResult(
    val report: ValidationReport,
    val presentation: ValidatedPresentation?,
) {
    init {
        require(report.checks is PresentationChecks) { "Report has to be a presentation report" }
        require((presentation != null) == (report.decision == ValidationDecision.ACCEPTED)) {
            "A presentation is present if and only if the report is accepted"
        }
    }
}
