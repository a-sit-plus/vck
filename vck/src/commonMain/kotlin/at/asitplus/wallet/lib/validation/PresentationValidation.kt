package at.asitplus.wallet.lib.validation

import at.asitplus.iso.Document
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.jws.SdJwtSigned
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
 *
 * For mdoc presentations of an ISO/IEC 18013-5 proximity session, use [forMdoc].
 */
data class PresentationContext @JvmOverloads constructor(
    /** The nonce the holder's proof has to contain. A blank challenge is never answered, see [forMdoc]. */
    val challenge: String,
    /**
     * The OpenID4VP client identifier, or `origin:<origin>` over the Digital Credentials API. A blank audience is never
     * answered, see [forMdoc].
     */
    val audience: String,
    /** The transport-specific session transcript, required for mdoc device authentication. */
    val sessionTranscript: SessionTranscript? = null,
    val transactionData: List<TransactionDataBase64Url>? = null,
    /** Whether the request requires a holder proof, i.e. DCQL `require_cryptographic_holder_binding`. */
    val requireHolderBinding: Boolean = true,
    /**
     * The mdoc reader's ephemeral private key `EReaderKey.Priv` of the session of [sessionTranscript], required for
     * mdoc MAC authentication (ISO/IEC 18013-5:2021, 9.1.3.5). Without it, documents authenticated with a `deviceMac`
     * can not be verified, only those with a `deviceSignature`.
     */
    val eReaderKey: KeyAgreementPrivateValue.ECDH? = null,
) {
    companion object {
        /**
         * The context of mdoc device authentication, e.g. as an ISO/IEC 18013-5 proximity reader: the device signature
         * or MAC covers the [sessionTranscript], which binds the request, but neither a challenge nor an audience.
         * Presentations of other formats are therefore rejected with this context.
         *
         * @param eReaderKey the reader's ephemeral private key of the session, to verify documents authenticated with a
         * `deviceMac`
         */
        @JvmOverloads
        fun forMdoc(
            sessionTranscript: SessionTranscript,
            eReaderKey: KeyAgreementPrivateValue.ECDH? = null,
        ) = PresentationContext(
            challenge = "",
            audience = "",
            sessionTranscript = sessionTranscript,
            eReaderKey = eReaderKey,
        )
    }
}

/**
 * A presentation that passed every required check, with the credentials it contains.
 */
sealed interface ValidatedPresentation {
    /** Every credential of this presentation, e.g. to display their claims. */
    val credentials: List<ValidatedCredential>

    data class VpJwt(
        val presentation: VerifiablePresentationJws,
        override val credentials: List<ValidatedCredential.VcJwt>,
    ) : ValidatedPresentation

    data class VcJwt(
        val credential: ValidatedCredential.VcJwt
    ) : ValidatedPresentation {
        override val credentials get() = listOf(credential)
    }

    data class SdJwt(
        val credential: ValidatedCredential.SdJwtVc,
        /**
         * The signed key binding JWT, present if the request required holder binding and the holder proved possession
         * of the bound key. A key binding JWT the request did not require is not checked, and therefore not present.
         */
        val keyBinding: JwsCompactTyped<KeyBindingJws>?,
    ) : ValidatedPresentation {
        override val credentials get() = listOf(credential)

        /** The SD-JWT as presented, with the disclosures of [credential] and the verified [keyBinding]. */
        val sdJwtSigned: SdJwtSigned get() = credential.sdJwtSigned.copy(keyBindingJws = keyBinding)
    }

    data class MdocDocument(
        val document: Document,
        val credential: ValidatedCredential.IsoMdoc,
    ) : ValidatedPresentation {
        override val credentials get() = listOf(credential)
    }
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

    /**
     * Why the presentation is rejected: the cause of its first check that does not pass, otherwise of the first
     * rejecting check of its first rejected credential, see [ValidationReport.namedChecks]; `null` if it is accepted.
     * For callers reporting a single error, e.g. the legacy results of verifiers.
     */
    fun rejection(): Throwable? = report.firstRejection()
}
