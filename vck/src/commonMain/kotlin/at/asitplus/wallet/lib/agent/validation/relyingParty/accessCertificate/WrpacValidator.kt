@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestData
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.evaluateAccessCertificate
import io.github.aakira.napier.Napier
import kotlin.time.Clock

/**
 * Class to verify access certificates
 * Validations:
 *  - Certificate trust anchors
 *  - Linkage to the presentation request (OID4VP only)
 *  - Identifier is either legal or natural person
 **/
@Deprecated("Validate relying parties with at.asitplus.wallet.lib.validation.RelyingPartyValidator. To be removed in the next major release.")
object WrpacValidator {

    /**
     * Validates the access certificate of [validationData] with the checks of
     * [at.asitplus.wallet.lib.validation.RelyingPartyValidator], except the signature of the request, and fails with
     * the cause of the first one that does not pass.
     */
    suspend operator fun invoke(
        validationData: WrpRequestData,
        certificateTrustAnchors: TrustedCertificates
    ): KmmResult<WrpacValidationResult> = catching {
        val certificateChain = requireNotNull(validationData.accessCertificate.certificateChain) {
            "certificate chain is null"
        }
        Napier.d("validating request x5c, count=${certificateChain.size}")
        val evaluation = evaluateAccessCertificate(
            chain = certificateChain,
            signature = CheckOutcome.NotApplicable,
            clientId = validationData.clientId,
            anchors = certificateTrustAnchors,
            source = "certificateTrustAnchors",
            now = Clock.System.now(),
        )
        with(evaluation.checks) {
            listOf(clientId, trust.outcome, timeliness, parsing).forEach {
                if (it is CheckOutcome.Failed) throw it.throwable
                if (it is CheckOutcome.Blocked) throw it.cause ?: IllegalStateException("A check is blocked")
            }
        }
        WrpacValidationResult(
            chain = certificateChain,
            identifierResult = evaluation.identifier,
            validLinkage = true
        )
    }

    object Constants {
        val OID_ORGANIZATION_IDENTIFIER = ObjectIdentifier("2.5.4.97")
        val OID_SERIAL_NUMBER = ObjectIdentifier("2.5.4.5")
    }
}
