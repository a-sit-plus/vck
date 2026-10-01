package at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpChainValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestData
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

/**
 * Class to verify access certificates
 * Validations:
 *  - Certificate trust anchors
 *  - Linkage to the presentation request (OID4VP only)
 *  - Identifier is either legal or natural person
 **/
object WrpacValidator {

    suspend operator fun invoke(
        validationData: WrpRequestData,
        certificateTrustAnchors: TrustedCertificates
    ): KmmResult<WrpacValidationResult> = catching {
        val certificateChain = requireNotNull(validationData.accessCertificate.certificateChain) {
            "certificate chain is null"
        }
        Napier.d("validating request x5c, count=${certificateChain.size}")

        val validLinkage = validationData.clientId?.let { clientId ->
            validateX509HashBinding(clientId, certificateChain).getOrThrow()
        } ?: true

        WrpChainValidator(
            chain = certificateChain,
            certificateTrustAnchors = certificateTrustAnchors
        ).getOrThrow()

        val identifierResult = certificateChain.leaf.getWrpIdentifier().getOrThrow()
        WrpacValidationResult(
            chain = certificateChain,
            identifierResult = identifierResult,
            validLinkage = validLinkage
        )
    }

    private fun validateX509HashBinding(clientId: String, chain: CertificateChain?) = catching {
        require(!chain.isNullOrEmpty()) {
            "x509_hash validation failed, request x5c missing."
        }
        require(clientId.startsWith("x509_hash:")) {
            "x509_hash validation failed, client_id not starting with `x509_hash:`"
        }

        val expectedHash = clientId.removePrefix("x509_hash:")
        val calculatedHash = catchingUnwrapped {
            chain.first().encodeToDer().sha256().encodeToString(Base64UrlStrict)
        }.getOrElse {
            throw Throwable("x509_hash calculation from request x5c[0] failed.", it)
        }

        require(calculatedHash == expectedHash) {
            "x509_hash binding failed: expected $expectedHash but got $calculatedHash"
        }
        true
    }

    object Constants {
        val OID_ORGANIZATION_IDENTIFIER = ObjectIdentifier("2.5.4.97")
        val OID_SERIAL_NUMBER = ObjectIdentifier("2.5.4.5")
    }
}
