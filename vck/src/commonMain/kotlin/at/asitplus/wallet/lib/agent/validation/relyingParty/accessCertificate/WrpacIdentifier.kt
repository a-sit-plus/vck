package at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate

import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacValidator.Constants.OID_ORGANIZATION_IDENTIFIER
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacValidator.Constants.OID_SERIAL_NUMBER
import kotlinx.serialization.Serializable

/**
 * Helper interface for the access certificate identifier
 */
@Serializable
sealed interface WrpacIdentifier {
    val identifier: String

    @Serializable
    data class WrpacNaturalIdentifier(override val identifier: String) : WrpacIdentifier

    @Serializable
    data class WrpacLegalIdentifier(override val identifier: String) : WrpacIdentifier
}

/**
 * Extension function to extract access certificate identifier
 * See: ETSI TS 119 475 V1.2.1 - 5.1.2 and 5.1.4
 */
fun X509Certificate.getWrpIdentifier() = catching {
    this.tbsCertificate.subjectName.firstOrNull { it.attrsAndValues.any { it.oid == OID_ORGANIZATION_IDENTIFIER } }
        ?.attrsAndValues?.first { it.oid == OID_ORGANIZATION_IDENTIFIER }?.value.let {
            (it as? Asn1Primitive)?.content?.decodeToString()
        }?.let {
            return@catching WrpacIdentifier.WrpacLegalIdentifier(it)
        }

    this.tbsCertificate.subjectName.firstOrNull { it.attrsAndValues.any { it.oid == OID_SERIAL_NUMBER } }
        ?.attrsAndValues?.first { it.oid == OID_SERIAL_NUMBER }?.value.let {
            (it as? Asn1Primitive)?.content?.decodeToString()
        }?.let {
            return@catching WrpacIdentifier.WrpacNaturalIdentifier(it)
        }

    throw Throwable("Unable to extract access certificate identifier")
}
