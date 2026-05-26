package at.asitplus.wallet.lib.etsi

import at.asitplus.etsi.EtsiX509CertificateSerializer
import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.etsi.TEName
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.Serializable

class LoTEFilterService {

    fun extractTrustedCertificates(lote: ListOfTrustedEntities, criteria: LoTEFilterCriteria): List<TrustedCertificate> {
        val entities = lote.trustedEntitiesList ?: return emptyList()

        return entities.flatMap { entity ->
            val providerName = entity.trustedEntityInformation.teName

            entity.trustedEntityServices
                .filter { it.serviceInformation.serviceTypeIdentifier?.string == criteria.expectedServiceType }
                .flatMap { service -> service.serviceInformation.serviceDigitalIdentity.x509Certificates }
                .filter { cert -> cert?.hasMatchingOrganization(providerName) == true }
                .map { cert -> TrustedCertificate(cert, providerName, criteria.expectedServiceType) }
        }
    }

    // Checks if any organization name matches the provider's TEName
    private fun X509Certificate.hasMatchingOrganization(providerName: TEName): Boolean {
        val orgName = tbsCertificate.subjectName
            .flatMap { it.attrsAndValues }
            .filterIsInstance<AttributeTypeAndValue.Organization>()
            .firstOrNull()
            ?.asStringOrNull() ?: return false

        return providerName.any { it.value.equals(orgName, ignoreCase = true) }
    }
    private fun AttributeTypeAndValue.Organization.asStringOrNull(): String? = when (val element = value) {
        is Asn1Primitive -> runCatching { Asn1String.decodeFromTlv(element).value }.getOrNull()
        else -> element.toString()
    }
}

data class TrustedCertificate(
    val certificate: @Serializable(with = EtsiX509CertificateSerializer::class) X509Certificate?,
    val providerName: TEName,
    val serviceType: String
)

data class LoTEFilterCriteria(
    val expectedServiceType: String,
)