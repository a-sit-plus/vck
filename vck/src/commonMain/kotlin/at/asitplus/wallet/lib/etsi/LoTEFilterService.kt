package at.asitplus.wallet.lib.etsi

import at.asitplus.etsi.EtsiX509CertificateSerializer
import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.etsi.TEName
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.Serializable

/**
 * Service to filter and extract trusted X.509 certificates from an ETSI List of Trusted Entities (LoTE)
 */
class LoTEFilterService {

    /**
     * Extracts certificates matching the requested service type identifier where
     * the certificate's subject organization aligns with the trusted provider's registered names
     */
    fun extractTrustedCertificates(sourceUrl: String, lote: ListOfTrustedEntities, criteria: LoTEFilterCriteria): List<TrustedCertificate> {
        val entities = lote.trustedEntitiesList ?: return emptyList()
        val loteType = lote.listAndSchemeInformation?.loteType?.toString()
        return entities.flatMap { entity ->
            val providerName = entity.trustedEntityInformation.teName

            entity.trustedEntityServices
                .filter { service ->
                    val serviceTypeId = service.serviceInformation.serviceTypeIdentifier?.string

                    if (serviceTypeId != null) {
                        // Field is present. Check if it matches type
                        serviceTypeId.contains(criteria.expectedServiceType.type, ignoreCase = true)
                    } else {
                        // Field is absent. The services inherit the list's default type
                        loteType?.contains(criteria.expectedServiceType.type, ignoreCase = true) == true ||
                        sourceUrl.contains(criteria.expectedServiceType.type, ignoreCase = true)
                    }
                }
                .flatMap { service -> service.serviceInformation.serviceDigitalIdentity.x509Certificates }
                .filter { cert -> cert?.hasMatchingOrganization(providerName) == true }
                .map { cert -> TrustedCertificate(cert, providerName, criteria.expectedServiceType) }
        }
    }

    /**
     * Checks if the Organization (O) attribute within the certificate's Subject Name matches
     * any of the localized names declared in the provider's [TEName] block.
     */
    private fun X509Certificate.hasMatchingOrganization(providerName: TEName): Boolean {
        val orgName = tbsCertificate.subjectName
            .flatMap { it.attrsAndValues }
            .filterIsInstance<AttributeTypeAndValue.Organization>()
            .firstOrNull()
            ?.asStringOrNull() ?: return false

        return providerName.any { it.value.equals(orgName, ignoreCase = true) }
    }

    /**
     * Unwraps the Organization value wrapper into a standard String,
     */
    private fun AttributeTypeAndValue.Organization.asStringOrNull(): String? = when (val element = value) {
        is Asn1Primitive -> runCatching { Asn1String.decodeFromTlv(element).value }.getOrNull()
        else -> element.toString()
    }
}

data class TrustedCertificate(
    val certificate: @Serializable(with = EtsiX509CertificateSerializer::class) X509Certificate?,
    val providerName: TEName,
    val serviceType: LoTEServiceType
)

data class LoTEFilterCriteria(
    val expectedServiceType: LoTEServiceType,
)

enum class LoTEServiceType(
    val type: String,
    val fileName: String,
    private val identifiers: List<String> = emptyList()
) {
    PID("pid", "pid-providers.json", listOf("urn:eudi:pid:", "eu.europa.ec.eudi.pid.")),
    MDL("mdl", "mdl-providers.json", listOf("org.iso.18013.5.1.mDL")),
    WRPAC("wrpac", "wrpac-providers.json"),
    WALLET("wallet", "wallet-providers.json"),
    EAA("eaa", "pub-eaa-providers.json");

    fun defaultUrl(baseUrl: String = DEFAULT_BASE_URL) = "$baseUrl/$fileName"

    companion object {
        const val DEFAULT_BASE_URL = "https://acceptance.trust.tech.ec.europa.eu/lists/eudiw"
        val defaultUrls = entries.map { it.defaultUrl() }

        fun fromSchemeIdentifier(schemeIdentifier: String?): LoTEServiceType {
            if (schemeIdentifier.isNullOrBlank()) return EAA

            return entries.firstOrNull { entry ->
                entry.identifiers.any { schemeIdentifier.contains(it, ignoreCase = true) }
            } ?: EAA
        }
    }
}