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

enum class LoTEServiceType(val type: String) {
    PID("pid"),
    MDL("mdl"),
    WRPAC("wrpac"),
    EAA("eaa"),
    WALLET("wallet");

    companion object {
        /**
         * Resolves a raw scheme type string into a safe Enum
         */
        fun fromSchemeType(rawSchemeType: String?): LoTEServiceType? {
            if (rawSchemeType.isNullOrBlank()) return null

            return when {
                rawSchemeType.contains("pid", ignoreCase = true) -> PID
                rawSchemeType.contains("mdl", ignoreCase = true) -> MDL
                rawSchemeType.contains("wrpac", ignoreCase = true) -> WRPAC
                rawSchemeType.contains("eaa", ignoreCase = true) -> EAA
                rawSchemeType.contains("wallet", ignoreCase = true) -> WALLET
                else -> null
            }
        }
    }
}