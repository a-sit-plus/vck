package at.asitplus.wallet.lib.etsi

import at.asitplus.etsi.ETSI19602.EU_PID_PROVIDERS_FETCH_URL
import at.asitplus.etsi.ETSI19602.EU_PID_PROVIDERS_SCHEME_COMMUNITY_RULES
import at.asitplus.etsi.ETSI19602.EU_PID_PROVIDERS_SCHEME_TYPE
import at.asitplus.etsi.ETSI19602.EU_PID_PROVIDERS_STATUS_DETERMINATION_APPROACH
import at.asitplus.etsi.ETSI19602.EU_PID_PROVIDERS_SVC_TYPE_ISSUANCE
import at.asitplus.etsi.ETSI19602.EU_PID_PROVIDERS_SVC_TYPE_REVOCATION
import at.asitplus.etsi.ETSI19602.EU_PUB_EAA_PROVIDERS_FETCH_URL
import at.asitplus.etsi.ETSI19602.EU_PUB_EAA_PROVIDERS_SCHEME_COMMUNITY_RULES
import at.asitplus.etsi.ETSI19602.EU_PUB_EAA_PROVIDERS_SCHEME_TYPE
import at.asitplus.etsi.ETSI19602.EU_PUB_EAA_PROVIDERS_STATUS_DETERMINATION_APPROACH
import at.asitplus.etsi.ETSI19602.EU_PUB_EAA_PROVIDERS_SVC_TYPE_ISSUANCE
import at.asitplus.etsi.ETSI19602.EU_PUB_EAA_PROVIDERS_SVC_TYPE_REVOCATION
import at.asitplus.etsi.ETSI19602.EU_WALLET_PROVIDERS_FETCH_URL
import at.asitplus.etsi.ETSI19602.EU_WALLET_PROVIDERS_SCHEME_COMMUNITY_RULES
import at.asitplus.etsi.ETSI19602.EU_WALLET_PROVIDERS_SCHEME_TYPE
import at.asitplus.etsi.ETSI19602.EU_WALLET_PROVIDERS_STATUS_DETERMINATION_APPROACH
import at.asitplus.etsi.ETSI19602.EU_WALLET_PROVIDERS_SVC_TYPE_ISSUANCE
import at.asitplus.etsi.ETSI19602.EU_WALLET_PROVIDERS_SVC_TYPE_REVOCATION
import at.asitplus.etsi.ETSI19602.EU_WRPAC_PROVIDERS_FETCH_URL
import at.asitplus.etsi.ETSI19602.EU_WRPAC_PROVIDERS_SCHEME_COMMUNITY_RULES
import at.asitplus.etsi.ETSI19602.EU_WRPAC_PROVIDERS_SCHEME_TYPE
import at.asitplus.etsi.ETSI19602.EU_WRPAC_PROVIDERS_STATUS_DETERMINATION_APPROACH
import at.asitplus.etsi.ETSI19602.EU_WRPAC_PROVIDERS_SVC_TYPE_ISSUANCE
import at.asitplus.etsi.ETSI19602.EU_WRPAC_PROVIDERS_SVC_TYPE_REVOCATION
import at.asitplus.etsi.ETSI19602.EU_mDL_PROVIDERS_FETCH_URL
import at.asitplus.etsi.ETSI19602.EU_mDL_PROVIDERS_SCHEME_COMMUNITY_RULES
import at.asitplus.etsi.ETSI19602.EU_mDL_PROVIDERS_SCHEME_TYPE
import at.asitplus.etsi.ETSI19602.EU_mDL_PROVIDERS_STATUS_DETERMINATION_APPROACH
import at.asitplus.etsi.ETSI19602.EU_mDL_PROVIDERS_SVC_TYPE_ISSUANCE
import at.asitplus.etsi.ETSI19602.EU_mDL_PROVIDERS_SVC_TYPE_REVOCATION
import at.asitplus.etsi.EtsiCountryCode
import at.asitplus.etsi.EtsiX509CertificateSerializer
import at.asitplus.etsi.ListAndSchemeInformation
import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.etsi.TEName
import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.Serializable

enum class ServiceKind { ISSUANCE, REVOCATION }

/**
 * Service to filter and extract trusted X.509 certificates from an ETSI List of Trusted Entities (LoTE)
 */
class LoTEFilterService {

    /**
     * Extracts certificates matching the requested service type identifier for Issuance.
     */
    fun extractIssuanceCertificates(
        lote: ListOfTrustedEntities,
        profile: LoteProfile
    ): List<TrustedCertificate> = extractTrustedCertificates(lote, profile, ServiceKind.ISSUANCE)

    /**
     * Extracts certificates matching the requested service type identifier for Revocation.
     */
    fun extractRevocationCertificates(
        lote: ListOfTrustedEntities,
        profile: LoteProfile
    ): List<TrustedCertificate> = extractTrustedCertificates(lote, profile, ServiceKind.REVOCATION)

    /**
     * Core extraction logic handling both Issuance and Revocation based on [ServiceKind].
     */
    private fun extractTrustedCertificates(
        lote: ListOfTrustedEntities,
        profile: LoteProfile,
        kind: ServiceKind = ServiceKind.ISSUANCE
    ): List<TrustedCertificate> {
        if (!checkListAndSchemeInformation(lote.listAndSchemeInformation, profile)) {
            return emptyList()
        }

        val (matcher, targetServiceType) = when (kind) {
            ServiceKind.ISSUANCE -> profile::matchesServiceTypeIssuance to profile.serviceTypeIdentifierIssuance
            ServiceKind.REVOCATION -> profile::matchesServiceTypeRevocation to profile.serviceTypeIdentifierRevocation
        }

        val entities = lote.trustedEntitiesList ?: return emptyList()
        return entities.flatMap { entity ->
            val providerName = entity.trustedEntityInformation.teName

            entity.trustedEntityServices
                .filter { service ->
                    matcher(service.serviceInformation.serviceTypeIdentifier?.string)
                }
                .flatMap { service -> service.serviceInformation.serviceDigitalIdentity.x509Certificates }
                .filter { cert -> cert?.hasMatchingOrganization(providerName) == true }
                .map { cert -> TrustedCertificate(cert, providerName, targetServiceType) }
        }
    }

    @Deprecated(
        "Replaced with extractIssuanceCertificates/extractRevocationCertificates, which take a LoteProfile instead of LoTEFilterCriteria",
        ReplaceWith("extractIssuanceCertificates(lote, profile)")
    )
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
                .map { cert -> TrustedCertificate(cert, providerName, criteria.expectedServiceType.type) }
        }
    }

    /**
     * Validates that the List and Scheme Information metadata aligns with the expected [LoteProfile].
     */
    private fun checkListAndSchemeInformation(
        listAndSchemeInformation: ListAndSchemeInformation?,
        profile: LoteProfile
    ): Boolean {
        if (listAndSchemeInformation == null) return false

        val matchesLoteType = profile.matchesLoteType(listAndSchemeInformation.loteType?.toString())
        val matchesStatus =
            profile.matchesStatusDeterminationApproach(listAndSchemeInformation.statusDeterminationApproach?.toString())
        val matchesRules = profile.matchesSchemeCommunityRules(
            listAndSchemeInformation.schemeTypeCommunityRules?.map { it.uniformResourceIdentifier }
        )
        val matchesTerritory = profile.matchesSchemeTerritory(listAndSchemeInformation.schemeTerritory)

        return matchesLoteType && matchesStatus && matchesRules && matchesTerritory
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
    val serviceType: String
)

sealed class LoteProfile(
    val fetchUrl: String,
    val loteType: String,
    val statusDeterminationApproach: String,
    val schemeCommunityRules: List<Rfc3986UniformResourceIdentifier>,
    val serviceTypeIdentifierIssuance: String,
    val serviceTypeIdentifierRevocation: String,
    val schemeCountryCode: EtsiCountryCode = EtsiCountryCode("EU")
) {

    fun matchesLoteType(loteTypeUri: String?): Boolean {
        if (loteTypeUri.isNullOrBlank()) return false
        return loteTypeUri.equals(loteType, ignoreCase = true)
    }

    fun matchesStatusDeterminationApproach(approachUri: String?): Boolean {
        if (approachUri.isNullOrBlank()) return false
        return approachUri.equals(statusDeterminationApproach, ignoreCase = true)
    }

    fun matchesSchemeCommunityRules(rulesUri: List<Rfc3986UniformResourceIdentifier>?): Boolean {
        if (rulesUri.isNullOrEmpty()) return false
        if (rulesUri.size != schemeCommunityRules.size) return false
        return rulesUri.toSet() == schemeCommunityRules.toSet()
    }

    fun matchesServiceTypeIssuance(serviceTypeUri: String?): Boolean {
        if (serviceTypeUri.isNullOrBlank()) return false
        return serviceTypeUri.equals(serviceTypeIdentifierIssuance, ignoreCase = true)
    }

    fun matchesServiceTypeRevocation(serviceTypeUri: String?): Boolean {
        if (serviceTypeUri.isNullOrBlank()) return false
        return serviceTypeUri.equals(serviceTypeIdentifierRevocation, ignoreCase = true)
    }

    fun matchesSchemeTerritory(countryCode: EtsiCountryCode?): Boolean {
        if (countryCode == null) return false
        return countryCode.string.equals(schemeCountryCode.string, ignoreCase = true)
    }

    data object PID : LoteProfile(
        fetchUrl = EU_PID_PROVIDERS_FETCH_URL,
        loteType = EU_PID_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_PID_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier(EU_PID_PROVIDERS_SCHEME_COMMUNITY_RULES)),
        serviceTypeIdentifierIssuance = EU_PID_PROVIDERS_SVC_TYPE_ISSUANCE,
        serviceTypeIdentifierRevocation = EU_PID_PROVIDERS_SVC_TYPE_REVOCATION
    )

    data object mDL : LoteProfile(
        fetchUrl = EU_mDL_PROVIDERS_FETCH_URL,
        loteType = EU_mDL_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_mDL_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier(EU_mDL_PROVIDERS_SCHEME_COMMUNITY_RULES)),
        serviceTypeIdentifierIssuance = EU_mDL_PROVIDERS_SVC_TYPE_ISSUANCE,
        serviceTypeIdentifierRevocation = EU_mDL_PROVIDERS_SVC_TYPE_REVOCATION
    )

    data object WRPAC : LoteProfile(
        fetchUrl = EU_WRPAC_PROVIDERS_FETCH_URL,
        loteType = EU_WRPAC_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_WRPAC_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier(EU_WRPAC_PROVIDERS_SCHEME_COMMUNITY_RULES)),
        serviceTypeIdentifierIssuance = EU_WRPAC_PROVIDERS_SVC_TYPE_ISSUANCE,
        serviceTypeIdentifierRevocation = EU_WRPAC_PROVIDERS_SVC_TYPE_REVOCATION
    )

    data object WALLET : LoteProfile(
        fetchUrl = EU_WALLET_PROVIDERS_FETCH_URL,
        loteType = EU_WALLET_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_WALLET_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier(EU_WALLET_PROVIDERS_SCHEME_COMMUNITY_RULES)),
        serviceTypeIdentifierIssuance = EU_WALLET_PROVIDERS_SVC_TYPE_ISSUANCE,
        serviceTypeIdentifierRevocation = EU_WALLET_PROVIDERS_SVC_TYPE_REVOCATION
    )

    data object EAA : LoteProfile(
        fetchUrl = EU_PUB_EAA_PROVIDERS_FETCH_URL,
        loteType = EU_PUB_EAA_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_PUB_EAA_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier(EU_PUB_EAA_PROVIDERS_SCHEME_COMMUNITY_RULES)),
        serviceTypeIdentifierIssuance = EU_PUB_EAA_PROVIDERS_SVC_TYPE_ISSUANCE,
        serviceTypeIdentifierRevocation = EU_PUB_EAA_PROVIDERS_SVC_TYPE_REVOCATION
    )

    companion object {

        val defaultUrls: List<String> by lazy {
            listOf(PID, mDL, WRPAC, WALLET, EAA).map { it.fetchUrl }
        }

        fun fromSchemeIdentifier(identifier: String?): LoteProfile {
            if (identifier.isNullOrBlank()) return EAA

            return when {
                identifier.contains("pid", ignoreCase = true) -> PID
                identifier.contains("mdl", ignoreCase = true) -> mDL
                else -> EAA
            }
        }
    }
}

@Deprecated("Replaced by LoteProfile")
data class LoTEFilterCriteria(
    val expectedServiceType: LoTEServiceType,
)

@Deprecated("Replaced by LoteProfile")
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