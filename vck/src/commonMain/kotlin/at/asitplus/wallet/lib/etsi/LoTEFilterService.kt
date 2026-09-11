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
import at.asitplus.etsi.EtsiX509CertificateSerializer
import at.asitplus.etsi.ListAndSchemeInformation
import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.etsi.TEName
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
    /**
     * Validates that the List and Scheme Information metadata aligns with the expected [LoteProfile].
     */
    private fun checkListAndSchemeInformation(
        listAndSchemeInformation: ListAndSchemeInformation?,
        profile: LoteProfile
    ): Boolean {
        if (listAndSchemeInformation == null) return false

        val matchesLoteType = profile.matchesLoteType(listAndSchemeInformation.loteType?.toString())
        val matchesStatus = profile.matchesStatusDeterminationApproach(listAndSchemeInformation.statusDeterminationApproach?.toString())
        val matchesRules = listAndSchemeInformation.schemeTypeCommunityRules?.any { rule ->
            profile.matchesSchemeCommunityRules(rule.uniformResourceIdentifier.toString())
        } ?: false

        return matchesLoteType && matchesStatus && matchesRules
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
    val schemeCommunityRules: String,
    val serviceTypeIdentifierIssuance: String,
    val serviceTypeIdentifierRevocation: String,
) {

    fun matchesLoteType(loteTypeUri: String?): Boolean {
        if (loteTypeUri.isNullOrBlank()) return false
        return loteTypeUri.equals(loteType, ignoreCase = true)
    }

    fun matchesStatusDeterminationApproach(approachUri: String?): Boolean {
        if (approachUri.isNullOrBlank()) return false
        return approachUri.equals(statusDeterminationApproach, ignoreCase = true)
    }

    fun matchesSchemeCommunityRules(rulesUri: String?): Boolean {
        if (rulesUri.isNullOrBlank()) return false
        return rulesUri.equals(schemeCommunityRules, ignoreCase = true)
    }

    fun matchesServiceTypeIssuance(serviceTypeUri: String?): Boolean {
        if (serviceTypeUri.isNullOrBlank()) return false
        return serviceTypeUri.equals(serviceTypeIdentifierIssuance, ignoreCase = true)
    }

    fun matchesServiceTypeRevocation(serviceTypeUri: String?): Boolean {
        if (serviceTypeUri.isNullOrBlank()) return false
        return serviceTypeUri.equals(serviceTypeIdentifierRevocation, ignoreCase = true)
    }

    data object PID : LoteProfile(
        fetchUrl = EU_PID_PROVIDERS_FETCH_URL,
        loteType = EU_PID_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_PID_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = EU_PID_PROVIDERS_SCHEME_COMMUNITY_RULES,
        serviceTypeIdentifierIssuance = EU_PID_PROVIDERS_SVC_TYPE_ISSUANCE,
        serviceTypeIdentifierRevocation = EU_PID_PROVIDERS_SVC_TYPE_REVOCATION
    )

    data object mDL : LoteProfile(
        fetchUrl = EU_mDL_PROVIDERS_FETCH_URL,
        loteType = EU_mDL_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_mDL_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = EU_mDL_PROVIDERS_SCHEME_COMMUNITY_RULES,
        serviceTypeIdentifierIssuance = EU_mDL_PROVIDERS_SVC_TYPE_ISSUANCE,
        serviceTypeIdentifierRevocation = EU_mDL_PROVIDERS_SVC_TYPE_REVOCATION
    )

    data object WRPAC : LoteProfile(
        fetchUrl = EU_WRPAC_PROVIDERS_FETCH_URL,
        loteType = EU_WRPAC_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_WRPAC_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = EU_WRPAC_PROVIDERS_SCHEME_COMMUNITY_RULES,
        serviceTypeIdentifierIssuance = EU_WRPAC_PROVIDERS_SVC_TYPE_ISSUANCE,
        serviceTypeIdentifierRevocation = EU_WRPAC_PROVIDERS_SVC_TYPE_REVOCATION
    )

    data object WALLET : LoteProfile(
        fetchUrl = EU_WALLET_PROVIDERS_FETCH_URL,
        loteType = EU_WALLET_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_WALLET_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = EU_WALLET_PROVIDERS_SCHEME_COMMUNITY_RULES,
        serviceTypeIdentifierIssuance = EU_WALLET_PROVIDERS_SVC_TYPE_ISSUANCE,
        serviceTypeIdentifierRevocation = EU_WALLET_PROVIDERS_SVC_TYPE_REVOCATION
    )

    data object EAA : LoteProfile(
        fetchUrl = EU_PUB_EAA_PROVIDERS_FETCH_URL,
        loteType = EU_PUB_EAA_PROVIDERS_SCHEME_TYPE,
        statusDeterminationApproach = EU_PUB_EAA_PROVIDERS_STATUS_DETERMINATION_APPROACH,
        schemeCommunityRules = EU_PUB_EAA_PROVIDERS_SCHEME_COMMUNITY_RULES,
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