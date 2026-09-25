package at.asitplus.wallet.lib.etsi

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

    /** The [LoteProfile] whose List and Scheme Information matches [lote] */
    fun profileOf(lote: ListOfTrustedEntities): LoteProfile? =
        LoteProfile.entries.firstOrNull { checkListAndSchemeInformation(lote.listAndSchemeInformation, it) }

    /**
     * Extracts issuance certificates of [lote], for the profile detected from its own metadata.
     * For callers that have already selected the lists, e.g. per credential type
     */
    fun extractIssuanceCertificates(lote: ListOfTrustedEntities): List<TrustedCertificate> =
        profileOf(lote)?.let { extractIssuanceCertificates(lote, it) }.orEmpty()

    /**
     * Extracts revocation certificates of [lote], for the profile detected from its own metadata.
     * Used for status list signers, where the lists have already been selected by the caller.
     */
    fun extractRevocationCertificates(lote: ListOfTrustedEntities): List<TrustedCertificate> =
        profileOf(lote)?.let { extractRevocationCertificates(lote, it) }.orEmpty()

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
                .map { cert -> TrustedCertificate(cert, providerName, LoTEServiceType.fromSchemeIdentifier(targetServiceType), targetServiceType) }
        }
    }

    @Deprecated("Replaced with extractIssuanceCertificates/extractRevocationCertificates, which take a LoteProfile instead of LoTEFilterCriteria")
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

/** `serviceType` property should be removed in future */
data class TrustedCertificate(
    val certificate: @Serializable(with = EtsiX509CertificateSerializer::class) X509Certificate?,
    val providerName: TEName,
    @Deprecated(
        "Kept only for compatibility. Use serviceTypeIdentifier instead",
        ReplaceWith("serviceTypeIdentifier")
    )
    val serviceType: LoTEServiceType,
    val serviceTypeIdentifier: String = serviceType.type
)

/**
 * Deployment stage of the European Commission's trust infrastructure, serving the Lists of Trusted
 * Entities. Every stage publishes the same set of [LoteProfile] lists below its own [baseUrl].
 */
enum class LoTEStage(val baseUrl: String) {
    DEVELOPMENT("https://development.trust.tech.ec.europa.eu/lists/eudiw"),
    ACCEPTANCE("https://acceptance.trust.tech.ec.europa.eu/lists/eudiw"),
    PRODUCTION("https://trust.tech.ec.europa.eu/lists/eudiw");

    /** URL to fetch the list of [profile] from, as published on this stage. */
    fun fetchUrl(profile: LoteProfile): String = profile.fetchUrl(baseUrl)

    /** URLs of all lists published on this stage. */
    val fetchUrls: List<String> get() = LoteProfile.fetchUrls(baseUrl)
}

sealed class LoteProfile(
    /** Name of the file this list is published as, relative to the base URL of a [LoTEStage]. */
    val fileName: String,
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

    open fun matchesServiceTypeIssuance(serviceTypeUri: String?): Boolean {
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

    /** URL to fetch this list from, below [baseUrl], e.g. [LoTEStage.baseUrl]. */
    fun fetchUrl(baseUrl: String): String = "${baseUrl.trimEnd('/')}/$fileName"

    /** URL to fetch this list from, as published on [stage]. */
    fun fetchUrl(stage: LoTEStage): String = fetchUrl(stage.baseUrl)

    data object PID : LoteProfile(
        fileName = "pid-providers.json",
        loteType = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
        statusDeterminationApproach = "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU",
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier("http://uri.etsi.org/19602/PIDProviders/schemerules/EU")),
        serviceTypeIdentifierIssuance = "http://uri.etsi.org/19602/SvcType/PID/Issuance",
        serviceTypeIdentifierRevocation = "http://uri.etsi.org/19602/SvcType/PID/Revocation"
    )

    data object mDL : LoteProfile(
        fileName = "mdl-providers.json",
        loteType = "http://trust.ec.europa.eu/lists/mDL/mDLProvidersListType",
        statusDeterminationApproach = "http://trust.ec.europa.eu/lists/mDL/mDLProvidersListStatusDetn",
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier("http://trust.ec.europa.eu/lists/mDL/schemerules")),
        serviceTypeIdentifierIssuance = "http://trust.ec.europa.eu/lists/mDL/SvcType/Issuance",
        serviceTypeIdentifierRevocation = "http://trust.ec.europa.eu/lists/mDL/SvcType/Revocation"
    ) {
        // Not in the spec (https://eidas.ec.europa.eu/efda/wallet/lists-of-trusted-entities/mdl-providers), but present in DIGIT's LOTE.
        private val legacyIssuanceIdentifier = "http://uri.etsi.org/19602/SvcType/mDL/Issuance"

        override fun matchesServiceTypeIssuance(serviceTypeUri: String?) =
            serviceTypeUri.equals(serviceTypeIdentifierIssuance, ignoreCase = true) ||
                    serviceTypeUri.equals(legacyIssuanceIdentifier, ignoreCase = true)
    }

    data object WRPAC : LoteProfile(
        fileName = "wrpac-providers.json",
        loteType = "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList",
        statusDeterminationApproach = "http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU",
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier("http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU")),
        serviceTypeIdentifierIssuance = "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
        serviceTypeIdentifierRevocation = "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation"
    )

    data object WALLET : LoteProfile(
        fileName = "wallet-providers.json",
        loteType = "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList",
        statusDeterminationApproach = "http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU",
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier("http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU")),
        serviceTypeIdentifierIssuance = "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance",
        serviceTypeIdentifierRevocation = "http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation"
    )

    data object EAA : LoteProfile(
        fileName = "pub-eaa-providers.json",
        loteType = "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList",
        statusDeterminationApproach = "http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU",
        schemeCommunityRules = listOf(Rfc3986UniformResourceIdentifier("http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU")),
        serviceTypeIdentifierIssuance = "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
        serviceTypeIdentifierRevocation = "http://uri.etsi.org/19602/SvcType/PubEAA/Revocation"
    )

    companion object {
        private val PID_IDENTIFIER_PREFIXES = listOf("urn:eudi:pid:", "eu.europa.ec.eudi.pid.")
        private val MDL_IDENTIFIER_PREFIXES = listOf("org.iso.18013.5.1.mDL")

        /** All known profiles, i.e. all lists published per [LoTEStage]. */
        val entries: List<LoteProfile> by lazy {
            listOf(PID, mDL, WRPAC, WALLET, EAA)
        }

        /** URLs of all lists published below [baseUrl]. */
        fun fetchUrls(baseUrl: String): List<String> = entries.map { it.fetchUrl(baseUrl) }

        /** URLs of all lists published on [stages], in the order the stages are passed. */
        fun fetchUrls(stages: Iterable<LoTEStage>): List<String> =
            stages.flatMap { stage -> fetchUrls(stage.baseUrl) }

        /** URLs of all lists published on [stages], in the order the stages are passed. */
        fun fetchUrls(vararg stages: LoTEStage): List<String> = fetchUrls(stages.asIterable())

        fun fromSchemeIdentifier(identifier: String?): LoteProfile {
            if (identifier.isNullOrBlank()) return EAA

            return when {
                PID_IDENTIFIER_PREFIXES.any { identifier.startsWith(it, ignoreCase = true) } -> PID
                MDL_IDENTIFIER_PREFIXES.any { identifier.startsWith(it, ignoreCase = true) } -> mDL
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