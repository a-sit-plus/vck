package at.asitplus.wallet.lib.data

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.ClaimDescription
import at.asitplus.openid.DisplayProperties
import at.asitplus.openid.OpenId4VciClaimsPathPointer
import at.asitplus.openid.OpenId4VciClaimsPathPointerSegmentIndex
import at.asitplus.openid.OpenId4VciClaimsPathPointerSegmentString
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadata
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPathSegmentIndex
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPathSegmentName

object ConstantIndex {

    enum class CredentialRepresentation {
        PLAIN_JWT,
        SD_JWT,
        ISO_MDOC,
    }

    /**
     * Implement this interface to provide custom credential definitions to this library.
     */
    interface CredentialScheme {
        /**
         * Schema URL of the credential, used in protocols to map
         * from the requested schema to the internal attribute type used in [at.asitplus.wallet.lib.agent.Issuer]
         * when issuing credentials.
         */
        val schemaUri: String

        /**
         * The `type` of the credential when using [CredentialRepresentation.PLAIN_JWT].
         * Will not be used for other representations.
         * Previously this has been used as the subtype of `CredentialSubject`, but this class has been removed.
         */
        val vcType: String?
            get() = null

        /**
         * Type used for `vct` when using [CredentialRepresentation.SD_JWT].
         */
        val sdJwtType: String?
            get() = null

        /**
         * Namespace to use for attributes of this credential type, when using [CredentialRepresentation.ISO_MDOC].
         *
         * From ISO/IEC 18013-5:
         * There is no requirement for the `NameSpace` format. An approach to avoid collisions is to use the
         * following general format: `[Reverse Domain].[Domain Specific Extension]`.
         */
        val isoNamespace: String?
            get() = null

        /**
         * ISO DocType to use for attributes of this credential type, when using [CredentialRepresentation.ISO_MDOC].
         *
         * From ISO/IEC 18013-5:
         * There is no requirement for the `DocType` format. An approach to avoid collisions is to use the
         * following general format: `[Reverse Domain].[Domain Specific Extension]`.
         */
        val isoDocType: String?
            get() = null

        /**
         * List of claims that may be issued separately when requested in format [CredentialRepresentation.SD_JWT]
         * or [CredentialRepresentation.ISO_MDOC].
         */
        val claimNames: Collection<String>
            get() = listOf()

        val claimDescriptions: Collection<ClaimDescription>
            get() = listOf()

        /**
         * Supported representations for this credential
         */
        val supportedRepresentations: Collection<CredentialRepresentation>
            get() = listOf(
                CredentialRepresentation.PLAIN_JWT,
                CredentialRepresentation.SD_JWT,
                CredentialRepresentation.ISO_MDOC
            )
    }

    object AtomicAttribute2023 : CredentialScheme {
        const val CLAIM_GIVEN_NAME = "given_name"
        const val CLAIM_FAMILY_NAME = "family_name"
        const val CLAIM_DATE_OF_BIRTH = "date_of_birth"
        const val CLAIM_PORTRAIT = "portrait"
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/AtomicAttribute2023.json"
        override val vcType: String = "AtomicAttribute2023"
        override val sdJwtType: String = "AtomicAttribute2023"
        override val isoNamespace: String = "at.a-sit.wallet.atomic-attribute-2023"
        override val isoDocType: String = "at.a-sit.wallet.atomic-attribute-2023.iso"
        override val claimNames: Collection<String> = listOf(
            CLAIM_GIVEN_NAME,
            CLAIM_FAMILY_NAME,
            CLAIM_DATE_OF_BIRTH,
            CLAIM_PORTRAIT
        )
    }

    val CredentialScheme.supportsSdJwt
        get() = supportedRepresentations.contains(CredentialRepresentation.SD_JWT) && sdJwtType != null

    val CredentialScheme.supportsVcJwt
        get() = supportedRepresentations.contains(CredentialRepresentation.PLAIN_JWT) && vcType != null

    val CredentialScheme.supportsIso
        get() = supportedRepresentations.contains(CredentialRepresentation.ISO_MDOC)
                && isoNamespace != null && isoDocType != null

}

// To be replaced in an upcoming PR
fun SdJwtTypeMetadata.toCredentialScheme() = object : ConstantIndex.CredentialScheme {
    override val schemaUri: String
        get() = "https://schema.example.com"

    override val sdJwtType: String
        get() = vct.string

    override val claimDescriptions: Collection<ClaimDescription>
        get() = claims?.map {
            ClaimDescription(
                path = OpenId4VciClaimsPathPointer(it.path.map {
                    when (it) {
                        is SdJwtTypeMetadataClaimInformationPathSegmentIndex -> OpenId4VciClaimsPathPointerSegmentIndex(
                            it.ulong.also {
                                if (it > UInt.MAX_VALUE) {
                                    throw UnsupportedOperationException("This implementation only supports claims path pointer indices up to ${UInt.MAX_VALUE}, but got $it")
                                }
                            }.toUInt()
                        )

                        is SdJwtTypeMetadataClaimInformationPathSegmentName -> OpenId4VciClaimsPathPointerSegmentString(
                            it.string
                        )

                        null -> null
                    }
                }.toNonEmptyList()),
                mandatory = it.isMandatory,
                display = it.display?.map {
                    DisplayProperties(
                        locale = it.locale.string,
                        name = it.label,
                        description = it.description,
                    )
                }?.toSet()
            )
        } ?: setOf()

    override val supportedRepresentations: Collection<ConstantIndex.CredentialRepresentation>
        get() = listOf(ConstantIndex.CredentialRepresentation.SD_JWT)
}