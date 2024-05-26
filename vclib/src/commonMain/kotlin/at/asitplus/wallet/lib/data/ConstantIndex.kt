package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements

object ConstantIndex {

    enum class CredentialRepresentation {
        PLAIN_JWT,
        SD_JWT,
        ISO_MDOC,
    }

    interface CredentialScheme {
        /**
         * Schema URL of the credential, used in protocols to map
         * from the requested schema to the internal attribute type used in [at.asitplus.wallet.lib.agent.Issuer]
         * when issuing credentials.
         */
        val schemaUri: String

        /**
         * Name of the subclass of [CredentialSubject] and thus the `type` of the credential,
         * when using [CredentialRepresentation.PLAIN_JWT].
         *
         * Is for also used for `vct` when using [CredentialRepresentation.SD_JWT],
         * which will be removed in a future version of this library.
         */
        val vcType: String

        /**
         * Namespace to use for attributes of this credential type.
         *
         * From ISO/IEC 18013-5:
         * There is no requirement for the `NameSpace` format. An approach to avoid collisions is to use the
         * following general format: `[Reverse Domain].[Domain Specific Extension]`.
         */
        val isoNamespace: String

        /**
         * ISO DocType to use for attributes of this credential type.
         *
         * From ISO/IEC 18013-5:
         * There is no requirement for the `DocType` format. An approach to avoid collisions is to use the
         * following general format: `[Reverse Domain].[Domain Specific Extension]`.
         */
        val isoDocType: String

        /**
         * List of claims that may be issued separately when requested in format [CredentialRepresentation.SD_JWT]
         * or [CredentialRepresentation.ISO_MDOC].
         */
        val claimNames: Collection<String>
    }

    object AtomicAttribute2023 : CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/AtomicAttribute2023.json"
        override val vcType: String = "AtomicAttribute2023"
        override val isoNamespace: String = "at.a-sit.wallet.atomic-attribute-2023"
        override val isoDocType: String = "at.a-sit.wallet.atomic-attribute-2023.iso"
        override val claimNames: Collection<String> = listOf()
    }

    object MobileDrivingLicence2023 : CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/MobileDrivingLicence2023.json"
        override val vcType: String = "MobileDrivingLicence"
        override val isoNamespace: String = "org.iso.18013.5.1"
        override val isoDocType: String = "org.iso.18013.5.1.mDL"
        override val claimNames: Collection<String> = MobileDrivingLicenceDataElements.ALL_ELEMENTS.toList()
    }

}
