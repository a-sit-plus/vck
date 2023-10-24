package at.asitplus.wallet.lib.data

object ConstantIndex {

    enum class CredentialFormat {
        ISO_18013,
        W3C_VC
    }

    enum class CredentialRepresentation {
        PLAIN_JWT,
        SD_JWT,
        // TODO ISO_MDOC,
    }

    interface CredentialScheme {
        /**
         * Schema URL of the credential, used in protocols to map
         * from the requested schema to the internal attribute type used in [at.asitplus.wallet.lib.agent.Issuer]
         * when issuing credentials.
         */
        val schemaUri: String

        /**
         * Name of the subclass of [CredentialSubject] and thus the `type` of the credential.
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
         * Form of the credential, either according to ISO 18013 (mobile driving licence) or W3C VC Data Model.
         */
        val credentialFormat: CredentialFormat

    }

    object AtomicAttribute2023 : CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/AtomicAttribute2023.json"
        override val vcType: String = "AtomicAttribute2023"
        override val credentialFormat: CredentialFormat = CredentialFormat.W3C_VC
        override val isoNamespace: String = "at.a-sit.wallet.atomic-attribute-2023"
        override val isoDocType: String = "at.a-sit.wallet.atomic-attribute-2023.iso"
    }

    object MobileDrivingLicence2023 : CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/MobileDrivingLicence2023.json"
        override val vcType: String = "MobileDrivingLicence"
        override val credentialFormat: CredentialFormat = CredentialFormat.ISO_18013
        override val isoNamespace: String = "org.iso.18013.5.1"
        override val isoDocType: String = "org.iso.18013.5.1.mDL"
    }

}
