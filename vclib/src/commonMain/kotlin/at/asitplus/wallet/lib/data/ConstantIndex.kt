package at.asitplus.wallet.lib.data

object ConstantIndex {

    enum class CredentialFormat {
        ISO_18013,
        W3C_VC
    }

    enum class CredentialRepresentation {
        PLAIN_JWT,
        SD_JWT,
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
         * Form of the credential, either according to ISO 18013 (mobile driving licence) or W3C VC Data Model.
         */
        val credentialFormat: CredentialFormat

    }

    object AtomicAttribute2023 : CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/AtomicAttribute2023.json"
        override val vcType: String = "AtomicAttribute2023"
        override val credentialFormat: CredentialFormat = CredentialFormat.W3C_VC
    }

    object MobileDrivingLicence2023 : CredentialScheme {
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/MobileDrivingLicence2023.json"
        override val vcType: String = "MobileDrivingLicence"
        override val credentialFormat: CredentialFormat = CredentialFormat.ISO_18013
    }

}
