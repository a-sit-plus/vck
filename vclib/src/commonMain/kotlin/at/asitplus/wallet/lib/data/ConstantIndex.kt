package at.asitplus.wallet.lib.data

object ConstantIndex {

    interface CredentialScheme {
        /**
         * Goal code used in [at.asitplus.wallet.lib.agent.IssueCredentialProtocol].
         */
        val goalCodeIssue: String

        /**
         * Goal code used in [at.asitplus.wallet.lib.agent.PresentProofProtocol].
         */
        val goalCodeRequestProof: String

        /**
         * Name of the credential definition, used in several protocols.
         */
        val credentialDefinitionName: String

        /**
         * Schema URL of the credential, used in [at.asitplus.wallet.lib.agent.IssueCredentialProtocol] to map
         * from the requested schema to the internal attribute type used in [at.asitplus.wallet.lib.agent.Issuer]
         * when issuing credentials.
         */
        val schemaUri: String

        /**
         * Name of the subclass of [CredentialSubject] and thus the `type` of the credential.
         */
        val vcType: String
    }

    object Parser {
        private val mapGoalCodeToScheme = mutableMapOf<String, CredentialScheme>()

        fun parseGoalCode(goalCode: String) = when (goalCode) {
            in listOf(Generic.goalCodeIssue, Generic.goalCodeRequestProof) -> Generic
            in mapGoalCodeToScheme -> mapGoalCodeToScheme[goalCode]
            else -> null
        }

        internal fun registerGoalCode(scheme: CredentialScheme) {
            mapGoalCodeToScheme += scheme.goalCodeIssue to scheme
            mapGoalCodeToScheme += scheme.goalCodeRequestProof to scheme
        }
    }

    object Generic : CredentialScheme {
        override val goalCodeIssue: String = "issue-vc-generic"
        override val goalCodeRequestProof: String = "request-proof-generic"
        override val credentialDefinitionName: String = "generic"
        override val schemaUri: String = SchemaIndex.CRED_GENERIC
        override val vcType: String = "AtomicAttribute"
    }

}
