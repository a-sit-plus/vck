package at.asitplus.wallet.lib.data

object AttributeIndex {

    private val schemeSet = mutableSetOf<ConstantIndex.CredentialScheme>()

    init {
        schemeSet += ConstantIndex.AtomicAttribute2023
        schemeSet += ConstantIndex.MobileDrivingLicence2023
    }

    internal fun registerAttributeType(scheme: ConstantIndex.CredentialScheme) {
        schemeSet += scheme
    }

    /**
     * Matches the passed [uri] against all known schemes from [ConstantIndex.CredentialScheme.schemaUri]
     */
    fun resolveSchemaUri(uri: String): ConstantIndex.CredentialScheme? {
        return schemeSet.firstOrNull { it.schemaUri == uri }
    }

    /**
     * Matches the passed [type] against all known types from [ConstantIndex.CredentialScheme.vcType]
     */
    fun resolveAttributeType(type: String): ConstantIndex.CredentialScheme? {
        return schemeSet.firstOrNull { it.vcType == type }
    }

}