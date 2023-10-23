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
     * May return an empty list, if the Schema is not known
     */
    fun resolveSchemaUri(uri: String): ConstantIndex.CredentialScheme? {
        return schemeSet.firstOrNull { it.schemaUri == uri }
    }

}