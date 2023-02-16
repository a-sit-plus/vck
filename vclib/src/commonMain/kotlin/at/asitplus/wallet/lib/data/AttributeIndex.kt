package at.asitplus.wallet.lib.data

object AttributeIndex {

    private val schemeSet = mutableSetOf<ConstantIndex.CredentialScheme>()

    internal fun registerAttributeType(scheme: ConstantIndex.CredentialScheme) {
        schemeSet += scheme
    }

    /**
     * May return an empty list, if the Schema is not known,
     * or it does not issue atomic credentials (see [getTypeOfAttributeForSchemaUri])
     */
    fun getListOfAttributesForSchemaUri(uri: String) = when (uri) {
        SchemaIndex.CRED_GENERIC -> genericAttributes
        else -> listOf()
    }

    /**
     * May return an empty list, if the Schema is not known
     */
    fun getTypeOfAttributeForSchemaUri(uri: String): String? {
        return schemeSet.firstOrNull { it.schemaUri == uri }?.vcType
    }

    /**
     * List of all known attributes for a "generic" credential
     */
    val genericAttributes = listOf(
        "given-name",
        "family-name",
        "date-of-birth",
        "identifier",
        "picture",
    ).map { "${SchemaIndex.ATTR_GENERIC_PREFIX}/$it" }

}