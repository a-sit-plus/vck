package at.asitplus.wallet.lib.data

object AttributeIndex {

    var schemeSet = setOf<ConstantIndex.CredentialScheme>()
        private set

    init {
        schemeSet += ConstantIndex.AtomicAttribute2023
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

    /**
     * Matches the passed [sdJwtType] against all known types from [ConstantIndex.CredentialScheme.sdJwtType]
     */
    fun resolveSdJwtAttributeType(sdJwtType: String): ConstantIndex.CredentialScheme? {
        return schemeSet.firstOrNull { it.sdJwtType == sdJwtType }
    }

    /**
     * Matches the passed [namespace] against all known namespace from [ConstantIndex.CredentialScheme.isoNamespace]
     */
    fun resolveIsoNamespace(namespace: String): ConstantIndex.CredentialScheme? {
        // allow for extension to the namespace by appending ".countryname" or anything else, according to spec
        return schemeSet.filter { it.isoNamespace != null }
            .firstOrNull { it.isoNamespace!!.startsWith(namespace) || namespace.startsWith(it.isoNamespace!!) }
    }

    /**
     * Matches the passed [docType] against all known docTypes from [ConstantIndex.CredentialScheme.isoDocType]
     */
    fun resolveIsoDoctype(docType: String): ConstantIndex.CredentialScheme? {
        // allow for extension to the namespace by appending ".countryname" or anything else, according to spec
        return schemeSet.filter { it.isoDocType != null }
            .firstOrNull { it.isoDocType!!.startsWith(docType) || docType.startsWith(it.isoDocType!!) }
    }

    /**
     * Compares the input to all CredentialScheme identifiers and on match returns it plus its associated `ConstantIndex.CredentialRepresentation` if applicable
     */
    fun resolveCredential(input: String): Pair<ConstantIndex.CredentialScheme, ConstantIndex.CredentialRepresentation?>? {
        return resolveAttributeType(input)?.let { it to ConstantIndex.CredentialRepresentation.PLAIN_JWT}
            ?: resolveSdJwtAttributeType(input)?.let { it to ConstantIndex.CredentialRepresentation.SD_JWT}
            ?: resolveIsoNamespace(input)?.let { it to ConstantIndex.CredentialRepresentation.ISO_MDOC}
            ?: resolveIsoDoctype(input)?.let { it to ConstantIndex.CredentialRepresentation.ISO_MDOC}
            ?: resolveSchemaUri(input)?.let { it to null}
    }
}