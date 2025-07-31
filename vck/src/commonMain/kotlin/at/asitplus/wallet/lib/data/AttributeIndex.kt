package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme

object AttributeIndex {

    var schemeSet = setOf<CredentialScheme>()
        private set

    init {
        schemeSet += ConstantIndex.AtomicAttribute2023
    }

    internal fun registerAttributeType(scheme: CredentialScheme) {
        schemeSet += scheme
    }

    /**
     * Matches the passed [uri] against all known schemes from [ConstantIndex.CredentialScheme.schemaUri].
     */
    fun resolveSchemaUri(uri: String): CredentialScheme? =
        schemeSet.firstOrNull { it.schemaUri == uri }

    /**
     * Matches the passed [type] against all known types from [ConstantIndex.CredentialScheme.vcType].
     */
    fun resolveAttributeType(type: String): CredentialScheme? =
        schemeSet.firstOrNull { it.vcType == type }

    /**
     * Matches the passed [sdJwtType] against all known types from [ConstantIndex.CredentialScheme.sdJwtType].
     */
    fun resolveSdJwtAttributeType(sdJwtType: String): CredentialScheme? =
        schemeSet.firstOrNull { it.sdJwtType == sdJwtType }

    /**
     * Matches the passed [namespace] against all known namespace from [ConstantIndex.CredentialScheme.isoNamespace].
     *
     * Allows for extension to the namespace by appending ".countryname" or anything else, according to spec.
     */
    fun resolveIsoNamespace(namespace: String): CredentialScheme? =
        schemeSet.filter { it.isoNamespace != null }
            .firstOrNull { it.isoNamespace!!.startsWith(namespace) || namespace.startsWith(it.isoNamespace!!) }

    /**
     * Matches the passed [docType] against all known docTypes from [ConstantIndex.CredentialScheme.isoDocType].
     *
     * Allows for extension to the namespace by appending ".countryname" or anything else, according to spec.
     */
    fun resolveIsoDoctype(docType: String): CredentialScheme? =
        schemeSet.filter { it.isoDocType != null }
            .firstOrNull { it.isoDocType!!.startsWith(docType) || docType.startsWith(it.isoDocType!!) }

}