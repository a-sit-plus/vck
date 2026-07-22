package at.asitplus.wallet.lib.data

/**
 * Fallback for any credential identifier that we don't recognize but still need to parse.
 * May not be the ideal solution, but this prevents a lot of nullable return types and should make life for apps easier.
 */
data class UnknownCredentialScheme(val representation: CredentialRepresentation) : CredentialScheme {
    @Deprecated("Use other identifiers instead, e.g. `vcType` or `sdJwtType` or `isoDocType`")
    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown.json"
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(representation)
}