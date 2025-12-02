package at.asitplus.wallet.lib.data.rfc.tokenStatusList

/**
 * Marker type for status list content that describe the revocation / suspension state of
 * credentials.
 *
 * Two transport formats are supported:
 * - [StatusList] for the IETF OAuth Status List draft (compressed bitset, referenced from JOSE/COSE).
 * - [IdentifierList] for ISO 18013-5 mobile document revocation (identifier list with optional
 *   certificate anchor).
 */
sealed class RevocationList {

    /**
     * `kind` lets runtime components (issuers, resolvers, validators) pick the correct
     * serialization and validation pipeline without relying on generics, which are awkward to use across
     * KMP interfaces.
     */
    enum class Kind{
        /** OAuth Status List (draft-ietf-oauth-status-list) bitset-based representation. */
        STATUS_LIST,
        /** ISO 18013-5 IdentifierList representation. */
        IDENTIFIER_LIST
    }
}
