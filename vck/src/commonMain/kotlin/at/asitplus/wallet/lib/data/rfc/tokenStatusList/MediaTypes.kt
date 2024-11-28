package at.asitplus.wallet.lib.data.rfc.tokenStatusList

/**
 * "application/statuslist+json" for Status List in JSON format
 *
 * "application/statuslist+jwt" for Status List in JWT format
 *
 * "application/statuslist+cbor" for Status List in CBOR format
 *
 * "application/statuslist+cwt" for Status List in CWT format
 */
data object MediaTypes {
    data object Application {
        const val STATUSLIST_JSON = "application/statuslist+json"
        const val STATUSLIST_JWT = "application/statuslist+jwt"
        const val STATUSLIST_CBOR = "application/statuslist+cbor"
        const val STATUSLIST_CWT = "application/statuslist+cwt"
    }
}