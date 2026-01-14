package at.asitplus.wallet.lib.data.rfc.tokenStatusList

data object MediaTypes {
    /** `statuslist+jwt` */
    const val STATUSLIST_JWT = "statuslist+jwt"
    data object Application {
        /** `application/statuslist+json` */
        const val STATUSLIST_JSON = "application/statuslist+json"

        /** `application/statuslist+jwt` */
        const val STATUSLIST_JWT = "application/statuslist+jwt"

        /** `application/statuslist+cbor` */
        const val STATUSLIST_CBOR = "application/statuslist+cbor"

        /** `application/statuslist+cwt` */
        const val STATUSLIST_CWT = "application/statuslist+cwt"

        const val IDENTIFIERLIST_CWT = "application/identifierlist+cwt"
    }
}