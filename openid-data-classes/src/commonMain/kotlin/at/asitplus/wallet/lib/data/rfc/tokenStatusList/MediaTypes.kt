package at.asitplus.wallet.lib.data.rfc.tokenStatusList

data object MediaTypes {
    /** `statuslist+jwt` */
    const val STATUSLIST_JWT = "statuslist+jwt"

    data object Application {
        /** `application/statuslist+jwt` */
        const val STATUSLIST_JWT = "application/statuslist+jwt"

        /** `application/statuslist+cwt` */
        const val STATUSLIST_CWT = "application/statuslist+cwt"

        /** `application/identifierlist+cwt` */
        const val IDENTIFIERLIST_CWT = "application/identifierlist+cwt"

    }
}
