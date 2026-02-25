package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaTypes

data object MediaTypes {
    /** `statuslist+jwt` */
    const val STATUSLIST_JWT = MediaTypes.STATUSLIST_JWT

    data object Application {
        /** `application/oauth-authz-req+jwt` */
        const val AUTHZ_REQ_JWT = "application/oauth-authz-req+jwt"

        /** `application/statuslist+jwt` */
        const val STATUSLIST_JWT = MediaTypes.Application.STATUSLIST_JWT

        /** `application/statuslist+cwt` */
        const val STATUSLIST_CWT = MediaTypes.Application.STATUSLIST_CWT

        @Suppress("DEPRECATION")
        @Deprecated(
            message = "Unsigned status list media types were removed from the OAuth Status List specification.",
            level = DeprecationLevel.WARNING,
        )
        const val STATUSLIST_JSON = MediaTypes.Application.STATUSLIST_JSON

        @Suppress("DEPRECATION")
        @Deprecated(
            message = "Unsigned status list media types were removed from the OAuth Status List specification.",
            level = DeprecationLevel.WARNING,
        )
        const val STATUSLIST_CBOR = MediaTypes.Application.STATUSLIST_CBOR

        /** `application/identifierlist+cwt` */
        const val IDENTIFIERLIST_CWT = MediaTypes.Application.IDENTIFIERLIST_CWT

        /** `application/json` */
        const val JSON = "application/json"

        /** `application/jwt` */
        const val JWT = "application/jwt"
    }
}
