package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.MediaTypes.Application.INTROSPECTION_JWT
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaTypes
import io.ktor.http.ContentType

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

        /** `application/identifierlist+cwt` */
        const val IDENTIFIERLIST_CWT = MediaTypes.Application.IDENTIFIERLIST_CWT

        /** `application/json` */
        const val JSON = "application/json"

        /** `application/jwt` */
        const val JWT = "application/jwt"

        /** `application/token-introspection+jwt` */
        const val INTROSPECTION_JWT = "application/token-introspection+jwt"
    }
}

/**
 * KTOR integration: Receiver parameter for namespace
 * See [MediaTypes.Application.INTROSPECTION_JWT]
 */
@Suppress("UnusedReceiverParameter")
val ContentType.Application.IntrospectionJwt: ContentType
    get() = ContentType.parse(INTROSPECTION_JWT)