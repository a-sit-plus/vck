package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaTypes

data object MediaTypes {
    const val AUTHZ_REQ_JWT = "application/oauth-authz-req+jwt";
    const val STATUSLIST_JWT = MediaTypes.STATUSLIST_JWT
    data object Application {
        const val STATUSLIST_JWT = MediaTypes.Application.STATUSLIST_JWT
        const val STATUSLIST_JSON = MediaTypes.Application.STATUSLIST_JSON
        const val STATUSLIST_CWT = MediaTypes.Application.STATUSLIST_CWT
        const val STATUSLIST_CBOR = MediaTypes.Application.STATUSLIST_CBOR
    }
}