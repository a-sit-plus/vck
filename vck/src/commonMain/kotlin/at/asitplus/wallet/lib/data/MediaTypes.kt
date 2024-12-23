package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaTypes as TokenStatusRfcMediaTypes


data object MediaTypes {
    data object Application {
        const val STATUSLIST_JWT = TokenStatusRfcMediaTypes.Application.STATUSLIST_JWT
        const val STATUSLIST_JSON = TokenStatusRfcMediaTypes.Application.STATUSLIST_JSON
        const val STATUSLIST_CWT = TokenStatusRfcMediaTypes.Application.STATUSLIST_CWT
        const val STATUSLIST_CBOR = TokenStatusRfcMediaTypes.Application.STATUSLIST_CBOR
    }
}