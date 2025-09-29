package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidvci.MapStore

/** Use only for testing! */
class FixedMapStore(var value: AuthenticationRequestParameters?) : MapStore<String, AuthenticationRequestParameters> {

    override suspend fun put(key: String, value: AuthenticationRequestParameters) {
        this.value = value
    }

    override suspend fun get(key: String): AuthenticationRequestParameters? = value

    override suspend fun remove(key: String): AuthenticationRequestParameters? = value.also { value = null }
}