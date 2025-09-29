package io.kotest.provided.at.asitplus.wallet.lib.openid

import at.asitplus.wallet.lib.oidvci.NonceService

/** Use only for testing! */
class FixedNonceService : NonceService {

    private var nonce: String? = "01999506-7074-7baf-9602-ae175207cad6"

    override suspend fun provideNonce(): String =
        nonce ?: error("No nonce provided")

    override suspend fun verifyNonce(it: String): Boolean =
        (it == nonce)

    override suspend fun verifyAndRemoveNonce(it: String): Boolean =
        (it == nonce).also { this.nonce = null }
}