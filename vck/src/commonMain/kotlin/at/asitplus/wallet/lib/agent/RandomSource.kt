package at.asitplus.wallet.lib.agent

import org.kotlincrypto.random.CryptoRand

sealed class RandomSource {
    abstract fun nextBytes(size: Int): ByteArray

    object Secure : RandomSource() {
        override fun nextBytes(size: Int) =
            with(ByteArray(size)) { CryptoRand.nextBytes(this) }
    }

    object Default : RandomSource() {
        override fun nextBytes(size: Int) =
            kotlin.random.Random.nextBytes(size)
    }
}
