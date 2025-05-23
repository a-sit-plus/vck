@file:OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.cinterop.ExperimentalForeignApi
import kotlin.experimental.ExperimentalNativeApi


/**
 * Default implementation of a crypto service for iOS.
 *
 * The primary goal is to provide a minimal implementation so that unit tests in the `commonTest` module run successfully.
 *
 * Beware: It does **not** implement encryption, decryption, key agreement and message digest correctly.
 */
@Suppress("UNCHECKED_CAST")
actual open class PlatformCryptoShim {

    actual open fun encrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<AuthenticatedCiphertext> {
        return KmmResult.success(
            AuthenticatedCiphertext(
                input.reversedArray(),
                "authtag-${key.encodeToString(Base64Strict)}".encodeToByteArray()
            )
        )
    }

    actual open suspend fun decrypt(
        key: ByteArray,
        iv: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        authTag: ByteArray,
        algorithm: JweEncryption
    ): KmmResult<ByteArray> {
        return if (authTag.contentEquals("authtag-${key.encodeToString(Base64Strict)}".encodeToByteArray()))
            KmmResult.success(input.reversedArray())
        else
            KmmResult.failure(IllegalArgumentException())
    }

    actual open fun hmac(key: ByteArray, algorithm: JweEncryption, input: ByteArray): KmmResult<ByteArray> {
        return KmmResult.success("hmac".encodeToByteArray() + key)
    }

}
