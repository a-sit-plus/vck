@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.mac.mac
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.verifierFor
import kotlin.jvm.JvmOverloads

fun interface VerifySignatureFun {
    suspend operator fun invoke(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: SignatureAlgorithm,
        publicKey: CryptoPublicKey,
    ): KmmResult<SignatureVerifier.Success>
}

class VerifySignature : VerifySignatureFun {
    override suspend operator fun invoke(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: SignatureAlgorithm,
        publicKey: CryptoPublicKey
    ): KmmResult<SignatureVerifier.Success> = catching {
        algorithm.verifierFor(publicKey).verify(SignatureInput(input), signature)
    }
}

class InvalidMacException @JvmOverloads constructor(
    message: String,
    cause: Throwable? = null,
) : Throwable(message, cause)

fun interface VerifyMacFun {
    data object Success

    suspend operator fun invoke(
        input: ByteArray,
        tag: ByteArray,
        algorithm: MessageAuthenticationCode,
        key: ByteArray
    ): KmmResult<Success>
}

class VerifyMac() : VerifyMacFun {
    override suspend fun invoke(
        input: ByteArray,
        tag: ByteArray,
        algorithm: MessageAuthenticationCode,
        key: ByteArray
    ): KmmResult<VerifyMacFun.Success> = catching {
        val realTag = algorithm.mac(key, input)
        if (realTag.contentEquals(tag))
            VerifyMacFun.Success
        else
            throw InvalidMacException("Mac is invalid.")
    }

}
