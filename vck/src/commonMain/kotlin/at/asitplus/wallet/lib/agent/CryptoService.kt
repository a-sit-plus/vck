@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.MessageAuthenticationCode
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.mac.mac
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.signum.supreme.sign.verifierFor

fun interface VerifySignatureFun {
    suspend operator fun invoke(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: SignatureAlgorithm,
        publicKey: CryptoPublicKey,
    ): KmmResult<Verifier.Success>
}

class VerifySignature() : VerifySignatureFun {
    override suspend operator fun invoke(
        input: ByteArray,
        signature: CryptoSignature,
        algorithm: SignatureAlgorithm,
        publicKey: CryptoPublicKey
    ): KmmResult<Verifier.Success> = algorithm.verifierFor(publicKey).transform {
        it.verify(SignatureInput(input), signature)
    }
}

class InvalidMac(message: String, cause: Throwable? = null): Throwable(message, cause)

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
        val realTag = algorithm.mac(key, input).getOrThrow()
        if (realTag.contentEquals(tag))
            VerifyMacFun.Success
        else
            throw InvalidMac("Mac is invalid.")
    }

}
