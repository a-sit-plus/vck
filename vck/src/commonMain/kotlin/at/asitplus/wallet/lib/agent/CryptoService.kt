@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.signum.supreme.sign.verifierFor

typealias VerifySignatureFun = (
    input: ByteArray,
    signature: CryptoSignature,
    algorithm: SignatureAlgorithm,
    publicKey: CryptoPublicKey,
) -> KmmResult<Verifier.Success>

object VerifySignature {
    operator fun invoke(): VerifySignatureFun = { input, signature, algorithm, publicKey ->
        algorithm.verifierFor(publicKey).transform {
            it.verify(SignatureInput(input), signature)
        }
    }
}
