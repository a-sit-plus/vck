@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.NonceTrait
import at.asitplus.signum.indispensable.symmetric.SealedBox
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt

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
