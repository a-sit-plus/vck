@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package at.asitplus.wallet.ios

import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.internals.corecall
import at.asitplus.signum.internals.createCFDictionary
import at.asitplus.signum.internals.manage
import at.asitplus.signum.supreme.sign.makeVerifier
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.cinterop.memScoped
import platform.Security.SecKeyCreateRandomKey
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeEC

val SecKeySignerTest by matrixSuite {

    test("signs with transient SecKey") {
        // Command-line iOS tests lack Keychain entitlements; the app tests permanent storage.
        val privateKey = memScoped {
            corecall {
                SecKeyCreateRandomKey(createCFDictionary {
                    kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                    kSecAttrKeySizeInBits mapsTo 256
                }, error)
            }.manage()
        }
        val signer = SignerAdapter.fromSecKey(privateKey.value, SignatureAlgorithm.ECDSAwithSHA256).getOrThrow()
        val message = "SecKey-backed Signum signer".encodeToByteArray()

        val signature = signer.sign(message).signature

        signer.makeVerifier().getOrThrow().verify(message, signature).isSuccess shouldBe true
    }
}
