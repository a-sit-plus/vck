package at.asitplus.wallet.lib

import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.wallet.lib.agent.KeyStoreMaterial
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyStore
import java.security.Security

class KeyStoreMaterialTest : FreeSpec({

    val ks = KeyStore.getInstance("JKS")
    ks.load(KeyStoreMaterial::class.java.getResourceAsStream("/pw_bar_kpw_foo_alias_foo.jks"), "bar".toCharArray())
    "Without Cert" {
        val material = KeyStoreMaterial(ks, keyAlias = "foo", privateKeyPassword = "foo".toCharArray())
        material.sign(byteArrayOf()).shouldBeInstanceOf<SignatureResult.Success<*>>()

        material.getCertificate().shouldBeNull()
    }
    "With Cert" {
        val material = KeyStoreMaterial(
            keyStore = ks,
            keyAlias = "foo",
            privateKeyPassword = "foo".toCharArray(),
            certAlias = "foo"
        )
        material.sign(byteArrayOf()).shouldBeInstanceOf<SignatureResult.Success<*>>()

        material.getCertificate().shouldNotBeNull()
    }

    "With BC Prov and Cert" {
        Security.addProvider(BouncyCastleProvider())
        val material = KeyStoreMaterial(
            keyStore = ks,
            keyAlias = "foo",
            privateKeyPassword = "foo".toCharArray(),
            certAlias = "foo",
            providerName = "BC"
        )
        material.sign(byteArrayOf()).shouldBeInstanceOf<SignatureResult.Success<*>>()

        material.getCertificate().shouldNotBeNull()
    }

})