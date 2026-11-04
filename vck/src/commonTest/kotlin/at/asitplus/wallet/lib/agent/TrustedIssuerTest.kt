package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureTrustedCertificate
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun
import at.asitplus.wallet.lib.jws.JwsHeaderJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlinx.serialization.builtins.serializer

/**
 * Verification of issuer signatures against a list of trusted issuer certificates, see
 * [requireTrustedSigningCertificate].
 */
val TrustedIssuerTest by matrixSuite {

    "JWS signed by a certificate issued by a trusted CA is verified" {
        val ca = TestCertificateAuthority()
        val signed = signJws(ca.issue())

        VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf(ca.certificate) })(signed)
            .getOrThrow()
    }

    "JWS signed by a certificate issued by an untrusted CA is not verified" {
        val ca = TestCertificateAuthority()
        val signed = signJws(ca.issue())

        val otherCa = TestCertificateAuthority()
        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf(otherCa.certificate) })(signed)
                .getOrThrow()
        }.message.shouldNotBeNull() shouldContain "No valid trust anchor"
    }

    "JWS signed by a trusted self-signed certificate is verified" {
        val issuerKey = selfSignedKey()
        val signed = signJws(issuerKey)

        VerifyJwsObjectTrustedCertificate(
            trustedIssuers = { setOf(issuerKey.getCertificate()!!) },
        )(signed).getOrThrow()
    }

    "JWS signed by a directly listed CA-issued end-entity certificate is verified" {
        val signer = TestCertificateAuthority().issue()
        val signed = signJws(signer)

        VerifyJwsObjectTrustedCertificate(
            trustedIssuers = { setOf(signer.getCertificate()!!) },
        )(signed).getOrThrow()
    }

    "JWS signed by a directly listed certificate transported with its unlisted issuer is verified" {
        val ca = TestCertificateAuthority()
        val signer = ca.issue()
        val signed = signJws(signer, JwsHeaderIdentifierFun { header, keyMaterial ->
            header.copy(certificateChain = listOf(keyMaterial.getCertificate()!!, ca.certificate))
        })

        VerifyJwsObjectTrustedCertificate(
            trustedIssuers = { setOf(signer.getCertificate()!!) },
        )(signed).getOrThrow()
    }

    "JWS signed by an untrusted self-signed certificate is not verified" {
        val signed = signJws(selfSignedKey())

        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(
                trustedIssuers = { setOf(TestCertificateAuthority().certificate) },
            )(signed).getOrThrow()
        }.message.shouldNotBeNull() shouldContain "must not be self-signed"
    }

    "JWS signed by an expired but trusted self-signed certificate is not verified" {
        val issuerKey = selfSignedKey(validFrom = Clock.System.now() - 10.minutes, validity = 1.minutes)
        val signed = signJws(issuerKey)

        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(
                trustedIssuers = { setOf(issuerKey.getCertificate()!!) },
            )(signed).getOrThrow()
        }.message.shouldNotBeNull() shouldContain "not valid at"
    }

    "JWS transporting the trust anchor as the last certificate of its chain is verified" {
        val ca = TestCertificateAuthority()
        val issuerKey = ca.issue()
        val anchor = ca.certificate
        // the trust anchor is known out-of-band anyway, so shipping it with the JWS is ignored
        val signed = signJws(issuerKey, JwsHeaderIdentifierFun { header, keyMaterial ->
            header.copy(certificateChain = listOf(keyMaterial.getCertificate()!!, anchor))
        })

        VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf(anchor) })(signed).getOrThrow()
    }

    "JWS transporting the trust anchor before another certificate is not verified" {
        val ca = TestCertificateAuthority()
        val issuerKey = ca.issue()
        val anchor = ca.certificate
        val unrelated = TestCertificateAuthority().certificate
        val signed = signJws(issuerKey, JwsHeaderIdentifierFun { header, keyMaterial ->
            header.copy(certificateChain = listOf(keyMaterial.getCertificate()!!, anchor, unrelated))
        })

        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf(anchor) })(signed).getOrThrow()
        }.message.shouldNotBeNull() shouldContain "last one of the chain"
    }

    "JWS without a certificate chain is not verified, even for a trusted issuer" {
        val ca = TestCertificateAuthority()
        val issuerKey = ca.issue()
        val signed = signJws(issuerKey, JwsHeaderJwk())

        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf(ca.certificate) })(signed)
                .getOrThrow()
        }.message.shouldNotBeNull() shouldContain "No certificate"
    }

    "JWS is not verified against an empty trust list" {
        val signed = signJws(TestCertificateAuthority().issue())

        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf() })(signed).getOrThrow()
        }.message.shouldNotBeNull() shouldContain "No trusted issuer"
    }

    "CoseSigned by a certificate issued by a trusted CA is verified" {
        val ca = TestCertificateAuthority()
        val signed = signCose(ca.issue())

        VerifyCoseSignatureTrustedCertificate<ByteArray>(
            trustedIssuers = { setOf(ca.certificate) },
        )(signed, byteArrayOf(), null).getOrThrow()
    }

    "CoseSigned by a directly listed CA-issued end-entity certificate is verified" {
        val signer = TestCertificateAuthority().issue()
        val signed = signCose(signer)

        VerifyCoseSignatureTrustedCertificate<ByteArray>(
            trustedIssuers = { setOf(signer.getCertificate()!!) },
        )(signed, byteArrayOf(), null).getOrThrow()
    }

    "CoseSigned by a certificate issued by an untrusted CA is not verified" {
        val signed = signCose(TestCertificateAuthority().issue())

        VerifyCoseSignatureTrustedCertificate<ByteArray>(
            trustedIssuers = { setOf(TestCertificateAuthority().certificate) },
        )(signed, byteArrayOf(), null).isFailure shouldBe true
    }
}

private suspend fun signJws(
    keyMaterial: KeyMaterial,
    headerModifier: JwsHeaderIdentifierFun = JwsHeaderCertOrJwk(),
) = SignJwt<String>(keyMaterial, headerModifier)(
    null, "payload", String.serializer()
).getOrThrow().jws

private suspend fun signCose(keyMaterial: KeyMaterial) =
    SignCose<ByteArray>(keyMaterial, unprotectedHeaderModifier = CoseHeaderCertificate())(
        protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256),
        unprotectedHeader = CoseHeader(),
        payload = byteArrayOf(1, 2, 3),
        serializer = kotlinx.serialization.builtins.ByteArraySerializer(),
    ).getOrThrow()
