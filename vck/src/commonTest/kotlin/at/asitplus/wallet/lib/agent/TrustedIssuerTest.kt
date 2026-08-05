package at.asitplus.wallet.lib.agent

import at.asitplus.iso.MobileSecurityObject
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureTrustedCertificate
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun
import at.asitplus.wallet.lib.jws.JwsHeaderJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.builtins.serializer
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

/**
 * Verification of issuer signatures against a list of trusted issuer certificates, see
 * [requireTrustedSigningCertificate].
 */
val TrustedIssuerTest by matrixSuite {

    "JWS signed by a certificate issued by a trusted CA is verified" {
        val ca = TestCertificateAuthority()
        val signed = signJws(ca.issue())

        VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf(ca.certificate()) })(signed)
            .getOrThrow()
    }

    "JWS signed by a certificate issued by an untrusted CA is not verified" {
        val ca = TestCertificateAuthority()
        val signed = signJws(ca.issue())

        val otherCa = TestCertificateAuthority()
        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf(otherCa.certificate()) })(signed)
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

    "JWS signed by an untrusted self-signed certificate is not verified" {
        val signed = signJws(selfSignedKey())

        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(
                trustedIssuers = { setOf(TestCertificateAuthority().certificate()) },
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

    "JWS transporting the trust anchor in its certificate chain is not verified" {
        val ca = TestCertificateAuthority()
        val issuerKey = ca.issue()
        val anchor = ca.certificate()
        // the trust anchor has to be known out-of-band, so shipping it with the JWS must not help
        val signed = signJws(issuerKey, JwsHeaderIdentifierFun { header, keyMaterial ->
            header.copy(certificateChain = listOf(keyMaterial.getCertificate()!!, anchor))
        })

        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf(anchor) })(signed).getOrThrow()
        }.message.shouldNotBeNull() shouldContain "must not be transported"
    }

    "JWS without a certificate chain is not verified, even for a trusted issuer" {
        val ca = TestCertificateAuthority()
        val issuerKey = ca.issue()
        val signed = signJws(issuerKey, JwsHeaderJwk())

        shouldThrowAny {
            VerifyJwsObjectTrustedCertificate(trustedIssuers = { setOf(ca.certificate()) })(signed)
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
            trustedIssuers = { setOf(ca.certificate()) },
        )(signed, byteArrayOf(), null).getOrThrow()
    }

    "CoseSigned by a certificate issued by an untrusted CA is not verified" {
        val signed = signCose(TestCertificateAuthority().issue())

        VerifyCoseSignatureTrustedCertificate<ByteArray>(
            trustedIssuers = { setOf(TestCertificateAuthority().certificate()) },
        )(signed, byteArrayOf(), null).isFailure shouldBe true
    }

    "mdoc credential of a trusted issuer is verified, of an untrusted issuer is not" {
        val ca = TestCertificateAuthority()
        val holderKey = EphemeralKeyWithoutCert()
        val credential = DummyCredentialDataProvider.issueIsoMdoc(
            IssuerAgent(
                keyMaterial = ca.issue(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default,
            ),
            holderKey,
        ) as Issuer.IssuedCredential.Iso

        ValidatorMdoc(verifyCoseSignature = issuerCoseVerifier<MobileSecurityObject> { setOf(ca.certificate()) })
            .verifyIsoCred(credential.issuerSigned).getOrThrow()

        shouldThrowAny {
            ValidatorMdoc(
                verifyCoseSignature = issuerCoseVerifier<MobileSecurityObject> {
                    setOf(TestCertificateAuthority().certificate())
                },
            ).verifyIsoCred(credential.issuerSigned).getOrThrow()
        }
    }

    "HolderAgent stores an SD-JWT of a trusted issuer only" {
        val ca = TestCertificateAuthority()
        val holderKey = EphemeralKeyWithoutCert()
        val credential = IssuerAgent(
            keyMaterial = ca.issue(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
        ).issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKey.publicKey,
                ConstantIndex.AtomicAttribute2023,
                SD_JWT,
            ).getOrThrow()
        ).getOrThrow().toStoreCredentialInput()

        HolderAgent(holderKey, trustedIssuers = { setOf(ca.certificate()) })
            .storeCredential(credential).getOrThrow()

        shouldThrowAny {
            HolderAgent(holderKey, trustedIssuers = { setOf(TestCertificateAuthority().certificate()) })
                .storeCredential(credential).getOrThrow()
        }
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
