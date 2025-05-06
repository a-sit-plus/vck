package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.*
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.jws.SdJwtSigned
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.types.shouldBeInstanceOf


class ValidatorUnavailableTest : FreeSpec() {

    private lateinit var issuer: Issuer
    private lateinit var verifierKeyMaterial: KeyMaterial
    private lateinit var validator: Validator

    init {
        beforeEach {
            validator = Validator(
                resolveStatusListToken = { throw IllegalArgumentException() },
            )
            issuer = IssuerAgent(
                EphemeralKeyWithSelfSignedCert(),
                validator = validator,
            )
            verifierKeyMaterial = EphemeralKeyWithoutCert()
        }

        "JWT credential is valid even if resolveStatusListToken throws exception" {
            val credential = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey, AtomicAttribute2023, PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            validator.verifyVcJws(credential.vcJws, verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<SuccessJwt>()
        }

        "SD-JWT credential is valid even if resolveStatusListToken throws exception" {
            val credential = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey, AtomicAttribute2023, SD_JWT,
                ).getOrThrow()
            ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()

            validator.verifySdJwt(SdJwtSigned.parse(credential.vcSdJwt)!!, verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<SuccessSdJwt>()
        }

        "MDOC credential is valid even if resolveStatusListToken throws exception" {
            val credential = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey, AtomicAttribute2023, ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            val issuerKey: CoseKey? =
                credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()?.let {
                    runCatching { X509Certificate.decodeFromDer(it) }.getOrNull()?.publicKey?.toCoseKey()
                        ?.getOrNull()
                }

            validator.verifyIsoCred(credential.issuerSigned, issuerKey)
                .shouldBeInstanceOf<SuccessIso>()
        }

    }

}
