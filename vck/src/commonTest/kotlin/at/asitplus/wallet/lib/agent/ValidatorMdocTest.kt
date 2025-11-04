package at.asitplus.wallet.lib.agent

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import de.infix.testBalloon.framework.core.TestExecutionScope
import de.infix.testBalloon.framework.core.TestSuite
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlin.time.Clock

private data class Config(
    val issuer: Issuer,
    val statusListIssuer: StatusListIssuer,
    val issuerCredentialStore: IssuerCredentialStore,
    val issuerKeyMaterial: KeyMaterial,
    val verifierKeyMaterial: KeyMaterial,
    val validator: ValidatorMdoc
) {

    companion object {
        fun random(): Config {
            val issuerKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            return Config(
                validator = ValidatorMdoc(
                    validator = Validator(
                        tokenStatusResolver = TokenStatusResolverImpl(
                            resolveStatusListToken = {
                                if (Random.nextBoolean()) StatusListJwt(
                                    statusListIssuer.issueStatusListJwt(),
                                    resolvedAt = Clock.System.now(),
                                ) else {
                                    StatusListCwt(
                                        statusListIssuer.issueStatusListCwt(),
                                        resolvedAt = Clock.System.now(),
                                    )
                                }
                            },
                        )
                    )
                ),
                issuerCredentialStore = issuerCredentialStore,
                issuerKeyMaterial = issuerKeyMaterial,
                issuer = IssuerAgent(
                    keyMaterial = issuerKeyMaterial,
                    issuerCredentialStore = issuerCredentialStore,
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ),
                statusListIssuer = statusListIssuer,
                verifierKeyMaterial = EphemeralKeyWithoutCert()
            )
        }
    }
}

val ValidatorMdocTest by testSuite {
    with(Config.random()) {
        "credentials are valid for" {
            val credential = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow()
            credential.shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            val issuerKey: CoseKey? =
                credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()?.let {
                    catchingUnwrapped { X509Certificate.decodeFromDer(it) }.getOrNull()?.decodedPublicKey?.getOrNull()
                        ?.toCoseKey()
                        ?.getOrNull()
                }

            validator.verifyIsoCred(credential.issuerSigned, issuerKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessIso>()
        }
    }
    with(Config.random()) {
        "revoked credentials are not valid" {
            val credential = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow()
            credential.shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            val issuerKey: CoseKey? =
                credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()?.let {
                    catchingUnwrapped { X509Certificate.decodeFromDer(it) }.getOrNull()?.decodedPublicKey?.getOrNull()
                        ?.toCoseKey()
                        ?.getOrNull()
                }

            val value = validator.verifyIsoCred(credential.issuerSigned, issuerKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessIso>()
            issuerCredentialStore.setStatus(
                timePeriod = FixedTimePeriodProvider.timePeriod,
                index = credential.issuerSigned.issuerAuth.payload!!.status!!.statusList.index,
                status = TokenStatus.Invalid,
            ) shouldBe true
            validator.checkRevocationStatus(value.issuerSigned)
                .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
        }
    }
}
