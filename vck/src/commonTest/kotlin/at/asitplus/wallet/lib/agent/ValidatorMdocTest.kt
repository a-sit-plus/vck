package at.asitplus.wallet.lib.agent

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlin.time.Clock


val ValidatorMdocTest by testSuite {

    lateinit var issuer: Issuer
    lateinit var statusListIssuer: StatusListIssuer
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var issuerKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var validator: ValidatorMdoc

    TestConfig.aroundEach {
        validator = ValidatorMdoc(
            validator = Validator(
                tokenStatusResolver = TokenStatusResolverImpl(
                    resolveStatusListToken = {
                        if (Random.nextBoolean()) StatusListToken.StatusListJwt(
                            statusListIssuer.issueStatusListJwt(),
                            resolvedAt = Clock.System.now(),
                        ) else {
                            StatusListToken.StatusListCwt(
                                statusListIssuer.issueStatusListCwt(),
                                resolvedAt = Clock.System.now(),
                            )
                        }
                    },
                )
            )
        )
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuerKeyMaterial = EphemeralKeyWithSelfSignedCert()
        issuer = IssuerAgent(
            keyMaterial = issuerKeyMaterial,
            issuerCredentialStore = issuerCredentialStore,
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        it()
    }

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
