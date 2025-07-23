package at.asitplus.wallet.lib.agent

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock
import kotlin.random.Random


class ValidatorMdocTest : FreeSpec() {

    private lateinit var issuer: Issuer
    private lateinit var statusListIssuer: StatusListIssuer
    private lateinit var issuerCredentialStore: IssuerCredentialStore
    private lateinit var issuerKeyMaterial: KeyMaterial
    private lateinit var verifierKeyMaterial: KeyMaterial
    private lateinit var validator: ValidatorMdoc

    init {
        beforeEach {
            validator = ValidatorMdoc(
                validator = Validator(
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
            issuerCredentialStore = InMemoryIssuerCredentialStore()
            issuerKeyMaterial = EphemeralKeyWithSelfSignedCert()
            issuer = IssuerAgent(issuerKeyMaterial, issuerCredentialStore = issuerCredentialStore)
            statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            verifierKeyMaterial = EphemeralKeyWithoutCert()
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
                    catchingUnwrapped { X509Certificate.decodeFromDer(it) }.getOrNull()?.publicKey?.toCoseKey()
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
                    catchingUnwrapped { X509Certificate.decodeFromDer(it) }.getOrNull()?.publicKey?.toCoseKey()
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
