package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.iso.sha256
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlin.also
import kotlin.random.Random


class ValidatorMdocTest : FreeSpec() {

    private lateinit var issuer: Issuer
    private lateinit var statusListIssuer: StatusListIssuer
    private lateinit var issuerCredentialStore: IssuerCredentialStore
    private lateinit var issuerKeyMaterial: KeyMaterial
    private lateinit var verifierKeyMaterial: KeyMaterial
    private lateinit var validator: Validator

    init {
        beforeEach {
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
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow()
            credential.shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            val issuerKey: CoseKey? =
                credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()?.let {
                    runCatching { X509Certificate.decodeFromDer(it) }.getOrNull()?.publicKey?.toCoseKey()
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
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow()
            credential.shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            val issuerKey: CoseKey? =
                credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()?.let {
                    runCatching { X509Certificate.decodeFromDer(it) }.getOrNull()?.publicKey?.toCoseKey()
                        ?.getOrNull()
                }

            val value = validator.verifyIsoCred(credential.issuerSigned, issuerKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessIso>()
            issuerCredentialStore.setStatus(
                credential.issuerSigned.namespaces!!.get(ConstantIndex.AtomicAttribute2023.isoNamespace)!!.entries.map {
                    it.value
                } .sortedBy {
                    it.digestId
                }.toString().encodeToByteArray().sha256().encodeToString(Base16(strict = true)),
                status = TokenStatus.Invalid,
                FixedTimePeriodProvider.timePeriod,
            ) shouldBe true
            validator.checkRevocationStatus(value.issuerSigned)
                .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
        }
    }
}
