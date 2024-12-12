package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlin.random.Random


class ValidatorMdocTest : FreeSpec() {

    private lateinit var issuer: Issuer
    private lateinit var issuerCredentialStore: IssuerCredentialStore
    private lateinit var issuerJwsService: JwsService
    private lateinit var issuerKeyMaterial: KeyMaterial
    private lateinit var verifierKeyMaterial: KeyMaterial
    private lateinit var validator: Validator

    init {
        beforeEach {
            validator = Validator(
                resolveStatusListToken = {
                    if (Random.nextBoolean()) StatusListToken.StatusListJwt(
                        JwsSigned.deserialize(
                            StatusListTokenPayload.serializer(),
                            issuer.issueStatusListJwt(),
                        ).getOrThrow(),
                        resolvedAt = Clock.System.now(),
                    ) else {
                        StatusListToken.StatusListCwt(
                            CoseSigned.deserialize(
                                StatusListTokenPayload.serializer(),
                                issuer.issueStatusListCwt(),
                            ).getOrThrow(),
                            resolvedAt = Clock.System.now(),
                        )
                    }
                },
            )
            issuerCredentialStore = InMemoryIssuerCredentialStore()
            issuerKeyMaterial = EphemeralKeyWithoutCert()
            issuer = IssuerAgent(
                issuerKeyMaterial,
                issuerCredentialStore,
                validator = validator,
            )
            issuerJwsService = DefaultJwsService(DefaultCryptoService(issuerKeyMaterial))
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

            val issuerKey = credential.issuerSigned.issuerAuth.combinedCoseHeader.publicKey

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

            val issuerKey = credential.issuerSigned.issuerAuth.also {
                println(it)
            }.combinedCoseHeader.publicKey

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
            validator.checkRevocationStatus(value.issuerSigned) shouldBe TokenStatus.Invalid
        }
    }
}
