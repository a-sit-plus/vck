package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SdJwtTypeMetadata
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderModifierFun
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.comparables.shouldNotBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes


val ValidatorSdJwtTest by testSuite {

    withFixtureGenerator {
        object {
            val validator = ValidatorSdJwt()
            val issuer = IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            fun buildCredentialData(): CredentialToBeIssued.VcSd = DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                SD_JWT,
            ).getOrThrow().shouldBeInstanceOf<CredentialToBeIssued.VcSd>()


            suspend fun issueVcSd(
                credential: CredentialToBeIssued.VcSd,
                holderKeyMaterial: KeyMaterial,
                buildCnf: Boolean = true,
                scrambleSubject: Boolean = false,
            ): Issuer.IssuedCredential {
                val issuanceDate = Clock.System.now()
                val signIssuedSdJwt: SignJwtFun<JsonObject> = SignJwt(holderKeyMaterial, JwsHeaderCertOrJwk())
                val vcId = "urn:uuid:${uuid4()}"
                val expirationDate = credential.expiration
                val subjectId = credential.subjectPublicKey.didEncoded
                val (sdJwt, disclosures) = credential.claims.toSdJsonObject(RandomSource.Default, credential.sdAlgorithm)
                val vcSdJwt = VerifiableCredentialSdJwt(
                    subject = if (scrambleSubject) subjectId.reversed() else subjectId,
                    notBefore = issuanceDate,
                    issuer = "https://issuer.example.com/",
                    expiration = expirationDate,
                    issuedAt = issuanceDate,
                    jwtId = vcId,
                    verifiableCredentialType = credential.scheme.sdJwtType ?: credential.scheme.schemaUri,
                    selectiveDisclosureAlgorithm = credential.sdAlgorithm.toIanaName(),
                    confirmationClaim = if (!buildCnf) null else
                        ConfirmationClaim(jsonWebKey = credential.subjectPublicKey.toJsonWebKey())
                )
                val vcSdJwtObject = vckJsonSerializer.encodeToJsonElement(vcSdJwt).jsonObject
                val entireObject = buildJsonObject {
                    sdJwt.forEach {
                        put(it.key, it.value)
                    }
                    vcSdJwtObject.forEach {
                        put(it.key, it.value)
                    }
                }
                // inclusion of x5c/jwk may change when all clients can look up the issuer-signed key web-based,
                // i.e. this issuer provides `.well-known/jwt-vc-issuer` file
                val jws = signIssuedSdJwt(
                    JwsContentTypeConstants.SD_JWT,
                    entireObject,
                    JsonObject.serializer(),
                ).getOrElse {
                    throw RuntimeException("Signing failed", it)
                }
                val sdJwtSigned = SdJwtSigned.issued(jws, disclosures.toList())
                val vcInSdJwt = (listOf(jws.serialize()) + disclosures).joinToString("~", postfix = "~")
                vcInSdJwt shouldBe sdJwtSigned.serialize()
                return Issuer.IssuedCredential.VcSdJwt(
                    sdJwtVc = vcSdJwt,
                    signedSdJwtVc = sdJwtSigned,
                    scheme = credential.scheme,
                    subjectPublicKey = credential.subjectPublicKey,
                    userInfo = credential.userInfo,
                )
            }

        }
    }- {

        "credentials are valid for holder's key" {
            val credential = it.issuer.issueCredential(it.buildCredentialData()).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>().apply {
                    // Assert the issuanceOffset in IssuerAgent
                    sdJwtVc.issuedAt.shouldNotBeNull() shouldBeLessThan Clock.System.now().minus(1.minutes)
                    sdJwtVc.issuedAt.shouldNotBeNull() shouldNotBeGreaterThan Clock.System.now()
                }

            it.validator.verifySdJwt(credential.signedSdJwtVc, it.holderKeyMaterial.publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessSdJwt>()
        }

        "credentials are not valid for some other key" {
            val credential = it.issuer.issueCredential(it.buildCredentialData()).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()

            it.validator.verifySdJwt(credential.signedSdJwtVc, EphemeralKeyWithoutCert().publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.ValidationError>()
        }

        "credentials without cnf are not valid" {
            val credential = it.issueVcSd(
                it.buildCredentialData(),
                it.holderKeyMaterial,
                buildCnf = false,
            ).shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()

            it.validator.verifySdJwt(credential.signedSdJwtVc, it.holderKeyMaterial.publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.ValidationError>()
        }

        "credentials with random subject are valid" {
            val credential = it.issueVcSd(
                it.buildCredentialData(),
                it.holderKeyMaterial,
                scrambleSubject = true,
            ).shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()

            it.validator.verifySdJwt(credential.signedSdJwtVc, it.holderKeyMaterial.publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessSdJwt>()
        }

        "credentials are valid with vctm added" {
            val typeMetadata = SdJwtTypeMetadata(
                verifiableCredentialType = "https://www.w3.org/2018/credentials/v1"
            )
            val vctm = typeMetadata.let {
                joseCompliantSerializer.encodeToString(it).encodeToByteArray().encodeToString(Base64UrlStrict)
            }
            val credentialDataWithVctm = it.buildCredentialData().let {
                it.copy(modifyHeader = JwsHeaderModifierFun {
                    it.copy(vcTypeMetadata = setOf(vctm))
                })
            }
            val credential = it.issuer.issueCredential(credentialDataWithVctm).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>().also {
                    it.signedSdJwtVc.jws.header.vcTypeMetadata.shouldNotBeNull().shouldBeSingleton().first().let {
                        it.decodeToByteArray(Base64UrlStrict).decodeToString().let {
                            joseCompliantSerializer.decodeFromString<SdJwtTypeMetadata>(it)
                        }
                    } shouldBe typeMetadata
                }

            it.validator.verifySdJwt(credential.signedSdJwtVc, it.holderKeyMaterial.publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessSdJwt>().apply {
                    sdJwtSigned.jws.header.vcTypeMetadata.shouldNotBeNull().shouldBeSingleton().first().let {
                        it.decodeToByteArray(Base64UrlStrict).decodeToString().let {
                            joseCompliantSerializer.decodeFromString<SdJwtTypeMetadata>(it)
                        }
                    } shouldBe typeMetadata
                }
        }
    }

}
