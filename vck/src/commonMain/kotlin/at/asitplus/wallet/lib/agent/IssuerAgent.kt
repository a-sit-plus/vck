package at.asitplus.wallet.lib.agent

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Extract credentialSubject id from a JsonElement
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceKeyInfo
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ValueDigest
import at.asitplus.iso.ValueDigestList
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.cbor.SignCoseFun
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.ktx.extractId
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtExt
import at.asitplus.wallet.lib.jws.SignJwtExtFun
import at.asitplus.wallet.lib.jws.SignJwtFun
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.github.z4kn4fein.semver.Version
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * An agent that implements [Issuer], i.e., it issues credentials for other agents.
 */
class IssuerAgent @JvmOverloads constructor(
    /** Key material used to sign credentials in [signIssuedVc], [signIssuedSdJwt], [signMobileSecurityObject]. */
    override val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    private val issuerCredentialStore: IssuerCredentialStore = InMemoryIssuerCredentialStore(),
    private val clock: Clock = Clock.System,
    /** Time to adjust the [Clock.now] for issuance date of credentials. */
    private val issuanceOffset: Duration = (-3).minutes,
    override val cryptoAlgorithms: Set<SignatureAlgorithm> = setOf(keyMaterial.signatureAlgorithm),
    /** The identifier used in `issuer` properties of credentials (JWT VC and SD JWT). */
    private val identifier: UniformResourceIdentifier,
    private val signIssuedSdJwt: SignJwtExtFun<JsonObject> =
        SignJwtExt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signIssuedVc: SignJwtFun<VerifiableCredentialJws> =
        SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signMobileSecurityObject: SignCoseFun<MobileSecurityObject> =
        SignCose(keyMaterial, CoseHeaderNone(), CoseHeaderCertificate()),
    /** Source for random bytes, i.e., salts for selective-disclosure items. */
    private val randomSource: RandomSource = RandomSource.Secure,
    /** Set if we want to set the `status` claim of issued credentials to point to a Status List */
    private val statusListAgent: StatusListAgent? = StatusListAgent(
        issuerCredentialStore = issuerCredentialStore as? InMemoryIssuerCredentialStore ?: InMemoryIssuerCredentialStore(),
    )
) : Issuer {

    /**
     * Wraps the credential-to-be-issued in [credential] into a single instance of [CredentialToBeIssued],
     * according to the representation, i.e., it essentially signs the credential with the issuer key.
     */
    override suspend fun issueCredential(
        credential: CredentialToBeIssued,
    ): KmmResult<Issuer.IssuedCredential> = catching {
        val issuanceDate = clock.now().minus(issuanceOffset.absoluteValue).truncateToSeconds()
        when (credential) {
            is CredentialToBeIssued.Iso -> issueMdoc(credential, issuanceDate)
            is CredentialToBeIssued.VcJwt -> issueVc(credential, issuanceDate)
            is CredentialToBeIssued.VcSd -> issueVcSd(credential, issuanceDate)
        }
    }

    private suspend fun issueMdoc(
        credential: CredentialToBeIssued.Iso,
        issuanceDate: Instant,
    ): Issuer.IssuedCredential {
        val expirationDate = credential.expiration
        val coseKey = credential.subjectPublicKey.toCoseKey()
            .getOrElse { throw IllegalStateException("Could not create subject COSE key", it) }
        val deviceKeyInfo = DeviceKeyInfo(coseKey)
        val mso = MobileSecurityObject(
            parsedVersion = Version(1, 0),
            digest = credential.digest,
            valueDigests = mapOf(
                credential.scheme.isoNamespace to ValueDigestList(credential.issuerSignedItems.map {
                    ValueDigest.fromIssuerSignedItem(it, credential.scheme.isoNamespace, credential.digest)
                })
            ),
            deviceKeyInfo = deviceKeyInfo,
            docType = credential.scheme.isoDocType,
            validityInfo = ValidityInfo(
                signed = issuanceDate,
                validFrom = issuanceDate,
                validUntil = expirationDate,
            ),
            status = statusListAgent?.provideStatusReference(credential, issuanceDate)
        )
        val issuerSigned = IssuerSigned.fromIssuerSignedItems(
            namespacedItems = mapOf(credential.scheme.isoNamespace to credential.issuerSignedItems),
            issuerAuth = signMobileSecurityObject(
                protectedHeader = null,
                unprotectedHeader = null,
                payload = mso,
                serializer = MobileSecurityObject.serializer(),
            ).getOrThrow(),
        )
        Napier.i("issueMdoc: $issuerSigned")
        return Issuer.IssuedCredential.Iso(
            issuerSigned = issuerSigned,
            scheme = credential.scheme,
            subjectPublicKey = credential.subjectPublicKey,
            userInfo = credential.userInfo
        ).also {
            issuerCredentialStore.onCredentialIssued(it)
        }
    }

    private suspend fun issueVc(
        credential: CredentialToBeIssued.VcJwt,
        issuanceDate: Instant,
    ): Issuer.IssuedCredential {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val vc = VerifiableCredential(
            id = vcId,
            issuer = identifier.string,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            credentialStatus = statusListAgent?.provideStatusReference(credential, issuanceDate),
            credentialSubject = credential.subject,
            credentialType = credential.scheme.vcType,
        )

        val vcInJws = signIssuedVc(
            type = JwsContentTypeConstants.JWT,
            payload = vc.toJws(),
            serializer = VerifiableCredentialJws.serializer(),
        ).getOrElse {
            throw IllegalStateException("Could not sign VC", it)
        }
        Napier.i("issueVc: $vcInJws")
        return Issuer.IssuedCredential.VcJwt(
            vc = vc,
            signedVcJws = vcInJws,
            scheme = credential.scheme,
            subjectPublicKey = credential.subjectPublicKey,
            userInfo = credential.userInfo,
        ).also {
            issuerCredentialStore.onCredentialIssued(it)
        }
    }

    private suspend fun issueVcSd(
        credential: CredentialToBeIssued.VcSd,
        issuanceDate: Instant,
    ): Issuer.IssuedCredential {
        val expirationDate = credential.expiration
        val subjectId = credential.subjectPublicKey.didEncoded // TODO not necessarily!
        val (sdJwt, disclosures) = credential.claims.toSdJsonObject(randomSource, credential.sdAlgorithm)
        val cnf = ConfirmationClaim(jsonWebKey = credential.subjectPublicKey.toJsonWebKey())
        val vcSdJwt = VerifiableCredentialSdJwt(
            subject = subjectId,
            notBefore = issuanceDate,
            issuer = identifier.string,
            expiration = expirationDate,
            issuedAt = issuanceDate,
            verifiableCredentialType = credential.scheme.sdJwtType,
            selectiveDisclosureAlgorithm = credential.sdAlgorithm.toIanaName(),
            confirmationClaim = cnf,
            statusElement = statusListAgent?.provideStatusReference(credential, issuanceDate)
        )
        val vcSdJwtObject = joseCompliantSerializer.encodeToJsonElement(vcSdJwt).jsonObject
        val entireObject = buildJsonObject {
            sdJwt.forEach {
                put(it.key, it.value)
            }
            vcSdJwtObject.forEach {
                put(it.key, it.value)
            }
        }
        val jws = signIssuedSdJwt(
            JwsContentTypeConstants.SD_JWT,
            entireObject,
            JsonObject.serializer(),
            credential.modifyHeader,
        ).getOrElse {
            throw IllegalStateException("Could not sign SD-JWT", it)
        }
        val sdJwtSigned = SdJwtSigned.issued(jws.jws, disclosures.toList())
            .also { Napier.i("issueVcSd: $it") }
        return Issuer.IssuedCredential.VcSdJwt(
            sdJwtVc = vcSdJwt,
            signedSdJwtVc = sdJwtSigned,
            scheme = credential.scheme,
            subjectPublicKey = credential.subjectPublicKey,
            userInfo = credential.userInfo,
        ).also {
            issuerCredentialStore.onCredentialIssued(it)
        }
    }

    private fun VerifiableCredential.toJws() = VerifiableCredentialJws(
        vc = this,
        subject = credentialSubject.extractId(),
        notBefore = issuanceDate,
        issuer = issuer,
        expiration = expirationDate,
        jwtId = id
    )
}
