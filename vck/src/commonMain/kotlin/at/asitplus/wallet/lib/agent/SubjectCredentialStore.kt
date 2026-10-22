package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.csc.api.serializers.Base64X509CertificateSerializer
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.sha256
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.validation.CredentialValidationResult
import at.asitplus.wallet.lib.validation.ValidatedCredential
import io.ktor.utils.io.core.toByteArray
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.String

/**
 * Stores all credentials that a subject has received
 */
interface SubjectCredentialStore {

    /**
     * Implementations should store [entry] in a secure way, and return it for future reference.
     * Passed entries hold credentials that have been validated before, see [HolderAgent.storeAccepted], built e.g.
     * with [StoreEntry.fromPreparedCredential].
     */
    suspend fun storeCredential(entry: StoreEntry): KmmResult<StoreEntry>

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param vc Instance of [VerifiableCredentialJws]
     * @param vcSerialized Serialized form of [VerifiableCredential]
     */
    @Deprecated(
        "Use storeCredential(StoreEntry)",
        ReplaceWith(
            "storeCredential(SubjectCredentialStore.StoreEntry.Vc(vcSerialized = vcSerialized, vc = vc, " +
                    "renewalInfo = renewalInfo, issuer = issuer, schemeIdentifier = scheme.vcType)).getOrThrow()"
        )
    )
    suspend fun storeCredential(
        vc: VerifiableCredentialJws,
        vcSerialized: String,
        scheme: VcJwtCredentialScheme,
        renewalInfo: CredentialRenewalInfo? = null,
        issuer: X509Certificate? = null
    ): StoreEntry = storeCredential(
        StoreEntry.Vc(
            vcSerialized = vcSerialized,
            vc = vc,
            renewalInfo = renewalInfo,
            issuer = issuer,
            schemeIdentifier = scheme.vcType,
        )
    ).getOrThrow()

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param vc Instance of [VerifiableCredentialSdJwt]
     * @param vcSerialized Serialized form of [at.asitplus.wallet.lib.jws.SdJwtSigned]
     */
    @Deprecated(
        "Use storeCredential(StoreEntry)",
        ReplaceWith(
            "storeCredential(SubjectCredentialStore.StoreEntry.SdJwt(vcSerialized = vcSerialized, sdJwt = vc, " +
                    "disclosures = disclosures, renewalInfo = renewalInfo, issuer = issuer, " +
                    "schemeIdentifier = scheme.sdJwtType)).getOrThrow()"
        )
    )
    suspend fun storeCredential(
        vc: VerifiableCredentialSdJwt,
        vcSerialized: String,
        disclosures: Map<String, SelectiveDisclosureItem?>,
        scheme: SdJwtCredentialScheme,
        renewalInfo: CredentialRenewalInfo? = null,
        issuer: X509Certificate? = null
    ): StoreEntry = storeCredential(
        StoreEntry.SdJwt(
            vcSerialized = vcSerialized,
            sdJwt = vc,
            disclosures = disclosures,
            renewalInfo = renewalInfo,
            issuer = issuer,
            schemeIdentifier = scheme.sdJwtType,
        )
    ).getOrThrow()

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param issuerSigned Instance of [IssuerSigned] (an ISO credential)
     */
    @Deprecated(
        "Use storeCredential(StoreEntry)",
        ReplaceWith(
            "storeCredential(SubjectCredentialStore.StoreEntry.Iso(issuerSigned = issuerSigned, " +
                    "renewalInfo = renewalInfo, issuer = issuer, schemeIdentifier = scheme.isoDocType)).getOrThrow()"
        )
    )
    suspend fun storeCredential(
        issuerSigned: IssuerSigned,
        scheme: IsoMdocCredentialScheme,
        renewalInfo: CredentialRenewalInfo? = null,
        issuer: X509Certificate? = null
    ): StoreEntry = storeCredential(
        StoreEntry.Iso(
            issuerSigned = issuerSigned,
            renewalInfo = renewalInfo,
            issuer = issuer,
            schemeIdentifier = scheme.isoDocType,
        )
    ).getOrThrow()

    /**
     * Return all stored credentials.
     * Selective Disclosure: Specify list of credential schemes in [credentialSchemes].
     */
    suspend fun getCredentials(credentialSchemes: Collection<CredentialScheme>? = null)
            : KmmResult<List<StoreEntry>>

    @Serializable
    sealed interface StoreEntry {
        val credentialFormat: CredentialFormatEnum
        val renewalInfo: CredentialRenewalInfo?
        val issuer: X509Certificate?
        val schemeIdentifier: String
        suspend fun resolveScheme(): CredentialScheme

        @Serializable
        data class Vc(
            @SerialName("vc-serialized")
            val vcSerialized: String,
            @SerialName("vc")
            val vc: VerifiableCredentialJws,
            @SerialName("credential-renewal-info")
            override val renewalInfo: CredentialRenewalInfo? = null,
            @Serializable(with = Base64X509CertificateSerializer::class)
            override val issuer: X509Certificate? = null,
            /** See [VcJwtCredentialScheme.vcType] or `vc.vc.type` */
            @SerialName("scheme-identifier")
            override val schemeIdentifier: String
        ) : StoreEntry {

            override suspend fun resolveScheme(): CredentialScheme =
                AttributeIndex.resolveIdentifier(schemeIdentifier, PLAIN_JWT)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.JWT_VC

            companion object {
                /** Parses from a serialized JWS with payload [VerifiableCredentialJws] */
                fun fromString(
                    input: String
                ): KmmResult<Vc> = catching {
                    JwsCompactTyped<VerifiableCredentialJws>(input).let { vcJws ->
                        Vc(
                            vcSerialized = input,
                            vc = vcJws.payload,
                            renewalInfo = null,
                            issuer = vcJws.jws.jwsHeader.certificateChain?.leaf,
                            schemeIdentifier = vcJws.payload.vc.type.first { it != VERIFIABLE_CREDENTIAL },
                        )
                    }
                }
            }
        }

        @Serializable
        data class SdJwt(
            @SerialName("vc-serialized")
            val vcSerialized: String,
            @SerialName("sd-jwt")
            val sdJwt: VerifiableCredentialSdJwt,
            /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
            @SerialName("disclosures")
            val disclosures: Map<String, SelectiveDisclosureItem?>,
            @SerialName("credential-renewal-info")
            override val renewalInfo: CredentialRenewalInfo? = null,
            @Serializable(with = Base64X509CertificateSerializer::class)
            override val issuer: X509Certificate? = null,
            /** See [SdJwtCredentialScheme.sdJwtType] or `sdJwt.verifiableCredentialType` */
            @SerialName("scheme-identifier")
            override val schemeIdentifier: String
        ) : StoreEntry {

            override suspend fun resolveScheme(): CredentialScheme =
                AttributeIndex.resolveIdentifier(schemeIdentifier, SD_JWT)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.DC_SD_JWT

            companion object {
                /** Parses from a serialized [SdJwtSigned] (being a JWS with disclosures appended) */
                fun fromString(
                    input: String
                ): KmmResult<SdJwt> = catching {
                    SdJwtSigned.parseCatching(input).getOrThrow().let { sdJwt ->
                        val payload = sdJwt.jws.getPayload<VerifiableCredentialSdJwt>().getOrThrow()
                        SdJwt(
                            vcSerialized = input,
                            sdJwt = payload,
                            disclosures = SdJwtDecoded(sdJwt).validDisclosures,
                            renewalInfo = null,
                            issuer = sdJwt.jws.jwsHeader.certificateChain?.leaf,
                            schemeIdentifier = payload.verifiableCredentialType,
                        )
                    }
                }
            }
        }

        @Serializable
        data class Iso(
            @SerialName("issuer-signed")
            val issuerSigned: IssuerSigned,
            @SerialName("credential-renewal-info")
            override val renewalInfo: CredentialRenewalInfo? = null,
            @Serializable(with = Base64X509CertificateSerializer::class)
            override val issuer: X509Certificate? = null,
            /** See [IsoMdocCredentialScheme.isoDocType] or `issuerSigned.issuerAuth.payload.docType` */
            @SerialName("scheme-identifier")
            override val schemeIdentifier: String
        ) : StoreEntry {

            override suspend fun resolveScheme(): CredentialScheme =
                AttributeIndex.resolveIdentifier(schemeIdentifier, ISO_MDOC)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.MSO_MDOC

            companion object {
                /**
                 * Parses from a base64url-encoded (as in OpenID4VCI 1.0, A.2.4), or base64-encoded, CBOR-encoded
                 * [IssuerSigned]
                 */
                fun fromString(
                    input: String
                ): KmmResult<Iso> = catching {
                    coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(input.decodeToByteArray(Base64())).let {
                        Iso(
                            issuerSigned = it,
                            renewalInfo = null,
                            issuer = it.issuerAuth.issuerCertificate(),
                            schemeIdentifier = requireNotNull(it.issuerAuth.payload?.docType) {
                                "docType missing from issuerAuth"
                            },
                        )
                    }
                }
            }
        }

        @Throws(IllegalArgumentException::class)
        fun getDcApiId(): String = when (this) {
            is Vc -> vc.jwtId
            is SdJwt -> sdJwt.jwtId
                ?: joseCompliantSerializer.encodeToString(sdJwt).toByteArray().sha256().toHexString()

            is Iso -> coseCompliantSerializer.encodeToByteArray(issuerSigned).sha256().toHexString()
        }

        companion object {
            /**
             * The entry for the credential of [prepared], to pass to [SubjectCredentialStore.storeCredential], built from
             * what its validation verified, see [CredentialValidationResult.unacceptedCredential]: also for a rejected
             * but intact credential, so store it only if its report is accepted, or the user accepted it, see
             * [HolderAgent.storeAccepted] and [HolderAgent.storeAfterUserConsent].
             * Fails for a credential that is not intact.
             */
            fun fromPreparedCredential(prepared: PreparedCredentialStorage): KmmResult<StoreEntry> = catching {
                val validated = requireNotNull(prepared.validation.unacceptedCredential) {
                    "The credential is not intact"
                }
                when (val credential = prepared.credential) {
                    is Holder.StoreCredentialInput.Vc -> Vc(
                        vcSerialized = credential.vcJws,
                        vc = (validated as ValidatedCredential.VcJwt).credential,
                        renewalInfo = prepared.renewalInfo,
                        issuer = credential.signedVcJws.jws.jwsHeader.certificateChain?.leaf,
                        schemeIdentifier = credential.scheme.vcType,
                    )

                    is Holder.StoreCredentialInput.SdJwt -> SdJwt(
                        vcSerialized = credential.vcSdJwt,
                        sdJwt = (validated as ValidatedCredential.SdJwtVc).credential,
                        disclosures = validated.disclosures,
                        renewalInfo = prepared.renewalInfo,
                        issuer = credential.signedSdJwtVc.jws.jwsHeader.certificateChain?.leaf,
                        schemeIdentifier = credential.scheme.sdJwtType,
                    )

                    is Holder.StoreCredentialInput.Iso -> Iso(
                        issuerSigned = (validated as ValidatedCredential.IsoMdoc).issuerSigned,
                        renewalInfo = prepared.renewalInfo,
                        issuer = credential.issuerSigned.issuerAuth.issuerCertificate(),
                        schemeIdentifier = credential.scheme.isoDocType,
                    )
                }
            }
        }
    }
}

/** The issuer certificate of an ISO credential, the first one of the `x5chain` in [this] `issuerAuth`. */
private fun CoseSigned<*>.issuerCertificate(): X509Certificate? =
    unprotectedHeader?.certificateChain?.firstOrNull()?.let { X509Certificate.decodeFromDer(it) }

/**
 * Holds all information needed to refresh a credential, pass it to `OpenId4VciClient.refreshCredentialReturningResult`.
 */
@Serializable
data class CredentialRenewalInfo(
    /** Even if refresh token is not returned, other properties are used to initiate full re-issuance process */
    val refreshToken: String?,
    val issuerMetadata: IssuerMetadata,
    val oauthMetadata: OAuth2AuthorizationServerMetadata,
    val credentialFormat: SupportedCredentialFormat,
    val credentialIdentifier: String,
)
