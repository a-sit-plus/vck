package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.csc.api.serializers.Base64X509CertificateSerializer
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.sha256
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import io.ktor.utils.io.core.toByteArray
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray
import kotlin.String

/**
 * Stores all credentials that a subject has received
 */
interface SubjectCredentialStore {

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param vc Instance of [VerifiableCredentialJws]
     * @param vcSerialized Serialized form of [VerifiableCredential]
     */
    suspend fun storeCredential(
        vc: VerifiableCredentialJws,
        vcSerialized: String,
        scheme: VcJwtCredentialScheme,
        renewalInfo: CredentialRenewalInfo? = null,
        issuer: Certificate? = null
    ): StoreEntry

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param vc Instance of [VerifiableCredentialSdJwt]
     * @param vcSerialized Serialized form of [at.asitplus.wallet.lib.jws.SdJwtSigned]
     */
    suspend fun storeCredential(
        vc: VerifiableCredentialSdJwt,
        vcSerialized: String,
        disclosures: Map<String, SelectiveDisclosureItem?>,
        scheme: SdJwtCredentialScheme,
        renewalInfo: CredentialRenewalInfo? = null,
        issuer: Certificate? = null
    ): StoreEntry

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param issuerSigned Instance of [IssuerSigned] (an ISO credential)
     */
    suspend fun storeCredential(
        issuerSigned: IssuerSigned,
        scheme: IsoMdocCredentialScheme,
        renewalInfo: CredentialRenewalInfo? = null,
        issuer: Certificate? = null
    ): StoreEntry

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
        val issuer: Certificate?
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
            override val issuer: Certificate? = null,
            /** See [VcJwtCredentialScheme.vcType] or `vc.vc.type` */
            @SerialName("scheme-identifier")
            override val schemeIdentifier: String
        ) : StoreEntry {

            override suspend fun resolveScheme(): CredentialScheme =
                AttributeIndex.resolveIdentifier(schemeIdentifier, PLAIN_JWT)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.JWT_VC
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
            override val issuer: Certificate? = null,
            /** See [SdJwtCredentialScheme.sdJwtType] or `sdJwt.verifiableCredentialType` */
            @SerialName("scheme-identifier")
            override val schemeIdentifier: String
        ) : StoreEntry {

            override suspend fun resolveScheme(): CredentialScheme =
                AttributeIndex.resolveIdentifier(schemeIdentifier, SD_JWT)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.DC_SD_JWT
        }

        @Serializable
        data class Iso(
            @SerialName("issuer-signed")
            val issuerSigned: IssuerSigned,
            @SerialName("credential-renewal-info")
            override val renewalInfo: CredentialRenewalInfo? = null,
            @Serializable(with = Base64X509CertificateSerializer::class)
            override val issuer: Certificate? = null,
            /** See [IsoMdocCredentialScheme.isoDocType] or `issuerSigned.issuerAuth.payload.docType` */
            @SerialName("scheme-identifier")
            override val schemeIdentifier: String
        ) : StoreEntry {

            override suspend fun resolveScheme(): CredentialScheme =
                AttributeIndex.resolveIdentifier(schemeIdentifier, ISO_MDOC)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.MSO_MDOC
        }

        @Throws(IllegalArgumentException::class)
        suspend fun getDcApiId(): String = when (this) {
            is Vc -> vc.jwtId
            is SdJwt -> sdJwt.jwtId
                ?: joseCompliantSerializer.encodeToString(sdJwt).toByteArray().sha256().toHexString()

            is Iso -> coseCompliantSerializer.encodeToByteArray(issuerSigned).sha256().toHexString()
        }

    }
}

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
