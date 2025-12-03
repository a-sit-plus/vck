package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catchingUnwrapped
import at.asitplus.dif.ClaimFormat
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.sha256
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.IsoMdocFallbackCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtFallbackCredentialScheme
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.VcFallbackCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.ktor.utils.io.core.toByteArray
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray

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
        scheme: ConstantIndex.CredentialScheme,
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
        scheme: ConstantIndex.CredentialScheme,
    ): StoreEntry

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param issuerSigned Instance of [IssuerSigned] (an ISO credential)
     */
    suspend fun storeCredential(
        issuerSigned: IssuerSigned,
        scheme: ConstantIndex.CredentialScheme,
    ): StoreEntry

    /**
     * Return all stored credentials.
     * Selective Disclosure: Specify list of credential schemes in [credentialSchemes].
     */
    suspend fun getCredentials(credentialSchemes: Collection<ConstantIndex.CredentialScheme>? = null)
            : KmmResult<List<StoreEntry>>

    @Serializable
    sealed interface StoreEntry {
        val schemaUri: String
        val scheme: ConstantIndex.CredentialScheme?
            get() = AttributeIndex.resolveSchemaUri(schemaUri) ?: getFallbackScheme()
        val credentialFormat: CredentialFormatEnum
        val claimFormat: ClaimFormat

        fun getFallbackScheme(): ConstantIndex.CredentialScheme?

        @Serializable
        data class Vc(
            @SerialName("vc-serialized")
            val vcSerialized: String,
            @SerialName("vc")
            val vc: VerifiableCredentialJws,
            @SerialName("schema-uri")
            override val schemaUri: String,
        ) : StoreEntry {
            override fun getFallbackScheme(): ConstantIndex.CredentialScheme =
                VcFallbackCredentialScheme(vc.vc.type.first { it != VERIFIABLE_CREDENTIAL })

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.JWT_VC
            override val claimFormat: ClaimFormat = ClaimFormat.JWT_VP
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
            @SerialName("schema-uri")
            override val schemaUri: String,
        ) : StoreEntry {
            override fun getFallbackScheme(): ConstantIndex.CredentialScheme =
                SdJwtFallbackCredentialScheme(sdJwt.verifiableCredentialType)

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.DC_SD_JWT
            override val claimFormat: ClaimFormat = ClaimFormat.SD_JWT
        }

        @Serializable
        data class Iso(
            @SerialName("issuer-signed")
            val issuerSigned: IssuerSigned,
            @SerialName("schema-uri")
            override val schemaUri: String,
        ) : StoreEntry {
            override fun getFallbackScheme(): ConstantIndex.CredentialScheme? = catchingUnwrapped {
                IsoMdocFallbackCredentialScheme(issuerSigned.issuerAuth.payload?.docType!!)
            }.getOrNull()

            override val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.MSO_MDOC
            override val claimFormat: ClaimFormat = ClaimFormat.MSO_MDOC
        }

        @OptIn(ExperimentalStdlibApi::class)
        @Throws(IllegalArgumentException::class)
        fun getDcApiId(): String = when (this) {
            is Vc -> vc.jwtId
            is SdJwt -> sdJwt.jwtId
                ?: sdJwt.subject
                ?: joseCompliantSerializer.encodeToString(sdJwt).toByteArray().sha256().toHexString()

            is Iso -> coseCompliantSerializer.encodeToByteArray(issuerSigned).sha256().toHexString()
        }

    }
}
