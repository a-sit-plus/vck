package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.InputDescriptor
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.Hashes
import at.asitplus.openid.SignatureQualifier
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.TransactionData
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.openid.RequestOptions
import at.asitplus.wallet.lib.openid.RequestOptionsInterface
import kotlinx.datetime.Clock

/**
 * Verifier with access to [TransactionData] class can now generate requests containing [TransactionData]
 */
class RqesOidcVerifier(
    private val clientIdScheme: ClientIdScheme,
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    jwsService: JwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
    verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
    verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(DefaultVerifierCryptoService()),
    timeLeewaySeconds: Long = 300L,
    clock: Clock = Clock.System,
    nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests, to verify the authn response to it */
    stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
) : OpenId4VpVerifier(
    clientIdScheme,
    keyMaterial,
    verifier,
    jwsService,
    verifierJwsService,
    verifierCoseService,
    timeLeewaySeconds,
    clock,
    nonceService,
    stateToAuthnRequestStore
) {

    data class ExtendedRequestOptions(
        val baseRequestOptions: RequestOptions,
        val rqesParameters: RqesParameters? = null,
    ) : RequestOptionsInterface by baseRequestOptions {
        override fun toInputDescriptor(
            containerJwt: FormatContainerJwt,
            containerSdJwt: FormatContainerSdJwt,
        ): List<InputDescriptor> = credentials.map { requestOptionCredential ->
            rqesParameters?.let { parameter ->
                val deserialized =
                    parameter.transactionData.map {
                        vckJsonSerializer.decodeFromString(
                            TransactionData.serializer(),
                            it
                        )
                    }
                QesInputDescriptor(
                    id = requestOptionCredential.buildId(),
                    format = requestOptionCredential.toFormatHolder(containerJwt, containerSdJwt),
                    constraints = requestOptionCredential.toConstraint(),
                    transactionData = deserialized
                )
            } ?: DifInputDescriptor(
                id = requestOptionCredential.buildId(),
                format = requestOptionCredential.toFormatHolder(containerJwt, containerSdJwt),
                constraints = requestOptionCredential.toConstraint(),
            )
        }
    }

    /**
     * Parameters defined in the CSC extension of [AuthenticationRequestParameters]
     */
    data class RqesParameters(
        val transactionData: Set<String>,
        val lang: String? = null,
        val credentialID: ByteArray? = null,
        val signatureQualifier: SignatureQualifier? = null,
        val numSignatures: Int? = null,
        val hashes: Hashes? = null,
        val hashAlgorithmOid: ObjectIdentifier? = null,
        val description: String? = null,
        val accountToken: JsonWebToken? = null,
        val clientData: String? = null,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as RqesParameters

            if (numSignatures != other.numSignatures) return false
            if (lang != other.lang) return false
            if (credentialID != null) {
                if (other.credentialID == null) return false
                if (!credentialID.contentEquals(other.credentialID)) return false
            } else if (other.credentialID != null) return false
            if (signatureQualifier != other.signatureQualifier) return false
            if (hashes != other.hashes) return false
            if (hashAlgorithmOid != other.hashAlgorithmOid) return false
            if (description != other.description) return false
            if (accountToken != other.accountToken) return false
            if (clientData != other.clientData) return false
            if (transactionData != other.transactionData) return false

            return true
        }

        override fun hashCode(): Int {
            var result = numSignatures ?: 0
            result = 31 * result + (lang?.hashCode() ?: 0)
            result = 31 * result + (credentialID?.contentHashCode() ?: 0)
            result = 31 * result + (signatureQualifier?.hashCode() ?: 0)
            result = 31 * result + (hashes?.hashCode() ?: 0)
            result = 31 * result + (hashAlgorithmOid?.hashCode() ?: 0)
            result = 31 * result + (description?.hashCode() ?: 0)
            result = 31 * result + (accountToken?.hashCode() ?: 0)
            result = 31 * result + (clientData?.hashCode() ?: 0)
            result = 31 * result + (transactionData?.hashCode() ?: 0)
            return result
        }
    }

    override suspend fun enrichAuthnRequest(
        params: AuthenticationRequestParameters,
        requestOptions: RequestOptionsInterface,
    ): AuthenticationRequestParameters = with(requestOptions as? ExtendedRequestOptions) {
        params.copy(
            lang = this?.rqesParameters?.lang,
            credentialID = this?.rqesParameters?.credentialID,
            signatureQualifier = this?.rqesParameters?.signatureQualifier,
            numSignatures = this?.rqesParameters?.numSignatures,
            hashes = this?.rqesParameters?.hashes,
            hashAlgorithmOid = this?.rqesParameters?.hashAlgorithmOid,
            description = this?.rqesParameters?.description,
            accountToken = this?.rqesParameters?.accountToken,
            clientData = this?.rqesParameters?.clientData,
            transactionData = this?.rqesParameters?.transactionData,
        )
    }

}
