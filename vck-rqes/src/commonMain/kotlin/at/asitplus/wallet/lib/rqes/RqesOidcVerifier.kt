package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.Hashes
import at.asitplus.openid.SignatureQualifier
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.TransactionData
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.NonceService
import com.benasher44.uuid.uuid4
import kotlinx.datetime.Clock

/**
 * Verifier with access to [TransactionData] class can now generate requests containing [TransactionData]
 */
class RqesOidcVerifier(
    private val clientIdScheme: ClientIdScheme,
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    private val verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    private val jwsService: JwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
    private val verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(DefaultVerifierCryptoService()),
    timeLeewaySeconds: Long = 300L,
    private val clock: Clock = Clock.System,
    private val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests, to verify the authn response to it */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
) : OidcSiopVerifier(
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
        val rqesParameters: RqesParameters?,
    ) : RequestOptionsInterface by baseRequestOptions {
        override fun toPresentationDefinition(): PresentationDefinition? =
            PresentationDefinition(
                id = uuid4().toString(),
                inputDescriptors = this.credentials.map {
                    it.toInputDescriptor1(this.rqesParameters?.transactionData)
                },
            )

        fun RequestOptionsCredential.toInputDescriptor1(transactionData: Set<String>?): InputDescriptor =
            if (transactionData.isNullOrEmpty()) {
                DifInputDescriptor(
                    id = buildId(),
                    format = toFormatHolder(),
                    constraints = toConstraint(),
                )
            } else {
                val deserialized =
                    transactionData.map { vckJsonSerializer.decodeFromString(TransactionData.serializer(), it) }
                QesInputDescriptor(
                    id = buildId(), format = toFormatHolder(), constraints = toConstraint(), transactionData = deserialized
                )
            }
    }

    /**
     * Parameters defined in the CSC extension of [AuthenticationRequestParameters]
     */
    data class RqesParameters(
        val lang: String? = null,
        val credentialID: ByteArray? = null,
        val signatureQualifier: SignatureQualifier? = null,
        val numSignatures: Int? = null,
        val hashes: Hashes? = null,
        val hashAlgorithmOid: ObjectIdentifier? = null,
        val description: String? = null,
        val accountToken: JsonWebToken? = null,
        val clientData: String? = null,
        val transactionData: Set<String>? = null,
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
    ): AuthenticationRequestParameters = with(requestOptions as ExtendedRequestOptions) {
        params.copy(
            lang = this.rqesParameters?.lang,
            credentialID = this.rqesParameters?.credentialID,
            signatureQualifier = this.rqesParameters?.signatureQualifier,
            numSignatures = this.rqesParameters?.numSignatures,
            hashes = this.rqesParameters?.hashes,
            hashAlgorithmOid = this.rqesParameters?.hashAlgorithmOid,
            description = this.rqesParameters?.description,
            accountToken = this.rqesParameters?.accountToken,
            clientData = this.rqesParameters?.clientData,
            transactionData = this.rqesParameters?.transactionData,
        )
    }

}
