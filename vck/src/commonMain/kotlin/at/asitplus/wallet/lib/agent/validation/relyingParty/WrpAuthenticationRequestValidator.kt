package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsTyped
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate.WrpCwtRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate.WrpJwtRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest.WrpDcqlCredentialQuery
import io.github.aakira.napier.Napier
import kotlinx.serialization.decodeFromByteArray

/**
 * Parses an authentication request and wraps necessary data for WRP validation.
 */
object WrpAuthenticationRequestValidator {

    operator fun invoke(
        request: RequestParametersFrom<*>
    ): KmmResult<WrpRequestData> = catching {
        when (request) {
            is RequestParametersFrom.Jws<*> -> {
                val request = request.jwsTyped as? JwsTyped<JwsCompact, AuthenticationRequestParameters>
                    ?: throw UnsupportedWrpRequestException("Unable to cast request as JwsTyped<JwsCompact, AuthenticationRequestParameters>")
                val clientId = requireNotNull(request.payload.clientId) { "No client_id in request" }
                val verifierInfo = request.payload.verifierInfo
                    ?: throw MissingRegistrationCertificateException("No verifier_info in request")
                invoke(clientId, request.jws.jwsHeader.certificateChain, verifierInfo, request.payload.dcqlQuery)
                    .getOrThrow()
            }

            is RequestParametersFrom.OpenId4VpDcApiSigned -> {
                val clientId = requireNotNull(request.parameters.clientId) { "No client_id in request" }
                val verifierInfo = request.parameters.verifierInfo
                    ?: throw MissingRegistrationCertificateException("No verifier_info in request")
                invoke(clientId, request.jwsTyped.jws.jwsHeader.certificateChain, verifierInfo, request.parameters.dcqlQuery)
                    .getOrThrow()
            }

            // Its signatures name different identities, so only the caller knows which of them were authenticated
            is RequestParametersFrom.OpenId4VpDcApiMultiSigned -> throw UnsupportedWrpRequestException(
                "Multisigned requests are validated per authenticated signer, see wrpRequestDataOfSigners"
            )

            is RequestParametersFrom.IsoMdocDcApi -> throw UnsupportedWrpRequestException(
                "Session transcript is required for ISO mdoc reader authentication"
            )

            else -> throw UnsupportedWrpRequestException("Request not supported for validation: $request")
        }
    }

    /**
     * Data to validate the identity of one signer of a request, which signed with [certificateChain] as [clientId] and
     * attached [verifierInfo], for the credentials requested in [dcqlQuery].
     *
     * The registration certificate in [verifierInfo] is mapped to the credential queries named in its
     * [VerifierInfo.credentialIds], or to all of them if that is absent. A request without a registration certificate
     * fails with [MissingRegistrationCertificateException], unless [registrationCertificateRequired] is `false`, e.g.
     * for a signer that only carries an access certificate. The registration certificate is parsed before
     * [dcqlQuery] is required, so that a missing or invalid one is reported as such.
     */
    operator fun invoke(
        clientId: String?,
        certificateChain: CertificateChain?,
        verifierInfo: Collection<VerifierInfo>?,
        dcqlQuery: DCQLQuery?,
        registrationCertificateRequired: Boolean = true,
    ): KmmResult<WrpRequestData> = catching {
        val hasRegistrationCertificate = verifierInfo.orEmpty().any {
            it.format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true)
        }
        val registrationCertificate: Map<WrpRegistrationCertificate, List<WrpCredentialRequest>> =
            if (hasRegistrationCertificate || registrationCertificateRequired) {
                val (entry, jwsTyped) = verifierInfo.orEmpty().parseSingleRegistrationCertificate()
                val query = requireNotNull(dcqlQuery) { "No DCQL query in request" }
                mapOf(WrpJwtRegistrationCertificate(jwsTyped = jwsTyped) to query.credentialRequestsFor(entry))
            } else {
                emptyMap()
            }
        WrpRequestData(
            clientId = clientId,
            accessCertificate = WrpAccessCertificate(certificateChain),
            registrationCertificate = registrationCertificate,
        )
    }

    /** The credential queries [entry] applies to, see [VerifierInfo.credentialIds]. */
    private fun DCQLQuery.credentialRequestsFor(entry: VerifierInfo): List<WrpCredentialRequest> {
        val credentialIds = entry.credentialIds ?: return credentials.map { WrpDcqlCredentialQuery(it) }
        val queryIds = credentials.map { it.id.string }.toSet()
        if (!queryIds.containsAll(credentialIds)) {
            throw InvalidRegistrationCertificateException(
                "Registration certificate refers to unknown credential queries ${credentialIds - queryIds}"
            )
        }
        return credentials.filter { it.id.string in credentialIds }.map { WrpDcqlCredentialQuery(it) }
    }

    suspend operator fun invoke(
        request: RequestParametersFrom.IsoMdocDcApi,
        sessionTranscript: SessionTranscript
    ): KmmResult<WrpRequestData> = catching {
        val deviceRequest = request.parameters.isoMdocRequest.deviceRequest
        // Checked before reader authentication, so that a missing WRPRC is reported as such regardless of the WRPAC
        if (deviceRequest.docRequests.all { it.itemsRequest.value.requestInfo?.euWrprc == null }) {
            throw MissingRegistrationCertificateException("No DocRequest contains a registration certificate")
        }
        val accessCertificateChain = ReaderAuthenticationVerifier()(deviceRequest, sessionTranscript).getOrThrow()
        val registrationCertificate: Map<WrpRegistrationCertificate, List<WrpCredentialRequest>> =
            deviceRequest.docRequests.map { docRequest ->
                val euWrprcBytes = docRequest.itemsRequest.value.requestInfo?.euWrprc
                    ?: throw InvalidRegistrationCertificateException(
                        "Registration certificate missing in DocRequest $docRequest, while other DocRequests contain one"
                    )
                val registrationCertificate = catchingUnwrapped {
                    val euWrprc = coseCompliantSerializer.decodeFromByteArray<CoseSigned<ByteArray>>(euWrprcBytes)
                    WrpCwtRegistrationCertificate(cose = euWrprc, payload = parseCose(euWrprc = euWrprc))
                }.getOrElse {
                    throw InvalidRegistrationCertificateException("Could not parse WRPRC in DocRequest $docRequest", it)
                }
                Pair(registrationCertificate, listOf(WrpCredentialRequest.WrpDocRequest(docRequest)))
            }.groupBy({ it.first }, { it.second })
                .mapValues { (_, requests) -> requests.flatten() }

        WrpRequestData(
            accessCertificate = WrpAccessCertificate(accessCertificateChain),
            registrationCertificate = registrationCertificate
        )
    }

    /**
     * Parses the only registration certificate in [this], keeping the cause in the exception if it can not be parsed.
     */
    private fun Collection<VerifierInfo>.parseSingleRegistrationCertificate(): Pair<VerifierInfo, JwsCompactTyped<WrpPayload>> {
        val registrationCertificates = filter { it.format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true) }
        if (registrationCertificates.isEmpty()) {
            throw MissingRegistrationCertificateException("No WRPRC in verifier_info")
        }
        val registrationCertificate = registrationCertificates.singleOrNull()
            ?: throw InvalidRegistrationCertificateException(
                "Request must contain exactly one WRPRC, but contains ${registrationCertificates.size}"
            )
        return catchingUnwrapped { registrationCertificate to JwsCompactTyped<WrpPayload>(registrationCertificate.data) }.getOrElse {
            throw InvalidRegistrationCertificateException("Could not parse WRPRC", it)
        }
    }

    fun VerifierInfo.parseJws() = catchingUnwrapped {
        require(format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true))
        JwsCompactTyped<WrpPayload>(data)
    }.onFailure { Napier.w("Failed to parse JWS data for $this (${REGISTRATION_CERT_FORMAT}).", it) }
        .getOrNull()

    fun parseCose(euWrprc: CoseSigned<ByteArray>): WrpPayload {
        val type = euWrprc.protectedHeader.type ?: throw IllegalArgumentException("Missing typ header in euWrprc.")
        if (type != "rc-wrp+cwt") {
            throw IllegalArgumentException("Invalid typ header in euWrprc: expected 'rc-wrp+cwt', got '$type'.")
        }

        val payloadBytes = euWrprc.payload ?: throw IllegalStateException("euWrprc payload not found.")
        return coseCompliantSerializer.decodeFromByteArray<WrpPayload>(bytes = payloadBytes)
    }
}
