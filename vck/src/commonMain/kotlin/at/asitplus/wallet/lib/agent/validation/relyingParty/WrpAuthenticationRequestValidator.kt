package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsTyped
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

    operator fun invoke(request: RequestParametersFrom<*>) = catching {
        when (request) {
            is RequestParametersFrom.Jws<*> -> {
                val request = request.jwsTyped as? JwsTyped<JwsCompact, AuthenticationRequestParameters>
                    ?: throw IllegalArgumentException("Unable to cast request as JwsTyped<JwsCompact, AuthenticationRequestParameters>")
                val clientId = requireNotNull(request.payload.clientId) { "No client_id in request" }
                val verifierInfo = requireNotNull(request.payload.verifierInfo) { "No verifier_info in request" }
                val jwsTyped = verifierInfo.mapNotNull { it.parseJws() }.singleOrNull()
                    ?: throw IllegalArgumentException("Request must contain exactly one WRPRC")
                val registrationCertificate = WrpJwtRegistrationCertificate(jwsTyped = jwsTyped)
                val dcqlQuery = requireNotNull(request.payload.dcqlQuery) { "No DCQL query in request" }
                val wrpCredentialRequest = dcqlQuery.credentials.map { WrpDcqlCredentialQuery(it) }
                val accessCertificate = WrpAccessCertificate(request.jws.jwsHeader.certificateChain)

                WrpRequestData(
                    clientId = clientId,
                    accessCertificate = accessCertificate,
                    registrationCertificate = mapOf(registrationCertificate to wrpCredentialRequest),
                )
            }

            is RequestParametersFrom.OpenId4VpDcApiSigned -> {
                val dcqlQuery = requireNotNull(request.parameters.dcqlQuery) { "No DCQL query in request" }
                requireNotNull(request.parameters.clientId) { "No client_id in request" }
                val verifierInfo = requireNotNull(request.parameters.verifierInfo) { "No verifier_info in request" }
                val jwsTyped = verifierInfo.mapNotNull { it.parseJws() }.singleOrNull()
                    ?: throw IllegalArgumentException("Request must contain exactly one WRPRC")
                val registrationCertificate = WrpJwtRegistrationCertificate(jwsTyped = jwsTyped)
                val wrpCredentialRequest = dcqlQuery.credentials.map { WrpDcqlCredentialQuery(it) }
                val accessCertificate = WrpAccessCertificate(request.jwsTyped.jws.jwsHeader.certificateChain)

                WrpRequestData(
                    clientId = request.parameters.clientId,
                    accessCertificate = accessCertificate,
                    registrationCertificate = mapOf(registrationCertificate to wrpCredentialRequest)
                )
            }

            is RequestParametersFrom.IsoMdocDcApi -> {
                val deviceRequest = request.parameters.isoMdocRequest.deviceRequest
                // TODO: Verify readerAuth/readerAuthAll against the session transcript before trusting
                // the certificate chain asserted by the device request. A valid WRPAC chain alone
                // does not prove that its leaf key signed this request.
                val accessCertificateChain = deviceRequest.extractCertificateChain()
                val registrationCertificate: Map<WrpRegistrationCertificate, List<WrpCredentialRequest>> =
                    deviceRequest.docRequests.mapIndexed { _, docRequest ->
                        val euWrprcBytes = requireNotNull(docRequest.itemsRequest.value.requestInfo?.euWrprc) {
                            "Registration certificate missing in DocRequest $docRequest"
                        }
                        val euWrprc = coseCompliantSerializer.decodeFromByteArray<CoseSigned<ByteArray>>(euWrprcBytes)
                        val payload = parseCose(euWrprc = euWrprc)
                        val registrationCertificate = WrpCwtRegistrationCertificate(cose = euWrprc, payload = payload)
                        Pair(registrationCertificate, listOf(WrpCredentialRequest.WrpDocRequest(docRequest)))
                    }.groupBy({ it.first }, { it.second })
                        .mapValues { (_, listen) -> listen.flatten() }

                WrpRequestData(
                    accessCertificate = WrpAccessCertificate(accessCertificateChain),
                    registrationCertificate = registrationCertificate
                )
            }

            else -> throw IllegalArgumentException("Request not supported for validation: $this")
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
