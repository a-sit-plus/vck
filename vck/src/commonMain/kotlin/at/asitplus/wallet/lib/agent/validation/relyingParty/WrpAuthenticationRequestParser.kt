package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.KmmResult
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
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import io.github.aakira.napier.Napier
import kotlinx.serialization.decodeFromByteArray

fun interface WrpAuthenticationRequestValidatorFun {
    suspend operator fun invoke(request: RequestParametersFrom<*>): KmmResult<WrpRequestData>
}

class WrpAuthenticationRequestValidator : WrpAuthenticationRequestValidatorFun {
    override suspend fun invoke(request: RequestParametersFrom<*>) = catching {
        when (request) {
            is RequestParametersFrom.Jws<*> -> {
                (request.jwsTyped as? JwsTyped<JwsCompact, AuthenticationRequestParameters>)?.let { request ->
                    val clientId = request.payload.clientId ?: throw Throwable("client_id required but is null")
                    val verifierInfo =
                        request.payload.verifierInfo ?: throw Throwable("verifier_info required but is null")
                    val jwsTyped = verifierInfo.mapNotNull { parseJws(it) }.let {
                        if (it.size != 1) throw Throwable("Request must contain exactly one registration certificate")
                        it.first()
                    }

                    val registrationCertificate =
                        WrpRegistrationCertificate.WrpJwtRegistrationCertificate(jwsTyped = jwsTyped)

                    val wrpCredentialRequest = request.payload.dcqlQuery?.credentials?.map {
                        WrpCredentialRequest.WrpDcqlCredentialQuery(it)
                    } ?: throw Throwable("")


                    request.payload.dcqlQuery?.let {
                        WrpRequestData(
                            clientId = clientId,
                            accessCertificate = WrpAccessCertificate(request.jws.jwsHeader.certificateChain),
                            registrationCertificate = mapOf(registrationCertificate to wrpCredentialRequest),
                        )
                    }
                } ?: throw Throwable("Unable to cast request as JwsTyped<JwsCompact, AuthenticationRequestParameters>")
            }

            is RequestParametersFrom.OpenId4VpDcApiSigned -> {
                request.parameters.dcqlQuery?.let {
                    request.parameters.clientId ?: throw Throwable("client_id required but is null")

                    val verifierInfo =
                        request.parameters.verifierInfo ?: throw Throwable("verifier_info required but is null")
                    val jwsTyped = verifierInfo.mapNotNull { parseJws(it) }.let {
                        if (it.size != 1) throw Throwable("Request must contain exactly one registration certificate")
                        it.first()
                    }

                    val registrationCertificate =
                        WrpRegistrationCertificate.WrpJwtRegistrationCertificate(jwsTyped = jwsTyped)

                    val wrpCredentialRequest = it.credentials.map {
                        WrpCredentialRequest.WrpDcqlCredentialQuery(it)
                    }

                    WrpRequestData(
                        clientId = request.parameters.clientId,
                        accessCertificate = WrpAccessCertificate(request.jwsTyped.jws.jwsHeader.certificateChain),
                        registrationCertificate = mapOf(registrationCertificate to wrpCredentialRequest)
                    )
                } ?: throw Throwable("DcqlQuery is null")

            }

            is RequestParametersFrom.IsoMdocDcApi -> {

                val deviceRequest = request.parameters.isoMdocRequest.deviceRequest
                val accessCertificateChain = deviceRequest.extractCertificateChain()

                val registrationCertificate: Map<WrpRegistrationCertificate, List<WrpCredentialRequest>> =
                    deviceRequest.docRequests.associate {
                        val euWrprc = it.itemsRequest.value.requestInfo?.euWrprc
                            ?: throw Throwable("Registration certificate missing in DocRequest $it")
                        val payload = parseCose(euWrprc = euWrprc)
                        val registrationCertificate =
                            WrpRegistrationCertificate.WrpCwtRegistrationCertificate(cose = euWrprc, payload = payload)
                        Pair(registrationCertificate, listOf(WrpCredentialRequest.WrpDocRequest(it)))
                    }

                WrpRequestData(
                    accessCertificate = WrpAccessCertificate(accessCertificateChain),
                    registrationCertificate = registrationCertificate
                )
            }

            else -> {
                throw Throwable("Request not supported for validation $this")
            }
        }
    }

    fun parseJws(verifierInfo: VerifierInfo) = catching {
        if (!verifierInfo.format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true)) {
            Napier.w("skipping $this, expected '$REGISTRATION_CERT_FORMAT' but got '${verifierInfo.format}'.")
            return@catching null
        }
        val jwsTyped = catchingUnwrapped {
            JwsCompactTyped<WrpPayload>(verifierInfo.data)
        }.getOrElse {
            Napier.w("$this ($REGISTRATION_CERT_FORMAT) contains invalid JWS data.", throwable = it)
            return@catching null
        }
        jwsTyped
    }.getOrNull()

    fun parseCose(euWrprc: CoseSigned<ByteArray>): WrpPayload {
        val type = euWrprc.protectedHeader.type ?: throw IllegalArgumentException("Missing typ header in euWrprc.")
        if (type != "rc-wrp+cwt") {
            throw IllegalArgumentException("Invalid typ header in euWrprc: expected 'rc-wrp+cwt', got '$type'.")
        }

        val payloadBytes = euWrprc.payload ?: throw IllegalStateException("euWrprc payload not found.")
        return coseCompliantSerializer.decodeFromByteArray<WrpPayload>(bytes = payloadBytes)
    }
}