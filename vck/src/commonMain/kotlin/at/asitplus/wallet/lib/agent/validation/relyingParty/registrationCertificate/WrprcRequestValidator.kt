package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.catchingUnwrapped
import at.asitplus.etsi.relyingParty.WrpCredentialMetaDomain
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.SingleClaimReference
import io.github.aakira.napier.Napier
import kotlinx.serialization.Serializable

typealias RequestCredentialAttributesValidity = List<Pair<SingleClaimReference, Boolean>>
typealias RequestDataValidationResult = Map<String, RequestDataValidity?>

@Serializable
data class RequestDataValidity(
    val credentialTypeValidity: Boolean,
    val credentialAttributesValidity: RequestCredentialAttributesValidity,
)

fun RequestDataValidity.isValid(): Boolean =
    this.credentialTypeValidity && !credentialAttributesValidity.any { it.second == false }

fun CredentialPresentationRequest.toWrpCredentialRequest() = when (this) {
    is DCQLRequest -> this.dcqlQuery.credentials.map {
        WrpCredentialRequest.WrpDcqlCredentialQuery(it)
    }.toSet()

    is CredentialPresentationRequest.IsoDeviceRetrieval -> this.deviceRequest.docRequests.map {
        WrpCredentialRequest.WrpDocRequest(it)
    }.toSet()

    else -> throw Throwable("Unsupported")
}

/**
 * Class to validate a presentation request against registration certificates.
 **/
class WrprcRequestValidator {
    suspend fun requestCheck(
        presentationRequest: CredentialPresentationRequest,
        verifierInfos: Set<VerifierInfo>,
    ): Result<RequestDataValidationResult> = catchingUnwrapped {
        matchRequestToVerifierInfo(presentationRequest, verifierInfos).mapNotNull { (request, verifierInfo) ->
            validateCredentialRequest(request, verifierInfo)
        }.toMap()
    }

    /**
     * Matches credential request to a corresponding registration certificate.
     * Falls back to a registration certificate (without a scope) which at least matches the credential type
     */
    private fun matchCredentialToVerifierInfo(
        request: WrpCredentialRequest,
        verifierInfos: Set<VerifierInfo>,
    ) = request.getMeta().let { meta ->
        request to when (request) {
            is WrpCredentialRequest.WrpDcqlCredentialQuery -> {
                verifierInfos.firstOrNull { it.credentialIds?.contains(request.query.id.string) == true } ?: run {
                    matchVerifierInfoFallback(meta, verifierInfos.filterUnscoped())
                }
            }

            is WrpCredentialRequest.WrpDocRequest -> {
                matchVerifierInfoFallback(meta, verifierInfos.filterUnscoped())
            }
        }
    }

    private fun Set<VerifierInfo>.filterUnscoped(): Set<VerifierInfo> =
        filterTo(mutableSetOf()) { it.credentialIds == null }

    private fun matchVerifierInfoFallback(
        queryMeta: WrpCredentialMetaDomain,
        verifierInfos: Set<VerifierInfo>,
    ) = when (queryMeta) {
        is WrpCredentialMetaDomain.WrpDocTypeDomain -> {
            verifierInfos.firstOrNull {
                it.getPayload()?.credentials?.any { credential ->
                    catchingUnwrapped {
                        queryMeta.contains(credential.meta.toDomain() as WrpCredentialMetaDomain.WrpDocTypeDomain)
                    }.getOrElse {
                        Napier.e("matchVerifierInfoFallback: failed to cast ${credential.meta}")
                        false
                    }
                } == true
            }
        }

        is WrpCredentialMetaDomain.WrpVctTypeDomain -> {
            verifierInfos.firstOrNull {
                it.getPayload()?.credentials?.any { credential ->
                    catchingUnwrapped {
                        queryMeta.contains(credential.meta.toDomain() as WrpCredentialMetaDomain.WrpVctTypeDomain)
                    }.getOrElse {
                        Napier.e("matchVerifierInfoFallback: failed to cast ${credential.meta}")
                        false
                    }
                } == true
            }
        }
    }


    private suspend fun validateCredentialRequest(
        request: WrpCredentialRequest, verifierInfo: VerifierInfo?
    ): Pair<String, RequestDataValidity?>? = catchingUnwrapped {
        request.id to verifierInfo?.getPayload()?.let { payload ->
            RequestDataValidity(
                credentialTypeValidity = checkCredentialTypesValidity(request, payload),
                credentialAttributesValidity = checkAttributesValidity(request, payload)
            )
        }
    }.getOrElse {
        Napier.w("WrprcRequestValidator.validateCredentialRequest failed with:", tag = LOG_TAG, throwable = it)
        null
    }

    private fun matchRequestToVerifierInfo(
        presentationRequest: CredentialPresentationRequest, verifierInfos: Set<VerifierInfo>
    ): Map<WrpCredentialRequest, VerifierInfo?> = presentationRequest.toWrpCredentialRequest().associate {
        matchCredentialToVerifierInfo(it, verifierInfos)
    }

    private suspend fun checkAttributesValidity(
        credentialRequest: WrpCredentialRequest, wrpPayload: WrpPayload
    ): RequestCredentialAttributesValidity = run {
        val attributes = credentialRequest.getAttributes()
        val meta = credentialRequest.getMeta()
        val representation = credentialRequest.getRepresentation()
        checkAttributes(wrpPayload, representation, meta, attributes)
    }

    private fun checkCredentialTypesValidity(
        credentialRequest: WrpCredentialRequest, wrpPayload: WrpPayload
    ): Boolean = checkCredentialTypes(credentialRequest.getMeta(), wrpPayload)

    private fun checkCredentialTypes(
        metadata: WrpCredentialMetaDomain, wrpPayload: WrpPayload
    ): Boolean = run {
        val metaList = wrpPayload.credentials.map {
            it.meta
        }
        when (metadata) {
            is WrpCredentialMetaDomain.WrpDocTypeDomain -> {
                metaList.any { meta ->
                    catchingUnwrapped {
                        metadata.contains(meta.toDomain() as WrpCredentialMetaDomain.WrpDocTypeDomain)
                    }.getOrDefault(false)
                }
            }

            is WrpCredentialMetaDomain.WrpVctTypeDomain -> {
                metaList.any { meta ->
                    catchingUnwrapped {
                        metadata.contains(meta.toDomain() as WrpCredentialMetaDomain.WrpVctTypeDomain)
                    }.getOrDefault(false)
                }
            }
        }
    }

    private fun checkAttributes(
        wrpPayload: WrpPayload,
        representation: ConstantIndex.CredentialRepresentation,
        meta: WrpCredentialMetaDomain,
        attributes: Collection<SingleClaimReference?>?
    ): RequestCredentialAttributesValidity = catchingUnwrapped {
        when (representation) {
            ISO_MDOC -> {
                val listCredentialDto = wrpPayload.credentials.filter {
                    catchingUnwrapped {
                        val meta = (meta as? WrpCredentialMetaDomain.WrpDocTypeDomain)?.doctypeValue
                        it.meta.doctypeValue == meta
                    }.getOrDefault(false)
                }
                attributes?.mapNotNull { attribute ->
                    val claim = attribute as? MdocClaimReference ?: return@mapNotNull null
                    val claimName = claim.claimName
                    attribute to (listCredentialDto.firstOrNull()?.claim?.any { it.path.contains(claimName) } ?: false)
                } ?: throw Throwable("checkAttributes: no claims match request")
            }

            SD_JWT -> {
                val listCredentialDto = wrpPayload.credentials.filter {
                    catchingUnwrapped {
                        val meta = (meta as? WrpCredentialMetaDomain.WrpVctTypeDomain)?.vctValues?.firstOrNull()
                        it.meta.vctValues?.contains(meta) ?: run {
                            Napier.w("Sd-jwt but vctValues null", tag = LOG_TAG)
                            return@catchingUnwrapped false
                        }
                    }.getOrDefault(false)
                }
                attributes?.mapNotNull { attribute ->
                    val claim = attribute as? JsonClaimReference ?: return@mapNotNull null
                    val claimName = (claim.normalizedJsonPath.segments.last() as NameSegment).memberName
                    if (claimName == "vct") return@mapNotNull null
                    attribute to (listCredentialDto.firstOrNull()?.claim?.any { it.path.contains(claimName) } ?: false)
                } ?: throw Throwable("checkAttributes: no claims match request")
            }

            PLAIN_JWT -> {
                TODO("PLAIN_JWT not supported")
            }
        }
    }.getOrElse { throw Throwable("checkAttributes: failed with $it") }

    private fun WrpCredentialMetaDomain.WrpDocTypeDomain.contains(other: WrpCredentialMetaDomain.WrpDocTypeDomain): Boolean =
        this.doctypeValue == other.doctypeValue

    private fun WrpCredentialMetaDomain.WrpVctTypeDomain.contains(other: WrpCredentialMetaDomain.WrpVctTypeDomain): Boolean =
        this.vctValues.any { other.vctValues.contains(it) }

    private companion object Constants {
        const val LOG_TAG = "WrprcRequestValidator"
    }
}

fun VerifierInfo.getPayload() = catchingUnwrapped { JwsCompactTyped<WrpPayload>(this.data).payload }.getOrNull()
