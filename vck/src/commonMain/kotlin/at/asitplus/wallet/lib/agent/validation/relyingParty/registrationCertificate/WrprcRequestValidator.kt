package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.etsi.relyingParty.WrpCredential
import at.asitplus.etsi.relyingParty.WrpCredentialMetaDomain
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.SingleClaimReference
import io.github.aakira.napier.Napier
import kotlinx.serialization.Serializable

fun interface WrprcRequestValidatorFun {
    suspend operator fun invoke(
        request: WrpCredentialRequest, payload: WrpPayload
    ): KmmResult<Pair<WrpCredentialRequest, RequestDataValidity>?>
}

/**
 * Class to validate a credential request against a registration certificates.
 * Validations:
 *  - Requested credential type
 *  - Requested attributes
 **/
class WrprcRequestValidator : WrprcRequestValidatorFun {
    override suspend fun invoke(
        request: WrpCredentialRequest, payload: WrpPayload
    ) = catching {
        request to payload.let { payload ->
            RequestDataValidity(
                credentialTypeValidity = checkCredentialTypesValidity(request, payload),
                credentialAttributesValidity = checkAttributesValidity(request, payload)
            )
        }
    }

    private suspend fun checkAttributesValidity(
        credentialRequest: WrpCredentialRequest, wrpPayload: WrpPayload
    ): RequestCredentialAttributesValidity = run {
        val attributes = credentialRequest.getAttributes() ?: run {
            throw Throwable("Unable to extract attributes from $credentialRequest")
        }
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
            is WrpCredentialMetaDomain.WrpDocTypeDomain -> metaList.any { meta ->
                catchingUnwrapped {
                    metadata.contains(meta.toDomain() as WrpCredentialMetaDomain.WrpDocTypeDomain)
                }.getOrDefault(false)
            }


            is WrpCredentialMetaDomain.WrpVctTypeDomain -> metaList.any { meta ->
                catchingUnwrapped {
                    metadata.contains(meta.toDomain() as WrpCredentialMetaDomain.WrpVctTypeDomain)
                }.getOrDefault(false)
            }

        }
    }

    private fun checkAttributes(
        wrpPayload: WrpPayload,
        representation: ConstantIndex.CredentialRepresentation,
        meta: WrpCredentialMetaDomain,
        attributes: Collection<SingleClaimReference>,
    ): RequestCredentialAttributesValidity {
        val entries = matchingCredentialEntries(wrpPayload, meta)
        val bestEntry = entries.maxByOrNull { entry -> attributes.count { entry.matchesAttribute(it, representation) } }
        return attributes.map { attribute ->
            attribute to (bestEntry?.matchesAttribute(attribute, representation) ?: false)
        }
    }

    private fun matchingCredentialEntries(
        wrpPayload: WrpPayload,
        meta: WrpCredentialMetaDomain,
    ): List<WrpCredential> = wrpPayload.credentials.filter { credential ->
        catchingUnwrapped {
            when (meta) {
                is WrpCredentialMetaDomain.WrpDocTypeDomain ->
                    (credential.meta.toDomain() as? WrpCredentialMetaDomain.WrpDocTypeDomain)
                        ?.let { meta.contains(it) } == true

                is WrpCredentialMetaDomain.WrpVctTypeDomain ->
                    (credential.meta.toDomain() as? WrpCredentialMetaDomain.WrpVctTypeDomain)
                        ?.let { meta.contains(it) } == true
            }
        }.getOrDefault(false)
    }

    private fun WrpCredential.matchesAttribute(
        attribute: SingleClaimReference,
        representation: ConstantIndex.CredentialRepresentation,
    ): Boolean = when (representation) {
        ISO_MDOC -> {
            val claim = attribute as? MdocClaimReference ?: return false
            this.claim.any { it.path == listOf(claim.namespace, claim.claimName) }
        }

        SD_JWT -> {
            val claim = attribute as? JsonClaimReference ?: return false
            val segments = claim.normalizedJsonPath.segments.map { (it as? NameSegment)?.memberName }
            if (segments.contains(null)) return false
            if (segments.lastOrNull() == "vct") return true
            this.claim.any { it.path == segments }
        }

        PLAIN_JWT -> false
    }

    private fun WrpCredentialMetaDomain.WrpDocTypeDomain.contains(other: WrpCredentialMetaDomain.WrpDocTypeDomain): Boolean =
        this.doctypeValue == other.doctypeValue

    private fun WrpCredentialMetaDomain.WrpVctTypeDomain.contains(other: WrpCredentialMetaDomain.WrpVctTypeDomain): Boolean =
        this.vctValues.any { other.vctValues.contains(it) }
}

typealias RequestCredentialAttributesValidity = List<Pair<SingleClaimReference, Boolean>>
typealias RequestDataValidation = List<Pair<WrpCredentialRequest, RequestDataValidity>>

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
    }

    is CredentialPresentationRequest.IsoDeviceRetrieval -> this.deviceRequest.docRequests.map {
        WrpCredentialRequest.WrpDocRequest(it)
    }

    else -> throw Throwable("Unsupported CredentialPresentationRequest $this")
}
