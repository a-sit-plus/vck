package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.etsi.relyingParty.WrpCredentialMetaDomain
import at.asitplus.iso.DocRequest
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.IndexSegment
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLAmbiguousClaimsQuery
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.SingleClaimReference
import kotlinx.serialization.Serializable

/*
Sealed interface for supported request types to allow generic validation and serialized transport.
 */
@Serializable
sealed interface WrpCredentialRequest {
    fun getMeta(): WrpCredentialMetaDomain

    suspend fun getRepresentation(): CredentialRepresentation

    suspend fun getAttributes(): Collection<SingleClaimReference>

    @Serializable
    data class WrpDcqlCredentialQuery(val query: DCQLCredentialQuery) :
        WrpCredentialRequest {
        override fun getMeta(): WrpCredentialMetaDomain =
            when (val meta = this.query.meta) {
                is DCQLIsoMdocCredentialMetadataAndValidityConstraints -> WrpCredentialMetaDomain.WrpDocTypeDomain(meta.doctypeValue)
                is DCQLSdJwtCredentialMetadataAndValidityConstraints -> WrpCredentialMetaDomain.WrpVctTypeDomain(
                    vctValues = meta.vctValues.toNonEmptyList()
                )

                else -> throw IllegalStateException("Unsupported meta data ${this.query.meta}")
            }

        override suspend fun getRepresentation(): CredentialRepresentation = when (this.query.format) {
            CredentialFormatEnum.DC_SD_JWT -> SD_JWT
            CredentialFormatEnum.MSO_MDOC -> ISO_MDOC
            else -> PLAIN_JWT
        }

        override suspend fun getAttributes(): Collection<SingleClaimReference> = this.query.claims?.associateWith {
            when (it) {
                is DCQLJsonClaimsQuery -> JsonClaimReference(
                    NormalizedJsonPath(it.path.map {
                        when (it) {
                            is DCQLClaimsPathPointerSegment.IndexSegment -> IndexSegment(it.index)
                            is DCQLClaimsPathPointerSegment.NameSegment -> NameSegment(it.name)
                            DCQLClaimsPathPointerSegment.NullSegment -> null
                        }
                    }.takeWhile {
                        it != null
                    }.filterNotNull())
                )

                is DCQLIsoMdocClaimsQuery -> MdocClaimReference(namespace = it.namespace, claimName = it.claimName)

                is DCQLAmbiguousClaimsQuery -> throw IllegalStateException("Unsupported claims query format: $it")
            }
        }?.values ?: emptyList()
    }

    @Serializable
    data class WrpDocRequest(val query: DocRequest) : WrpCredentialRequest {
        override fun getMeta(): WrpCredentialMetaDomain =
            WrpCredentialMetaDomain.WrpDocTypeDomain(this.query.itemsRequest.value.docType)

        override suspend fun getRepresentation(): CredentialRepresentation = ISO_MDOC

        override suspend fun getAttributes(): Collection<SingleClaimReference> =
            this.query.itemsRequest.value.namespaces.flatMap { (namespace, itemsRequestList) ->
                itemsRequestList.entries.map {
                    MdocClaimReference(namespace = namespace, claimName = it.dataElementIdentifier)
                }
            }
    }

}
