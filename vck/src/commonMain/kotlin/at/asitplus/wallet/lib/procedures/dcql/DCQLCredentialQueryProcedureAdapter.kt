package at.asitplus.wallet.lib.procedures.dcql

import at.asitplus.KmmResult
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import kotlin.jvm.JvmInline

@JvmInline
value class DCQLCredentialQueryAdapter(val dcqlCredentialQuery: DCQLCredentialQuery) {
    fun executeCredentialQueryAgainstCredential(
        credential: SubjectCredentialStore.StoreEntry,
    ): KmmResult<DCQLCredentialQueryMatchingResult> =
        dcqlCredentialQuery.executeCredentialQueryAgainstCredential(
            credential = credential,
            credentialFormatExtractor = {
                when (it) {
                    is SubjectCredentialStore.StoreEntry.Iso -> CredentialFormatEnum.MSO_MDOC
                    is SubjectCredentialStore.StoreEntry.SdJwt -> CredentialFormatEnum.VC_SD_JWT
                    is SubjectCredentialStore.StoreEntry.Vc -> CredentialFormatEnum.JWT_VC
                }
            },
            mdocCredentialDoctypeExtractor = {
                if (it !is SubjectCredentialStore.StoreEntry.Iso) {
                    throw IllegalArgumentException("Value is not an MDOC credential")
                }
                it.scheme!!.isoDocType!!
            },
            sdJwtCredentialTypeExtractor = {
                if (it !is SubjectCredentialStore.StoreEntry.SdJwt) {
                    throw IllegalArgumentException("Value is not an SD-JWT credential")
                }
                it.scheme!!.sdJwtType!!
            },
            credentialClaimStructureExtractor = {
                when (it) {
                    is SubjectCredentialStore.StoreEntry.Iso -> {
                        DCQLCredentialClaimStructure.IsoMdocStructure(
                            it.issuerSigned.namespaces?.mapValues {
                                it.value.entries.associate {
                                    it.value.elementIdentifier to it.value.elementValue
                                }
                            } ?: mapOf()
                        )
                    }

                    else -> DCQLCredentialClaimStructure.JsonBasedStructure(
                        CredentialToJsonConverter.toJsonElement(it)
                    )
                }
            }
        )
}

