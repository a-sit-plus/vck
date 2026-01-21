package at.asitplus.wallet.lib.procedures.dcql

import at.asitplus.KmmResult
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import kotlin.jvm.JvmInline

@JvmInline
value class DCQLQueryAdapter(val dcqlQuery: DCQLQuery) {
    fun select(
        credentials: List<SubjectCredentialStore.StoreEntry>
    ): KmmResult<DCQLQueryResult<SubjectCredentialStore.StoreEntry>> = dcqlQuery.execute(
        availableCredentials = credentials,
        credentialFormatExtractor = { it.credentialFormat },
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
        jwtVcCredentialTypeExtractor = {
            if (it !is SubjectCredentialStore.StoreEntry.Vc) {
                throw IllegalArgumentException("Value is not an JWT-VC credential")
            }
            it.vc.vc.type.toList()
        },
        credentialClaimStructureExtractor = { storeEntry ->
            when (storeEntry) {
                is SubjectCredentialStore.StoreEntry.Iso -> DCQLCredentialClaimStructure.IsoMdocStructure(
                    storeEntry.issuerSigned.namespaces?.mapValues { entry ->
                        entry.value.entries.associate {
                            it.value.elementIdentifier to it.value.elementValue
                        }
                    } ?: mapOf()
                )

                else -> DCQLCredentialClaimStructure.JsonBasedStructure(
                    CredentialToJsonConverter.toJsonElement(storeEntry)
                )
            }
        }
    )
}