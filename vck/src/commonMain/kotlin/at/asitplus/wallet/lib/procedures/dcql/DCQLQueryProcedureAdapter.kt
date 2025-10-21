package at.asitplus.wallet.lib.procedures.dcql

import at.asitplus.KmmResult
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLAuthorityKeyIdentifier
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.SdJwtSigned
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
        credentialClaimStructureExtractor = {
            when (it) {
                is SubjectCredentialStore.StoreEntry.Iso -> DCQLCredentialClaimStructure.IsoMdocStructure(
                    it.issuerSigned.namespaces?.mapValues {
                        it.value.entries.associate {
                            it.value.elementIdentifier to it.value.elementValue
                        }
                    } ?: mapOf()
                )

                else -> DCQLCredentialClaimStructure.JsonBasedStructure(CredentialToJsonConverter.toJsonElement(it))
            }
        },
        satisfiesCryptographicHolderBinding = {
            true // we currently assume all of our credentials to satisfy cryptographic holder binding
        },
        authorityKeyIdentifiers = {
            // TODO: how to extract authority key identifiers of corresponding valid certificate chain
            //  - are these even correct?
            when (it) {
                // TODO: correct key id?
                is SubjectCredentialStore.StoreEntry.Iso -> it.issuerSigned.issuerAuth.protectedHeader.certificateChain?.flatMap {
                    X509Certificate.decodeFromByteArray(it)?.toAuthorityKeyIdentifiers() ?: listOf()
                } ?: listOf()

                is SubjectCredentialStore.StoreEntry.SdJwt -> SdJwtSigned.parseCatching(
                    it.vcSerialized
                ).getOrThrow().jws.header.certificateChain?.flatMap {
                    it.toAuthorityKeyIdentifiers()
                } ?: listOf()

                is SubjectCredentialStore.StoreEntry.Vc -> JwsSigned.deserialize(
                    VerifiableCredentialJws.serializer(),
                    it.vcSerialized,
                    vckJsonSerializer
                ).getOrThrow().header.certificateChain?.flatMap {
                    it.toAuthorityKeyIdentifiers()
                } ?: listOf()
            }
        }
    )

    private fun X509Certificate.toAuthorityKeyIdentifiers() = tbsCertificate.extensions?.filter {
        // take all authority key identifiers from chain, assuming chain is validated elsewhere
        it.oid == authorityKeyIdentiferObjectIdentifier
    }?.map {
        DCQLAuthorityKeyIdentifier(it.value.asOctetString().content)
    } ?: listOf()
}

// source: https://www.alvestrand.no/objectid/2.5.29.35.html
@OptIn(ExperimentalUnsignedTypes::class)
private val authorityKeyIdentiferObjectIdentifier = ObjectIdentifier(2u, 5u, 29u, 35u)
