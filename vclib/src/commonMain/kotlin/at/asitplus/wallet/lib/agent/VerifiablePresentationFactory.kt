package at.asitplus.wallet.lib.agent

import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.dif.FieldQueryResults
import at.asitplus.wallet.lib.iso.DeviceAuth
import at.asitplus.wallet.lib.iso.DeviceSigned
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.IssuerSignedList
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlinx.serialization.cbor.ByteStringWrapper

class VerifiablePresentationFactory(
    private val jwsService: JwsService,
    private val coseService: CoseService,
    private val identifier: String,
) {
    suspend fun createVerifiablePresentation(
        challenge: String,
        audienceId: String,
        credential: SubjectCredentialStore.StoreEntry,
        fieldQueryResults: FieldQueryResults?,
    ): Holder.CreatePresentationResult? {
        val requestedClaims = fieldQueryResults?.mapNotNull { fieldQueryResult ->
            fieldQueryResult.value?.normalizedJsonPath
        }

        return when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> createVcPresentation(
                challenge = challenge,
                audienceId = audienceId,
                validCredentials = listOf(credential.vcSerialized)
            )

            is SubjectCredentialStore.StoreEntry.SdJwt -> createSdJwtPresentation(
                challenge = challenge,
                audienceId = audienceId,
                validSdJwtCredential = credential,
                requestedClaims = requestedClaims
            )

            is SubjectCredentialStore.StoreEntry.Iso -> createIsoPresentation(
                challenge = challenge,
                credential = credential,
                requestedClaims = requestedClaims
            )
        }
    }

    private suspend fun createIsoPresentation(
        challenge: String,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: List<NormalizedJsonPath>?
    ): Holder.CreatePresentationResult.Document? {
        val deviceSignature = coseService.createSignedCose(
            payload = challenge.encodeToByteArray(),
            addKeyId = false
        ).getOrNull() ?: return null
            .also { Napier.w("Could not create DeviceAuth for presentation") }

        // allows disclosure of attributes from different namespaces
        val namespaceToAttributesMap = requestedClaims?.mapNotNull { normalizedJsonPath ->
            // namespace + attribute
            val firstTwoNameSegments = normalizedJsonPath.segments.filterIndexed { index, _ ->
                // TODO: unsure how to deal with attributes with a depth of more than 2
                //  revealing the whole attribute for now, which is as fine grained as MDOC can do anyway
                index < 2
            }.filterIsInstance<NormalizedJsonPathSegment.NameSegment>()
            if (firstTwoNameSegments.size == 2) {
                val namespace = firstTwoNameSegments[0].memberName
                val attributeName = firstTwoNameSegments[1].memberName
                namespace to attributeName
            } else {
                // TODO: Not a namespaced attribute, how to deal with these?
                //  treating them as fields that are inherent to the credential for now
                //  -> no need for selective disclosure
                null
            }
        }?.groupBy {
            // grouping by namespace
            it.first
        }?.mapValues {
            // unrolling values to just the list of attribute names for that namespace
            it.value.map {
                it.second
            }
        }
        val disclosedItems = namespaceToAttributesMap?.mapValues { namespaceToAttributeNamesEntry ->
            val namespace = namespaceToAttributeNamesEntry.key
            val attributeNames = namespaceToAttributeNamesEntry.value
            IssuerSignedList(attributeNames.map { attributeName ->
                credential.issuerSigned.namespaces?.get(
                    namespace
                )?.entries?.find {
                    it.value.elementIdentifier == attributeName
                } ?: throw AttributeNotAvailableException(credential, namespace, attributeName)
            })
        }

        return Holder.CreatePresentationResult.Document(
            Document(
                docType = credential.scheme.isoDocType!!,
                issuerSigned = IssuerSigned(
                    namespaces = disclosedItems,
                    issuerAuth = credential.issuerSigned.issuerAuth
                ),
                deviceSigned = DeviceSigned(
                    namespaces = byteArrayOf(),
                    deviceAuth = DeviceAuth(
                        deviceSignature = deviceSignature
                    )
                )
            )
        )
    }

    private suspend fun createSdJwtPresentation(
        audienceId: String,
        challenge: String,
        validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
        requestedClaims: List<NormalizedJsonPath>?
    ): Holder.CreatePresentationResult.SdJwt? {
        val keyBindingJws = KeyBindingJws(
            issuedAt = Clock.System.now(),
            audience = audienceId,
            challenge = challenge
        )
        val jwsPayload = keyBindingJws.serialize().encodeToByteArray()
        val keyBinding = jwsService.createSignedJwsAddingParams(
            header = JwsHeader(
                type = JwsContentTypeConstants.KB_JWT,
                algorithm = jwsService.algorithm,
            ),
            payload = jwsPayload,
            addKeyId = true,
            addJsonWebKey = true,
            addX5c = false
        ).getOrElse {
            Napier.w("Could not create JWS for presentation", it)
            return null
        }
        val filteredDisclosures = validSdJwtCredential.disclosures
            .filter {
                it.discloseItem(requestedClaims?.mapNotNull { claimPath ->
                    // TODO: unsure how to deal with attributes with a depth of more than 1 (if they even should be supported)
                    //  revealing the whole attribute for now, which is as fine grained as SdJwt can do anyway
                    claimPath.segments.firstOrNull()?.let {
                        when (it) {
                            is NormalizedJsonPathSegment.NameSegment -> it.memberName
                            is NormalizedJsonPathSegment.IndexSegment -> null // can't disclose index
                        }
                    }
                })
            }.keys
        val sdJwt =
            (listOf(validSdJwtCredential.vcSerialized.substringBefore("~")) + filteredDisclosures + keyBinding.serialize())
                .joinToString("~")
        return Holder.CreatePresentationResult.SdJwt(sdJwt)
    }


    private fun Map.Entry<String, SelectiveDisclosureItem?>.discloseItem(requestedClaims: Collection<String>?): Boolean {
        // do not disclose by default
        return if (requestedClaims == null) {
            false
        } else {
            value?.let { it.claimName in requestedClaims } ?: false
        }
    }

    private fun ByteStringWrapper<IssuerSignedItem>.discloseItem(requestedClaims: Collection<String>?) =
        if (requestedClaims?.isNotEmpty() == true) {
            value.elementIdentifier in requestedClaims
        } else {
            true
        }

    /**
     * Creates a [VerifiablePresentation] with the given [validCredentials].
     *
     * Note: The caller is responsible that only valid credentials are passed to this function!
     */
    suspend fun createVcPresentation(
        validCredentials: List<String>,
        challenge: String,
        audienceId: String,
    ): Holder.CreatePresentationResult? {
        val vp = VerifiablePresentation(validCredentials)
        val vpSerialized = vp.toJws(challenge, identifier, audienceId).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val jws = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload).getOrElse {
            Napier.w("Could not create JWS for presentation", it)
            return null
        }
        return Holder.CreatePresentationResult.Signed(jws.serialize())
    }
}