package at.asitplus.wallet.lib.agent

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: According to the W3C Verifiable Credential Data Model 1.1 https://www.w3.org/TR/vc-data-model-1.1/#jwt-encoding,
 * "iss MUST represent the issuer property of a verifiable credential or the holder property of a verifiable presentation."
 * So in this case the issuer is the wallet holder, represented by it's DID.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.sha256
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.ClaimsQueryResults
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SdJwtConstants.NAME_SD
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.extensions.sdHashInput
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import io.github.aakira.napier.Napier
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Clock

class VerifiablePresentationFactory(
    private val keyMaterial: KeyMaterial,
    private val signVerifiablePresentation: SignJwtFun<VerifiablePresentationJws> =
        SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signKeyBinding: SignJwtFun<KeyBindingJws> =
        SignJwt(keyMaterial, JwsHeaderNone()),
) {

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credentialAndDisclosedAttributes: Map<StoreEntry.Iso, Collection<NormalizedJsonPath>>,
    ): KmmResult<CreatePresentationResult> = catching {
        createIsoPresentation(
            request = request,
            credentialAndRequestedClaims = credentialAndDisclosedAttributes,
        )
    }

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: StoreEntry,
        disclosedAttributes: Collection<NormalizedJsonPath>,
    ): KmmResult<CreatePresentationResult> = catching {
        when (credential) {
            is StoreEntry.Vc -> createVcPresentation(
                request = request,
                validCredentials = listOf(credential),
            )

            is StoreEntry.SdJwt -> createSdJwtPresentation(
                request = request,
                validSdJwtCredential = credential,
                requestedClaims = disclosedAttributes,
            )

            is StoreEntry.Iso -> createIsoPresentation(
                request = request,
                credentialAndRequestedClaims = mapOf(credential to disclosedAttributes),
            )
        }
    }

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: StoreEntry,
        disclosedAttributes: DCQLCredentialQueryMatchingResult,
    ): KmmResult<CreatePresentationResult> = catching {
        when (credential) {
            is StoreEntry.Vc -> if (disclosedAttributes !is AllClaimsMatchingResult) {
                throw IllegalArgumentException("Credential type only allows disclosure of all attributes.")
            } else createVcPresentation(
                request = request,
                validCredentials = listOf(credential),
            )

            is StoreEntry.SdJwt -> createSdJwtPresentation(
                request = request,
                validSdJwtCredential = credential,
                requestedClaims = disclosedAttributes.toRequestedSdJwtClaims(credential),
            )

            is StoreEntry.Iso -> createIsoPresentation(
                request = request,
                credentialAndRequestedClaims = mapOf(credential to disclosedAttributes.toRequestedIsoClaims(credential)),
            )
        }
    }

    private fun DCQLCredentialQueryMatchingResult.toRequestedSdJwtClaims(
        credential: StoreEntry.SdJwt
    ): List<NormalizedJsonPath> = when (this) {
        AllClaimsMatchingResult -> credential.disclosures.entries.map {
            NormalizedJsonPath() + it.value!!.claimName!!
        }

        is ClaimsQueryResults -> this.claimsQueryResults.map {
            it as DCQLClaimsQueryResult.JsonResult
        }.flatMap {
            it.nodeList.map {
                it.normalizedJsonPath
            }
        }
    }

    private fun DCQLCredentialQueryMatchingResult.toRequestedIsoClaims(
        credential: StoreEntry.Iso,
    ) = when (this) {
        AllClaimsMatchingResult -> credential.issuerSigned.namespaces!!.entries.flatMap { namespace ->
            namespace.value.entries.map {
                NormalizedJsonPath() + namespace.key + it.value.elementIdentifier
            }
        }

        is ClaimsQueryResults -> claimsQueryResults.map {
            it as DCQLClaimsQueryResult.IsoMdocResult
        }.map {
            NormalizedJsonPath() + it.namespace + it.claimName
        }
    }

    private suspend fun createIsoPresentation(
        request: PresentationRequestParameters,
        credentialAndRequestedClaims: Map<StoreEntry.Iso, Collection<NormalizedJsonPath>>,
    ) = CreatePresentationResult.DeviceResponse(
        deviceResponse = DeviceResponse(
            version = "1.0",
            documents = credentialAndRequestedClaims.map { (credential, requestedClaims) ->
                credential.discloseRequestedClaims(requestedClaims, request)
            }.toTypedArray(),
            status = 0U,
        ),
    )

    // allows disclosure of attributes from different namespaces
    private suspend fun StoreEntry.Iso.discloseRequestedClaims(
        requestedClaims: Collection<NormalizedJsonPath>,
        request: PresentationRequestParameters,
    ): Document {
        // grouping by namespace and all requested claims for that namespace
        val namespaceToAttributesMap: Map<String, List<String>> = requestedClaims
            .mapNotNull { it.toIsoNamespaceAttribute() }
            .groupBy { it.first }
            .mapValues { it.value.map { it.second } }
        val disclosedItems = namespaceToAttributesMap.mapValues { entry ->
            entry.value.map {
                discloseItem(entry.key, it)
            }
        }

        val docType = scheme?.isoDocType
            ?: issuerSigned.issuerAuth.payload?.docType
            ?: throw PresentationException("Scheme not known or not registered")
        val deviceNameSpaceBytes = ByteStringWrapper(DeviceNameSpaces(mapOf()))
        val input = IsoDeviceSignatureInput(docType, deviceNameSpaceBytes)
        val deviceSignature = request.calcIsoDeviceSignaturePlain(input)
            ?: throw PresentationException("calcIsoDeviceSignature not implemented")

        return Document(
            docType = docType,
            issuerSigned = IssuerSigned.fromIssuerSignedItems(
                namespacedItems = disclosedItems,
                issuerAuth = issuerSigned.issuerAuth
            ),
            deviceSigned = DeviceSigned(
                namespaces = deviceNameSpaceBytes,
                deviceAuth = DeviceAuth(
                    deviceSignature = deviceSignature
                )
            )
        )
    }

    /** Returns map of first element (namespace) to second element (attribute name) */
    private fun NormalizedJsonPath.toIsoNamespaceAttribute() = with(firstTwoSegments()) {
        if (size == 2) {
            first().memberName to last().memberName
        } else {
            // Treating non-namespaced attributes as fields that are inherent to the credential for now
            //  -> no need for selective disclosure
            Napier.w("Not a namespaced attribute, ignoring: $this. This may be a bug.")
            null
        }
    }

    private fun NormalizedJsonPath.firstTwoSegments() = segments.take(2)
        .filterIsInstance<NormalizedJsonPathSegment.NameSegment>()

    private fun StoreEntry.Iso.discloseItem(
        namespace: String,
        attributeName: String
    ): IssuerSignedItem = issuerSigned.namespaces?.get(namespace)
        ?.entries?.find { it.value.elementIdentifier == attributeName }
        ?.value
        ?: throw PresentationException("Attribute not available in credential: $['$namespace']['$attributeName']")

    private suspend fun createSdJwtPresentation(
        request: PresentationRequestParameters,
        validSdJwtCredential: StoreEntry.SdJwt,
        requestedClaims: Collection<NormalizedJsonPath>,
    ): CreatePresentationResult.SdJwt {
        val disclosures = validSdJwtCredential.loadDisclosures(requestedClaims)
        val keyBinding = createKeyBindingJws(request, SdJwtSigned.sdHashInput(validSdJwtCredential, disclosures))
        val issuerSignedJwsSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
        val issuerSignedJws =
            JwsSigned.deserialize(JsonElement.serializer(), issuerSignedJwsSerialized, vckJsonSerializer)
                .getOrElse { throw PresentationException(it) }
        val sdJwt = SdJwtSigned.presented(issuerSignedJws, disclosures, keyBinding)
        return CreatePresentationResult.SdJwt(sdJwt.serialize(), sdJwt)
    }

    private fun StoreEntry.SdJwt.loadDisclosures(
        requestedClaims: Collection<NormalizedJsonPath>
    ): Set<String> {
        val nameSegments = requestedClaims.flatMap { it.segments }
            .filterIsInstance<NormalizedJsonPathSegment.NameSegment>()

        val disclosuresByName = nameSegments.mapNotNull { claim ->
            disclosures.entries.firstOrNull { it.value?.claimName == claim.memberName }
        }.toSet()

        // Inner disclosures when an object has been requested by name (above), but contains more _sd entries
        val innerDisclosures = disclosures.entries.filter { claim ->
            val digest = sdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256
            claim.asHashedDisclosure(digest)?.let { hashedDisclosure ->
                disclosuresByName.any { it.containsHashedDisclosure(hashedDisclosure) }
            } == true
        }.toSet()

        return (disclosuresByName.map { it.key } + innerDisclosures.map { it.key }).toSet()
    }

    private fun Map.Entry<String, SelectiveDisclosureItem?>.asHashedDisclosure(digest: Digest): String? =
        value?.toDisclosure()?.hashDisclosure(digest)

    private fun Map.Entry<String, SelectiveDisclosureItem?>.containsHashedDisclosure(hashDisclosure: String): Boolean =
        asJsonObject()?.sdElements()?.strings()?.any { it == hashDisclosure } == true

    private fun Map.Entry<String, SelectiveDisclosureItem?>.asJsonObject(): JsonObject? =
        (value?.claimValue as? JsonObject?)

    private fun JsonObject.sdElements(): JsonArray? = (get(NAME_SD) as? JsonArray?)

    private fun JsonArray.strings(): List<String> = mapNotNull { (it as? JsonPrimitive?)?.content }

    private suspend fun createKeyBindingJws(
        request: PresentationRequestParameters,
        hashInput: String,
    ): JwsSigned<KeyBindingJws> = signKeyBinding(
        JwsContentTypeConstants.KB_JWT,
        KeyBindingJws(
            issuedAt = Clock.System.now().truncateToSeconds(),
            audience = request.audience,
            challenge = request.nonce,
            sdHash = hashInput.encodeToByteArray().sha256(),
            transactionDataHashes = request.transactionData?.hash(request.transactionDataHashesAlgorithm),
            transactionDataHashesAlgorithmString = request.transactionDataHashesAlgorithm?.toIanaName(),
        ),
        KeyBindingJws.serializer(),
    ).getOrElse {
        throw PresentationException(it)
    }

    /**
     * Creates a [VerifiablePresentation] with the given [validCredentials].
     *
     * Note: The caller is responsible that only valid credentials are passed to this function!
     */
    suspend fun createVcPresentation(
        validCredentials: List<StoreEntry.Vc>,
        request: PresentationRequestParameters,
    ): CreatePresentationResult.VcJwsPresentationData = with(
        signVerifiablePresentation(
            JwsContentTypeConstants.JWT,
            VerifiablePresentation(validCredentials.map { it.vcSerialized }).toJws(
                request.nonce,
                keyMaterial.publicKey.didEncoded,
                request.audience
            ),
            VerifiablePresentationJws.serializer(),
        ).getOrElse {
            throw PresentationException(it)
        }) {
        CreatePresentationResult.VpJws(serialize(), this)
    }
}
