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
                disclosures = credential.loadDisclosures(disclosedAttributes),
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
                disclosures = credential.loadDisclosures(disclosedAttributes),
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
        disclosures: Set<String>,
    ): CreatePresentationResult.SdJwt {
        val keyBinding = createKeyBindingJws(request, SdJwtSigned.sdHashInput(validSdJwtCredential, disclosures))
        val issuerSignedJwsSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
        val issuerSignedJws =
            JwsSigned.deserialize(JsonElement.serializer(), issuerSignedJwsSerialized, vckJsonSerializer)
                .getOrElse { throw PresentationException(it) }
        val sdJwt = SdJwtSigned.presented(issuerSignedJws, disclosures, keyBinding)
        return CreatePresentationResult.SdJwt(sdJwt.serialize(), sdJwt)
    }

    private fun StoreEntry.SdJwt.loadDisclosures(
        disclosedAttributes: DCQLCredentialQueryMatchingResult
    ): Set<String> = when (disclosedAttributes) {
        AllClaimsMatchingResult -> disclosures.keys
        is ClaimsQueryResults -> loadDisclosures(disclosedAttributes.toRequestedSdJwtClaims(this))
    }

    private fun StoreEntry.SdJwt.loadDisclosures(
        requestedClaims: Collection<NormalizedJsonPath>
    ): Set<String> {
        val digest = sdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256
        val disclosuresByDigest = disclosures.entries.mapNotNull { disclosure ->
            disclosure.asHashedDisclosure(digest)?.let { it to disclosure }
        }.toMap()
        val issuerSignedJwsSerialized = vcSerialized.substringBefore("~")
        val payload = JwsSigned.deserialize(JsonElement.serializer(), issuerSignedJwsSerialized, vckJsonSerializer)
            .getOrElse { throw PresentationException(it) }
            .payload as? JsonObject
            ?: throw PresentationException("SD-JWT payload is not a JSON object")

        return requestedClaims.flatMapTo(mutableSetOf()) { claim ->
            payload.loadDisclosuresForPath(claim.segments, disclosuresByDigest)
        }
    }

    private fun JsonElement.loadDisclosuresForPath(
        segments: List<NormalizedJsonPathSegment>,
        disclosuresByDigest: Map<String, Map.Entry<String, SelectiveDisclosureItem?>>,
    ): Set<String> = when {
        segments.isEmpty() -> collectNestedDisclosures(disclosuresByDigest)
        this is JsonObject -> loadObjectDisclosuresForPath(segments, disclosuresByDigest)
        this is JsonArray -> loadArrayDisclosuresForPath(segments, disclosuresByDigest)
        else -> emptySet()
    }

    private fun JsonObject.loadObjectDisclosuresForPath(
        segments: List<NormalizedJsonPathSegment>,
        disclosuresByDigest: Map<String, Map.Entry<String, SelectiveDisclosureItem?>>,
    ): Set<String> = when (val firstSegment = segments.first()) {
        is NormalizedJsonPathSegment.NameSegment -> {
            get(firstSegment.memberName)?.loadDisclosuresForPath(segments.drop(1), disclosuresByDigest)
                ?: referencedDisclosures(disclosuresByDigest)
                    .firstOrNull { it.value?.claimName == firstSegment.memberName }
                    ?.let { disclosure ->
                        setOf(disclosure.key) + disclosure.nested(segments, disclosuresByDigest)
                    }
                ?: emptySet()
        }

        is NormalizedJsonPathSegment.IndexSegment -> emptySet()
    }

    private fun JsonArray.loadArrayDisclosuresForPath(
        segments: List<NormalizedJsonPathSegment>,
        disclosuresByDigest: Map<String, Map.Entry<String, SelectiveDisclosureItem?>>,
    ): Set<String> = when (val firstSegment = segments.first()) {
        is NormalizedJsonPathSegment.IndexSegment ->
            getOrNull(firstSegment.index.toInt())?.let { element ->
                element.asArrayDisclosureDigest()
                    ?.let(disclosuresByDigest::get)
                    ?.let { disclosure ->
                        setOf(disclosure.key) + disclosure.nested(segments, disclosuresByDigest)
                    }
                    ?: element.loadDisclosuresForPath(segments.drop(1), disclosuresByDigest)
            } ?: emptySet()

        is NormalizedJsonPathSegment.NameSegment -> emptySet()
    }

    private fun Map.Entry<String, SelectiveDisclosureItem?>.nested(
        segments: List<NormalizedJsonPathSegment>,
        disclosuresByDigest: Map<String, Map.Entry<String, SelectiveDisclosureItem?>>
    ): Iterable<String> = value?.claimValue?.loadDisclosuresForPath(
        segments.drop(1),
        disclosuresByDigest,
    ) ?: emptySet()

    private fun JsonElement.collectNestedDisclosures(
        disclosuresByDigest: Map<String, Map.Entry<String, SelectiveDisclosureItem?>>,
    ): Set<String> = when (this) {
        is JsonObject -> {
            val referencedDisclosures = referencedDisclosures(disclosuresByDigest)
            val nestedCleartextDisclosures = entries
                .filterNot { it.key == NAME_SD }
                .flatMapTo(mutableSetOf()) { it.value.collectNestedDisclosures(disclosuresByDigest) }
            val nestedReferencedDisclosures = referencedDisclosures.flatMapTo(mutableSetOf()) { disclosure ->
                setOf(disclosure.key) + (
                        disclosure.value?.claimValue?.collectNestedDisclosures(disclosuresByDigest) ?: emptySet()
                        )
            }
            nestedCleartextDisclosures + nestedReferencedDisclosures
        }

        is JsonArray -> flatMapTo(mutableSetOf()) { element ->
            element.asArrayDisclosureDigest()
                ?.let(disclosuresByDigest::get)
                ?.let { disclosure ->
                    setOf(disclosure.key) + (
                            disclosure.value?.claimValue?.collectNestedDisclosures(disclosuresByDigest) ?: emptySet()
                            )
                }
                ?: element.collectNestedDisclosures(disclosuresByDigest)
        }

        else -> emptySet()
    }

    private fun JsonObject.referencedDisclosures(
        disclosuresByDigest: Map<String, Map.Entry<String, SelectiveDisclosureItem?>>,
    ) = sdElements()?.strings()?.mapNotNull(disclosuresByDigest::get).orEmpty()

    private fun JsonElement.asArrayDisclosureDigest(): String? =
        (this as? JsonObject)?.get("...")?.let { it as? JsonPrimitive }?.content

    private fun Map.Entry<String, SelectiveDisclosureItem?>.asHashedDisclosure(digest: Digest): String? =
        value?.toDisclosure()?.hashDisclosure(digest)

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
