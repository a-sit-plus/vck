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
import at.asitplus.iso.ZkDocument
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.*
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SdJwtConstants.NAME_SD
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.extensions.sdHashInput
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.zk.iso.IsoMdocZkEngine
import io.github.aakira.napier.Napier
import io.github.z4kn4fein.semver.Version
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
    private val mdocZkEngine: IsoMdocZkEngine = IsoMdocZkEngine()
) {
    @Deprecated("Use createVerifiablePresentation(request, isoPresentationParameters) instead")
    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credentialAndDisclosedAttributes: Map<StoreEntry.Iso, Collection<NormalizedJsonPath>>,
    ): KmmResult<CreatePresentationResult.DeviceResponse> = createVerifiablePresentation(
        request = request,
        isoPresentationParameters = credentialAndDisclosedAttributes.map { (credential, claims) ->
            IsoPresentationParameters.create(credential, claims).getOrThrow()
        }
    )

    /**
     * Creates one Device Response while preserving every selected document and its order. A collection is used rather
     * than a map because one credential may satisfy more than one `DocRequest`.
     */
    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        isoPresentationParameters: Collection<IsoPresentationParameters>,
    ): KmmResult<CreatePresentationResult.DeviceResponse> = catching {
        createIsoPresentation(
            request = request,
            isoPresentationParameters = isoPresentationParameters,
        )
    }

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: StoreEntry,
        disclosedAttributes: Collection<NormalizedJsonPath>,
        zkMetadata: ZkMetadata? = null
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
                isoPresentationParameters = listOf(IsoPresentationParameters.create(
                    credential = credential,
                    claims = disclosedAttributes,
                    zkMetadata = zkMetadata
                ).getOrThrow()),
            )
        }
    }

    suspend fun createVerifiablePresentation(
        request: PresentationRequestParameters,
        credential: StoreEntry,
        disclosedAttributes: DCQLCredentialQueryMatchingResult,
        zkMetadata: ZkMetadata? = null
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
                isoPresentationParameters = listOf(IsoPresentationParameters.create(
                    credential, disclosedAttributes.toRequestedIsoClaims(credential), zkMetadata).getOrThrow()
                ),
            )
        }
    }

    private fun DCQLCredentialQueryMatchingResult.toRequestedSdJwtClaims(
        credential: StoreEntry.SdJwt
    ): List<NormalizedJsonPath> = when (this) {
        AllMandatoryClaimsMatchingResult -> emptyList()

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
        AllMandatoryClaimsMatchingResult -> emptyList()

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
        isoPresentationParameters: Collection<IsoPresentationParameters>,
    ): CreatePresentationResult.DeviceResponse {
        suspend fun disclosePlainDocument(param: IsoPresentationParameters) = param.credential
            .discloseRequestedClaims(param.claims, request)
            .getOrThrow()

        val plainDocuments = mutableListOf<Document>()
        val zkDocuments = mutableListOf<ZkDocument>()

        isoPresentationParameters.forEach { param ->
            val zkMetadata = param.zkMetadata
            if (zkMetadata is ZkMetadata.IsoMdocZk) {
                mdocZkEngine.generate(request, param).fold(
                    onSuccess = { zkDocuments += it.toZkDocument() },
                    onFailure = { error ->
                        if (zkMetadata.zkInfo.zkRequired) throw error
                        plainDocuments += disclosePlainDocument(param)
                    }
                )
            } else {
                plainDocuments += disclosePlainDocument(param)
            }
        }

        return CreatePresentationResult.DeviceResponse(
            deviceResponse = DeviceResponse(
                parsedVersion = Version(1, 0),
                documents = plainDocuments.toTypedArray(),
                zkDocuments = zkDocuments.toTypedArray(),
                status = 0u
            ),
        )
    }


    // allows disclosure of attributes from different namespaces
    private suspend fun StoreEntry.Iso.discloseRequestedClaims(
        requestedClaims: Collection<NormalizedJsonPath>,
        request: PresentationRequestParameters,
    ): KmmResult<Document> = catching {
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

        val deviceNameSpaceBytes = ByteStringWrapper(DeviceNameSpaces(mapOf()))
        val input = IsoDeviceSignatureInput(schemeIdentifier, deviceNameSpaceBytes)
        val deviceSignature = request.calcIsoDeviceSignaturePlain(input)
            ?: throw PresentationException("calcIsoDeviceSignature not implemented")

        Document(
            docType = schemeIdentifier,
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
        val digest = validSdJwtCredential.sdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256
        val digestInput = SdJwtSigned.sdHashInput(validSdJwtCredential, disclosures)
        val keyBinding = createKeyBindingJws(request, digestInput, digest)
        val issuerSignedJwsSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
        val issuerSignedJws =
            catching { JwsCompact(issuerSignedJwsSerialized) }
                .getOrElse { throw PresentationException(it) }
        val sdJwt = SdJwtSigned.presented(issuerSignedJws, disclosures, keyBinding)
        return CreatePresentationResult.SdJwt(sdJwt.serialize(), sdJwt)
    }

    private fun StoreEntry.SdJwt.loadDisclosures(
        disclosedAttributes: DCQLCredentialQueryMatchingResult
    ): Set<String> = when (disclosedAttributes) {
        AllMandatoryClaimsMatchingResult -> emptySet()
        AllClaimsMatchingResult -> disclosures.keys
        is ClaimsQueryResults -> loadDisclosures(disclosedAttributes.toRequestedSdJwtClaims(this))
    }

    private fun StoreEntry.SdJwt.loadDisclosures(
        requestedClaims: Collection<NormalizedJsonPath>
    ): Set<String> {
        val digest = sdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256
        // Hash the original serialized disclosure (the map key): re-serializing the parsed item may
        // produce different bytes than the issuer signed, e.g. for foreign issuers serializing with
        // whitespace, and digests are computed over the exact bytes (RFC 9901, section 4.2.3)
        val disclosuresByDigest = disclosures.entries.associateBy { it.key.hashDisclosure(digest) }
        val issuerSignedJwsSerialized = vcSerialized.substringBefore("~")
        val payload = JwsCompact(issuerSignedJwsSerialized).getPayload<JsonObject>()
            .getOrElse { throw PresentationException(it) }
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

    private fun JsonObject.sdElements(): JsonArray? = (get(NAME_SD) as? JsonArray?)

    private fun JsonArray.strings(): List<String> = mapNotNull { (it as? JsonPrimitive?)?.content }

    private suspend fun createKeyBindingJws(
        request: PresentationRequestParameters,
        hashInput: String,
        digest: Digest,
    ): JwsCompactTyped<KeyBindingJws> = signKeyBinding(
        JwsContentTypeConstants.KB_JWT,
        KeyBindingJws(
            issuedAt = Clock.System.now().truncateToSeconds(),
            audience = request.audience,
            challenge = request.nonce,
            sdHash = digest.digest(hashInput.encodeToByteArray()),
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
        CreatePresentationResult.VpJws(toString(), this)
    }
}
