package at.asitplus.wallet.lib.zk.iso

import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.iso.wrapInCborTag
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.agent.IsoDeviceSignatureInput
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import io.github.aakira.napier.Napier
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.zkp.ZkSystemParamValue
import org.multipaz.request.MdocRequestedClaim
import org.multipaz.mdoc.zkp.ZkSystemSpec as MultipazZkSystemSpec
import org.multipaz.mdoc.zkp.ZkDocument as MultipazZkDocument

internal fun MultipazZkDocument.toZkDocument(): ZkDocument =
    coseCompliantSerializer.decodeFromByteArray(Cbor.encode(toDataItem()))

internal fun ZkDocument.toMultipazZkDocument(): MultipazZkDocument =
    MultipazZkDocument.fromDataItem(Cbor.decode(coseCompliantSerializer.encodeToByteArray(this)))


internal fun MultipazZkSystemSpec.copyWithParameters(
    id: String = this.id,
    system: String = this.system,
): MultipazZkSystemSpec {
    return MultipazZkSystemSpec(id = id, system = system).also { newSpec ->
        this.params.forEach { (key, value) ->
            when (value) {
                is ZkSystemParamValue.StringValue -> newSpec.addParam(key, value.value)
                is ZkSystemParamValue.LongValue -> newSpec.addParam(key, value.value)
                is ZkSystemParamValue.DoubleValue -> newSpec.addParam(key, value.value)
                is ZkSystemParamValue.BooleanValue -> newSpec.addParam(key, value.value)
            }
        }
    }
}
fun SessionTranscript.toMultipazSessionTranscript(): DataItem {
    val serialized = coseCompliantSerializer.encodeToByteArray(this)
    return Cbor.decode(serialized)
}

suspend fun Document.toMultipazDocument(): MdocDocument {
    val serializedZkDocument = coseCompliantSerializer.encodeToByteArray(this)
    return MdocDocument.fromDataItem(Cbor.decode(serializedZkDocument))
}

internal suspend fun StoreEntry.Iso.discloseRequestedClaims(
    requestedClaims: Collection<NormalizedJsonPath>,
    sessionTranscript: SessionTranscript,
    signDeviceAuthDetached: at.asitplus.wallet.lib.cbor.SignCoseDetachedFun<ByteArray>
): Document {
    val claimsByNamespace = requestedClaims
        .map { it.toIsoNamespaceAttribute() }
        .groupBy({ it.first }, { it.second })

    require(claimsByNamespace.size == 1) {
        "All requested claims must belong to the same namespace for Longfellow-ZK compatibility."
    }

    val disclosedItems = claimsByNamespace.mapValues { (ns, claims) ->
        claims.map { discloseItem(ns, it) }
    }

    val deviceNameSpaceBytes = ByteStringWrapper(DeviceNameSpaces(emptyMap()))
    val input = IsoDeviceSignatureInput(schemeIdentifier, deviceNameSpaceBytes)

    val deviceSignature = calculateDeviceSignature(
        input,
        sessionTranscript,
        signDeviceAuthDetached
    )

    return Document(
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

private suspend fun calculateDeviceSignature(
    input: IsoDeviceSignatureInput,
    sessionTranscript: SessionTranscript,
    signDeviceAuthDetached: at.asitplus.wallet.lib.cbor.SignCoseDetachedFun<ByteArray>
):  CoseSigned<ByteArray> {
    val deviceAuthentication = DeviceAuthentication(
        type = DeviceAuthentication.TYPE,
        sessionTranscript = sessionTranscript,
        docType = input.docType,
        namespaces = input.deviceNameSpaceBytes
    )
    val deviceAuthenticationBytes = coseCompliantSerializer
        .encodeToByteArray(ByteStringWrapper(deviceAuthentication))
        .wrapInCborTag(24)
    Napier.d("Device authentication signature input is ${deviceAuthenticationBytes.toHexString()}")
    return signDeviceAuthDetached(
        protectedHeader = null,
        unprotectedHeader = null,
        payload = deviceAuthenticationBytes,
        serializer = ByteArraySerializer()
    ).getOrElse { e ->
        Napier.w("Could not create DeviceAuth for presentation", e)
        throw PresentationException(e)
    }
}

private fun StoreEntry.Iso.discloseItem(
    namespace: String,
    attributeName: String
): IssuerSignedItem = issuerSigned.namespaces?.get(namespace)
    ?.entries?.find { it.value.elementIdentifier == attributeName }
    ?.value
    ?: throw PresentationException("Attribute not available in credential: $['$namespace']['$attributeName']")


private fun NormalizedJsonPath.toIsoNamespaceAttribute(): Pair<String, String> {
    require(segments.size == 2 && segments.all { it is NormalizedJsonPathSegment.NameSegment }) {
        "Path must strictly consist of a namespace and an attribute element name: $this"
    }
    val namespace = (segments[0] as NormalizedJsonPathSegment.NameSegment).memberName
    val attribute = (segments[1] as NormalizedJsonPathSegment.NameSegment).memberName
    return namespace to attribute
}

internal fun MultipazZkSystemSpec.toZkSystemSpec() = ZkSystemSpec(
    id = id,
    system = system,
    params = params.entries.associate { (key, paramValue) ->
        key to when (paramValue) {
            is ZkSystemParamValue.BooleanValue -> paramValue.value
            is ZkSystemParamValue.StringValue -> paramValue.value
            is ZkSystemParamValue.DoubleValue -> paramValue.value
            is ZkSystemParamValue.LongValue -> paramValue.value
        }
    }
)

internal fun ZkSystemSpec.toMultipazZkSystemSpec(): MultipazZkSystemSpec = MultipazZkSystemSpec(id, system).also { spec ->
    params.forEach { (key, value) ->
        when (value) {
            is String -> spec.addParam(key, value)
            is Boolean -> spec.addParam(key, value)
            is Double -> spec.addParam(key, value)
            is Float -> spec.addParam(key, value.toDouble())
            is Long -> spec.addParam(key, value)
            is Int -> spec.addParam(key, value.toLong())
            is Short -> spec.addParam(key, value.toLong())
            is Byte -> spec.addParam(key, value.toLong())
            else -> throw IllegalArgumentException(
                "Cannot convert to Multipaz ZkSystemSpec due to unsupported parameter value type: " +
                        "${value::class.simpleName ?: value::class} for key '$key'"
            )
        }
    }
}

internal fun NormalizedJsonPath.toMdocRequestedClaim(
    docType: String,
): MdocRequestedClaim {
    require(segments.size == 2 && segments.all { it is NormalizedJsonPathSegment.NameSegment }) {
        "Expected an mdoc claim path with a namespace and data element: $this"
    }

    val (namespaceName, dataElementName) = segments
        .map { (it as NormalizedJsonPathSegment.NameSegment).memberName }

    return MdocRequestedClaim(
        docType = docType,
        namespaceName = namespaceName,
        dataElementName = dataElementName,
        intentToRetain = false, // TODO: Consider using the actual value instead of a place holder "false"
    )
}
