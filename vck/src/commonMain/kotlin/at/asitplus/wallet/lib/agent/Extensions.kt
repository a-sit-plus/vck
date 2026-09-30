package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.wrapInCborTag
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.digest
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.Base64URLTransactionDataSerializer
import at.asitplus.wallet.lib.data.SdJwtConstants
import io.ktor.util.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray

internal fun List<TransactionDataBase64Url>.hash(digest: Digest?): List<ByteArray> =
    map { transactionData -> transactionData.digest(digest ?: Digest.SHA256) }

internal fun getCommonHashesAlgorithms(transactionData: List<TransactionDataBase64Url>?): Set<String>? {
    val listOfSets = transactionData?.map {
        joseCompliantSerializer.decodeFromJsonElement(Base64URLTransactionDataSerializer, it).transactionDataHashAlgorithms
    }
    return if (listOfSets == null || listOfSets.any { it == null }) {
        null
    } else {
        listOfSets.filterNotNull()
            .reduceOrNull { acc, set -> acc intersect set }
            ?.takeIf { it.isNotEmpty() }
    }
}

@Throws(IllegalArgumentException::class)
fun Digest.toIanaName(): String =
    when (this) {
        Digest.SHA256 -> SdJwtConstants.SHA_256
        Digest.SHA384 -> SdJwtConstants.SHA_384
        Digest.SHA512 -> SdJwtConstants.SHA_512
        Digest.SHA1 -> throw IllegalArgumentException("SHA1 not supported")
    }

// see https://www.iana.org/assignments/named-information/named-information.xhtml
@Throws(IllegalArgumentException::class)
internal fun String?.toDigest(): Digest? =
    when (this?.toLowerCasePreservingASCIIRules()) {
        SdJwtConstants.SHA_256 -> Digest.SHA256
        SdJwtConstants.SHA_384 -> Digest.SHA384
        SdJwtConstants.SHA_512 -> Digest.SHA512
        null -> null
        else -> throw Exception("Unsupported digest name $this")
    }


/**
 * Returns a single [IssuerSignedItem] for the specified [namespace] and [attributeName],
 * wrapped in a [KmmResult]. Fails with [IllegalArgumentException] if the item is missing.
 */
fun SubjectCredentialStore.StoreEntry.Iso.discloseItem(
    namespace: String,
    attributeName: String
): KmmResult<IssuerSignedItem> = catching {
    issuerSigned.namespaces?.get(namespace)
        ?.entries?.find { it.value.elementIdentifier == attributeName }
        ?.value
        ?: throw IllegalArgumentException("Attribute not available in credential: $['$namespace']['$attributeName']")
}


/**
 * Encodes and signs an ISO 18013-5 [DeviceAuthentication] payload.
 *
 * @param input The device signature input parameters.
 * @param sessionTranscript The session transcript for the current transaction.
 * @return A [KmmResult] with the [ByteArray] payload, or a failure if encoding or signing fails.
 */
fun calculateIsoDeviceAuthenticationBytes(
    input: IsoDeviceSignatureInput,
    sessionTranscript: SessionTranscript,
): KmmResult<ByteArray> = catching {
    val deviceAuthentication = DeviceAuthentication(
        type = DeviceAuthentication.TYPE,
        sessionTranscript = sessionTranscript,
        docType = input.docType,
        namespaces = input.deviceNameSpaceBytes
    )
    coseCompliantSerializer
        .encodeToByteArray(ByteStringWrapper(deviceAuthentication))
        .wrapInCborTag(24)
}

/**
 * Signs the pre-encoded [DeviceAuthentication] payload using COSE detached signature.
 *
 * @param deviceAuthenticationBytes The encoded CBOR bytes of the [DeviceAuthentication] structure.
 * @param signDeviceAuthDetached Callback function that performs the COSE signature over the payload.
 * @return A [KmmResult] containing the signed [CoseSigned] structure, or a failure if signing fails.
 */
suspend fun calculateIsoDeviceSignature(
    deviceAuthenticationBytes: ByteArray,
    signDeviceAuthDetached: SignCoseDetachedFun<ByteArray>
) = signDeviceAuthDetached(
    protectedHeader = null,
    unprotectedHeader = null,
    payload = deviceAuthenticationBytes,
    serializer = ByteArraySerializer()
)


/** Returns map of first element (namespace) to second element (attribute name) */
fun NormalizedJsonPath.toIsoNamespaceAttribute() = with(firstTwoSegments()) {
    if (size == 2) {
        first().memberName to last().memberName
    } else {
        // Treating non-namespaced attributes as fields that are inherent to the credential for now
        //  -> no need for selective disclosure
        null
    }
}

private fun NormalizedJsonPath.firstTwoSegments() = segments.take(2)
    .filterIsInstance<NormalizedJsonPathSegment.NameSegment>()