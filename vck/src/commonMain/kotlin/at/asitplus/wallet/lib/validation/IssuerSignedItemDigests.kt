package at.asitplus.wallet.lib.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.ValueDigestList
import at.asitplus.iso.wrapInCborTag
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer

/**
 * Whether the digest of this issuer-signed item, over its encoded bytes, equals the digest the MSO signs for its
 * digest ID in [valueDigests] of its namespace, computed with [digest] (ISO/IEC 18013-5:2021, 9.3.1 *Inspection
 * procedure for issuer data authentication*). A missing digest ID does not match.
 */
internal fun ByteStringWrapper<IssuerSignedItem>.matchesDigest(
    valueDigests: ValueDigestList?,
    digest: Digest,
): Boolean {
    val issuerHash = valueDigests?.entries?.firstOrNull { it.key == value.digestId } ?: return false
    // The digest is over IssuerSignedItemBytes, i.e. the item wrapped in CBOR tag 24 (0xD818)
    // TODO Only true in AgentIsoMdocTest when we are not deserializing the ByteStringWrapper in the issuerSignedItems
    val input = if (serialized.encodeToString(Base16Strict).uppercase().startsWith("D818")) serialized
    else coseCompliantSerializer.encodeToByteArray(ByteArraySerializer(), serialized).wrapInCborTag(24)
    return digest.digest(input).contentEquals(issuerHash.value)
}

/**
 * One [DisclosedItemValidation] for every issuer-signed item supplied in [issuerSigned], in the order supplied:
 * the item matches its digest in [mso] (a missing digest ID fails like a mismatching digest), and no digest ID or
 * element identifier is supplied twice in a namespace. Items are decoded with the [IssuerSigned] they belong to, so
 * their parsing passed.
 */
internal fun validateIssuerSignedItems(
    issuerSigned: IssuerSigned,
    mso: MobileSecurityObject,
): List<DisclosedItemValidation> = issuerSigned.namespaces.orEmpty().flatMap { (namespace, items) ->
    val seenDigestIds = mutableSetOf<UInt>()
    val seenElements = mutableSetOf<String>()
    items.entries.map { item ->
        val digest = if (item.matchesDigest(mso.valueDigests[namespace], mso.digest)) Passed
        else Failed(IllegalArgumentException("The item does not match the digest the issuer signed"))
        val unique = seenDigestIds.add(item.value.digestId) and seenElements.add(item.value.elementIdentifier)
        DisclosedItemValidation(
            reference = DisclosedItemReference.Mdoc(namespace, item.value.elementIdentifier, item.value.digestId),
            parsing = Passed,
            digest = digest,
            structure = if (unique) Passed
            else Failed(IllegalArgumentException("The digest ID or element identifier is supplied more than once")),
        )
    }
}
