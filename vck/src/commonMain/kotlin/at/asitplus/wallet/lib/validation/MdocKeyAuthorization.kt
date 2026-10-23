package at.asitplus.wallet.lib.validation

import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.KeyAuthorization
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed

/**
 * Whether these `keyAuthorizations` of an MSO authorize its device key to authenticate every data element in
 * [deviceNameSpaces], i.e. every element an mdoc returns in `DeviceSigned`. An mdoc only authenticates elements its
 * key is authorized for, and the reader validates this as part of mdoc authentication (ISO/IEC 18013-5:2021, 9.1.3.4;
 * ISO/IEC DIS 18013-5 second edition, 12.8.2 step 1):
 *  - without `keyAuthorizations`, the device key is not restricted;
 *  - an authorized namespace authorizes every element of it, an authorized data element only itself;
 *  - if present, they must not be empty, and a namespace authorized as a whole must not be in `dataElements`
 *    (9.1.2.4), nor may one of their arrays be empty (`[+ NameSpace]`, `{+ NameSpace => [+ DataElementIdentifier]}`).
 */
// TODO `KeyAuthorizations` "shall contain all the elements the key may sign or MAC" (9.1.2.4; second edition, 12.3.4),
//  so without them no element would be authorized. They are not required yet, as e.g. the QES approval of
//  `QesApprovalBinding` is authenticated in `DeviceSigned` by issuers that do not authorize it.
internal fun KeyAuthorization?.authorizes(deviceNameSpaces: DeviceNameSpaces): CheckOutcome {
    if (this == null) return Passed
    malformation()?.let { return Failed(IllegalArgumentException(it)) }
    val unauthorized = deviceNameSpaces.entries
        .flatMap { (namespace, items) -> items.entries.map { namespace to it.key } }
        .filterNot { (namespace, element) -> authorizes(namespace, element) }
    return if (unauthorized.isEmpty()) Passed
    else Failed(
        IllegalArgumentException(
            "The device key is not authorized to authenticate " +
                    unauthorized.joinToString { (namespace, element) -> "$element in $namespace" }
        )
    )
}

private fun KeyAuthorization.authorizes(namespace: String, element: String): Boolean =
    namespaces?.contains(namespace) == true || dataElements?.get(namespace)?.contains(element) == true

/** Why these authorizations violate ISO/IEC 18013-5:2021, 9.1.2.4, or `null` if they do not. */
private fun KeyAuthorization.malformation(): String? = when {
    namespaces == null && dataElements == null -> "The keyAuthorizations of the MSO are empty"
    namespaces?.isEmpty() == true -> "The keyAuthorizations of the MSO authorize an empty array of namespaces"
    dataElements?.isEmpty() == true -> "The keyAuthorizations of the MSO authorize an empty map of data elements"
    dataElements?.values?.any { it.isEmpty() } == true ->
        "The keyAuthorizations of the MSO authorize an empty array of data elements of a namespace"

    namespaces?.any { dataElements?.containsKey(it) == true } == true ->
        "The keyAuthorizations of the MSO authorize a namespace both as a whole and per data element"

    else -> null
}
