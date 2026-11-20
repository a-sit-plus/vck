package at.asitplus.iso

/**
 * Requests [common] and one of the [options], preferring earlier ones, like DCQL claim combinations
 * (OpenID4VP 1.0, 6.4.1): the first option is requested, and each of its data elements has the other options as
 * alternatives (ISO/IEC DIS 18013-5:2026, 10.2.4). Data elements that all options share are requested directly.
 * For example:
 *
 *  - `[age_over_18]`, `[age_in_years]`, `[birth_date]` requests `age_over_18` with the alternatives
 *    `[age_in_years]` and `[birth_date]`, the example of ISO/IEC DIS 18013-5:2026, 10.2.4
 *  - `[given_name, family_name]`, `[full_name]` requests both names, each with the alternative `[full_name]`
 *  - `[family_name, portrait]`, `[family_name]` requests only `family_name`
 *
 * The last case is the one ISO can not express exactly: an option that every other option contains, such as the
 * fallback of claims requested if available. ISO has no optional data elements, so only that option is requested,
 * which the verifier accepts, although it prefers more.
 *
 * Every response that satisfies the request contains one of the options, as it returns, for each data element of
 * the first option, either that element or all of another option. Alternative data elements are retained like the
 * one they replace, as "The intent_to_retain value of the requestedElement also applies to the alternative data
 * elements" (ibid.), so [intentToRetain] retaining them differently fails. Data elements of [intentToRetain] that are
 * not requested are ignored. The alternatives are added to [requestInfo], which must not have any of its own.
 *
 * Fails without [options], and if nothing is requested, as an `ItemsRequest` requests at least one data element
 * (`NameSpaces = {+ NameSpace => DataElements}`, ISO/IEC DIS 18013-5:2026, 10.2.3).
 */
fun ItemsRequest.Companion.ofCombinations(
    docType: String,
    common: Set<ElementReference>,
    options: List<Set<ElementReference>>,
    intentToRetain: Set<ElementReference> = setOf(),
    requestInfo: DocRequestInfo? = null,
): ItemsRequest {
    require(options.isNotEmpty()) {
        "At least one option of data elements is required"
    }
    require(requestInfo?.alternativeDataElements == null) {
        "The request info has alternative data elements already"
    }
    val shared = common + options.reduce { first, second -> first intersect second }
    val remaining = options.map { it - shared }.distinct()
    val firstOption = if (remaining.any { it.isEmpty() }) setOf() else remaining.first()
    val dataElements = shared + firstOption
    require(dataElements.isNotEmpty()) {
        "An ItemsRequest should request at least one data element, but none is requested here"
    }
    val alternatives = firstOption.map { element ->
        AlternativeDataElementsSet(
            requestedElement = element,
            alternativeElementSets = remaining.drop(1).map { it.toList() },
        )
    }
    alternatives.forEach { set ->
        val retained = set.requestedElement in intentToRetain
        val differently = set.alternativeElementSets.flatten().filter { (it in intentToRetain) != retained }
        require(differently.isEmpty()) {
            "The alternatives $differently are to be retained differently than ${set.requestedElement}"
        }
    }
    val namespaces = dataElements
        .groupBy(
            keySelector = { it.namespace },
            valueTransform = { SingleItemsRequest(it.dataElementIdentifier, it in intentToRetain) },
        )
        .mapValues { ItemsRequestList(it.value) }
    val info = when {
        alternatives.isEmpty() -> requestInfo
        requestInfo == null -> DocRequestInfo(alternativeDataElements = alternatives)
        else -> requestInfo.copy(alternativeDataElements = alternatives)
    }
    return ItemsRequest(docType = docType, namespaces = namespaces, requestInfo = info)
}
