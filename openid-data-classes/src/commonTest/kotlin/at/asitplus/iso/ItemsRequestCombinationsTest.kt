package at.asitplus.iso

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

private const val NAMESPACE = "org.iso.18013.5.1"
private const val DOC_TYPE = "org.iso.18013.5.1.mDL"

private fun element(name: String) = ElementReference(NAMESPACE, name)

private fun elements(vararg names: String) = names.map { element(it) }.toSet()

/** The `NameSpaces` requesting [names] in [NAMESPACE], in this order, retaining those of [retained]. */
private fun requesting(vararg names: String, retained: Set<String> = setOf()) =
    mapOf(NAMESPACE to ItemsRequestList(names.map { SingleItemsRequest(it, it in retained) }))

private val ItemsRequest.alternatives get() = requestInfo?.alternativeDataElements

val ItemsRequestCombinationsTest by matrixSuite {

    "requests" - {
        test("the first option, with the others as its alternatives (ISO/IEC DIS 18013-5:2026, 10.2.4)") {
            val options = listOf(elements("age_over_18"), elements("age_in_years"), elements("birth_date"))

            val itemsRequest = ItemsRequest.ofCombinations(DOC_TYPE, common = setOf(), options = options)

            itemsRequest.apply {
                docType shouldBe DOC_TYPE
                namespaces shouldBe requesting("age_over_18")
                alternatives shouldBe listOf(
                    AlternativeDataElementsSet(
                        requestedElement = element("age_over_18"),
                        alternativeElementSets = listOf(
                            listOf(element("age_in_years")),
                            listOf(element("birth_date")),
                        ),
                    )
                )
            }
        }

        test("the common data elements with the first option") {
            val options = listOf(elements("postal_code"), elements("locality", "region"))

            val itemsRequest = ItemsRequest.ofCombinations(DOC_TYPE, elements("family_name"), options)

            itemsRequest.apply {
                namespaces shouldBe requesting("family_name", "postal_code")
                alternatives shouldBe listOf(
                    AlternativeDataElementsSet(
                        requestedElement = element("postal_code"),
                        alternativeElementSets = listOf(listOf(element("locality"), element("region"))),
                    )
                )
            }
        }

        test("each data element of the first option with the other options as alternatives") {
            val options = listOf(elements("given_name", "family_name"), elements("full_name"))

            val itemsRequest = ItemsRequest.ofCombinations(DOC_TYPE, setOf(), options)

            itemsRequest.apply {
                namespaces shouldBe requesting("given_name", "family_name")
                alternatives shouldBe listOf(
                    AlternativeDataElementsSet(element("given_name"), listOf(listOf(element("full_name")))),
                    AlternativeDataElementsSet(element("family_name"), listOf(listOf(element("full_name")))),
                )
            }
        }

        test("the data elements all options share directly") {
            val options = listOf(elements("a", "b"), elements("a", "c"))

            val itemsRequest = ItemsRequest.ofCombinations(DOC_TYPE, setOf(), options)

            itemsRequest.apply {
                namespaces shouldBe requesting("a", "b")
                alternatives shouldBe listOf(AlternativeDataElementsSet(element("b"), listOf(listOf(element("c")))))
            }
        }

        test("options that overlap without a data element all of them share") {
            val options = listOf(elements("a", "b"), elements("b", "c"), elements("a", "c"))

            val itemsRequest = ItemsRequest.ofCombinations(DOC_TYPE, setOf(), options)

            val others = listOf(listOf(element("b"), element("c")), listOf(element("a"), element("c")))
            itemsRequest.apply {
                namespaces shouldBe requesting("a", "b")
                alternatives shouldBe listOf(
                    AlternativeDataElementsSet(element("a"), others),
                    AlternativeDataElementsSet(element("b"), others),
                )
            }
        }

        test("only an option every other one contains, as for data elements if available") {
            val options = listOf(elements("given_name", "portrait"), elements("given_name"))

            val itemsRequest = ItemsRequest.ofCombinations(DOC_TYPE, setOf(), options)

            itemsRequest.apply {
                namespaces shouldBe requesting("given_name")
                requestInfo shouldBe null
            }
        }

        test("a single option as it is") {
            val options = listOf(elements("given_name", "portrait"))

            val itemsRequest = ItemsRequest.ofCombinations(DOC_TYPE, elements("family_name"), options)

            itemsRequest.apply {
                namespaces shouldBe requesting("family_name", "given_name", "portrait")
                requestInfo shouldBe null
            }
        }
    }

    "retains" - {
        val options = listOf(elements("age_over_18"), elements("birth_date"))

        test("the data elements to retain, keeping the other values of the request info") {
            val intentToRetain = elements("family_name")

            val itemsRequest = ItemsRequest.ofCombinations(
                docType = DOC_TYPE,
                common = elements("family_name"),
                options = options,
                intentToRetain = intentToRetain,
                requestInfo = DocRequestInfo(uniqueDocSetRequired = true),
            )

            itemsRequest.apply {
                namespaces shouldBe requesting("family_name", "age_over_18", retained = setOf("family_name"))
                requestInfo.shouldNotBeNull().uniqueDocSetRequired shouldBe true
                alternatives.shouldNotBeNull().single().requestedElement shouldBe element("age_over_18")
            }
        }

        test("an alternative data element like the one it replaces") {
            val intentToRetain = elements("age_over_18", "birth_date", "issuing_country")

            val itemsRequest = ItemsRequest.ofCombinations(DOC_TYPE, setOf(), options, intentToRetain)

            itemsRequest.namespaces shouldBe requesting("age_over_18", retained = setOf("age_over_18"))
        }
    }

    "fails" - {
        test("without options") {
            val options = listOf<Set<ElementReference>>()

            shouldThrow<IllegalArgumentException> {
                ItemsRequest.ofCombinations(DOC_TYPE, elements("family_name"), options)
            }
        }

        test("if nothing is requested") {
            val options = listOf(elements("portrait"), setOf())

            shouldThrow<IllegalArgumentException> { ItemsRequest.ofCombinations(DOC_TYPE, setOf(), options) }
        }

        test("for an alternative data element retained differently than the one it replaces") {
            val options = listOf(elements("age_over_18"), elements("birth_date"))

            shouldThrow<IllegalArgumentException> {
                ItemsRequest.ofCombinations(DOC_TYPE, setOf(), options, intentToRetain = elements("birth_date"))
            }
        }

        test("for request info with alternatives of its own") {
            val alternatives = listOf(AlternativeDataElementsSet(element("age_over_18"), listOf(listOf(element("x")))))
            val requestInfo = DocRequestInfo(alternativeDataElements = alternatives)

            shouldThrow<IllegalArgumentException> {
                ItemsRequest.ofCombinations(
                    docType = DOC_TYPE,
                    common = setOf(),
                    options = listOf(elements("age_over_18")),
                    requestInfo = requestInfo,
                )
            }
        }
    }
}
