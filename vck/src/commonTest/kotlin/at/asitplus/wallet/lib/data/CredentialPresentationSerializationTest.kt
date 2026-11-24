package at.asitplus.wallet.lib.data

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestId
import at.asitplus.iso.DocRequestSubmissionOption
import at.asitplus.iso.ElementReference
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.IsoDeviceRetrieval
import at.asitplus.wallet.lib.data.rfc3986.toUri
import io.github.z4kn4fein.semver.Version
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

val CredentialPresentationSerializationTest by matrixSuite {
    val namespace = AtomicAttribute2023.isoNamespace

    "an ISO Device Retrieval presentation keeps its submissions by DocRequestId, its data elements as arrays" {
        val issuerSigned = IssuerAgent(
            keyMaterial = EphemeralKeyWithoutCert(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
        ).issueCredential(
            DummyCredentialDataProvider.getCredential(
                subjectPublicKey = EphemeralKeyWithoutCert().publicKey,
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
            ).getOrThrow()
        ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>().issuerSigned
        // Only a string data element, as decoding other values from JSON needs their registered serializers
        val credential = SubjectCredentialStore.StoreEntry.Iso(
            issuerSigned = IssuerSigned.fromIssuerSignedItems(
                namespacedItems = mapOf(
                    namespace to issuerSigned.namespaces.orEmpty().getValue(namespace).entries
                        .map { it.value }.filter { it.elementIdentifier == CLAIM_GIVEN_NAME }
                ),
                issuerAuth = issuerSigned.issuerAuth,
            ),
            schemeIdentifier = AtomicAttribute2023.isoDocType,
        )
        val request = IsoDeviceRetrieval(
            DeviceRequest(
                parsedVersion = Version(1, 0),
                docRequests = arrayOf(
                    DocRequest(
                        ByteStringWrapper(
                            ItemsRequest(
                                docType = AtomicAttribute2023.isoDocType,
                                namespaces = mapOf(
                                    namespace to ItemsRequestList(listOf(SingleItemsRequest(CLAIM_GIVEN_NAME, false)))
                                ),
                            )
                        )
                    )
                ),
            )
        )
        val presentation: CredentialPresentation = CredentialPresentation.IsoDeviceRetrievalPresentation(
            presentationRequest = request,
            docRequestSubmissions = mapOf(
                DocRequestId(0) to listOf(
                    DocRequestSubmissionOption(credential, listOf(ElementReference(namespace, CLAIM_GIVEN_NAME)))
                )
            ),
        )

        val serialized = joseCompliantSerializer.encodeToString(CredentialPresentation.serializer(), presentation)

        joseCompliantSerializer.parseToJsonElement(serialized).jsonObject["docRequestSubmissions"].shouldNotBeNull()
            .jsonObject.apply {
                keys shouldBe setOf("0")
                getValue("0").jsonArray.single().jsonObject["disclosedElements"] shouldBe
                        JsonArray(listOf(JsonArray(listOf(JsonPrimitive(namespace), JsonPrimitive(CLAIM_GIVEN_NAME)))))
            }
        // Compared as JSON, as an empty unprotected COSE header of the issued credential decodes as none
        joseCompliantSerializer.decodeFromString(CredentialPresentation.serializer(), serialized)
            .shouldBeInstanceOf<CredentialPresentation.IsoDeviceRetrievalPresentation>()
            .let { joseCompliantSerializer.encodeToString(CredentialPresentation.serializer(), it) } shouldBe serialized
    }

    "a data element without exactly a name space and an identifier is rejected" - {
        listOf("""["org.iso.18013.5.1"]""", """["org.iso.18013.5.1","family_name","age_over_18"]""").asData() test {
            shouldThrowAny {
                joseCompliantSerializer.decodeFromString(
                    DocRequestSubmissionOption.serializer(String.serializer()),
                    """{"credential":"credential","disclosedElements":[$it]}""",
                )
            }
        }
    }
}
