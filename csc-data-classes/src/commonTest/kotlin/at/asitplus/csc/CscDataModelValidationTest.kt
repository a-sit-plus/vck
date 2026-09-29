package at.asitplus.csc

import at.asitplus.csc.datamodel.authorization.SignatureCreationApproval
import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SignatureFormat
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.basic.SignedEnvelopeProperty
import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentRepresentations
import at.asitplus.csc.datamodel.requests.CredentialDeletionRequest
import at.asitplus.csc.datamodel.requests.SignatureCreationRequest
import at.asitplus.csc.datamodel.requests.SignatureRequest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

private val validationJson = Json {
    encodeDefaults = false
    explicitNulls = false
}

private val sha256Oid = ObjectIdentifier("2.16.840.1.101.3.4.2.1")

val CscDataModelAssertionsTest by matrixSuite {
    test("AdES rejects envelope properties from a different signature format") {
        shouldThrow<IllegalArgumentException> {
            AdesParameters(
                signatureFormat = SignatureFormat.PADES,
                signedEnvelopeProperty = SignedEnvelopeProperty.ATTACHED,
            )
        }
    }

    test("credential deletion enforces the conditional revocation reason") {
        shouldThrow<IllegalArgumentException> { CredentialDeletionRequest("credential", revoke = true) }
        shouldThrow<IllegalArgumentException> {
            CredentialDeletionRequest("credential", revoke = true, revocationReason = 7)
        }
        CredentialDeletionRequest("credential", revoke = true, revocationReason = 1).revocationReason shouldBe 1
    }

    test("document representations require one or more non-empty hashes") {
        shouldThrow<IllegalArgumentException> { DocumentRepresentations(hashes = emptyList()) }
        shouldThrow<IllegalArgumentException> { DocumentRepresentations(hashes = listOf(byteArrayOf())) }
    }

    test("signature creation approval enforces its conditional and cardinality rules") {
        shouldThrow<IllegalArgumentException> {
            SignatureCreationApproval(
                numSignatures = 1,
                documentDigests = listOf(DocumentInfo(hash = byteArrayOf(1))),
                hashAlgorithmOid = sha256Oid,
            )
        }
        shouldThrow<IllegalArgumentException> {
            SignatureCreationApproval(
                signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
                numSignatures = 0,
                documentDigests = listOf(DocumentInfo(hash = byteArrayOf(1))),
                hashAlgorithmOid = sha256Oid,
            )
        }
        shouldThrow<IllegalArgumentException> {
            SignatureCreationApproval(
                signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
                numSignatures = 1,
                documentDigests = emptyList(),
                hashAlgorithmOid = sha256Oid,
            )
        }
    }

    test("flattened request serializers reject ambiguous document shapes") {
        shouldThrow<SerializationException> {
            validationJson.decodeFromString<SignatureCreationRequest>(
                """{
                    "document":"AQID",
                    "href":"https://example.com/contract.pdf",
                    "signAlgo":"1.2.840.10045.4.3.2"
                }""",
            )
        }
        shouldThrow<SerializationException> {
            validationJson.decodeFromString<SignatureRequest>(
                """{
                    "document":"AQID",
                    "href":"https://example.com/contract.pdf",
                    "signatureQualifier":"eu_eidas_qes"
                }""",
            )
        }
    }
}
