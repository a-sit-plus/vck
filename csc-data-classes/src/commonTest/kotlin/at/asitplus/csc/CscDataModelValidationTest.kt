package at.asitplus.csc

import at.asitplus.csc.datamodel.authorization.SignatureCreationApproval
import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SignatureFormat
import at.asitplus.csc.datamodel.basic.SignedEnvelopeProperty
import at.asitplus.csc.datamodel.documents.DocumentRepresentations
import at.asitplus.csc.datamodel.requests.CredentialDeletionRequest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val CscDataModelAssertionsTest by matrixSuite {

    test("AdES envelope properties are asserted against the signature format") {
        shouldThrow<IllegalArgumentException> {
            AdesParameters(
                signatureFormat = SignatureFormat.PADES,
                signedEnvelopeProperty = SignedEnvelopeProperty.ATTACHED,
            )
        }
    }

    test("credential deletion asserts RFC 5280 reason rules") {
        shouldThrow<IllegalArgumentException> { CredentialDeletionRequest("credential", revoke = true) }
        shouldThrow<IllegalArgumentException> {
            CredentialDeletionRequest("credential", revoke = true, revocationReason = 7)
        }
        CredentialDeletionRequest("credential", revoke = true, revocationReason = 1).revocationReason shouldBe 1
    }

    test("document representations assert one or more non-empty hashes") {
        shouldThrow<IllegalArgumentException> { DocumentRepresentations(hashes = emptyList()) }
        shouldThrow<IllegalArgumentException> { DocumentRepresentations(hashes = listOf(byteArrayOf())) }
    }

    test("approval asserts conditional fields and positive counts") {
        shouldThrow<IllegalArgumentException> {
            SignatureCreationApproval(
                numSignatures = 0,
                documentDigests = emptyList(),
                hashAlgorithmOid = ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
            )
        }
    }
}
