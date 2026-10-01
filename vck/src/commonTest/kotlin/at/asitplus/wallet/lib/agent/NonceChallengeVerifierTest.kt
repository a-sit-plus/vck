package at.asitplus.wallet.lib.agent

import at.asitplus.testballoon.matrix.matrixSuite
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe

val NonceChallengeVerifierTest by matrixSuite {

    test("the challenge of a request is consumable exactly once") {
        val verifier = NonceChallengeVerifier(verifierId = "urn:${uuid4()}")
        val request = verifier.createPresentationRequest()

        verifier.consumeChallenge(request.nonce).challenge shouldBe request.nonce

        // a response is not retryable, and a challenge we never issued is not ours to consume
        shouldThrowAny { verifier.consumeChallenge(request.nonce) }
        shouldThrowAny { verifier.consumeChallenge("not one of ours") }
    }
}
