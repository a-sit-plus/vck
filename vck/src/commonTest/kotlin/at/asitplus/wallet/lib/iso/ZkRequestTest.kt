package at.asitplus.wallet.lib.iso

import at.asitplus.iso.ZkRequest
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.testballoon.matrix.matrixSuite
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow

val ZkRequestTest by matrixSuite {
    "invalid ZkRequest: empty ZkSystemSpec list while zk is required" {
        shouldThrow<IllegalArgumentException> {
            ZkRequest(zkRequired = true, systemSpecs = emptyList())
        }
    }

    "invalid ZkRequest: identical ZkSystemSpec IDs" {
        shouldThrow<IllegalArgumentException> {
            val sameId = "same-id-${uuid4()}"

            ZkRequest(zkRequired = true, systemSpecs = listOf(
                ZkSystemSpec(id = sameId, system = uuid4().toString(), params = emptyMap()),
                ZkSystemSpec(id = sameId, system = uuid4().toString(), params = mapOf("something" to uuid4().toString()))
            ))
        }

    }
}