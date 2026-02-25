package at.asitplus.wallet.lib.cbor

import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkDocumentData
import at.asitplus.iso.ZkSignedItem
import at.asitplus.iso.ZkSignedList
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.equals.shouldBeEqual
import kotlinx.datetime.LocalDate
import kotlinx.serialization.encodeToByteArray

val ZkDocumentSerializationTest by testSuite {

    "Serialize then Deserialize to get identity" {
        val doc = ZkDocument(
            ByteStringWrapper(
                ZkDocumentData(
                    docType = uuid4().toString(),
                    zkSystemId = uuid4().toString(),
                    timestamp = LocalDate.parse("2026-01-01"),
                    issuerSigned = mapOf(
                        uuid4().toString() to ZkSignedList(
                            mutableListOf(
                                ZkSignedItem(
                                    uuid4().toString(),
                                    uuid4().toString()
                                ),
                                ZkSignedItem(
                                    uuid4().toString(),
                                    uuid4().toString()
                                ),
                                ZkSignedItem(
                                    uuid4().toString(),
                                    uuid4().toString()
                                )
                            )
                        ),
                        uuid4().toString() to ZkSignedList(
                            mutableListOf(
                                ZkSignedItem(
                                    uuid4().toString(),
                                    uuid4().toString()
                                )
                            )
                        ),

                        ),
                    deviceSigned = mapOf(
                        uuid4().toString() to ZkSignedList(
                            mutableListOf(
                                ZkSignedItem(
                                    uuid4().toString(),
                                    uuid4().toString()
                                ),
                                ZkSignedItem(
                                    uuid4().toString(),
                                    uuid4().toString()
                                )
                            )
                        )
                    ),
                )
            ),
            proof = "test".encodeToByteArray()
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(doc)
        val deserialized = coseCompliantSerializer.decodeFromByteArray(ZkDocument.serializer(), serialized)

        doc shouldBeEqual deserialized
    }


}
