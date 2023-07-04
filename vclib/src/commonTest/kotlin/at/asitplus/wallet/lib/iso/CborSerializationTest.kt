package at.asitplus.wallet.lib.iso

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.utils.io.core.toByteArray
import io.matthewnelson.component.encoding.base16.decodeBase16ToArray
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.datetime.LocalDate

class CborSerializationTest : FreeSpec({

    "mDL" {
        val mdl = MobileDrivingLicence(
            familyName = "Mustermann",
            givenName = "Max",
            dateOfBirth = LocalDate.parse("1970-01-01"),
            issueDate = LocalDate.parse("2018-08-09"),
            expiryDate = LocalDate.parse("2024-10-20"),
            issuingCountry = "AT",
            issuingAuthority = "LPD Steiermark",
            licenceNumber = "A/3f984/019",
            portrait = "foo".toByteArray(),
            drivingPrivileges = arrayOf(
                DrivingPrivilege(
                    vehicleCategoryCode = "A",
                    issueDate = LocalDate.parse("2018-08-09"),
                    expiryDate = LocalDate.parse("2024-10-20")
                )
            ),
            unDistinguishingSign = "AT"
        )

        val serialized = mdl.serialize().encodeBase16().uppercase()
        println(serialized)

        serialized shouldContain "76656869636C655F63617465676F72795F636F6465" // "vehicle_category_code"
        serialized shouldContain "69737375655F64617465" // "issue_date"
        serialized shouldContain "323031382D30382D3039" // "2018-08-09"
        serialized shouldContain "6578706972795F64617465" // "expiry_date"
        serialized shouldContain "6578706972795" // "2024-10-20"
    }

    "Driving Privilege" {
        val drivingPrivilege = DrivingPrivilege(
            vehicleCategoryCode = "A",
            issueDate = LocalDate.parse("2018-08-09"),
            expiryDate = LocalDate.parse("2024-10-20")
        )

        val serialized = drivingPrivilege.serialize().encodeBase16().uppercase()
        println(serialized)

        serialized shouldContain "76656869636C655F63617465676F72795F636F6465" // "vehicle_category_code"
        serialized shouldContain "69737375655F64617465" // "issue_date"
        serialized shouldContain "D903EC" // ISO mDL defines tag(1004) for CBOR type 6 for full-dates
        serialized shouldContain "323031382D30382D3039" // "2018-08-09"
        serialized shouldContain "6578706972795F64617465" // "expiry_date"
        serialized shouldContain "6578706972795" // "2024-10-20"
    }

    "Driving Privilege Deserialization" {
        val input = "a37576656869636c655f63617465676f72795f636f646561416a69737375655f64617465d903ec6a323031382d30382d" +
                "30396b6578706972795f64617465d903ec6a323032342d31302d3230"

        val deserialized = DrivingPrivilege.deserialize(input.uppercase().decodeBase16ToArray()!!)

        deserialized.shouldNotBeNull()
        deserialized.vehicleCategoryCode shouldBe "A"
        deserialized.issueDate shouldBe LocalDate.parse("2018-08-09")
        deserialized.expiryDate shouldBe LocalDate.parse("2024-10-20")
    }

})
