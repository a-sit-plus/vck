package at.asitplus.iso

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe

/**
 * ISO/IEC 18013-5:2021, 7.2.5
 */
val AgeAttestationTest by matrixSuite {

    /** Attestation statements present on the mDL of Table D.1, per actual holder age. */
    fun mdlOf(holderAge: Int): Map<String, Any?> = mapOf(
        "age_over_21" to (holderAge >= 21),
        "age_over_60" to (holderAge >= 60),
    )

    "Table D.1: requests answered by age_over_21 being TRUE" {
        listOf("age_over_18", "age_over_19", "age_over_20", "age_over_21").forEach { request ->
            listOf(21, 30, 60, 64).forEach { holderAge ->
                AgeAttestation.resolve(request, mdlOf(holderAge)) shouldBe "age_over_21"
            }
        }
    }

    "Table D.1: a 19 year old cannot answer requests below 21" {
        listOf("age_over_18", "age_over_19", "age_over_20").forEach { request ->
            AgeAttestation.resolve(request, mdlOf(19)).shouldBeNull()
        }
    }

    "Table D.1: a 19 year old answers age_over_21 with FALSE" {
        AgeAttestation.resolve("age_over_21", mdlOf(19)) shouldBe "age_over_21"
    }

    "Table D.1: requests between 21 and 60" {
        listOf("age_over_25", "age_over_30", "age_over_50").forEach { request ->
            // age_over_21 is FALSE and 21 <= NN, so step 2 answers
            AgeAttestation.resolve(request, mdlOf(19)) shouldBe "age_over_21"
            // nothing TRUE at or above NN, nothing FALSE at or below NN
            AgeAttestation.resolve(request, mdlOf(21)).shouldBeNull()
            AgeAttestation.resolve(request, mdlOf(30)).shouldBeNull()
            // age_over_60 is TRUE and 60 >= NN, so step 1 answers
            AgeAttestation.resolve(request, mdlOf(60)) shouldBe "age_over_60"
            AgeAttestation.resolve(request, mdlOf(64)) shouldBe "age_over_60"
        }
    }

    "Table D.1: age_over_60 is answered exactly" {
        listOf(19, 21, 30, 60, 64).forEach { holderAge ->
            AgeAttestation.resolve("age_over_60", mdlOf(holderAge)) shouldBe "age_over_60"
        }
    }

    "Table D.1: requests above 60" {
        listOf("age_over_63", "age_over_64", "age_over_65").forEach { request ->
            AgeAttestation.resolve(request, mdlOf(19)) shouldBe "age_over_60"
            AgeAttestation.resolve(request, mdlOf(21)) shouldBe "age_over_60"
            AgeAttestation.resolve(request, mdlOf(30)) shouldBe "age_over_60"
            AgeAttestation.resolve(request, mdlOf(60)).shouldBeNull()
            AgeAttestation.resolve(request, mdlOf(64)).shouldBeNull()
        }
    }

    "step 1 picks the nearest TRUE above the request, not the largest" {
        val mdl = mapOf(
            "age_over_18" to true,
            "age_over_25" to true,
            "age_over_30" to true,
            "age_over_65" to true,
        )
        AgeAttestation.resolve("age_over_23", mdl) shouldBe "age_over_25"
    }

    "step 2 picks the nearest FALSE below the request, not the smallest" {
        val mdl = mapOf(
            "age_over_18" to false,
            "age_over_21" to false,
        )
        AgeAttestation.resolve("age_over_23", mdl) shouldBe "age_over_21"
    }

    "step 1 wins over step 2" {
        val mdl = mapOf(
            "age_over_18" to false,
            "age_over_25" to true,
        )
        AgeAttestation.resolve("age_over_21", mdl) shouldBe "age_over_25"
    }

    "an exact match is returned as is" {
        AgeAttestation.resolve("age_over_18", mapOf("age_over_18" to true)) shouldBe "age_over_18"
        AgeAttestation.resolve("age_over_18", mapOf("age_over_18" to false)) shouldBe "age_over_18"
    }

    "a credential without any age attestation cannot answer" {
        AgeAttestation.resolve("age_over_18", mapOf("family_name" to "Mustermann")).shouldBeNull()
    }

    "non-boolean age attestations are ignored" {
        AgeAttestation.resolve("age_over_18", mapOf("age_over_21" to "true")).shouldBeNull()
    }

    "a non-age element is a plain presence check" {
        AgeAttestation.resolve("family_name", mapOf("family_name" to "Mustermann")) shouldBe "family_name"
        AgeAttestation.resolve("family_name", mapOf("given_name" to "Max")).shouldBeNull()
        // age_in_years and birth_date are not age attestations, they are ordinary elements
        AgeAttestation.resolve("age_in_years", mapOf("age_over_21" to true)).shouldBeNull()
    }

    "identifiers are parsed as defined in 7.2.5" {
        AgeAttestation.thresholdOf("age_over_00") shouldBe 0
        AgeAttestation.thresholdOf("age_over_99") shouldBe 99
        AgeAttestation.thresholdOf("age_over_8") shouldBe 8
        AgeAttestation.thresholdOf("age_over_100").shouldBeNull()
        AgeAttestation.thresholdOf("age_over_").shouldBeNull()
        AgeAttestation.thresholdOf("age_in_years").shouldBeNull()
        AgeAttestation.isAgeAttestation("age_over_18") shouldBe true
        AgeAttestation.isAgeAttestation("birth_date") shouldBe false
    }
}
