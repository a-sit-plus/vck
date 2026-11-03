package at.asitplus.etsi

import at.asitplus.testballoon.matrix.matrixSuite

val EtsiCountryCodeTest by matrixSuite {
    testSuite("accepts country codes, special values and codes found in published lists") {
        // C2 is used in https://development.trust.tech.ec.europa.eu/lists/eudiw/wallet-providers.json
        listOf("A", "AA", "EU", "UK", "EL", "C2").asData() test {
            EtsiCountryCode(it)
        }
    }
}
