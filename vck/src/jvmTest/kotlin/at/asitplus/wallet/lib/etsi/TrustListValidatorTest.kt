package at.asitplus.wallet.lib.etsi

import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe


val TrustListValidatorTest by matrixSuite {

    val trustAnchorPem = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDRzCCAi+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRTELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFTATBgNVBAMT\n" +
            "DFRydXN0IEFuY2hvcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALmZ\n" +
            "UYkRR+DNRbmEJ4ITAhbNRDmqrNsJw97iLE7bpFeflDUoNcJrZPZbC208bG+g5M0A\n" +
            "TzV0vOqg88Ds1/FjFDK1oPItqsiDImJIq0xb/et5w72WNPxHVrcsr7Ap6DHfdwLp\n" +
            "NMncqtzX92hU/iGVHLE/w/OCWwAIIbTHaxdrGMUG7DkJJ6iI7mzqpcyPvyAAo9O3\n" +
            "SHjJr+uw5vSrHRretnV2un0bohvGslN64MY/UIiRnPFwd2gD76byDzoM1ioyLRCl\n" +
            "lfBJ5sRDz9xrUHNigTAUdlblb6yrnNtNJmkrROYvkh6sLETUh9EYh0Ar+94fZVXf\n" +
            "GVi57Sw7x1jyANTlA40CAwEAAaNCMEAwHQYDVR0OBBYEFOR9X9FclYYILAWuvnW2\n" +
            "ZafZXahmMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n" +
            "DQEBCwUAA4IBAQCYoa9uR55KJTkpwyPihIgXHq7/Z8dx3qZlCJQwE5qQBZXIsf5e\n" +
            "C8Va/QjnTHOC4Gt4MwpnqqmoDqyqSW8pBVQgAUFAXqO91nLCQb4+/yfjiiNjzprp\n" +
            "xQlcqIZYjJSVtckH1IDWFLFeuGW+OgPPEFgN4hjU5YFIsE2r1i4+ixkeuorxxsK1\n" +
            "D/jYbVwQMXLqn1pjJttOPJwuA8+ho1f2c8FrKlqjHgOwxuHhsiGN6MKgs1baalpR\n" +
            "/lnNFCIpq+/+3cnhufDjvxMy5lg+cwgMCiGzCxn4n4dBMw41C+4KhNF7ZtKuKSZ1\n" +
            "eczztXD9NUkGUGw3LzpLDJazz3JhlZ/9pXzF\n" +
            "-----END CERTIFICATE-----"

    "valid signature" {
        val testCertPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT\n" +
                "B0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37\n" +
                "Xfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa\n" +
                "BGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47\n" +
                "RuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn\n" +
                "UGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+\n" +
                "VmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9\n" +
                "yrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ\n" +
                "XahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC\n" +
                "AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ\n" +
                "KoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m\n" +
                "tvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo\n" +
                "3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu\n" +
                "FMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s\n" +
                "6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG\n" +
                "QYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=\n" +
                "-----END CERTIFICATE-----\n"

        val trustList = listOf(X509Certificate.decodeFromPem(trustAnchorPem).getOrThrow())
        val leaf = X509Certificate.decodeFromPem(testCertPem).getOrThrow()

        leaf.isTrustedBy(trustList).isSuccess shouldBe true
    }

    "invalid signature" {
        val testCertPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgjCCAmqgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFjAUBgNVBAMT\n" +
                "DUJhZCBTaWduZWQgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDf\n" +
                "77zrq/d3vnq9i8r8Trn+BmzL4FkkTxewQRXNUnk6QnZ3Zi929sKAyv6cHCJK0r3p\n" +
                "JQj89gjkcHFt4Wsqzo9cRS/39ynAiCBoPqdOdCiy6J1AhKjMAVjrx0U597QUMKXj\n" +
                "jQvxpsLptqnn6kEX0VQzHqrChCbYogCHGVzyOEM8EA4KK8byAf2ZwUE34FqcSYjb\n" +
                "XtX2Kl+NsNGEBMTiqNEE82w+HmuRM5XYxG9+3EnCuT5O5b4WWqzsvYHAXEzgu+K0\n" +
                "ghe4Wail7rFP1Ho046GZCwUzi+U518bek8liQ9qiqS1L6oVa8dnQf7QDImDBIb5F\n" +
                "+2IJmU/NPAJwTNAhK3mBAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWu\n" +
                "vnW2ZafZXahmMB0GA1UdDgQWBBR73RA7SuDI3USFTog8WovNmSKTrzAOBgNVHQ8B\n" +
                "Af8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMB\n" +
                "Af8wDQYJKoZIhvcNAQELBQADggEBAWS/T/8EU0O0tLjvTs5hWudZV+co6/NMpRBk\n" +
                "gUjCI8VuNjpi/bmhLuNioJ3tCgLWlZ4Lhd9fLyOvktEo5HtJ0HNedz1Nq6+L4S+u\n" +
                "h8yYAIXSawnnyZLof8p67U4Z0hz7typr+a9FLpbkvOi6KUykbEgNOwES0+2PZLlf\n" +
                "0O3/I4JLkA7w0JXQi6CyOgVlRxF6fxw4O3Z/C+u560TndrUaISdyugt9a00gTmZc\n" +
                "9cQpAfZUn6WS0xp4D+xQ1h1l8BU0nXR32uODwxTh4PHh6sjZhY4pWrwbRgBjKkzI\n" +
                "iqEDzQlzqYwtPjIntlbAkwC4KM1pFaMwZU+WJ79rrPJGMGWFF3Y=\n" +
                "-----END CERTIFICATE-----\n"

        val trustList = listOf(X509Certificate.decodeFromPem(trustAnchorPem).getOrThrow())
        val leaf = X509Certificate.decodeFromPem(testCertPem).getOrThrow()

        leaf.isTrustedBy(trustList).isSuccess shouldBe false
    }

    "Invalid notBefore date" {
        val testCertPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDijCCAnKgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTQ3MDEwMTEyMDEwMFoXDTQ5MDEwMTEyMDEwMFowTjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHjAcBgNVBAMT\n" +
                "FUJhZCBub3RCZWZvcmUgRGF0ZSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
                "AQoCggEBAKdTl1qhx5hGD+CvPHQU/pDSJCVnLWeXmdblHoJ746b/bW3/GkXFSUPl\n" +
                "1yT36yl6CZJzUJqOYzFkSE3aN2vDcrjviJOAInET39JOxLTkc7J8DxCpz13PmliN\n" +
                "KpQl5p3fY3Lll8UumG/5mZsdphQSp2gIN6w68nJKS6Nmad46or/5l1qsAteEjIGx\n" +
                "a26CC6tV5yEqchk1Htsd4hJz7xUi7vijBM987pOidUjCYNltpZYQYvdbGIjl2LnX\n" +
                "ILVLy2B7Sska+bMVllQM6d932/mzFUxCXCR7eow5ZKo3dPAKOuwTnjTAR3MHfCij\n" +
                "/mRVgxSBDh017j55dVB16y0Si9flCfkCAwEAAaN8MHowHwYDVR0jBBgwFoAU5H1f\n" +
                "0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFGM+vBqe+6HyWaEvS5X+5t5WuIZA\n" +
                "MA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDwYDVR0T\n" +
                "AQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAtkgaLAbOwuudAqkh/5xJw8ur\n" +
                "RsA3e1joOqVXy3iP5Uj8o663gzdoBl+sIyDGntdx0h5GjR4QM/SWPlz5yxFrExe/\n" +
                "AaoxXHr77fYZfkgGBCLblxo3wb0iNpKz5OKmb4qtwEOpHygOpSSiV5e2wZDjhN1q\n" +
                "yR3v2lR5L2exD+k4l2Td/0w4uCpom62k+sWY36/h/zKiWFWhnIWqpHYyYOGhYzTM\n" +
                "EtJNWj6H0EWEoB1YNsNZYT3f2w4jOFa7oxfiqFS9kzXIjenc+MIt9uU6+oLFjdzt\n" +
                "jVCxa181mRD3+OiQw9SDtTZXEwPQmp0jj7B5bLGSKK477cAIX1uqxE7jyO8t2g==\n" +
                "-----END CERTIFICATE-----\n"

        val trustList = listOf(X509Certificate.decodeFromPem(trustAnchorPem).getOrThrow())
        val leaf = X509Certificate.decodeFromPem(testCertPem).getOrThrow()

        leaf.isTrustedBy(trustList).isSuccess shouldBe false
    }

    "invalid name chaining" {
        val  taPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT\n" +
                "B0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37\n" +
                "Xfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa\n" +
                "BGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47\n" +
                "RuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn\n" +
                "UGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+\n" +
                "VmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9\n" +
                "yrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ\n" +
                "XahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC\n" +
                "AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ\n" +
                "KoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m\n" +
                "tvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo\n" +
                "3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu\n" +
                "FMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s\n" +
                "6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG\n" +
                "QYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=\n" +
                "-----END CERTIFICATE-----"

        val testCertPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDjjCCAnagAwIBAgIBCTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMR29vZCBD\n" +
                "QSBSb290MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowYzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExMzAxBgNVBAMT\n" +
                "KkludmFsaWQgTmFtZSBDaGFpbmluZyBFRSBDZXJ0aWZpY2F0ZSBUZXN0MTCCASIw\n" +
                "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+nEW5gQmCvT4PQ4bfEwb8YmHX2\n" +
                "bhQjlGRTHO894s1c8ntn8sOGipmZujpyWKEnuLYYXnrx/8d6EaQ5iHWc2STa5xO2\n" +
                "/FYakp8YF7+wGIrvAKI2gXIaIFzFC6BBtZiDBb9esrLPA3tiu6u5F9WBsGWuA1TQ\n" +
                "jKqaTll9i5WvnXY8Fq4JbfHOeh9SCJKnyLtY/o6QqfJu4IvGIy3SVMUOpy35ZR6O\n" +
                "Hdy4JXBISnOe44NDd27PQNnkb7VlcvspL873wQSp5YJKW5tvoPMtCGegEssZIGGN\n" +
                "lN9bNTzeXAB+BfwtYoqP0Ej769uC6863UgGeWztLxe5YlvyS7CXaMmNdyosCAwEA\n" +
                "AaNrMGkwHwYDVR0jBBgwFoAUWAGEJBu8K1KUSj2lEHIUUfWvOskwHQYDVR0OBBYE\n" +
                "FBrADjt6tfm3fhTgKkOCvTN+XnXkMA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAO\n" +
                "MAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEBAHmYLicHjD0aYoBwgy4J\n" +
                "fY9KHQVyP3enwjKFrzxt3lLh0+hvUeJG49oxt3lRPjU5d7GJYSzB9hmbECnD8hYf\n" +
                "/NVRIa6UnLTK/blp3yc0fgYrZSFgzU77f6i51hxScIwprI/rNKUKjwYwPBQ6XZoS\n" +
                "Lb5nZkbFoSaPjorD7/rTBp1A0vPt9QNn8wBph59HSKyUnHm256Y5kv67Knkt5W11\n" +
                "tazp3HAc2nsE21MClKg4S4IHQYCva6p3KhViH5Wntu0AaG6Cl3eVbMDe+rzu2i7a\n" +
                "SsP+m1IhK/geXvUOHGkKQd0ESsNaHakpy5mQXpYbxxpem1NCcsbPPlipMa0AN5p/\n" +
                "ksU=\n" +
                "-----END CERTIFICATE-----"

        val trustList = listOf(
            X509Certificate.decodeFromPem(trustAnchorPem).getOrThrow(),
            X509Certificate.decodeFromPem(taPem).getOrThrow()
        )
        val leaf = X509Certificate.decodeFromPem(testCertPem).getOrThrow()

        val result = leaf.isTrustedBy(trustList)
        result.isSuccess shouldBe false
        result.exceptionOrNull()?.message shouldBe "No valid trust anchor could verify certificate"
    }
}