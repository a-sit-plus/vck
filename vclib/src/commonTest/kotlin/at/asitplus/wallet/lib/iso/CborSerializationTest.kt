package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.cbor.CoseSigned
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.utils.io.core.toByteArray
import io.matthewnelson.component.encoding.base16.decodeBase16ToArray
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.datetime.LocalDate
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray

class CborSerializationTest : FreeSpec({

    beforeSpec {
        Napier.base(DebugAntilog())
    }

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

    // From ISO/IEC 18013-5:2021(E), page 130
    "IssuerAuth Deserialization" {
        /**
         * In diagnostic notation:
         * [
         * << {1: -7} >>,
         * {
         * 33: h'308201EF30820195A00302010202143C4416EED784F3B413E48F56F075ABFA6D87EB84300A06082A
         * 8648CE3D04030230233114301206035504030C0B75746F7069612069616361310B300906035504061302555330
         * 1E170D3230313030313030303030305A170D3231313030313030303030305A30213112301006035504030C0975
         * 746F706961206473310B30090603550406130255533059301306072A8648CE3D020106082A8648CE3D03010703
         * 420004ACE7AB7340E5D9648C5A72A9A6F56745C7AAD436A03A43EFEA77B5FA7B88F0197D57D8983E1B37D3A539
         * F4D588365E38CBBF5B94D68C547B5BC8731DCD2F146BA381A83081A5301E0603551D120417301581136578616D
         * 706C65406578616D706C652E636F6D301C0603551D1F041530133011A00FA00D820B6578616D706C652E636F6D
         * 301D0603551D0E0416041414E29017A6C35621FFC7A686B7B72DB06CD12351301F0603551D2304183016801454
         * FA2383A04C28E0D930792261C80C4881D2C00B300E0603551D0F0101FF04040302078030150603551D250101FF
         * 040B3009060728818C5D050102300A06082A8648CE3D040302034800304502210097717AB9016740C8D7BCDAA4
         * 94A62C053BBDECCE1383C1ACA72AD08DBC04CBB202203BAD859C13A63C6D1AD67D814D43E2425CAF90D422422C
         * 04A8EE0304C0D3A68D'
         * },
         * <<
         * 24(<<
         * {
         * "version": "1.0",
         * "digestAlgorithm": "SHA-256",
         * "valueDigests":
         * {
         * "org.iso.18013.5.1":
         * {
         * 0: h'75167333B47B6C2BFB86ECCC1F438CF57AF055371AC55E1E359E20F254ADCEBF',
         * 1: h'67E539D6139EBD131AEF441B445645DD831B2B375B390CA5EF6279B205ED4571',
         * 2: h'3394372DDB78053F36D5D869780E61EDA313D44A392092AD8E0527A2FBFE55AE',
         * 3: h'2E35AD3C4E514BB67B1A9DB51CE74E4CB9B7146E41AC52DAC9CE86B8613DB555',
         * 4: h'EA5C3304BB7C4A8DCB51C4C13B65264F845541341342093CCA786E058FAC2D59',
         * 5: h'FAE487F68B7A0E87A749774E56E9E1DC3A8EC7B77E490D21F0E1D3475661AA1D',
         * 6: h'7D83E507AE77DB815DE4D803B88555D0511D894C897439F5774056416A1C7533',
         * 7: h'F0549A145F1CF75CBEEFFA881D4857DD438D627CF32174B1731C4C38E12CA936',
         * 8: h'B68C8AFCB2AAF7C581411D2877DEF155BE2EB121A42BC9BA5B7312377E068F66',
         * 9: h'0B3587D1DD0C2A07A35BFB120D99A0ABFB5DF56865BB7FA15CC8B56A66DF6E0C',
         * 10: h'C98A170CF36E11ABB724E98A75A5343DFA2B6ED3DF2ECFBB8EF2EE55DD41C881',
         * 11: h'B57DD036782F7B14C6A30FAAAAE6CCD5054CE88BDFA51A016BA75EDA1EDEA948',
         * 12: h'651F8736B18480FE252A03224EA087B5D10CA5485146C67C74AC4EC3112D4C3A'
         * },
         * "org.iso.18013.5.1.US":
         * {
         * 0: h'D80B83D25173C484C5640610FF1A31C949C1D934BF4CF7F18D5223B15DD4F21C',
         * 1: h'4D80E1E2E4FB246D97895427CE7000BB59BB24C8CD003ECF94BF35BBD2917E34',
         * 2: h'8B331F3B685BCA372E85351A25C9484AB7AFCDF0D2233105511F778D98C2F544',
         * 3: h'C343AF1BD1690715439161ABA73702C474ABF992B20C9FB55C36A336EBE01A87'
         * }
         * },
         * "deviceKeyInfo":
         * {
         * "deviceKey":
         * {
         * 1: 2,
         * -1: 1,
         * -2: h'96313D6C63E24E3372742BFDB1A33BA2C897DCD68AB8C753E4FBD48DCA6B7F9A',
         * -3: h'1FB3269EDD418857DE1B39A4E4A44B92FA484CAA722C228288F01D0C03A2C3D6'
         * }
         * },
         * "docType": "org.iso.18013.5.1.mDL",
         * "validityInfo":
         * {
         * "signed": 0("2020-10-01T13:30:02Z"),
         * "validFrom": 0("2020-10-01T13:30:02Z"),
         * "validUntil": 0("2021-10-01T13:30:02Z")
         * }
         * }
         * >>)
         * >>,
         * h'59E64205DF1E2F708DD6DB0847AED79FC7C0201D80FA55BADCAF2E1BCF5902E1E5A62E4 832044B890AD85
         * AA53F129134775D733754D7CB7A413766AEFF13CB2E'
         * ]
         */
        val input = """
            8443a10126a118215901f3308201ef30820195a00302010202143c4416eed784f3b413e48f56f075abfa6d87e
            b84300a06082a8648ce3d04030230233114301206035504030c0b75746f7069612069616361310b3009060355
            040613025553301e170d3230313030313030303030305a170d3231313030313030303030305a302131123010
            06035504030c0975746f706961206473310b30090603550406130255533059301306072a8648ce3d020106082
            a8648ce3d03010703420004ace7ab7340e5d9648c5a72a9a6f56745c7aad436a03a43efea77b5fa7b88f0197d
            57d8983e1b37d3a539f4d588365e38cbbf5b94d68c547b5bc8731dcd2f146ba381a83081a5301e0603551d120
            417301581136578616d706c65406578616d706c652e636f6d301c0603551d1f041530133011a00fa00d820b65
            78616d706c652e636f6d301d0603551d0e0416041414e29017a6c35621ffc7a686b7b72db06cd12351301f0603
            551d2304183016801454fa2383a04c28e0d930792261c80c4881d2c00b300e0603551d0f0101ff040403020780
            30150603551d250101ff040b3009060728818c5d050102300a06082a8648ce3d04030203480030450221009771
            7ab9016740c8d7bcdaa494a62c053bbdecce1383c1aca72ad08dbc04cbb202203bad859c13a63c6d1ad67d814d
            43e2425caf90d422422c04a8ee0304c0d3a68d5903a2d81859039da66776657273696f6e63312e306f64696765
            7374416c676f726974686d675348412d3235366c76616c756544696765737473a2716f72672e69736f2e313830
            31332e352e31ad00582075167333b47b6c2bfb86eccc1f438cf57af055371ac55e1e359e20f254adcebf015820
            67e539d6139ebd131aef441b445645dd831b2b375b390ca5ef6279b205ed45710258203394372ddb78053f36d5
            d869780e61eda313d44a392092ad8e0527a2fbfe55ae0358202e35ad3c4e514bb67b1a9db51ce74e4cb9b7146e
            41ac52dac9ce86b8613db555045820ea5c3304bb7c4a8dcb51c4c13b65264f845541341342093cca786e058fac
            2d59055820fae487f68b7a0e87a749774e56e9e1dc3a8ec7b77e490d21f0e1d3475661aa1d0658207d83e507ae
            77db815de4d803b88555d0511d894c897439f5774056416a1c7533075820f0549a145f1cf75cbeeffa881d4857d
            d438d627cf32174b1731c4c38e12ca936085820b68c8afcb2aaf7c581411d2877def155be2eb121a42bc9ba5b7
            312377e068f660958200b3587d1dd0c2a07a35bfb120d99a0abfb5df56865bb7fa15cc8b56a66df6e0c0a5820c
            98a170cf36e11abb724e98a75a5343dfa2b6ed3df2ecfbb8ef2ee55dd41c8810b5820b57dd036782f7b14c6a30
            faaaae6ccd5054ce88bdfa51a016ba75eda1edea9480c5820651f8736b18480fe252a03224ea087b5d10ca5485
            146c67c74ac4ec3112d4c3a746f72672e69736f2e31383031332e352e312e5553a4005820d80b83d25173c484c
            5640610ff1a31c949c1d934bf4cf7f18d5223b15dd4f21c0158204d80e1e2e4fb246d97895427ce7000bb59bb24
            c8cd003ecf94bf35bbd2917e340258208b331f3b685bca372e85351a25c9484ab7afcdf0d2233105511f778d98
            c2f544035820c343af1bd1690715439161aba73702c474abf992b20c9fb55c36a336ebe01a876d646576696365
            4b6579496e666fa1696465766963654b6579a40102200121582096313d6c63e24e3372742bfdb1a33ba2c897dc
            d68ab8c753e4fbd48dca6b7f9a2258201fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03
            a2c3d667646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e66
            6fa3667369676e6564c074323032302d31302d30315431333a33303a30325a6976616c696446726f6dc0743230
            32302d31302d30315431333a33303a30325a6a76616c6964556e74696cc074323032312d31302d30315431333a
            33303a30325a584059e64205df1e2f708dd6db0847aed79fc7c0201d80fa55badcaf2e1bcf5902e1e5a62e4832
            044b890ad85aa53f129134775d733754d7cb7a413766aeff13cb2e
        """.trimIndent().replace("\n", "").uppercase()

        val deserialized = CoseSigned.deserialize(input.decodeBase16ToArray()!!)
        deserialized.shouldNotBeNull()

        println(deserialized)
        // NOTE: deserialized.payload is a tagged CBOR bytestring with Tag 24 = 0xD818
        // TODO How to deserialize a tagged byte string?
        val stripped = deserialized.payload.drop(5).toByteArray()
        val parsed = MobileSecurityObject.deserialize(stripped)
        parsed.shouldNotBeNull()
        println(parsed)
    }

})
