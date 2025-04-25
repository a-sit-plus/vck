package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.cosef.CoseKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
class SessionTranscriptTest : FreeSpec({

    "local presentation" {
        val expectedEncodedSessionTranscript ="""
            83                                        # array(3)
               d8 18                                  #   encoded cbor data item, tag(24)
                  58 58                               #     bytes(88)
                     a20063312e30018201d818584ba40102 #       "\xa2\x00c1.0\x01\x82\x01\xd8\x18XK\xa4\x01\x02"
                     2001215820c334b05dc99df884cf84c8 #       " \x01!X \xc34\xb0]\xc9\x9d\xf8\x84\xcf\x84\xc8"
                     601fe06ba6acbfda595c9eeaf343555a #       "`\x1f\xe0k\xa6\xac\xbf\xdaY\\\x9e\xea\xf3CUZ"
                     c37f1641a122582051f157aacace8f46 #       "\xc3\x7f\x16A\xa1\"X Q\xf1W\xaa\xca\xce\x8fF"
                     a66e12280e6312f3889181bdcca222bc #       "\xa6n\x12(\x0ec\x12\xf3\x88\x91\x81\xbd\xcc\xa2\"\xbc"
                     2079eefcc1317fe5                 #       " y\xee\xfc\xc11\x7f\xe5"
                                                      #     encoded cbor data item
                                                      #       a2                                           # map(2)
                                                      #          00                                        #   unsigned(0)
                                                      #          63                                        #   text(3)
                                                      #             312e30                                 #     "1.0"
                                                      #          01                                        #   unsigned(1)
                                                      #          82                                        #   array(2)
                                                      #             01                                     #     unsigned(1)
                                                      #             d8 18                                  #     encoded cbor data item, tag(24)
                                                      #                58 4b                               #       bytes(75)
                                                      #                   a401022001215820c334b05dc99df884 #         "\xa4\x01\x02 \x01!X \xc34\xb0]\xc9\x9d\xf8\x84"
                                                      #                   cf84c8601fe06ba6acbfda595c9eeaf3 #         "\xcf\x84\xc8`\x1f\xe0k\xa6\xac\xbf\xdaY\\\x9e\xea\xf3"
                                                      #                   43555ac37f1641a122582051f157aaca #         "CUZ\xc3\x7f\x16A\xa1\"X Q\xf1W\xaa\xca"
                                                      #                   ce8f46a66e12280e6312f3889181bdcc #         "\xce\x8fF\xa6n\x12(\x0ec\x12\xf3\x88\x91\x81\xbd\xcc"
                                                      #                   a222bc2079eefcc1317fe5           #         "\xa2\"\xbc y\xee\xfc\xc11\x7f\xe5"
                                                      #                                                    #       encoded cbor data item
                                                      #                                                    #         a4                                     # map(4)
                                                      #                                                    #            01                                  #   unsigned(1)
                                                      #                                                    #            02                                  #   unsigned(2)
                                                      #                                                    #            20                                  #   negative(-1)
                                                      #                                                    #            01                                  #   unsigned(1)
                                                      #                                                    #            21                                  #   negative(-2)
                                                      #                                                    #            58 20                               #   bytes(32)
                                                      #                                                    #               c334b05dc99df884cf84c8601fe06ba6 #     "\xc34\xb0]\xc9\x9d\xf8\x84\xcf\x84\xc8`\x1f\xe0k\xa6"
                                                      #                                                    #               acbfda595c9eeaf343555ac37f1641a1 #     "\xac\xbf\xdaY\\\x9e\xea\xf3CUZ\xc3\x7f\x16A\xa1"
                                                      #                                                    #            22                                  #   negative(-3)
                                                      #                                                    #            58 20                               #   bytes(32)
                                                      #                                                    #               51f157aacace8f46a66e12280e6312f3 #     "Q\xf1W\xaa\xca\xce\x8fF\xa6n\x12(\x0ec\x12\xf3"
                                                      #                                                    #               889181bdcca222bc2079eefcc1317fe5 #     "\x88\x91\x81\xbd\xcc\xa2\"\xbc y\xee\xfc\xc11\x7f\xe5"
               d8 18                                  #   encoded cbor data item, tag(24)
                  58 4b                               #     bytes(75)
                     a401022001215820ff653193738cdce3 #       "\xa4\x01\x02 \x01!X \xffe1\x93s\x8c\xdc\xe3"
                     38ff42f607a0703a0a033010da16cdd4 #       "8\xffB\xf6\x07\xa0p:\n\x030\x10\xda\x16\xcd\xd4"
                     510a6bdf468b8833225820513d212d75 #       "Q\nk\xdfF\x8b\x883\"X Q=!-u"
                     ba67145157e458e1e75ba13e1b070fb5 #       "\xbag\x14QW\xe4X\xe1\xe7[\xa1>\x1b\x07\x0f\xb5"
                     7135b8fa46907c2bd07e4c           #       "q5\xb8\xfaF\x90|+\xd0~L"
                                                      #     encoded cbor data item
                                                      #       a4                                     # map(4)
                                                      #          01                                  #   unsigned(1)
                                                      #          02                                  #   unsigned(2)
                                                      #          20                                  #   negative(-1)
                                                      #          01                                  #   unsigned(1)
                                                      #          21                                  #   negative(-2)
                                                      #          58 20                               #   bytes(32)
                                                      #             ff653193738cdce338ff42f607a0703a #     "\xffe1\x93s\x8c\xdc\xe38\xffB\xf6\x07\xa0p:"
                                                      #             0a033010da16cdd4510a6bdf468b8833 #     "\n\x030\x10\xda\x16\xcd\xd4Q\nk\xdfF\x8b\x883"
                                                      #          22                                  #   negative(-3)
                                                      #          58 20                               #   bytes(32)
                                                      #             513d212d75ba67145157e458e1e75ba1 #     "Q=!-u\xbag\x14QW\xe4X\xe1\xe7[\xa1"
                                                      #             3e1b070fb57135b8fa46907c2bd07e4c #     ">\x1b\x07\x0f\xb5q5\xb8\xfaF\x90|+\xd0~L"
               82                                     #   array(2)
                  58 c0                               #     bytes(192)
                     91020f487315d1020961630101300104 #       "\x91\x02\x0fHs\x15\xd1\x02\tac\x01\x010\x01\x04"
                     6d646f631c1e580469736f2e6f72673a #       "mdoc\x1c\x1eX\x04iso.org:"
                     31383031333a646576696365656e6761 #       "18013:deviceenga"
                     67656d656e746d646f63a20063312e30 #       "gementmdoc\xa2\x00c1.0"
                     018201d818584ba401022001215820c3 #       "\x01\x82\x01\xd8\x18XK\xa4\x01\x02 \x01!X \xc3"
                     34b05dc99df884cf84c8601fe06ba6ac #       "4\xb0]\xc9\x9d\xf8\x84\xcf\x84\xc8`\x1f\xe0k\xa6\xac"
                     bfda595c9eeaf343555ac37f1641a122 #       "\xbf\xdaY\\\x9e\xea\xf3CUZ\xc3\x7f\x16A\xa1\""
                     582051f157aacace8f46a66e12280e63 #       "X Q\xf1W\xaa\xca\xce\x8fF\xa6n\x12(\x0ec"
                     12f3889181bdcca222bc2079eefcc131 #       "\x12\xf3\x88\x91\x81\xbd\xcc\xa2\"\xbc y\xee\xfc\xc11"
                     7fe55a2009016170706c69636174696f #       "\x7f\xe5Z \t\x01applicatio"
                     6e2f766e642e626c7565746f6f74682e #       "n/vnd.bluetooth."
                     6c652e6f6f6230021c010577000000e0 #       "le.oob0\x02\x1c\x01\x05w\x00\x00\x00\xe0"
                  58 ae                               #     bytes(174)
                     91021548721591020461630101300051 #       "\x91\x02\x15Hr\x15\x91\x02\x04ac\x01\x010\x00Q"
                     0206616301036e6663001c1e060a6973 #       "\x02\x06ac\x01\x03nfc\x00\x1c\x1e\x06\nis"
                     6f2e6f72673a31383031333a72656164 #       "o.org:18013:read"
                     6572656e676167656d656e746d646f63 #       "erengagementmdoc"
                     726561646572a10063312e301a201b01 #       "reader\xa1\x00c1.0\x1a \x1b\x01"
                     6170706c69636174696f6e2f766e642e #       "application/vnd."
                     626c7565746f6f74682e6c652e6f6f62 #       "bluetooth.le.oob"
                     30021c0311078c42ddfb12be9292de48 #       "0\x02\x1c\x03\x11\x07\x8cB\xdd\xfb\x12\xbe\x92\x92\xdeH"
                     dd39748fa77b0577000000e05c110a03 #       "\xdd9t\x8f\xa7{\x05w\x00\x00\x00\xe0\\\x11\n\x03"
                     69736f2e6f72673a31383031333a6e66 #       "iso.org:18013:nf"
                     636e6663010301ffff0402010000     #       "cnfc\x01\x03\x01\xff\xff\x04\x02\x01\x00\x00"

        """.decodeFromAnnotatedCbor()

        val coseEncodedEReaderKey = """
            a4                                     # map(4)
               01                                  #   unsigned(1)
               02                                  #   unsigned(2)
               20                                  #   negative(-1)
               01                                  #   unsigned(1)
               21                                  #   negative(-2)
               58 20                               #   bytes(32)
                  ff653193738cdce338ff42f607a0703a #     "\xffe1\x93s\x8c\xdc\xe38\xffB\xf6\x07\xa0p:"
                  0a033010da16cdd4510a6bdf468b8833 #     "\n\x030\x10\xda\x16\xcd\xd4Q\nk\xdfF\x8b\x883"
               22                                  #   negative(-3)
               58 20                               #   bytes(32)
                  513d212d75ba67145157e458e1e75ba1 #     "Q=!-u\xbag\x14QW\xe4X\xe1\xe7[\xa1"
                  3e1b070fb57135b8fa46907c2bd07e4c #     ">\x1b\x07\x0f\xb5q5\xb8\xfaF\x90|+\xd0~L"
        """.decodeFromAnnotatedCbor()

        val coseEncodedNFCHandover = """
            82                                     # array(2)
               58 c0                               #   bytes(192)
                  91020f487315d1020961630101300104 #     "\x91\x02\x0fHs\x15\xd1\x02\tac\x01\x010\x01\x04"
                  6d646f631c1e580469736f2e6f72673a #     "mdoc\x1c\x1eX\x04iso.org:"
                  31383031333a646576696365656e6761 #     "18013:deviceenga"
                  67656d656e746d646f63a20063312e30 #     "gementmdoc\xa2\x00c1.0"
                  018201d818584ba401022001215820c3 #     "\x01\x82\x01\xd8\x18XK\xa4\x01\x02 \x01!X \xc3"
                  34b05dc99df884cf84c8601fe06ba6ac #     "4\xb0]\xc9\x9d\xf8\x84\xcf\x84\xc8`\x1f\xe0k\xa6\xac"
                  bfda595c9eeaf343555ac37f1641a122 #     "\xbf\xdaY\\\x9e\xea\xf3CUZ\xc3\x7f\x16A\xa1\""
                  582051f157aacace8f46a66e12280e63 #     "X Q\xf1W\xaa\xca\xce\x8fF\xa6n\x12(\x0ec"
                  12f3889181bdcca222bc2079eefcc131 #     "\x12\xf3\x88\x91\x81\xbd\xcc\xa2\"\xbc y\xee\xfc\xc11"
                  7fe55a2009016170706c69636174696f #     "\x7f\xe5Z \t\x01applicatio"
                  6e2f766e642e626c7565746f6f74682e #     "n/vnd.bluetooth."
                  6c652e6f6f6230021c010577000000e0 #     "le.oob0\x02\x1c\x01\x05w\x00\x00\x00\xe0"
               58 ae                               #   bytes(174)
                  91021548721591020461630101300051 #     "\x91\x02\x15Hr\x15\x91\x02\x04ac\x01\x010\x00Q"
                  0206616301036e6663001c1e060a6973 #     "\x02\x06ac\x01\x03nfc\x00\x1c\x1e\x06\nis"
                  6f2e6f72673a31383031333a72656164 #     "o.org:18013:read"
                  6572656e676167656d656e746d646f63 #     "erengagementmdoc"
                  726561646572a10063312e301a201b01 #     "reader\xa1\x00c1.0\x1a \x1b\x01"
                  6170706c69636174696f6e2f766e642e #     "application/vnd."
                  626c7565746f6f74682e6c652e6f6f62 #     "bluetooth.le.oob"
                  30021c0311078c42ddfb12be9292de48 #     "0\x02\x1c\x03\x11\x07\x8cB\xdd\xfb\x12\xbe\x92\x92\xdeH"
                  dd39748fa77b0577000000e05c110a03 #     "\xdd9t\x8f\xa7{\x05w\x00\x00\x00\xe0\\\x11\n\x03"
                  69736f2e6f72673a31383031333a6e66 #     "iso.org:18013:nf"
                  636e6663010301ffff0402010000     #     "cnfc\x01\x03\x01\xff\xff\x04\x02\x01\x00\x00"
        """.decodeFromAnnotatedCbor()

        val eReaderCoseKey = CoseKey.deserialize(coseEncodedEReaderKey)
        val nfcHandover = NFCHandover.deserialize(coseEncodedNFCHandover)

        val encodedDeviceEngagement = """
            a2                                           # map(2)
               00                                        #   unsigned(0)
               63                                        #   text(3)
                  312e30                                 #     "1.0"
               01                                        #   unsigned(1)
               82                                        #   array(2)
                  01                                     #     unsigned(1)
                  d8 18                                  #     encoded cbor data item, tag(24)
                     58 4b                               #       bytes(75)
                        a401022001215820c334b05dc99df884 #         "\xa4\x01\x02 \x01!X \xc34\xb0]\xc9\x9d\xf8\x84"
                        cf84c8601fe06ba6acbfda595c9eeaf3 #         "\xcf\x84\xc8`\x1f\xe0k\xa6\xac\xbf\xdaY\\\x9e\xea\xf3"
                        43555ac37f1641a122582051f157aaca #         "CUZ\xc3\x7f\x16A\xa1\"X Q\xf1W\xaa\xca"
                        ce8f46a66e12280e6312f3889181bdcc #         "\xce\x8fF\xa6n\x12(\x0ec\x12\xf3\x88\x91\x81\xbd\xcc"
                        a222bc2079eefcc1317fe5           #         "\xa2\"\xbc y\xee\xfc\xc11\x7f\xe5"
                                                         #       encoded cbor data item
                                                         #         a4                                     # map(4)
                                                         #            01                                  #   unsigned(1)
                                                         #            02                                  #   unsigned(2)
                                                         #            20                                  #   negative(-1)
                                                         #            01                                  #   unsigned(1)
                                                         #            21                                  #   negative(-2)
                                                         #            58 20                               #   bytes(32)
                                                         #               c334b05dc99df884cf84c8601fe06ba6 #     "\xc34\xb0]\xc9\x9d\xf8\x84\xcf\x84\xc8`\x1f\xe0k\xa6"
                                                         #               acbfda595c9eeaf343555ac37f1641a1 #     "\xac\xbf\xdaY\\\x9e\xea\xf3CUZ\xc3\x7f\x16A\xa1"
                                                         #            22                                  #   negative(-3)
                                                         #            58 20                               #   bytes(32)
                                                         #               51f157aacace8f46a66e12280e6312f3 #     "Q\xf1W\xaa\xca\xce\x8fF\xa6n\x12(\x0ec\x12\xf3"
                                                         #               889181bdcca222bc2079eefcc1317fe5 #     "\x88\x91\x81\xbd\xcc\xa2\"\xbc y\xee\xfc\xc11\x7f\xe5"
        """.decodeFromAnnotatedCbor()

        val sessionTranscript = SessionTranscript.forNfc(
            deviceEngagementBytes = encodedDeviceEngagement,
            eReaderKeyBytes = eReaderCoseKey.getOrThrow().serialize(),
            nfcHandover = nfcHandover.getOrThrow()
        )

        sessionTranscript.oid4VPHandover shouldBe null
        sessionTranscript.nfcHandover shouldNotBe null
        sessionTranscript.serialize() shouldBe expectedEncodedSessionTranscript
    }

    "oid4vp" {
        val clientIdToHash = "543ad47d06158882c74cd2869dbbb09bd9f42b47cd0e15bf8809a7a83510ee3c"
            .decodeToByteArray(Base16)
        val responseUriToHash = "8ced6c43f0633b651ba7298d057c7fb3b01f983b079550d00171a495f0297382"
            .decodeToByteArray(Base16)
        val nonce = "7c25a392-ecd5-448e-b08a-067d077bc96b"
        val expectedEncodedSessionTranscript = """
            83                                        # array(3)
               f6                                     #   null, simple(22)
               f6                                     #   null, simple(22)
               83                                     #   array(3)
                  58 20                               #     bytes(32)
                     543ad47d06158882c74cd2869dbbb09b #       "T:\xd4}\x06\x15\x88\x82\xc7L\xd2\x86\x9d\xbb\xb0\x9b"
                     d9f42b47cd0e15bf8809a7a83510ee3c #       "\xd9\xf4+G\xcd\x0e\x15\xbf\x88\t\xa7\xa85\x10\xee<"
                  58 20                               #     bytes(32)
                     8ced6c43f0633b651ba7298d057c7fb3 #       "\x8c\xedlC\xf0c;e\x1b\xa7)\x8d\x05|\x7f\xb3"
                     b01f983b079550d00171a495f0297382 #       "\xb0\x1f\x98;\x07\x95P\xd0\x01q\xa4\x95\xf0)s\x82"
                  78 24                               #     text(36)
                     37633235613339322d656364352d3434 #       "7c25a392-ecd5-44"
                     38652d623038612d3036376430373762 #       "8e-b08a-067d077b"
                     63393662                         #       "c96b"
        """.decodeFromAnnotatedCbor()

        val sessionTranscript = SessionTranscript.forOpenId(
            OID4VPHandover(
                clientIdHash = clientIdToHash,
                responseUriHash = responseUriToHash,
                nonce = nonce
            ),
        )

        sessionTranscript.oid4VPHandover shouldNotBe null
        sessionTranscript.nfcHandover shouldBe null
        sessionTranscript.serialize() shouldBe expectedEncodedSessionTranscript
    }

})

private fun String.decodeFromAnnotatedCbor(): ByteArray =
    trimIndent().split("\n").joinToString("") { it.split("#").first().replace(" ", "") }.decodeToByteArray(Base16)
