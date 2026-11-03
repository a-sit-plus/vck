package at.asitplus.wallet.lib.iso

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.NFCHandover
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.OpenId4VpHandover
import at.asitplus.iso.OpenId4VpHandoverInfo
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.random.Random

val SessionTranscriptTest by matrixSuite {

    "Local presentation with NFC Handover" {
        val expectedEncodedSessionTranscript = """
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

        val eReaderCoseKey = coseCompliantSerializer.decodeFromByteArray<CoseKey>(coseEncodedEReaderKey)
        val nfcHandover = coseCompliantSerializer.decodeFromByteArray<NFCHandover>(coseEncodedNFCHandover)

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

        val sessionTranscript = SessionTranscript.Nfc(
            deviceEngagementBytes = encodedDeviceEngagement,
            eReaderKeyBytes = coseCompliantSerializer.encodeToByteArray(eReaderCoseKey),
            handover = nfcHandover
        )

        coseCompliantSerializer.encodeToByteArray(sessionTranscript) shouldBe expectedEncodedSessionTranscript
        expectedEncodedSessionTranscript.shouldRoundTripTo(sessionTranscript)
    }

    "Local presentation with QR Handover" {
        val expectedEncodedSessionTranscript = """
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
               f6                                     #   null, simple(22)

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

        val eReaderCoseKey = coseCompliantSerializer.decodeFromByteArray<CoseKey>(coseEncodedEReaderKey)

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

        val sessionTranscript = SessionTranscript.Qr(
            deviceEngagementBytes = encodedDeviceEngagement,
            eReaderKeyBytes = coseCompliantSerializer.encodeToByteArray(eReaderCoseKey)
        )
        coseCompliantSerializer.encodeToByteArray(sessionTranscript) shouldBe expectedEncodedSessionTranscript
        expectedEncodedSessionTranscript.shouldRoundTripTo(sessionTranscript)
    }

    "OpenID4VP 1.0" {
        val expectedEncodedSessionTranscript = """
            83                                 # array(3)
              f6                               #   null
              f6                               #   null
              82                               #   array(2)
                71                             #     string(17)
                  4f70656e494434565048616e646f #       "OpenID4VPHando"
                  766572                       #       "ver"
                58 20                          #     bytes(32)
                  048bc053c00442af9b8eed494cef #       "\x04\x8bÀSÀ\x04B¯\x9b\x8eíILï"
                  dd9d95240d254b046b11b6801372 #       "Ý\x9d\x95$\x0d%K\x04k\x11¶\x80\x13r"
                  2aad38ac                     #       "*­8¬"

        """.decodeFromAnnotatedCbor()

        val sessionTranscript = SessionTranscript.OpenId4Vp(
            OpenId4VpHandover(
                type = OpenId4VpHandover.TYPE_OPENID4VP,
                hash = coseCompliantSerializer.encodeToByteArray(
                    OpenId4VpHandoverInfo(
                        clientId = "x509_san_dns:example.com",
                        nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
                        jwkThumbprint = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
                            .decodeToByteArray(Base16Strict),
                        responseUrl = "https://example.com/response",
                    )
                ).sha256(),
            ),
        )
        coseCompliantSerializer.encodeToByteArray(sessionTranscript) shouldBe expectedEncodedSessionTranscript
        expectedEncodedSessionTranscript.shouldRoundTripTo(sessionTranscript)
    }

    "DC API" - {
        listOf(DCAPIHandover.TYPE_DCAPI, DCAPIHandover.TYPE_OPENID4VP).forEach { type -> type {
            val hash = Random.nextBytes(32)
            val expectedEncodedSessionTranscript = cborArray(
                byteArrayOf(0xf6.toByte()), // null
                byteArrayOf(0xf6.toByte()), // null
                cborArray(cborText(type), cborBytes(hash)),
            )
            val sessionTranscript = SessionTranscript.DcApi(DCAPIHandover(type, hash))

            coseCompliantSerializer.encodeToByteArray(sessionTranscript) shouldBe expectedEncodedSessionTranscript
            expectedEncodedSessionTranscript.shouldRoundTripTo(sessionTranscript)
        } }
    }

    "NFC Handover without Handover Request" {
        val handoverSelect = Random.nextBytes(40)
        val sessionTranscript = SessionTranscript.Nfc(
            deviceEngagementBytes = Random.nextBytes(30),
            eReaderKeyBytes = Random.nextBytes(77),
            handover = NFCHandover(handoverSelect = handoverSelect, handoverRequest = null),
        )
        val expectedEncodedSessionTranscript = cborArray(
            cborEncodedData(sessionTranscript.deviceEngagementBytes),
            cborEncodedData(sessionTranscript.eReaderKeyBytes),
            cborArray(cborBytes(handoverSelect), byteArrayOf(0xf6.toByte())),
        )

        coseCompliantSerializer.encodeToByteArray(sessionTranscript) shouldBe expectedEncodedSessionTranscript
        expectedEncodedSessionTranscript.shouldRoundTripTo(sessionTranscript)
    }

    "NFC transcript in DeviceAuthenticationBytes of ISO 18013-5 D.5.3" {
        val deviceAuthenticationBytes = iso18013AnnexDDeviceAuthenticationBytes.decodeToByteArray(Base16)
        val deviceAuthenticationEncoded = coseCompliantSerializer.decodeFromByteArray<ByteArray>(
            deviceAuthenticationBytes.drop(2).toByteArray() // tag 24
        )
        val deviceAuthentication = coseCompliantSerializer.decodeFromByteArray<DeviceAuthentication>(
            deviceAuthenticationEncoded
        )

        val sessionTranscript = deviceAuthentication.sessionTranscript.shouldBeInstanceOf<SessionTranscript.Nfc>()
        sessionTranscript.handover.handoverRequest.shouldNotBeNull()
        coseCompliantSerializer.encodeToByteArray(deviceAuthentication) shouldBe deviceAuthenticationEncoded
    }

    "decoding as another subtype fails" {
        val encoded = coseCompliantSerializer.encodeToByteArray<SessionTranscript>(
            SessionTranscript.Qr(Random.nextBytes(16), Random.nextBytes(16))
        )
        shouldThrowAny { coseCompliantSerializer.decodeFromByteArray<SessionTranscript.Nfc>(encoded) }
    }

    "unknown handovers are rejected" - {
        mapOf(
            "unknown type" to cborArray(cborText("unknown"), cborBytes(Random.nextBytes(32))),
            "OID4VPHandover of ISO 18013-7 2024" to cborArray(
                cborBytes(Random.nextBytes(32)), cborBytes(Random.nextBytes(32)), cborText("nonce")
            ),
            "empty array" to cborArray(),
        ).forEach { (name, handover) ->
            name {
                shouldThrowAny {
                    coseCompliantSerializer.decodeFromByteArray<SessionTranscript>(
                        cborArray(byteArrayOf(0xf6.toByte()), byteArrayOf(0xf6.toByte()), handover)
                    )
                }
            }
        }
    }

    "NFC handover without device engagement is rejected" {
        shouldThrowAny {
            coseCompliantSerializer.decodeFromByteArray<SessionTranscript>(
                cborArray(
                    byteArrayOf(0xf6.toByte()),
                    byteArrayOf(0xf6.toByte()),
                    cborArray(cborBytes(Random.nextBytes(8)), byteArrayOf(0xf6.toByte()))
                )
            )
        }
    }

    "DC API handover with device engagement is rejected" {
        shouldThrowAny {
            coseCompliantSerializer.decodeFromByteArray<SessionTranscript>(
                cborArray(
                    cborEncodedData(Random.nextBytes(8)),
                    cborEncodedData(Random.nextBytes(8)),
                    cborArray(cborText(DCAPIHandover.TYPE_DCAPI), cborBytes(Random.nextBytes(32)))
                )
            )
        }
    }

    "transcripts with only one of DeviceEngagementBytes and EReaderKeyBytes are rejected" {
        val null_ = byteArrayOf(0xf6.toByte())
        listOf(
            cborArray(cborEncodedData(Random.nextBytes(8)), null_, null_),
            cborArray(
                null_,
                cborEncodedData(Random.nextBytes(8)),
                cborArray(cborText(DCAPIHandover.TYPE_DCAPI), cborBytes(Random.nextBytes(32)))
            ),
        ).forEach {
            shouldThrowAny { coseCompliantSerializer.decodeFromByteArray<SessionTranscript>(it) }
        }
    }

    "malformed handovers are rejected, not decoded as another kind of handover" - {
        mapOf(
            // An indefinite-length text string with a byte string chunk, where an NFC handover is expected
            "malformed text string in NFC handover" to "83d8184100d8184100827f40f6",
            // The same where a handover without device engagement is expected
            "malformed text string in DC API handover" to "83f6f6827f405820" + "00".repeat(32),
        ).forEach { (name, hex) ->
            name {
                shouldThrowAny {
                    coseCompliantSerializer.decodeFromByteArray<SessionTranscript>(hex.decodeToByteArray(Base16))
                }
            }
        }
    }

    "transcripts with other than three elements are rejected" {
        val handover = cborArray(cborText(DCAPIHandover.TYPE_DCAPI), cborBytes(Random.nextBytes(32)))
        shouldThrowAny {
            coseCompliantSerializer.decodeFromByteArray<SessionTranscript>(
                cborArray(byteArrayOf(0xf6.toByte()), handover)
            )
        }
        shouldThrowAny {
            coseCompliantSerializer.decodeFromByteArray<SessionTranscript>(
                cborArray(byteArrayOf(0xf6.toByte()), byteArrayOf(0xf6.toByte()), handover, byteArrayOf(0xf6.toByte()))
            )
        }
    }

}

/** Decodes this to [expected], as a [SessionTranscript] and as its subtype, and re-encodes to the same bytes. */
private inline fun <reified T : SessionTranscript> ByteArray.shouldRoundTripTo(expected: T) {
    val decoded = coseCompliantSerializer.decodeFromByteArray<SessionTranscript>(this)
    decoded shouldBe expected
    coseCompliantSerializer.encodeToByteArray(decoded) shouldBe this
    coseCompliantSerializer.decodeFromByteArray<T>(this) shouldBe expected
}

private fun cborHeader(majorType: Int, length: Int): ByteArray = when {
    length < 24 -> byteArrayOf((majorType shl 5 or length).toByte())
    length < 256 -> byteArrayOf((majorType shl 5 or 24).toByte(), length.toByte())
    else -> byteArrayOf((majorType shl 5 or 25).toByte(), (length shr 8).toByte(), length.toByte())
}

private fun cborBytes(bytes: ByteArray) = cborHeader(2, bytes.size) + bytes
private fun cborText(text: String) = text.encodeToByteArray().let { cborHeader(3, it.size) + it }
private fun cborArray(vararg items: ByteArray) =
    items.fold(cborHeader(4, items.size)) { acc, item -> acc + item }

private fun cborEncodedData(bytes: ByteArray) = byteArrayOf(0xd8.toByte(), 0x18) + cborBytes(bytes)

/** DeviceAuthenticationBytes of ISO/IEC 18013-5:2021 D.5.3, with the session transcript of an NFC engagement. */
internal const val iso18013AnnexDDeviceAuthenticationBytes =
    "d818590271847444657669636541757468656e7469636174696f6e83d8185858a20063312e30018201d818584ba401022001215820" +
            "5a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c33823" +
            "7a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c7168" +
            "7013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f48" +
            "7315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f" +
            "6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f" +
            "63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b62434" +
            "3167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd9102254872159102026372" +
            "0102110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e" +
            "626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4823a1c110103" +
            "69736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766612e6e616e570301" +
            "01032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b020414756f72672e69736f2e31" +
            "383031332e352e312e6d444cd81841a0"
private fun String.decodeFromAnnotatedCbor(): ByteArray =
    trimIndent().split("\n").joinToString("") { it.split("#").first().replace(" ", "") }.decodeToByteArray(Base16)
