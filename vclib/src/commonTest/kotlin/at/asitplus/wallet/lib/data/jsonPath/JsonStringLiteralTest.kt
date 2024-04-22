package at.asitplus.wallet.lib.data.jsonPath

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class JsonStringLiteralTest : FreeSpec({
    "rfc8259" - {
        "unescapes backslash to backslash" {
            rfc8259Utils.unpackStringLiteral("\"\\\\\"") shouldBe "\\"
        }
        "unescapes slash to slash" {
            rfc8259Utils.unpackStringLiteral("\"\\/\"") shouldBe "/"
        }
        "unescapes quotation mark to quotation mark" {
            rfc8259Utils.unpackStringLiteral("\"\\\"\"") shouldBe "\""
        }
        "unescapes b to backspace" {
            rfc8259Utils.unpackStringLiteral("\"\\b\"") shouldBe Char(0x0008).toString()
        }
        "unescapes f to form feed" {
            rfc8259Utils.unpackStringLiteral("\"\\f\"") shouldBe Char(0x000C).toString()
        }
        "unescapes n to newline" {
            rfc8259Utils.unpackStringLiteral("\"\\n\"") shouldBe "\n"
        }
        "unescapes r to carriage return" {
            rfc8259Utils.unpackStringLiteral("\"\\r\"") shouldBe "\r"
        }
        "unescapes t to horizontal tab" {
            rfc8259Utils.unpackStringLiteral("\"\\t\"") shouldBe "\t"
        }
    }
    "rfc9535" - {
        "rfc8259 conformance" - {
            "double quoted" - {
                "unescapes backslash to backslash" {
                    rfc9535Utils.unpackStringLiteral("\"\\\\\"") shouldBe "\\"
                }
                "unescapes slash to slash" {
                    rfc9535Utils.unpackStringLiteral("\"\\/\"") shouldBe "/"
                }
                "unescapes quotation mark to quotation mark" {
                    rfc9535Utils.unpackStringLiteral("\"\\\"\"") shouldBe "\""
                }
                "unescapes b to backspace" {
                    rfc9535Utils.unpackStringLiteral("\"\\b\"") shouldBe Char(0x0008).toString()
                }
                "unescapes f to form feed" {
                    rfc9535Utils.unpackStringLiteral("\"\\f\"") shouldBe Char(0x000C).toString()
                }
                "unescapes n to newline" {
                    rfc9535Utils.unpackStringLiteral("\"\\n\"") shouldBe "\n"
                }
                "unescapes r to carriage return" {
                    rfc9535Utils.unpackStringLiteral("\"\\r\"") shouldBe "\r"
                }
                "unescapes t to horizontal tab" {
                    rfc9535Utils.unpackStringLiteral("\"\\t\"") shouldBe "\t"
                }
            }
            "single quoted" - {
                "unescapes backslash to backslash" {
                    rfc9535Utils.unpackStringLiteral("'\\\\'") shouldBe "\\"
                }
                "unescapes slash to slash" {
                    rfc9535Utils.unpackStringLiteral("'\\/'") shouldBe "/"
                }
                "unescapes quotation mark to quotation mark" {
                    rfc9535Utils.unpackStringLiteral("'\\''") shouldBe "'"
                }
                "unescapes b to backspace" {
                    rfc9535Utils.unpackStringLiteral("'\\b'") shouldBe Char(0x0008).toString()
                }
                "unescapes f to form feed" {
                    rfc9535Utils.unpackStringLiteral("'\\f'") shouldBe Char(0x000C).toString()
                }
                "unescapes n to newline" {
                    rfc9535Utils.unpackStringLiteral("'\\n'") shouldBe "\n"
                }
                "unescapes r to carriage return" {
                    rfc9535Utils.unpackStringLiteral("'\\r'") shouldBe "\r"
                }
                "unescapes t to horizontal tab" {
                    rfc9535Utils.unpackStringLiteral("'\\t'") shouldBe "\t"
                }
            }
        }
    }
})