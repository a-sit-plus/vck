package at.asitplus.wallet.lib.data.jsonPath

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class JsonStringLiteralTest : FreeSpec({
    "rfc8259" - {
        "unescapes backslash to backslash" {
            Rfc8259Utils.unpackStringLiteral("\"\\\\\"") shouldBe "\\"
        }
        "unescapes slash to slash" {
            Rfc8259Utils.unpackStringLiteral("\"\\/\"") shouldBe "/"
        }
        "unescapes quotation mark to quotation mark" {
            Rfc8259Utils.unpackStringLiteral("\"\\\"\"") shouldBe "\""
        }
        "unescapes b to backspace" {
            Rfc8259Utils.unpackStringLiteral("\"\\b\"") shouldBe Char(0x0008).toString()
        }
        "unescapes f to form feed" {
            Rfc8259Utils.unpackStringLiteral("\"\\f\"") shouldBe Char(0x000C).toString()
        }
        "unescapes n to newline" {
            Rfc8259Utils.unpackStringLiteral("\"\\n\"") shouldBe "\n"
        }
        "unescapes r to carriage return" {
            Rfc8259Utils.unpackStringLiteral("\"\\r\"") shouldBe "\r"
        }
        "unescapes t to horizontal tab" {
            Rfc8259Utils.unpackStringLiteral("\"\\t\"") shouldBe "\t"
        }
    }
    "rfc9535" - {
        "rfc8259 conformance" - {
            "double quoted" - {
                "unescapes backslash to backslash" {
                    Rfc9535Utils.unpackStringLiteral("\"\\\\\"") shouldBe "\\"
                }
                "unescapes slash to slash" {
                    Rfc9535Utils.unpackStringLiteral("\"\\/\"") shouldBe "/"
                }
                "unescapes quotation mark to quotation mark" {
                    Rfc9535Utils.unpackStringLiteral("\"\\\"\"") shouldBe "\""
                }
                "unescapes b to backspace" {
                    Rfc9535Utils.unpackStringLiteral("\"\\b\"") shouldBe Char(0x0008).toString()
                }
                "unescapes f to form feed" {
                    Rfc9535Utils.unpackStringLiteral("\"\\f\"") shouldBe Char(0x000C).toString()
                }
                "unescapes n to newline" {
                    Rfc9535Utils.unpackStringLiteral("\"\\n\"") shouldBe "\n"
                }
                "unescapes r to carriage return" {
                    Rfc9535Utils.unpackStringLiteral("\"\\r\"") shouldBe "\r"
                }
                "unescapes t to horizontal tab" {
                    Rfc9535Utils.unpackStringLiteral("\"\\t\"") shouldBe "\t"
                }
            }
            "single quoted" - {
                "unescapes backslash to backslash" {
                    Rfc9535Utils.unpackStringLiteral("'\\\\'") shouldBe "\\"
                }
                "unescapes slash to slash" {
                    Rfc9535Utils.unpackStringLiteral("'\\/'") shouldBe "/"
                }
                "unescapes quotation mark to quotation mark" {
                    Rfc9535Utils.unpackStringLiteral("'\\''") shouldBe "'"
                }
                "unescapes b to backspace" {
                    Rfc9535Utils.unpackStringLiteral("'\\b'") shouldBe Char(0x0008).toString()
                }
                "unescapes f to form feed" {
                    Rfc9535Utils.unpackStringLiteral("'\\f'") shouldBe Char(0x000C).toString()
                }
                "unescapes n to newline" {
                    Rfc9535Utils.unpackStringLiteral("'\\n'") shouldBe "\n"
                }
                "unescapes r to carriage return" {
                    Rfc9535Utils.unpackStringLiteral("'\\r'") shouldBe "\r"
                }
                "unescapes t to horizontal tab" {
                    Rfc9535Utils.unpackStringLiteral("'\\t'") shouldBe "\t"
                }
            }
        }
    }
})