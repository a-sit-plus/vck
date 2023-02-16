package at.asitplus.wallet.lib

import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.booleanArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import java.util.BitSet

class BitSetTest : FreeSpec({


    "Custom BitSet Implementation" - {


        "manual tests" {
            val kmm = KmmBitSet(0)
            val jvm = BitSet(0)

            2.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.toBitString() shouldBe "00100000"
            kmm.toBitString() shouldBe "00100000"

            8.let {
                kmm[it.toLong()] = true
                jvm[it] = true
            }
            jvm.toBitString() shouldBe "00100000 10000000"
            kmm.toBitString() shouldBe "00100000 10000000"


            2.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toBitString() shouldBe "00000000 10000000"
            kmm.toBitString() shouldBe "00000000 10000000"

            10.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toBitString() shouldBe "00000000 10000000"
            kmm.toBitString() shouldBe "00000000 10000000"


            8.let {
                kmm[it.toLong()] = false
                jvm[it] = false
            }

            jvm.toBitString() shouldBe ""
            kmm.toBitString() shouldBe ""


        }


        checkAll(
            iterations = 32,
            Arb.booleanArray(
                Arb.int(1..128),
                Arb.boolean()
            )
        ) { input ->
            withData(
                input.size,
                input.size / 2,
                input.size / 3,
                input.size / 4,
                input.size / 8,
                input.size / 10,
                1,
                0,
                input.size * 2,
                input.size * 4
            ) { size:Int ->
                val jvm = BitSet(size).also {
                    input.indices.shuffled().forEach { i -> it.set(i, input[i]) }
                }
                val kmm = withClue("size: $size") {
                    KmmBitSet(size.toLong()).also {
                        input.indices.shuffled().forEach { i -> it[i.toLong()] = input[i] }
                    }
                }

                withClue("\nKMM: ${kmm.toBitString()}\nJVM: ${jvm.toBitString()}") {
                    kmm.length() shouldBe jvm.length()
                }

                input.forEachIndexed { i, b ->
                    withClue("jvm[$i]") { jvm[i] shouldBe b }
                    withClue("kmm[$i]") { kmm[i.toLong()] shouldBe b }
                }

                withClue("first bit set") { kmm.nextSetBit(0).toInt() shouldBe jvm.nextSetBit(0) }

                val i = input.size - 1
                withClue(
                    "first bit set in second half\n" +
                            "KMM: ${kmm.toBitString()}\n" +
                            "JVM: ${jvm.toBitString()}"
                ) {
                    kmm.nextSetBit(i.toLong() / 2L).toInt() shouldBe jvm.nextSetBit(i / 2)
                }
                withClue(
                    "first bit set in last three quarters\n" +
                            "KMM: ${kmm.toBitString()}\n" +
                            "JVM: ${jvm.toBitString()}"
                ) {
                    kmm.nextSetBit(i.toLong() / 4L).toInt() shouldBe jvm.nextSetBit(i / 4)
                }
                withClue(
                    "first bit set in last 4/5 of bit set\n" +
                            "KMM: ${kmm.toBitString()}\n" +
                            "JVM: ${jvm.toBitString()}"
                ) {
                    kmm.nextSetBit(4L * i.toLong() / 5L).toInt() shouldBe jvm.nextSetBit(4 * i / 5)
                }
                kmm.toByteArray() shouldBe jvm.toByteArray()


                BitSet.valueOf(kmm.toByteArray()).toByteArray() shouldBe jvm.toByteArray()
                kmm.toByteArray().toBitSet().toByteArray() shouldBe jvm.toByteArray()
                jvm.toByteArray().toBitSet().toByteArray() shouldBe jvm.toByteArray()
               kmm.toByteArray().toBitSet().toByteArray() shouldBe kmm.toByteArray()

               jvm.toByteArray().toBitSet().toByteArray() shouldBe kmm.toByteArray()
                BitSet.valueOf(jvm.toByteArray()).toByteArray() shouldBe kmm.toByteArray()
                BitSet.valueOf(kmm.toByteArray()).toByteArray() shouldBe kmm.toByteArray()
                BitSet.valueOf(jvm.toByteArray()).toByteArray() shouldBe jvm.toByteArray()

            }
        }

        "toString() Tests" - {
            checkAll(
                iterations = 32,
                Arb.booleanArray(
                    Arb.int(1..128),
                    Arb.boolean()
                )
            ) { input ->
                withData(
                    input.size,
                    input.size / 2,
                    input.size / 3,
                    input.size / 4,
                    input.size / 8,
                    input.size / 10,
                    1,
                    0,
                    input.size * 2,
                    input.size * 4
                ) { size ->
                    val jvm = BitSet(size).also {
                        input.indices.shuffled().forEach { i -> it.set(i, input[i]) }
                    }
                    val kmm = withClue("size: $size") {
                        KmmBitSet(size.toLong()).also {
                            input.indices.shuffled().forEach { i -> it[i.toLong()] = input[i] }
                        }
                    }

                    input.forEachIndexed { i, b ->
                        withClue("jvm[$i]") { jvm[i] shouldBe b }
                        withClue("kmm[$i]") { kmm[i.toLong()] shouldBe b }
                    }

                    val truncated = input.dropLastWhile { !it }
                    val monotonicOrderedStr = truncated.chunked(8)
                        .map { byte ->
                            (0 until 8).map { kotlin.runCatching { byte[it] }.getOrElse { false } }
                                .joinToString(separator = "") { if (it) "1" else "0" }
                        }.joinToString(separator = " ") { it }

                    jvm.toBitString() shouldBe monotonicOrderedStr
                    kmm.toBitString() shouldBe monotonicOrderedStr
                }
            }
        }
    }
})
fun BitSet.toBitString()=toByteArray().toBitString()
