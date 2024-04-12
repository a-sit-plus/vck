package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathBaseVisitor
import at.asitplus.parser.generated.JSONPathParser
import kotlinx.serialization.json.JsonElement

internal class JSONPathFilterExpressionEvaluator(
    val rootNode: JsonElement,
    val currentNode: JsonElement,
    val functionExtensions: Map<String, FunctionExtensionEvaluator>
) : JSONPathBaseVisitor<JSONPathFilterExpressionValue>() {
    override fun visitLogicalExpr(ctx: JSONPathParser.LogicalExprContext): JSONPathFilterExpressionValue {
        val logicalExpressionEvaluator = JSONPathLogicalFilterExpressionEvaluator(
            rootNode = rootNode,
            currentNode = currentNode,
            functionExtensions = functionExtensions,
        )
        return JSONPathFilterExpressionValue.LogicalValue(logicalExpressionEvaluator.visitLogicalExpr(ctx))
    }

    override fun visitRelQuery(ctx: JSONPathParser.RelQueryContext): JSONPathFilterExpressionValue {
        return JSONPathFilterExpressionValue.NodeListValue(
            currentNode.matchJsonPath("$${ctx.segments().text}").map {
                it.value
            }
        )
    }

    override fun visitJsonpathQuery(ctx: JSONPathParser.JsonpathQueryContext): JSONPathFilterExpressionValue {
        return JSONPathFilterExpressionValue.NodeListValue(
            rootNode.matchJsonPath(ctx.text).map {
                it.value
            }
        )
    }

    override fun visitFunctionExpr(ctx: JSONPathParser.FunctionExprContext): JSONPathFilterExpressionValue {
        val functionExtensionName = ctx.functionName().text
        return functionExtensions[functionExtensionName]?.invoke(
            ctx.functionArgument().map {
                visitFunctionArgument(it)
            }
        ) ?: throw UnknownFunctionExtensionException(functionExtensionName)
    }

    override fun visitRelSingularQuery(ctx: JSONPathParser.RelSingularQueryContext): JSONPathFilterExpressionValue {
        val value =
            currentNode.matchJsonPath("$" + ctx.singularQuerySegments().text).firstOrNull()?.value
        return when (value) {
            null -> JSONPathFilterExpressionValue.NodeListValue(listOf())
            else -> value.toJSONPathFilterExpressionValue()
        }
    }

    override fun visitNumber(ctx: JSONPathParser.NumberContext): JSONPathFilterExpressionValue {
        // TODO: maybe support other number formats like Long?
        return JSONPathFilterExpressionValue.NumberValue.DoubleValue(
            ctx.text.toDouble()
        )
    }

    override fun visitStringLiteral(ctx: JSONPathParser.StringLiteralContext): JSONPathFilterExpressionValue {
        return JSONPathFilterExpressionValue.StringValue(
            ctx.toUnescapedString()
        )
    }

    override fun visitNull(ctx: JSONPathParser.NullContext): JSONPathFilterExpressionValue {
        return JSONPathFilterExpressionValue.NullValue
    }

    override fun visitTrue(ctx: JSONPathParser.TrueContext): JSONPathFilterExpressionValue {
        return JSONPathFilterExpressionValue.LogicalValue(true)
    }

    override fun visitFalse(ctx: JSONPathParser.FalseContext): JSONPathFilterExpressionValue {
        return JSONPathFilterExpressionValue.LogicalValue(false)
    }
}