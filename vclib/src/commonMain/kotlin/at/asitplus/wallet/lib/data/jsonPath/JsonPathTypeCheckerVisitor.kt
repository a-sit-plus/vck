package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathParser
import at.asitplus.parser.generated.JsonPathParserBaseVisitor

class JsonPathTypeCheckerVisitor(
    private val compiler: JsonPathCompiler,
) : JsonPathParserBaseVisitor<Boolean>() {
    // see section 2.4.3: Well-Typedness of Function Expressions
    // - https://datatracker.ietf.org/doc/rfc9535/
    override fun defaultResult(): Boolean {
        return true
    }

    override fun aggregateResult(aggregate: Boolean?, nextResult: Boolean): Boolean =
        (aggregate ?: true) and nextResult

    override fun visitFunction_expr(ctx: JsonPathParser.Function_exprContext): Boolean {
        val isFunctionArgumentsValid = ctx.function_argument().all {
            visitFunction_argument(it)
        }

        val extension =
            compiler.getFunctionExtensionManager()?.getExtension(ctx.FUNCTION_NAME().text)
                ?: return false
                    .also { compiler.getErrorListener()?.unknownFunctionExtension(ctx.FUNCTION_NAME().text) }

        val isArglistSizeConsistent = ctx.function_argument().size != extension.argumentTypes.size
        val coercedArgumentTypes = ctx.function_argument().mapIndexed { index, argument ->
                val expectedArgumentType = extension.argumentTypes.getOrNull(index)

                val argumentFunctionExpression = argument.function_expr()
                val argumentExtension =
                    argumentFunctionExpression
                        ?.FUNCTION_NAME()?.text?.let {
                            compiler.getFunctionExtensionManager()?.getExtension(it)
                        }

                when (expectedArgumentType) {
                    JsonPathExpressionTypeEnum.LogicalType -> when {
                        argumentExtension is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> JsonPathExpressionTypeEnum.LogicalType
                        argumentExtension is JsonPathFunctionExtension.NodesTypeFunctionExtension -> JsonPathExpressionTypeEnum.LogicalType // can be coerced
                        argument.filter_query() != null -> JsonPathExpressionTypeEnum.LogicalType // can be coerced
                        argument.logical_expr() != null -> JsonPathExpressionTypeEnum.LogicalType

                        argument.literal() != null -> JsonPathExpressionTypeEnum.ValueType
                        argumentExtension is JsonPathFunctionExtension.ValueTypeFunctionExtension -> JsonPathExpressionTypeEnum.ValueType // can't be coerced
                        else -> null
                    }

                    JsonPathExpressionTypeEnum.NodesType -> when {
                        argumentExtension is JsonPathFunctionExtension.NodesTypeFunctionExtension -> JsonPathExpressionTypeEnum.NodesType // can be coerced
                        argument.filter_query() != null -> JsonPathExpressionTypeEnum.NodesType

                        argument.literal() != null -> JsonPathExpressionTypeEnum.ValueType
                        argument.logical_expr() != null -> JsonPathExpressionTypeEnum.LogicalType
                        argumentExtension is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> JsonPathExpressionTypeEnum.LogicalType // can't be coerced
                        argumentExtension is JsonPathFunctionExtension.ValueTypeFunctionExtension -> JsonPathExpressionTypeEnum.ValueType // can't be coerced
                        else -> null
                    }

                    JsonPathExpressionTypeEnum.ValueType -> when {
                        argumentExtension is JsonPathFunctionExtension.ValueTypeFunctionExtension -> JsonPathExpressionTypeEnum.ValueType
                        argument.literal() != null -> JsonPathExpressionTypeEnum.ValueType
                        argument.filter_query() != null -> argument.filter_query()?.text?.let {
                            // must be a singular query
                            val asAbsQuery = "$${it.substring(1)}"
                            if(compiler.compile(asAbsQuery).isSingularQuery) JsonPathExpressionTypeEnum.ValueType
                            else JsonPathExpressionTypeEnum.NodesType
                        }

                        argument.logical_expr() != null -> JsonPathExpressionTypeEnum.LogicalType
                        argumentExtension is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> JsonPathExpressionTypeEnum.LogicalType
                        argumentExtension is JsonPathFunctionExtension.NodesTypeFunctionExtension -> JsonPathExpressionTypeEnum.NodesType
                        else -> null
                    }

                    null -> when {
                        argumentExtension is JsonPathFunctionExtension.ValueTypeFunctionExtension -> JsonPathExpressionTypeEnum.ValueType
                        argumentExtension is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> JsonPathExpressionTypeEnum.LogicalType
                        argumentExtension is JsonPathFunctionExtension.NodesTypeFunctionExtension -> JsonPathExpressionTypeEnum.NodesType
                        argument.literal() != null -> JsonPathExpressionTypeEnum.ValueType
                        argument.filter_query() != null -> JsonPathExpressionTypeEnum.NodesType
                        argument.logical_expr() != null -> JsonPathExpressionTypeEnum.LogicalType
                        else -> null
                    }
                }
            }

        val isCoercedArgumentTypesMatching = coercedArgumentTypes.zip(extension.argumentTypes).any {
            it.first != it.second
        }

        if((isArglistSizeConsistent == false) or (isCoercedArgumentTypesMatching == false)) {
            compiler.getErrorListener()?.invalidArglistForFunctionExtension(
                functionExtension = extension,
                coercedArgumentTypes = coercedArgumentTypes,
            )
        }

        return isArglistSizeConsistent and isCoercedArgumentTypesMatching and isFunctionArgumentsValid
    }

    override fun visitTest_expr(ctx: JsonPathParser.Test_exprContext): Boolean {
        return ctx.function_expr()?.let { functionExpressionContext ->
            val isFunctionExprValid = visitFunction_expr(functionExpressionContext)

            val isValidTestExpressionReturnType =
                when (compiler.getFunctionExtensionManager()
                    ?.getExtension(functionExpressionContext.FUNCTION_NAME().text)) {
                    is JsonPathFunctionExtension.NodesTypeFunctionExtension -> true
                    is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> true
                    null -> false
                    else -> {
                        compiler.getErrorListener()
                            ?.invalidFunctionExtensionForTestExpression(
                                functionExpressionContext.FUNCTION_NAME().text,
                            )
                        false
                    }
                }
            isFunctionExprValid and isValidTestExpressionReturnType
        } ?: true // otherwise this is a filter query and therefore testable
    }

    override fun visitComparison_expr(ctx: JsonPathParser.Comparison_exprContext): Boolean {
        // evaluate all comparables in order to find as many errors as possible
        // otherwise, a comparison always returns a boolean anyway
        return ctx.comparable().map {
            it.function_expr()?.let { functionExpressionContext ->
                val extension = compiler.getFunctionExtensionManager()
                    ?.getExtension(functionExpressionContext.FUNCTION_NAME().text)
                when (extension) {
                    null -> {} // unknown function is reported in visitComparable
                    is JsonPathFunctionExtension.ValueTypeFunctionExtension -> {}
                    else -> {
                        compiler.getErrorListener()?.invalidFunctionExtensionForComparable(
                            functionExpressionContext.FUNCTION_NAME().text,
                        )
                    }
                }
            }
            visitComparable(it)
        }.all {
            it
        }
    }
}