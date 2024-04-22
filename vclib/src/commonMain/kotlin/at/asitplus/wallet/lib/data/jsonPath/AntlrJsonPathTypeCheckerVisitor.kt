package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathParser
import at.asitplus.parser.generated.JsonPathParserBaseVisitor

class AntlrJsonPathTypeCheckerVisitor(
    private val compiler: JsonPathCompiler,
    private val errorListener: AntlrJsonPathTypeCheckerErrorListener?,
    private val functionExtensionRetriever: (String) -> JsonPathFunctionExtension<*>?,
) : JsonPathParserBaseVisitor<AntlrJsonPathTypeCheckerExpressionType>() {
    // see section 2.4.3: Well-Typedness of Function Expressions
    // - https://datatracker.ietf.org/doc/rfc9535/
    override fun defaultResult(): AntlrJsonPathTypeCheckerExpressionType {
        return AntlrJsonPathTypeCheckerExpressionType.NoType
    }

    override fun aggregateResult(
        aggregate: AntlrJsonPathTypeCheckerExpressionType?,
        nextResult: AntlrJsonPathTypeCheckerExpressionType
    ): AntlrJsonPathTypeCheckerExpressionType {
        if (nextResult == AntlrJsonPathTypeCheckerExpressionType.ErrorType) {
            return AntlrJsonPathTypeCheckerExpressionType.ErrorType
        }
        if (aggregate == AntlrJsonPathTypeCheckerExpressionType.ErrorType) {
            return AntlrJsonPathTypeCheckerExpressionType.ErrorType
        }
        return AntlrJsonPathTypeCheckerExpressionType.NoType
    }

    override fun visitFilter_query(ctx: JsonPathParser.Filter_queryContext): AntlrJsonPathTypeCheckerExpressionType {
        return if(compiler.compile("$${ctx.text.substring(1)}").isSingularQuery) {
            AntlrJsonPathTypeCheckerExpressionType.NodesType.FilterQuery.SingularQuery
        } else {
            AntlrJsonPathTypeCheckerExpressionType.NodesType.FilterQuery.NonSingularQuery
        }
    }

    override fun visitSingular_query(ctx: JsonPathParser.Singular_queryContext): AntlrJsonPathTypeCheckerExpressionType {
        return AntlrJsonPathTypeCheckerExpressionType.NodesType.FilterQuery.SingularQuery
    }

    override fun visitLogical_expr(ctx: JsonPathParser.Logical_exprContext): AntlrJsonPathTypeCheckerExpressionType {
        return AntlrJsonPathTypeCheckerExpressionType.LogicalType
    }

    override fun visitLiteral(ctx: JsonPathParser.LiteralContext): AntlrJsonPathTypeCheckerExpressionType {
        return AntlrJsonPathTypeCheckerExpressionType.ValueType.LiteralValueType
    }

    override fun visitFunction_expr(ctx: JsonPathParser.Function_exprContext): AntlrJsonPathTypeCheckerExpressionType {
        val functionArgumentTypes = ctx.function_argument().map {
            visitFunction_argument(it)
        }

        val extension =
            functionExtensionRetriever.invoke(ctx.FUNCTION_NAME().text)
                ?: return AntlrJsonPathTypeCheckerExpressionType.ErrorType
                    .also {
                        errorListener?.unknownFunctionExtension(ctx.FUNCTION_NAME().text)
                    }

        val isArglistSizeConsistent = ctx.function_argument().size == extension.argumentTypes.size
        val coercedArgumentTypes = functionArgumentTypes.mapIndexed { index, argumentType ->
            val expectedArgumentType = extension.argumentTypes.getOrNull(index)

            when (expectedArgumentType) {
                JsonPathExpressionType.LogicalType -> when (argumentType) {
                    is AntlrJsonPathTypeCheckerExpressionType.NodesType -> JsonPathExpressionType.LogicalType

                    else -> argumentType.jsonPathExpressionType
                }

                JsonPathExpressionType.NodesType -> argumentType.jsonPathExpressionType // no conversions

                JsonPathExpressionType.ValueType -> when (argumentType) {
                    is AntlrJsonPathTypeCheckerExpressionType.NodesType.FilterQuery.SingularQuery -> JsonPathExpressionType.ValueType
                    argumentExtension is JsonPathFunctionExtension.ValueTypeFunctionExtension -> JsonPathExpressionType.ValueType
                    argument.literal() != null -> JsonPathExpressionType.ValueType
                    argument.filter_query() != null -> argument.filter_query()?.text?.let {
                        // must be a singular query
                        val asJsonPathQuery = "$${it.substring(1)}"
                        if (compiler.compile(asJsonPathQuery).isSingularQuery) JsonPathExpressionType.ValueType
                        else JsonPathExpressionType.NodesType
                    }

                    argument.logical_expr() != null -> JsonPathExpressionType.LogicalType
                    argumentExtension is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> JsonPathExpressionType.LogicalType
                    argumentExtension is JsonPathFunctionExtension.NodesTypeFunctionExtension -> JsonPathExpressionType.NodesType
                    else -> argumentType.jsonPathExpressionType
                }

                null -> when {
                    argumentExtension is JsonPathFunctionExtension.ValueTypeFunctionExtension -> JsonPathExpressionType.ValueType
                    argumentExtension is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> JsonPathExpressionType.LogicalType
                    argumentExtension is JsonPathFunctionExtension.NodesTypeFunctionExtension -> JsonPathExpressionType.NodesType
                    argument.literal() != null -> JsonPathExpressionType.ValueType
                    argument.filter_query() != null -> JsonPathExpressionType.NodesType
                    argument.logical_expr() != null -> JsonPathExpressionType.LogicalType
                    else -> null
                }
            }
        }

        val isCoercedArgumentTypesMatching =
            coercedArgumentTypes.mapIndexed { index, jsonPathExpressionType ->
                jsonPathExpressionType == extension.argumentTypes.get(index)
            }.all {
                it
            }

        if ((isArglistSizeConsistent == false) or (isCoercedArgumentTypesMatching == false)) {
            errorListener?.invalidArglistForFunctionExtension(
                functionExtension = extension,
                coercedArgumentTypes = coercedArgumentTypes,
            )
        }

        return if (isArglistSizeConsistent and isCoercedArgumentTypesMatching and isFunctionArgumentsValid) {
            return when (extension) {
                is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> AntlrJsonPathTypeCheckerExpressionType.LogicalType
                is JsonPathFunctionExtension.NodesTypeFunctionExtension -> AntlrJsonPathTypeCheckerExpressionType.NodesType
                is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> AntlrJsonPathTypeCheckerExpressionType.LogicalType
            }
        }
    }

    override fun visitTest_expr(ctx: JsonPathParser.Test_exprContext): Boolean {
        return ctx.function_expr()?.let { functionExpressionContext ->
            val isFunctionExprValid = visitFunction_expr(functionExpressionContext)

            val isValidTestExpressionReturnType =
                when (functionExtensionRetriever.invoke(functionExpressionContext.FUNCTION_NAME().text)) {
                    is JsonPathFunctionExtension.NodesTypeFunctionExtension -> true
                    is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> true
                    null -> false
                    else -> {
                        errorListener
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
                val extension =
                    functionExtensionRetriever.invoke(functionExpressionContext.FUNCTION_NAME().text)
                when (extension) {
                    null -> {} // unknown function is reported in visitComparable
                    is JsonPathFunctionExtension.ValueTypeFunctionExtension -> {}
                    else -> {
                        errorListener?.invalidFunctionExtensionForComparable(
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

    override fun visitComparable(ctx: JsonPathParser.ComparableContext): Boolean {
        return super.visitComparable(ctx)
    }
}

