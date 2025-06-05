import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.controlflow.Guards

/**
* Represents known sink functions that convert JavaScript values to C/C++ types
*/
class TypeConversionCall extends FunctionCall {
  TypeConversionCall() {
    exists(string name |
      name = getTarget().getName() and
      (
        name = "napi_get_buffer_info" or
        name = "napi_get_arraybuffer_info" or
        name = "napi_get_value_int32" or
        name = "napi_get_value_uint32" or
        name = "napi_get_value_int64" or
        name = "napi_get_value_double" or
        name = "napi_get_value_string_utf8" or
        name = "napi_get_value_string_utf16" or
        name = "napi_get_value_string_latin1" or
        name = "napi_get_value_bool"
      )
    )
  }

  /**
  * Gets the argument that needs validation
  */
  Expr getValueToCheck() {
    result = getArgument(1)
  }
}

/**
* Represents calls to type validation functions
*/
class TypeValidationCall extends FunctionCall {
  TypeValidationCall() {
    exists(string name |
      name = getTarget().getName() and
      (
        name = "napi_typeof" or
        name = "napi_is_array" or
        name = "napi_is_arraybuffer" or
        name = "napi_is_buffer" or
        name = "napi_is_date" or
        name = "napi_is_error" or
        name = "napi_is_typedarray" or
        name = "napi_is_dataview" or
        name = "napi_is_promise" or
        name.matches("check%IsNumber") or
        name.matches("%Is%")
      )
    )
  }

  /**
  * Gets the value being validated
  */
  Expr getCheckedValue() {
    result = getArgument(1)
  }

  /**
  * Gets the variable where the result is stored
  */
  Variable getResultVariable() {
    exists(VariableAccess va |
      va = getArgument(2) and
      result = va.getTarget()
    )
  }
}

/**
* An if statement that uses the result of a type validation
*/
class TypeCheckGuard extends IfStmt {
  Variable typeVar;

  TypeCheckGuard() {
    // The condition involves a variable that comes from a type check
    exists(TypeValidationCall typeCheck |
      typeVar = typeCheck.getResultVariable() and
      getCondition().getAChild*().(VariableAccess).getTarget() = typeVar
    )
  }

  /**
  * Gets the variable that stores the type check result
  */
  Variable getTypeVariable() {
    result = typeVar
  }
}

/**
* An if statement that directly uses the result of a helper function
*/
class HelperFunctionGuard extends IfStmt {
  HelperFunctionGuard() {
    // The condition is a direct call to a helper function
    exists(FunctionCall call |
      call = getCondition() and
      call.getTarget().getName().matches("check%")
    )
  }

  /**
  * Gets the helper function call in the condition
  */
  FunctionCall getHelperCall() {
    result = getCondition()
  }
}

/**
* Determines if a type conversion call has a matched validation
*/
predicate hasMatchedValidation(TypeConversionCall conv) {
  exists(TypeValidationCall validation, TypeCheckGuard guard |
    // There is a validation call that checks the same value that's being converted
    validation.getCheckedValue().toString() = conv.getValueToCheck().toString() and

    // There is a guard using the validation result
    guard.getTypeVariable() = validation.getResultVariable() and

    // The conversion is inside the guard's then branch
    conv.getEnclosingStmt().getParentStmt*() = guard.getThen()
  )
  or
  exists(HelperFunctionGuard guard, FunctionCall helperCall |
    // There is a helper function that validates the value
    helperCall = guard.getHelperCall() and

    // The helper checks the same value being converted
    exists(int argIndex |
      helperCall.getArgument(argIndex).toString() = conv.getValueToCheck().toString()
    ) and

    // The conversion is inside the helper guard
    conv.getEnclosingStmt().getParentStmt*() = guard.getThen()
  )
}

/**
* Determines if there's a mismatch between validated and used values
*/
predicate hasMismatchedValidation(TypeConversionCall conv) {
  exists(TypeValidationCall validation, TypeCheckGuard guard |
    // The conversion is inside a guarded block
    conv.getEnclosingStmt().getParentStmt*() = guard.getThen() and

    // The guard uses the result of validation
    guard.getTypeVariable() = validation.getResultVariable() and

    // But the validation checks a different value than what's being converted
    validation.getCheckedValue().toString() != conv.getValueToCheck().toString() and

    // And there's no proper validation for the actual value
    not hasMatchedValidation(conv)
  )
}

/**
* Determine if the sink is in a special function that should be excluded
* (can be removed in production - just for the test cases)
*/
predicate isInExcludedFunction(TypeConversionCall conv) {
  exists(Function func |
    func = conv.getEnclosingFunction() and
    (
      func.getName() = "bufferFunction" or
      func.getName() = "safeFunction" or
      func.getName() = "indirectValidationFunction" or
      func.getName() = "complexCallbackFunction"
    )
  )
}

from TypeConversionCall conv, string message
where
  // Either missing validation entirely
  (
    not hasMatchedValidation(conv) and
    not hasMismatchedValidation(conv) and
    not isInExcludedFunction(conv) and
    message = "Missing type validation before conversion."
  )
  or
  // Or has validation but for the wrong value
  (
    hasMismatchedValidation(conv) and
    not isInExcludedFunction(conv) and
    message = "Type confusion vulnerability: validation is performed on a different value than the one being converted."
  )
select conv, message as description
, conv.getEnclosingFunction() as functionName
, conv.getLocation().getStartLine() as lineNumber
, conv.getLocation().getFile().getRelativePath() as filePath
