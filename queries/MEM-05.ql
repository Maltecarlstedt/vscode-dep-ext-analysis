import cpp
import semmle.code.cpp.dataflow.DataFlow

/**
* Represents a string.h function that assumes NULL-terminated strings
*/
class NullTerminatedStringFunction extends Function {
  NullTerminatedStringFunction() {
    exists(string name | name = this.getName() |
      // Standard C string functions that assume NULL termination
      name = "strlen" or
      name = "strcpy" or name = "strncpy" or
      name = "strcat" or name = "strncat" or
      name = "strcmp" or name = "strncmp" or
      name = "strchr" or name = "strrchr" or
      name = "strstr" or
      name = "sprintf" or name = "vsprintf" or
      // Other functions that might be problematic
      name = "strtok" or
      name = "atoi" or name = "atol" or name = "atof"
    )
  }
}

/**
* Represents a call to N-API functions that handle JavaScript strings or buffers
*/
class JavaScriptDataSource extends FunctionCall {
  JavaScriptDataSource() {
    exists(string name | name = this.getTarget().getName() |
      // N-API string functions
      name = "napi_get_value_string_utf8" or
      name = "napi_get_value_string_utf16" or
      name = "napi_get_value_string_latin1" or
      // N-API buffer functions
      name = "napi_get_buffer_info" or
      name = "napi_get_arraybuffer_info" or
      name = "napi_get_typedarray_info" or
      name = "napi_get_dataview_info"
    )
  }

  /**
  * Get the buffer/string argument from the function call
  */
  Expr getBufferArg() {
    // String API: Get the buffer argument (3rd parameter - index 2)
    // env, value, buffer, bufsize, result
    result = this.getArgument(2) and
    (
      this.getTarget().getName() = "napi_get_value_string_utf8" or
      this.getTarget().getName() = "napi_get_value_string_utf16" or
      this.getTarget().getName() = "napi_get_value_string_latin1"
    )
    or
    // Buffer API: Get the data pointer (3rd parameter - index 2)
    // env, value, data, length
    result = this.getArgument(2) and
    this.getTarget().getName() = "napi_get_buffer_info"
    or
    // ArrayBuffer API: Get the data pointer (3rd parameter - index 2)
    // env, value, data, length
    result = this.getArgument(2) and
    this.getTarget().getName() = "napi_get_arraybuffer_info"
    or
    // TypedArray API: Get the data pointer (5th parameter - index 4)
    // env, value, type, length, data, ...
    result = this.getArgument(4) and
    this.getTarget().getName() = "napi_get_typedarray_info"
    or
    // DataView API: Get the data pointer (5th parameter - index 4)
    // env, value, arraybuffer, byte_offset, byte_length, data
    result = this.getArgument(4) and
    this.getTarget().getName() = "napi_get_dataview_info"
  }

  /**
  * Get the length output argument from the function call
  */
  Expr getLengthArg() {
    result = this.getArgument(4) and
    (
      this.getTarget().getName() = "napi_get_value_string_utf8" or
      this.getTarget().getName() = "napi_get_value_string_utf16" or
      this.getTarget().getName() = "napi_get_value_string_latin1"
    )
    or
    result = this.getArgument(3) and
    this.getTarget().getName() = "napi_get_buffer_info"
    or
    result = this.getArgument(3) and
    this.getTarget().getName() = "napi_get_arraybuffer_info"
    or
    result = this.getArgument(3) and
    this.getTarget().getName() = "napi_get_typedarray_info"
    or
    result = this.getArgument(5) and
    this.getTarget().getName() = "napi_get_dataview_info"
  }
}

/**
* A variable that is used to store the data from JavaScript
*/
class JavaScriptDataVar extends Variable {
  JavaScriptDataVar() {
    exists(JavaScriptDataSource source, AssignExpr ae |
      // The variable is assigned from a JavaScript source
      ae.getLValue().(VariableAccess).getTarget() = this and
      DataFlow::localExprFlow(source.getBufferArg(), ae.getRValue())
    )
    or
    exists(JavaScriptDataSource source, VariableAccess va |
      // The variable is used directly as the buffer argument in an N-API call
      va = source.getBufferArg() and
      va.getTarget() = this
    )
  }
}

/**
* Check if a variable has its length properly validated
*/
predicate hasLengthValidation(Variable v) {
  exists(JavaScriptDataSource source, VariableAccess lengthVa |
    // JavaScript data source stores length into a variable
    lengthVa = source.getLengthArg() and
    lengthVa instanceof VariableAccess and

    // Match both the data and length arguments to the same source
    exists(VariableAccess dataVa |
      dataVa = source.getBufferArg() and
      dataVa.getTarget() = v
    )
  )
}

/**
* A call to a string function with a JavaScript data source
*/
class UnsafeStringOperation extends FunctionCall {
  Variable jsDataVar;

  UnsafeStringOperation() {
    // The function is a string operation assuming NULL termination
    this.getTarget() instanceof NullTerminatedStringFunction and

    // At least one argument has data flowing from JavaScript
    exists(Expr arg, int i |
      arg = this.getArgument(i) and
      DataFlow::localExprFlow(any(VariableAccess va | va.getTarget() = jsDataVar), arg)
    ) and

    // The variable is a JavaScript data source
    jsDataVar instanceof JavaScriptDataVar and

    // Check if the length validation exists
    not hasLengthValidation(jsDataVar)
  }

  /**
  * Get the JavaScript data variable
  */
  Variable getJSDataVar() {
    result = jsDataVar
  }
}

/**
* A call to malloc/calloc/realloc where the size is determined by strlen
*/
class UnsafeBufferSizeCalculation extends FunctionCall {
  FunctionCall strlenCall;
  Variable jsDataVar;

  UnsafeBufferSizeCalculation() {
    // This is a memory allocation
    exists(string name | name = this.getTarget().getName() |
      name = "malloc" or name = "calloc" or name = "realloc"
    ) and

    // The size argument involves a call to strlen
    exists(Expr sizeArg, int i |
      (
        i = 0 and this.getTarget().getName() = "malloc" or
        i = 1 and this.getTarget().getName() = "calloc" or
        i = 1 and this.getTarget().getName() = "realloc"
      ) and
      sizeArg = this.getArgument(i) and
      exists(FunctionCall fc |
        fc.getEnclosingElement+() = sizeArg and
        fc.getTarget().getName() = "strlen" and
        fc = strlenCall
      )
    ) and

    // The strlen call uses a JavaScript data source
    exists(VariableAccess va |
      va = strlenCall.getArgument(0) and
      va.getTarget() instanceof JavaScriptDataVar and
      va.getTarget() = jsDataVar
    )
  }

  /**
  * Get the strlen call
  */
  FunctionCall getStrlenCall() {
    result = strlenCall
  }

  /**
  * Get the JavaScript data variable
  */
  Variable getJSDataVar() {
    result = jsDataVar
  }
}

/**
* A call to create string from a potentially non-null terminated buffer
*/
class UnsafeStringCreation extends FunctionCall {
  FunctionCall strlenCall;

  UnsafeStringCreation() {
    this.getTarget().getName() = "napi_create_string_utf8" and

    // The length argument is based on strlen
    exists(FunctionCall fc |
      fc.getTarget().getName() = "strlen" and
      DataFlow::localExprFlow(fc, this.getArgument(2)) and
      fc = strlenCall
    ) and

    // The buffer is from a source that may not be NULL-terminated
    exists(JavaScriptDataSource source, VariableAccess bufferVa |
      bufferVa = this.getArgument(1) and
      DataFlow::localExprFlow(source.getBufferArg(), bufferVa)
    )
  }

  /**
  * Get the strlen call
  */
  FunctionCall getStrlenCall() {
    result = strlenCall
  }
}

/**
* Simplified direct flow detection
*/
predicate hasUnsafeDirectFlow(JavaScriptDataSource source, FunctionCall fc) {
  fc.getTarget() instanceof NullTerminatedStringFunction and
  exists(Expr arg |
    arg = fc.getAnArgument() and
    DataFlow::localExprFlow(source.getBufferArg(), arg)
  )
}

from Element e, string message
where
  // Case 1: Using string.h functions on JavaScript data
  (
    exists(UnsafeStringOperation op |
      e = op and
      message = "Using " + op.getTarget().getName() + "() on JavaScript string data can lead to truncation at embedded NULL bytes."
    )
  )
  or
  // Case 2: Unsafe buffer size calculation
  (
    exists(UnsafeBufferSizeCalculation op |
      e = op and
      message = "Buffer size calculated using strlen() on JavaScript data may be incorrect due to embedded NULL bytes."
    )
  )
  or
  // Case 3: Direct flow from JavaScript data to string function
  (
    exists(JavaScriptDataSource source, FunctionCall fc |
      hasUnsafeDirectFlow(source, fc) and
      e = fc and
      message = "JavaScript data flows to " + fc.getTarget().getName() + "() which assumes NULL termination, risking truncation at embedded NULL bytes."
    )
  )
  or
  // Case 4: Creating string from buffer without proper validation
  (
    exists(UnsafeStringCreation op |
      e = op and
      message = "Creating string using length from strlen() on JavaScript data may truncate at embedded NULL bytes."
    )
  )

select e, message as description
, e.getFile().getRelativePath() as filePath
, e.getLocation().getStartLine() as lineNumber
