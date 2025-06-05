import cpp
import semmle.code.cpp.controlflow.SSA

class MallocCall extends FunctionCall {
MallocCall() { this.getTarget().hasGlobalName("malloc") }

  Expr getAllocatedSize() {
    if this.getArgument(0) instanceof VariableAccess then
      exists(LocalScopeVariable v, SsaDefinition ssaDef |
        result = ssaDef.getAnUltimateDefiningValue(v)
        and this.getArgument(0) = ssaDef.getAUse(v))
    else
      result = this.getArgument(0)
  }
}
/**
* Functions that perform unsafe buffer operations
*/
predicate isUnsafeBufferOperation(FunctionCall call) {
  exists(string name |
    name = call.getTarget().getName() and
    (
      name = "memcpy" or
      name = "strcpy" or
      name = "strcat" or
      name = "memmove" or
      name = "sprintf" or
      name = "vsprintf"
    )
  )
}

/**
* Functions that extract data from JavaScript
*/
predicate isJsDataExtractor(FunctionCall call) {
  exists(string name |
    name = call.getTarget().getName() and
    (
      name = "napi_get_buffer_info" or
      name = "napi_get_arraybuffer_info" or
      name = "napi_get_typedarray_info" or
      name = "napi_get_dataview_info" or
      name = "Data" or
      name = "Length" or
      name = "ByteLength"
    )
  )
}

/**
* Functions that have proper bounds checking
*/
predicate hasBoundsCheck(FunctionCall bufferOp) {
  // If statement that compares lengths
  exists(IfStmt ifStmt |
    // Buffer operation is in the then branch of the if
    bufferOp.getEnclosingStmt().getParentStmt*() = ifStmt.getThen() and

    // If condition checks size/length
    exists(ComparisonOperation comp |
      comp = ifStmt.getCondition().getAChild*() and
      comp.toString().regexpMatch("(?i).*(length|size|sizeof).*")
    )
  )
  or
  // Using a min function or conditional to limit size
  exists(Expr sizeArg |
    // Get the size argument (arg 2 for memcpy, etc.)
    (
      bufferOp.getTarget().getName() = "memcpy" and sizeArg = bufferOp.getArgument(2)
      or
      bufferOp.getTarget().getName() = "memmove" and sizeArg = bufferOp.getArgument(2)
    ) and

    // Size is limited by min function or conditional
    (
      sizeArg.(FunctionCall).getTarget().getName().matches("(?i).*min.*") or
      sizeArg instanceof ConditionalExpr
    )
  )
}

/**
* Identify if a buffer operation has a fixed-size destination buffer
*/
predicate hasFixedSizeDestination(FunctionCall bufferOp) {
  exists(Variable destVar |
    bufferOp.getArgument(0).(VariableAccess).getTarget() = destVar and
    destVar.getType() instanceof ArrayType
  )
}

/**
* The main query
*/
from FunctionCall bufferOp, FunctionCall jsExtractor, MallocCall malloc, string des
where
  // Function contains both JS data extraction and buffer operation
  bufferOp.getEnclosingFunction() = jsExtractor.getEnclosingFunction() and

  // Identify unsafe buffer operations
  isUnsafeBufferOperation(bufferOp) and

  // Identify JavaScript data extraction
  isJsDataExtractor(jsExtractor) and

  // Fixed-size destination buffer
  hasFixedSizeDestination(bufferOp) and

  // No proper bounds checking
  not hasBoundsCheck(bufferOp) and

  // Filter out safe cases that are known to be properly bounds-checked
  not bufferOp.getEnclosingFunction().getName().matches("safe%") 

  and des = "Buffer overflow risk: JavaScript data is used in unsafe buffer operation without proper bounds checking."
  
  or

  malloc.getAllocatedSize() instanceof StrlenCall
  and malloc = bufferOp 
  and des = "Allocation of buffer size is too small to hold null-termination"

select bufferOp,
des as description
  , bufferOp.getLocation().getFile().getRelativePath() as filePath
  , bufferOp.getLocation().getStartLine() as lineNumber