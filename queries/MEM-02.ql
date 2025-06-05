import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Configuration for tracking flow from buffer allocations to N-API exposure
 */
module UninitializedBufferConfig implements DataFlow::ConfigSig {
  /**
   * Source: Allocations that don't initialize memory
   */  
  predicate isSource(DataFlow::Node source) {
    // C-style allocations
    exists(FunctionCall call | 
      source.asExpr() = call and
      (
        call.getTarget().hasName("malloc") or
        call.getTarget().hasName("realloc")
      )
    )
    or
    // C++ new[] allocations for char arrays
    exists(NewArrayExpr newExpr |
      source.asExpr() = newExpr and
      newExpr.getAllocatedType().getUnspecifiedType().(ArrayType).getBaseType().getName() = "char"
    )
    or
    // C++ new allocations for single chars (less common but possible)
    exists(NewExpr newExpr |
      source.asExpr() = newExpr and
      newExpr.getAllocatedType().getUnspecifiedType().getName() = "char"
    )
  }

  /**
   * Sink: Any uninitialized buffer reaching N-API functions
   * Simplified matching approach focusing on function names
   */
  predicate isSink(DataFlow::Node sink) {
    // Match any argument to any N-API function that could expose memory
    exists(FunctionCall call |
      // Match N-API functions by name pattern
      call.getTarget().hasName("napi_create_buffer") or
      call.getTarget().hasName("napi_create_buffer_copy") or
      call.getTarget().hasName("napi_create_external_arraybuffer") or
      call.getTarget().hasName("napi_create_typedarray") or
      call.getTarget().hasName("napi_create_dataview") or
      
      // C++ Napi:: class methods that could expose memory
      (call.getTarget().hasName("New") or call.getTarget().hasName("NewOrCopy")) and
      call.getTarget().getDeclaringType().getQualifiedName().matches("Napi::%")
    ) and
    (
      // Match ANY of the arguments that could be a buffer
      // This is less precise but more thorough than trying to match exact indices
      exists(FunctionCall call, int argIndex | 
        argIndex >= 0 and argIndex <= 5 and  // Check first 6 arguments
        sink.asExpr() = call.getArgument(argIndex) and
        // The argument should be a pointer type (typical for buffers)
        call.getArgument(argIndex).getType() instanceof PointerType
      )
    )
  }

  /**
   * Simpler barrier definition - anything that initializes memory
   */
  predicate isBarrier(DataFlow::Node node) {
    // Explicit initialization function calls
    exists(FunctionCall call |
      node.asExpr() = call.getArgument(0) and
      (
        call.getTarget().hasName("memset") or
        call.getTarget().hasName("memcpy") or
        call.getTarget().hasName("memmove") or
        call.getTarget().hasName("strcpy") or
        call.getTarget().hasName("strncpy") or
        call.getTarget().hasName("bzero")
      )
    )
    or
    // Safe allocation functions that initialize memory
    exists(FunctionCall call |
      node.asExpr() = call and
      (
        call.getTarget().hasName("calloc") or
        call.getTarget().hasName("strdup") or
        call.getTarget().hasName("strndup")
      )
    )
    or
    // Buffer element assignment (array indexing)
    exists(ArrayExpr arrayAccess |
      arrayAccess.getArrayBase() = node.asExpr() and
      exists(AssignExpr assign | assign.getLValue() = arrayAccess)
    )
  }
  
  /**
   * Additional flow steps to track buffer data across variables and functions
   */
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Assignment tracking
    exists(AssignExpr assign |
      pred.asExpr() = assign.getRValue() and
      succ.asExpr() = assign
    )
    or
    // Variable reference tracking
    exists(Variable v |
      pred.asExpr() = v.getAnAccess() and
      succ.asExpr() = v.getAnAccess() and
      not pred.asExpr() = succ.asExpr()
    )
    or
    // Function parameters tracking
    exists(Parameter param, FunctionCall call, int i |
      call.getArgument(i) = pred.asExpr() and 
      call.getTarget().getParameter(i) = param and
      param.getAnAccess() = succ.asExpr()
    )
    or
    // Cast expressions
    exists(CStyleCast cast |
      pred.asExpr() = cast.getExpr() and
      succ.asExpr() = cast
    )
    or
    // Track pointer arithmetic
    exists(PointerAddExpr ptrAdd |
      pred.asExpr() = ptrAdd.getLeftOperand() and
      succ.asExpr() = ptrAdd
    )
  }
}

// Create a TaintTracking module from our configuration
module UninitializedBufferFlow = TaintTracking::Global<UninitializedBufferConfig>;

// Import the path graph for showing the data flow path
import UninitializedBufferFlow::PathGraph

/**
 * Get a string representation of a function for better error reporting
 */
string getFunctionDisplayString(Function f) {
  result = f.getQualifiedName()
}

from UninitializedBufferFlow::PathNode source, UninitializedBufferFlow::PathNode sink
where UninitializedBufferFlow::flowPath(source, sink)
select 
  sink.getNode(), 
  source, 
  sink, 
  "Potential exposure of uninitialized buffer allocated at " + source.getNode().getLocation().getFile().getRelativePath() +
  " to JavaScript in function " + getFunctionDisplayString(sink.getNode().getFunction()) as description,
  source.getNode().getEnclosingCallable() as source_function,
  sink.getNode().getEnclosingCallable() as sink_function
  , sink.getLocation().getStartLine() as lineNumber

