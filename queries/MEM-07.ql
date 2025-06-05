import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
* Holds if the expression is a delete or delete[] expression
*/
predicate isDeleteExpr(Expr e) {
  exists(DeleteExpr del | e = del.getExpr()) or
  exists(DeleteArrayExpr del | e = del.getExpr())
}

/**
* Holds if the expression is a call to free()
*/
predicate isFreeCall(Expr e) {
  exists(FunctionCall call |
    call.getTarget().hasGlobalOrStdName("free") and
    e = call.getArgument(0)
  )
}

/**
* Module for detecting memory safety issues in Node.js native modules
*/
module MemorySafetyConfig implements DataFlow::ConfigSig {
  /**
  * Holds if `source` is a potential source of a freed pointer.
  */
  predicate isSource(DataFlow::Node source) {
    // Delete expressions
    isDeleteExpr(source.asExpr()) or
    // Free function calls
    isFreeCall(source.asExpr())
  }
  
  /**
  * Holds if `sink` is a potentially dangerous use of a pointer that might have been freed.
  * This includes:
  * - Dereferencing a pointer
  * - Using a pointer in a delete/free operation (potential double-free)
  * - Passing to a function that might dereference it
  */
  predicate isSink(DataFlow::Node sink) {
    // Case 1: Dereferencing a pointer (use-after-free)
    exists(PointerDereferenceExpr deref | 
      sink.asExpr() = deref.getOperand() 
    ) or
    
    // Case 2: Indexing into memory that might be freed
    exists(ArrayExpr ae | 
      sink.asExpr() = ae.getArrayBase() 
    ) or
    
    // Case 3: Double-free vulnerability
    isDeleteExpr(sink.asExpr()) or
    isFreeCall(sink.asExpr()) or
    
    // Case 4: Passing potentially freed memory to a function that might dereference it
    exists(FunctionCall call, int i |
      sink.asExpr() = call.getArgument(i) and
      not call.getTarget().hasGlobalOrStdName("free") and // exclude free itself
      not call.getTarget().hasName("operator=") // exclude assignment
    )
  }
  
  /**
  * Holds if the dataflow is sanitized at `node`.
  * This happens when a pointer is assigned a new value, nullified, or checked against null.
  */
  predicate isBarrier(DataFlow::Node node) {
    exists(AssignExpr assign | 
      // The pointer is reassigned a new value
      node.asExpr() = assign.getLValue() and
      
      // Make sure it's not being assigned to itself in some way
      not exists(VariableAccess va |
        va.getTarget() = assign.getLValue().(VariableAccess).getTarget() and
        assign.getRValue().getAChild*() = va
      )
    ) or
    
    // The pointer is checked against null, indicating defensive programming
    exists(EqualityOperation eq |
      eq instanceof EQExpr or eq instanceof NEExpr |
      node.asExpr() = eq.getAnOperand() and
      (
        eq.getAnOperand().getValue() = "0" or 
        exists(NullValue nv | eq.getAnOperand() = nv)
      )
    ) or
    
    // The pointer is nullified
    exists(AssignExpr assign |
      node.asExpr() = assign.getLValue() and
      (
        assign.getRValue().getValue() = "0" or
        exists(NullValue nv | assign.getRValue() = nv)
      )
    )
  }
  
  /**
  * Tracks pointer field accesses to improve precision
  */
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through field accesses like obj->field
    exists(FieldAccess fa | 
      pred.asExpr() = fa.getQualifier() and
      succ.asExpr() = fa
    ) or
    // Track through field accesses like obj.field
    exists(FieldAccess fieldAccess | 
      pred.asExpr() = fieldAccess.getQualifier() and
      succ.asExpr() = fieldAccess
    )
  }
}

/**
* Instantiate the global dataflow module with our configuration
*/
module MemorySafetyFlow = DataFlow::Global<MemorySafetyConfig>;

import MemorySafetyFlow::PathGraph

/**
* Determines if the sink represents a potential double-free
*/
predicate isDoubleFree(DataFlow::Node sink) {
  isDeleteExpr(sink.asExpr()) or isFreeCall(sink.asExpr())
}

/**
* Determines the type of vulnerability:
* - "use after free" for dereferencing freed memory
* - "double free" for attempting to free memory multiple times
*/
string getVulnerabilityType(DataFlow::Node sink) {
  isDoubleFree(sink) and result = "double free" or
  not isDoubleFree(sink) and result = "use after free"
}

/**
* Query to detect potential use-after-free and double-free vulnerabilities
*/
from MemorySafetyFlow::PathNode source, MemorySafetyFlow::PathNode sink, string message
where MemorySafetyFlow::flowPath(source, sink) and message = getVulnerabilityType(sink.getNode())
select sink.getNode(), source, sink, 
  "Potential " + getVulnerabilityType(sink.getNode()) + ": Memory is freed $@ and then " + message +  " $@." as description, 
  source.getNode(), "here", 
  sink.getNode(), "here"
  , sink.getLocation().getStartLine() as lineNumber
  , sink.getLocation().getFile().getRelativePath() as filePath