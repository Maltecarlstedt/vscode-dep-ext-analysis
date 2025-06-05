import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Predicate that holds for matching allocation and deallocation kinds
 */
predicate correspondingKinds(string allocKind, string freeKind) {
  allocKind = "malloc" and freeKind = "free"
  or
  allocKind = "new" and freeKind = "delete"
  or
  allocKind = "new[]" and freeKind = "delete[]"
}

/**
 * Predicate to identify allocation expressions and their kinds
 */
predicate allocationExpr(Expr e, string kind) {
  // New allocation
  exists(NewExpr new | 
    e = new and 
    kind = "new"
  )
  or
  // New array allocation
  exists(NewArrayExpr newArray | 
    e = newArray and 
    kind = "new[]"
  )
  or
  // Malloc family allocations
  exists(FunctionCall call |
    (
      call.getTarget().hasGlobalOrStdName("malloc") or
      call.getTarget().hasGlobalOrStdName("calloc") or
      call.getTarget().hasGlobalOrStdName("realloc")
    ) and
    e = call and
    kind = "malloc"
  )
}

/**
 * Predicate to identify deallocation expressions and their kinds
 */
predicate deallocationExpr(Expr e, Expr freed, string kind) {
  // Delete expression
  exists(DeleteExpr del |
    e = del and
    freed = del.getExpr() and
    kind = "delete"
  )
  or
  // Delete array expression
  exists(DeleteArrayExpr del |
    e = del and
    freed = del.getExpr() and
    kind = "delete[]"
  )
  or
  // Free function call
  exists(FunctionCall call |
    call.getTarget().hasGlobalOrStdName("free") and
    e = call and
    freed = call.getArgument(0) and
    kind = "free"
  )
}

/**
 * Module for detecting mismatched allocation/deallocation in Node.js native modules
 */
module MemorySafetyConfig implements DataFlow::ConfigSig {
  /**
   * Holds if `source` is a potential source (allocations only).
   */
  predicate isSource(DataFlow::Node source) {
    // Only allocation sources
    exists(Expr e, string kind |
      allocationExpr(e, kind) and
      source.asExpr() = e
    )
  }
  
  /**
   * Holds if `sink` is a deallocation of a pointer.
   */
  predicate isSink(DataFlow::Node sink) {
    // Only deallocation sinks
    exists(Expr e, Expr freed, string kind |
      deallocationExpr(e, freed, kind) and
      sink.asExpr() = freed
    )
  }
  
  /**
   * Holds if the dataflow is sanitized at `node`.
   */
  predicate isBarrier(DataFlow::Node node) {
    // Pointer is reassigned
    exists(AssignExpr assign | 
      node.asExpr() = assign.getLValue() and
      not exists(VariableAccess va |
        va.getTarget() = assign.getLValue().(VariableAccess).getTarget() and
        assign.getRValue().getAChild*() = va
      )
    )
    or
    // Pointer is nullified
    exists(AssignExpr assign |
      node.asExpr() = assign.getLValue() and
      (
        assign.getRValue().getValue() = "0" or
        exists(NullValue nv | assign.getRValue() = nv)
      )
    )
  }
  
  /**
   * Tracks pointer field accesses and other flow steps
   */
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through field accesses
    exists(FieldAccess fa | 
      pred.asExpr() = fa.getQualifier() and
      succ.asExpr() = fa
    )
    or
    // Track assignments
    exists(AssignExpr assign |
      assign.getRValue() = pred.asExpr() and
      assign.getLValue() = succ.asExpr()
    )
  }
}

/**
 * Instantiate the global dataflow module with our configuration
 */
module MemorySafetyFlow = DataFlow::Global<MemorySafetyConfig>;

import MemorySafetyFlow::PathGraph

/**
 * Get allocation type for a source node
 */
string getAllocationType(DataFlow::Node node) {
  exists(Expr e, string kind |
    allocationExpr(e, kind) and
    node.asExpr() = e and
    result = kind
  )
}

/**
 * Get deallocation type for a sink node
 */
string getDeallocationType(DataFlow::Node node) {
  exists(Expr e, Expr freed, string kind |
    deallocationExpr(e, freed, kind) and
    node.asExpr() = freed and
    result = kind
  )
}

/**
 * Determine if the allocation and deallocation types are mismatched
 */
string classifyVulnerability(MemorySafetyFlow::PathNode source, MemorySafetyFlow::PathNode sink) {
  exists(string allocKind, string deallocKind |
    allocKind = getAllocationType(source.getNode()) and
    deallocKind = getDeallocationType(sink.getNode()) and
    allocKind != "" and deallocKind != "" and
    not correspondingKinds(allocKind, deallocKind) and
    result = "mismatched " + allocKind + "/" + deallocKind
  )
}

/**
 * Get a descriptive message for the vulnerability
 */
string getVulnerabilityMessage(string vulnType) {
  vulnType = "mismatched malloc/delete" and result = "Memory allocated with 'malloc' is freed with 'delete'"
  or
  vulnType = "mismatched malloc/delete[]" and result = "Memory allocated with 'malloc' is freed with 'delete[]'"
  or
  vulnType = "mismatched new/free" and result = "Memory allocated with 'new' is freed with 'free'"
  or
  vulnType = "mismatched new[]/free" and result = "Memory allocated with 'new[]' is freed with 'free'"
  or
  vulnType = "mismatched new[]/delete" and result = "Memory allocated with 'new[]' is freed with 'delete'"
  or
  vulnType = "mismatched new/delete[]" and result = "Memory allocated with 'new' is freed with 'delete[]'"
}

from 
  MemorySafetyFlow::PathNode source, 
  MemorySafetyFlow::PathNode sink, 
  string vulnType
where 
  MemorySafetyFlow::flowPath(source, sink) and
  vulnType = classifyVulnerability(source, sink)
select 
  sink.getNode(),
  source, 
  sink, 
  "Potential " + vulnType + " vulnerability: " + getVulnerabilityMessage(vulnType) as description
  , sink.getLocation().getStartLine() as lineNumber
  , sink.getLocation().getFile().getRelativePath() as filePath