import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.controlflow.Guards

/**
 * Module for detecting memory leaks in Node.js C++ addons via N-API or node-addon-api
 */
module PersistentHandleTracking implements DataFlow::ConfigSig {

  /**
   * Identifies functions and methods that create persistent handles or references
   */
 additional class PersistentHandleCreation extends FunctionCall {
    PersistentHandleCreation() {
      // Node N-API handle creation functions
      getTarget().getName().matches("napi_create_reference") or
      
      // C++ node-addon-api reference creation
      getTarget().getName().matches("Persistent") or
      getTarget().getName().matches("Reference") or
      
      // Custom reference store methods - match broader patterns
      getTarget().getName().matches("%Store%Reference%") or
      getTarget().getName().matches("%Create%Reference%") or
      getTarget().getName().matches("%New%Reference%") or
      
      // Constructor calls that store references
      exists(Class c | 
        c.getName().matches("%Reference%") and
        getTarget() = c.getAConstructor()
      )
    }
    
    /**
     * Get the result variable that holds the created reference
     */
    Variable getResultVariable() {
      // For napi_create_reference, result is stored in the fourth argument
      if (getTarget().getName().matches("napi_create_reference")) then
        exists(VariableAccess va | 
          va = getArgument(3).(AddressOfExpr).getOperand() and
          result = va.getTarget()
        )
      else if exists(Declaration decl, Variable v | 
        // For direct variable initializations
        decl = v.getInitializer().getDeclaration() 
        and
        decl = this.getEnclosingFunction() and
        result = v
      ) then
        result = result
      else if exists(AssignExpr ae | 
        // For assignments to existing variables
        ae.getRValue().getAChild*() = this and
        ae.getLValue() instanceof VariableAccess and
        result = ae.getLValue().(VariableAccess).getTarget()
      ) then
        result = result
      else
        none()
    }
  }
  
  /**
   * Identifies handle cleanup functions for persistent references
   */
  additional class PersistentHandleCleanup extends FunctionCall {
    PersistentHandleCleanup() {
      // N-API cleanup functions
      getTarget().getName().matches("napi_delete_reference") or
      getTarget().getName().matches("napi_reference_unref") or
      
      // C++ node-addon-api cleanup methods
      getTarget().getName().matches("Reset") or
      getTarget().getName().matches("Unref") or
      
      // Custom cleanup patterns
      getTarget().getName().matches("%Delete%Reference%") or
      getTarget().getName().matches("%Free%Reference%") or
      getTarget().getName().matches("%Clean%Reference%") or
      getTarget().getName().matches("%Release%Reference%")
    }
    
    /**
     * Get the reference variable being cleaned up
     */
    Variable getCleanedVariable() {
      // For napi_delete_reference, the reference is the second argument
      if (getTarget().getName().matches("napi_delete_reference")) then
        result = getArgument(1).(VariableAccess).getTarget()
      else if (exists(VariableAccess va | 
        // For method calls on references
        va = getQualifier() and
        va.getTarget() instanceof Variable
      )) then
        result = getQualifier().(VariableAccess).getTarget()
      else
        // For other patterns, typically the first argument
        result = getArgument(0).(VariableAccess).getTarget()
    }
  }
  
  /**
   * Represents a destructor that should clean up references
   */
  additional  class ClassWithNapiReferences extends Class {
    ClassWithNapiReferences() {
      // Class has member variables that are references
      exists(MemberVariable mv | 
        mv.getDeclaringType() = this and
        (
          mv.getType().getName().matches("%Reference%") or
          mv.getType().getName().matches("%napi_ref%") or
          mv.getName().matches("%ref%") or
          mv.getName().matches("%handle%")
        )
      )
    }
    
    /**
     * Check if destructor properly cleans up references
     */
    predicate hasProperDestructor() {
      exists(Destructor d | 
        d.getDeclaringType() = this and
        exists(FunctionCall fc |
          // Destructor contains cleanup calls
          fc.getEnclosingFunction() = d and
          fc instanceof PersistentHandleCleanup
        )
      )
    }
  }
  
  /**
   * A source is a persistent reference creation
   */
  predicate isSource(DataFlow::Node source) {
    exists(PersistentHandleCreation creation |
      source.asExpr() = creation
    )
  }
  
  /**
   * A sink is a function that should clean up references but doesn't
   */
  predicate isSink(DataFlow::Node sink) {
    // Sinks are functions containing handle creations without proper cleanup
    exists(Function f | 
      f = sink.asExpr().(FunctionCall).getEnclosingFunction() and
      exists(PersistentHandleCreation creation |
        creation.getEnclosingFunction() = f and
        // The handle isn't properly cleaned up
        not isProperlyCleaned(creation)
      )
    )
    or
    // Classes with reference members but no proper cleanup in destructor
    exists(PersistentHandleTracking::ClassWithNapiReferences c |
      not c.hasProperDestructor() and
      sink.asExpr().getEnclosingFunction().(Constructor).getDeclaringType() = c
    )
  }
  
  /**
   * Check if a handle creation is properly cleaned up
   */
  additional predicate isProperlyCleaned(PersistentHandleCreation creation) {
    exists(PersistentHandleCleanup cleanup, Variable refVar |
      refVar = creation.getResultVariable() and
      cleanup.getCleanedVariable() = refVar and
      // Check cleanup is in all paths where necessary
      forall(ControlFlowNode cfn |
        cfn = creation.getASuccessor*() and
        cfn.getControlFlowScope() = creation.getEnclosingFunction() |
        exists(cleanup.getASuccessor*()) or
        exists(GuardCondition guard |
          // Allow conditional cleanups if properly guarded
          guard.controls(cleanup.getBasicBlock(), _) and
          guard.controls(cfn.getBasicBlock(), _)
        )
      )
    )
    or
    // Reference is stored in a member variable of class with proper destructor
    exists(ClassWithNapiReferences c, MemberVariable mv |
      c.hasProperDestructor() and
      mv.getDeclaringType() = c and
      exists(AssignExpr ae |
        ae.getRValue().getAChild*() = creation and
        ae.getLValue().(FieldAccess).getTarget() = mv
      )
    )
    or
    // Reference is returned to caller (transfers ownership)
    exists(ReturnStmt ret |
      ret.getEnclosingFunction() = creation.getEnclosingFunction() and
      ret.getExpr().getAChild*() = creation
    )
  }
  
  /**
   * Path barriers (cleanups) that prevent leaks
   */
  predicate isBarrier(DataFlow::Node node) {
    exists(PersistentHandleCleanup cleanup |
      node.asExpr() = cleanup
    )
    or
    // Also consider destructors as barriers for class objects
    exists(Destructor d, ClassWithNapiReferences c |
      c.hasProperDestructor() and
      d.getDeclaringType() = c and
      node.asExpr().getEnclosingFunction() = d
    )
  }
  
  /**
   * Additional flow steps to track handle usage
   */
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track flow through assignments
    exists(AssignExpr ae |
      pred.asExpr() = ae.getRValue() and
      succ.asExpr() = ae
    )
    or
    // Track flow through member variables
    exists(FieldAccess fa |
      pred.asExpr() = fa.getQualifier() and
      succ.asExpr() = fa
    )
    or
    // Track flow through vector/container operations
    exists(FunctionCall fc |
      fc.getTarget().getName().matches("push_back") and
      pred.asExpr() = fc.getArgument(0) and
      succ.asExpr() = fc
    )
  }
}

/**
 * Flow analysis for persistent handle leaks
 */
module PersistentHandleFlow = DataFlow::Global<PersistentHandleTracking>;
import PersistentHandleFlow::PathGraph

from Element target, string filePath, string message, string details
where
  // Function-level leaks
  (
    exists(PersistentHandleTracking::PersistentHandleCreation creation, Function f |
      target = creation and
      f = creation.getEnclosingFunction() and
      not PersistentHandleTracking::isProperlyCleaned(creation) and
      filePath = creation.getLocation().getFile().getRelativePath() and
      message = "Memory leak: " + creation.getTarget().getName() + " creates a handle that is never properly released" and
      details = "Function: " + f.getName()
    )
  )
  or
  // Class-level leaks
  (
    exists(PersistentHandleTracking::ClassWithNapiReferences c |
      target = c and
      not c.hasProperDestructor() and
      filePath = c.getLocation().getFile().getRelativePath() and
      message = "Memory leak: Class " + c.getName() + " contains reference members but lacks proper cleanup in destructor" and
      details = "Class: " + c.getName()
    )
  )
select
  target,
  filePath,
  message as description,
  details
  , target.getLocation().getStartLine() as lineNumber