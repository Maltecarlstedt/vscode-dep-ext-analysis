import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

/**
 * Recognizes Node.js addon API function declarations
 */
class NodeAddonOriginFunction extends Function {
  NodeAddonOriginFunction() {
    // Identify node-addon-api style function declarations
    exists(Parameter p |
      p = this.getParameter(0) and
      p.getType().getName().matches("%CallbackInfo%")
    )
    or
    // Traditional N-API style function declarations
    exists(Parameter p |
      p = this.getParameter(0) and
      p.getType().getName().matches("%napi_env%")
    )
    or
    // Functions called directly or indirectly from Node addon functions
    exists(FunctionCall call, NodeAddonOriginFunction addonFunc |
      call.getEnclosingFunction() = addonFunc and
      call.getTarget() = this
    )
    or
    // Ensure transitive calls are also covered (functions called by functions called by addon functions)
    exists(FunctionCall call |
      call.getTarget() = this and
      call.getEnclosingFunction() instanceof NodeAddonOriginFunction
    )
  }
}

/**
 * Identifies predictable temporary file path creation through string literals
 */
class TempFileStringLiteralSource extends DataFlow::Node {
  TempFileStringLiteralSource() {
    // String literals with temp path patterns
    exists(StringLiteral str |
      this.asExpr() = str and
      (
        str.getValue().matches("/tmp/%") or
        str.getValue().matches("%tmp%") or
        str.getValue().matches("%temp%") or
        str.getValue().matches("TEMP_FILE_PREFIX") or
        str.getValue().regexpMatch(".*vscode_extension_.*") or
        str.getValue().regexpMatch(".*\\.txt") or
        str.getValue().regexpMatch(".*\\.log")
      )
    )
  }
}

/**
 * Identifies macro accesses related to temporary files
 */
class TempFileMacroSource extends DataFlow::Node {
  TempFileMacroSource() {
    // Match on macro expansions for temp file prefixes
    exists(MacroInvocation mi |
      (
        mi.getMacroName().matches("%TEMP%") or
        mi.getMacroName().matches("%TMP%") or
        mi.getMacroName().matches("%temp%") or
        mi.getMacroName().matches("%tmp%") 
      ) and
      // Find expressions that contain this macro expansion
      exists(Expr e |
        // The macro must be part of the expression's expansion
        mi.getAGeneratedElement() = e.getAChild*() and
        this.asExpr() = e
      )
    )
  }
}

/**
 * Identifies process ID usage, which creates predictable filenames
 */
class PidSource extends DataFlow::Node {
  PidSource() {
    // getpid() calls
    exists(FunctionCall call |
      call.getTarget().hasGlobalOrStdName("getpid") and
      this.asExpr() = call
    )
    or
    // to_string/std::to_string of getpid() calls
    exists(FunctionCall toStrCall |
      toStrCall.getTarget().getName().matches("%to_string%") and
      exists(FunctionCall pidCall |
        pidCall.getTarget().hasGlobalOrStdName("getpid") and
        pidCall.getAChild*() = toStrCall.getArgument(0)
      ) and
      this.asExpr() = toStrCall
    )
    or
    // Variable assignments of getpid()
    exists(AssignExpr assign |
      exists(FunctionCall pidCall |
        pidCall.getTarget().hasGlobalOrStdName("getpid") and
        assign.getRValue() = pidCall
      ) and
      this.asExpr() = assign.getLValue()
    )
    or
    // Variable declarations initialized with getpid()
    exists(Variable var |
      exists(FunctionCall pidCall |
        pidCall.getTarget().hasGlobalOrStdName("getpid") and
        var.getInitializer().getExpr() = pidCall
      ) and
      this.asExpr() = var.getAnAccess()
    )
  }
}

/**
 * Identifies string operations that construct path names
 */
class StringPathConcatenation extends DataFlow::Node {
  StringPathConcatenation() {
    // String concatenation using + operator to form paths
    exists(AddExpr add |
      // Check if any part of the addition involves getpid() or PID variable
      (
        exists(FunctionCall pidCall |
          pidCall.getTarget().getName() = "getpid" and
          (
            pidCall.getAChild*() = add.getLeftOperand() or
            pidCall.getAChild*() = add.getRightOperand()
          )
        )
        or
        exists(Variable pidVar |
          (pidVar.getName() = "pid") and
          (
            pidVar.getAnAccess() = add.getLeftOperand().getAChild*() or
            pidVar.getAnAccess() = add.getRightOperand().getAChild*()
          )
        )
      ) and
      this.asExpr() = add
    )
    or
    // String concatenation with a filename extension
    exists(AddExpr add |
      (
        exists(StringLiteral str |
          (
            str = add.getRightOperand() and
            (str.getValue().regexpMatch(".*\\.txt") or str.getValue().regexpMatch(".*\\.log"))
          )
          or
          (
            str = add.getLeftOperand() and
            add.getRightOperand().getFullyConverted() instanceof FunctionCall
          )
        )
      ) and
      this.asExpr() = add
    )
    or
    // Match specific string construction patterns with std:: functions
    exists(FunctionCall call |
      (
        call.getTarget().getName() = "string" or
        call.getTarget().getName() = "append" or
        call.getTarget().getName() = "operator+"
      ) and
      // Check if any argument is related to a process ID or temp prefix
      (
        exists(FunctionCall pidCall |
          pidCall.getTarget().getName() = "getpid" and
          exists(Expr arg | 
            arg = call.getAnArgument() and 
            pidCall.getAChild*() = arg
          )
        )
        or
        exists(MacroInvocation mi |
          mi.getMacroName() = "TEMP_FILE_PREFIX" and
          exists(Expr arg |
            arg = call.getAnArgument() and
            mi.getAGeneratedElement() = arg.getAChild*()
          )
        )
      ) and
      this.asExpr() = call
    )
  }
}

/**
 * Variable declarations or accesses related to temp files
 */
class TempFileVariableSource extends DataFlow::Node {
  TempFileVariableSource() {
    // Variables related to temp file paths
    exists(Variable var |
      (
        var.getName().toLowerCase().matches("%temp%") or
        var.getName().toLowerCase().matches("%path%") or
        var.getName() = "temp_file_path"
      ) and
      this.asExpr() = var.getAnAccess()
    )
    or
    // Variables assigned with a string construction that includes PID
    exists(AssignExpr assign |
      exists(AddExpr add |
        add = assign.getRValue() and
        exists(FunctionCall pidCall |
          pidCall.getTarget().getName() = "getpid" and
          pidCall.getAChild*() = add.getAChild*()
        )
      ) and
      this.asExpr() = assign.getLValue()
    )
  }
}

/**
 * Combine all sources of insecure temporary file paths
 */
class InsecureTempFileSource extends DataFlow::Node {
  InsecureTempFileSource() {
    this instanceof TempFileStringLiteralSource or
    this instanceof TempFileMacroSource or
    this instanceof PidSource or
    this instanceof StringPathConcatenation or
    this instanceof TempFileVariableSource
  }
}

/**
 * Find the base variable/expression behind a c_str() call
 */
predicate getCStrBase(Expr cstrCall, Expr base) {
  exists(FunctionCall call |
    call = cstrCall and
    call.getTarget().getName() = "c_str" and
    base = call.getQualifier()
  )
}

/**
 * Sinks where temporary file paths are used for file creation
 */
class InsecureTempFileSink extends DataFlow::Node {
  InsecureTempFileSink() {
    // File operations in C++
    exists(FunctionCall call |
      (
        // File opening functions
        call.getTarget().getName() = "fopen" or
        call.getTarget().getName() = "open"
      ) and
      // Get either the argument itself or the base of a c_str() call
      (
        this.asExpr() = call.getArgument(0).getFullyConverted() or
        exists(Expr cstrCall |
          cstrCall = call.getArgument(0).getFullyConverted() and
          getCStrBase(cstrCall, this.asExpr())
        )
      )
    )
    or
    // Stream operations - specifically targeting file creation
    exists(FunctionCall streamCall |
      (
        streamCall.getTarget().getName().matches("%ofstream%") or
        streamCall.getTarget().getName().matches("%fstream%")
      ) and
      (
        // Either the argument is directly the path
        this.asExpr() = streamCall.getArgument(0) or
        // Or it's the base of a c_str() call
        exists(Expr cstrCall |
          cstrCall = streamCall.getArgument(0) and
          getCStrBase(cstrCall, this.asExpr())
        )
      )
    )
    or
    // Stream constructor - specifically focusing on file creation
    exists(ConstructorCall streamCtor |
      streamCtor.getTarget().getDeclaringType().getName().matches("%ofstream%") and
      (
        // Direct path argument
        this.asExpr() = streamCtor.getArgument(0) or
        // Or the base of a c_str() call
        exists(Expr cstrCall |
          cstrCall = streamCtor.getArgument(0) and
          getCStrBase(cstrCall, this.asExpr())
        )
      )
    )
    or
    // chmod operations with insecure permissions
    exists(FunctionCall call |
      call.getTarget().getName() = "chmod" and
      (
        // Either the direct path argument
        this.asExpr() = call.getArgument(0).getFullyConverted() or
        // Or the base of a c_str() call
        exists(Expr cstrCall |
          cstrCall = call.getArgument(0).getFullyConverted() and
          getCStrBase(cstrCall, this.asExpr())
        )
      ) and
      exists(Expr permExpr |
        permExpr = call.getArgument(1).getFullyConverted() and
        (
          // Literal 0666 or similar world-writable permission
          exists(Literal perm |
            perm = permExpr and
            (
              // Octal 0666 (world-readable/writable)
              perm.getValue().toInt() = 438 or 
              // Other insecure permissions
              perm.getValue().toInt() >= 432 // >= 0660
            )
          )
        )
      )
    )
    or
    // Returning a path from a Node.js addon function
    exists(ReturnStmt ret, NodeAddonOriginFunction func |
      ret.getEnclosingFunction() = func and
      (
        // Return of constructed file path
        exists(FunctionCall call |
          call.getTarget().getName().matches("%New%") and
          call.getTarget().getName().matches("%String%") and
          (
            // Direct path argument
            this.asExpr() = call.getArgument(0) or
            // Base of a c_str() call
            exists(Expr cstrCall |
              cstrCall = call.getArgument(0) and
              getCStrBase(cstrCall, this.asExpr())
            )
          )
        )
      ) and
      this.asExpr() = ret.getExpr().getAChild*()
    )
  }
}

/**
 * Configuration for taint tracking
 */
module InsecureTempFileConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { 
    source instanceof InsecureTempFileSource 
  }
  
  predicate isSink(DataFlow::Node sink) { 
    sink instanceof InsecureTempFileSink 
  }
  
  predicate isBarrier(DataFlow::Node node) {
    exists(FunctionCall call |
      // Calls to secure temporary file functions
      call.getTarget().getName() = ["mkstemp", "mkdtemp", "tmpfile"] and
      node.asExpr() = call
    )
  }
  
  // Additional taint steps
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // String concatenation
    exists(AddExpr add |
      (pred.asExpr() = add.getLeftOperand() or pred.asExpr() = add.getRightOperand()) and
      succ.asExpr() = add
    )
    or
    // Member function calls that modify strings
    exists(FunctionCall call |
      call.getTarget().getName() = ["append", "operator+", "operator+=", "c_str"] and
      (
        pred.asExpr() = call.getQualifier() or
        pred.asExpr() = call.getAnArgument()
      ) and
      succ.asExpr() = call
    )
    or
    // Special case: taint flows from string to c_str() result
    exists(FunctionCall cstrCall |
      cstrCall.getTarget().getName() = "c_str" and
      pred.asExpr() = cstrCall.getQualifier() and
      succ.asExpr() = cstrCall
    )
    or
    // Assignment
    exists(AssignExpr assign |
      pred.asExpr() = assign.getRValue() and
      succ.asExpr() = assign.getLValue()
    )
    or
    // Variable initialization
    exists(VariableAccess va, Variable var |
      var.getInitializer().getExpr().getAChild*() = pred.asExpr() and
      va.getTarget() = var and
      succ.asExpr() = va
    )
    or
    // to_string of a pid
    exists(FunctionCall toStrCall |
      toStrCall.getTarget().getName().matches("%to_string%") and
      pred.asExpr() = toStrCall.getArgument(0) and
      succ.asExpr() = toStrCall
    )
    or
    // Flow through variable declaration initializers
    exists(Variable var, Initializer init |
      var.getInitializer() = init and
      pred.asExpr() = init.getExpr() and
      exists(VariableAccess access |
        access.getTarget() = var and
        succ.asExpr() = access
      )
    )
    or
    // Flow through std::string constructor
    exists(FunctionCall stringCtor |
      stringCtor.getTarget().getName() = "string" and
      pred.asExpr() = stringCtor.getAnArgument() and
      succ.asExpr() = stringCtor
    )
  }
}

// Create the taint-tracking module
module InsecureTempFileFlow = TaintTracking::Global<InsecureTempFileConfig>;

import InsecureTempFileFlow::PathGraph

// Main query - modified to avoid duplicate sinks
from InsecureTempFileFlow::PathNode sink, NodeAddonOriginFunction func, InsecureTempFileFlow::PathNode source
where 
  InsecureTempFileFlow::flowPath(source, sink) and
  sink.getNode().asExpr().getEnclosingFunction() = func 
select sink.getNode(), source, sink, "Insecure temporary file creation in Node.js native addon using $@ with predictable pattern (PID-based naming)" as description, 
      source.getNode(), "static file path pattern"
      , source.getLocation().getStartLine() as lineNumber
      , source.getLocation().getFile().getRelativePath() as filePath
