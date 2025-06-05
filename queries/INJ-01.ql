
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

/**
* A JavaScript input extraction API call that serves as the initial taint source.
*/
class JavaScriptAPICall extends Expr {
  JavaScriptAPICall() {
    // Direct N-API string input extraction
    exists(FunctionCall fc |
      fc.getTarget().getName().matches("napi_get_value_string%") and
      this = fc.getArgument(2)
    )
    or
    // Node-API C++ wrapper method calls for string extraction
    exists(FunctionCall fc |
      (
        fc.getTarget().getName() = "ToString" or
        fc.getTarget().getName().matches("As%String%") or
        fc.getTarget().getName().matches("%GetString%")
      ) and
      this = fc
    )
  }
}

/**
* Variables assigned from JavaScript input.
*/
class TaintedVariable extends Variable {
  TaintedVariable() {
    // Variable is directly assigned from a JavaScript API call
    exists(AssignExpr assign, JavaScriptAPICall jsCall |
      assign.getLValue() = this.getAnAccess() and
      assign.getRValue() = jsCall
    )
    or
    // Variable initialization uses a JavaScript API call
    exists(JavaScriptAPICall jsCall |
      this.getInitializer().getExpr() = jsCall
    )
    or
    // Variable is assigned from another tainted variable
    exists(AssignExpr assign, TaintedVariable otherVar |
      assign.getLValue() = this.getAnAccess() and
      assign.getRValue() = otherVar.getAnAccess()
    )
  }
}

/**
* A command string variable that is built using tainted input.
*/
class CommandStringVariable extends Variable {
  CommandStringVariable() {
    // Variable is assigned from a concatenation involving a tainted variable
    exists(AssignExpr assign, AddExpr add, TaintedVariable taintedVar |
      assign.getLValue() = this.getAnAccess() and
      assign.getRValue() = add and
      (
        add.getLeftOperand() = taintedVar.getAnAccess() or
        add.getRightOperand() = taintedVar.getAnAccess()
      )
    )
    or
    // Variable initialization uses a concatenation involving a tainted variable
    exists(AddExpr add, TaintedVariable taintedVar |
      this.getInitializer().getExpr() = add and
      (
        add.getLeftOperand() = taintedVar.getAnAccess() or
        add.getRightOperand() = taintedVar.getAnAccess()
      )
    )
  }
}

/**
* A source of user-controlled data coming from JavaScript, focusing on variables
* that contain or are derived from JavaScript input.
*/
class JavaScriptInputSource extends DataFlow::Node {
  JavaScriptInputSource() {
    // Variables directly assigned from JavaScript API calls
    exists(TaintedVariable var |
      this.asExpr() = var.getAnAccess()
    )
    or
    // Command string variables built using tainted input
    exists(CommandStringVariable var |
      this.asExpr() = var.getAnAccess()
    )
    or
    // Original JavaScript API call (as a backup if variable tracking fails)
    exists(JavaScriptAPICall jsCall |
      this.asExpr() = jsCall
    )
  }
}

/**
* A system command execution function call.
*/
class CommandExecutionFunction extends Function {
  CommandExecutionFunction() {
    this.getName() = [
      "system", "popen", "_popen", "_system",
      "execl", "execlp", "execle", "execv", "execvp", "execvpe"
    ]
    or
    this.getName().matches("exec%")
  }
}

/**
* The command execution call that represents the actual sink.
*/
class CommandExecutionCall extends FunctionCall {
  CommandExecutionCall() {
    this.getTarget() instanceof CommandExecutionFunction
  }
  
  Expr getCommandArgument() {
    result = this.getArgument(0)
  }
}

/**
* A system command execution sink.
*/
class CommandExecutionSink extends DataFlow::Node {
  CommandExecutionCall execCall;
  
  CommandExecutionSink() {
    execCall.getTarget() instanceof CommandExecutionFunction and
    (
      this.asExpr() = execCall
    )
  }
  
  string getCommandName() {
    result = execCall.getTarget().getName()
  }
}

/**
* A specific sink for handling c_str() calls in command executions.
* This is needed to properly track data flow to command execution when c_str() is used.
*/
class CStrToCommandSink extends DataFlow::Node {
  FunctionCall cstrCall;
  CommandExecutionCall cmdCall;
  
  CStrToCommandSink() {
    // Find cases where c_str() result is passed to a command execution function
    cstrCall.getTarget().getName() = "c_str" and
    cmdCall.getCommandArgument() = cstrCall and
    this.asExpr() = cstrCall.getQualifier()
  }
  
  string getCommandName() {
    result = cmdCall.getTarget().getName()
  }
}

/**
* Sanitizing functions or operations for command injection.
*/
class CommandInjectionSanitizer extends DataFlow::Node {
  CommandInjectionSanitizer() {
    // Character checks/validations
    exists(ForStmt forLoop, IfStmt ifCheck, VariableAccess access |
      this.asExpr() = access and
      // Loop checking individual characters
      access.getTarget().getAnAccess() = forLoop.getCondition().getAChild*() and
      // If statement checking character validity
      exists(FunctionCall fc |
        (
          fc.getTarget().getName() = "isalnum" or
          fc.getTarget().getName() = "isalpha" or
          fc.getTarget().getName() = "isdigit"
        ) and
        fc = ifCheck.getCondition().getAChild*()
      ) and
      ifCheck.getParent+() = forLoop
    )
    or
    // Whitelist checks
    exists(IfStmt ifCheck, FunctionCall strcmp |
      this.asExpr() = ifCheck.getCondition().getAChild*() and
      (
        strcmp.getTarget().getName() = "strcmp" or
        strcmp.getTarget().getName() = "strncmp" or
        strcmp.getTarget().getName() = "strcasecmp"
      ) and
      strcmp = ifCheck.getCondition().getAChild*()
    )
    or
    // Common sanitization function names
    exists(FunctionCall fc |
      this.asExpr() = fc and
      fc.getTarget().getName().matches([
        "%sanitize%", "%Sanitize%", 
        "%escape%", "%Escape%", 
        "%validate%", "%Validate%"
      ])
    )
    or
    // Special character filtering in loops
    exists(ForStmt forLoop, IfStmt ifCheck |
      this.asExpr() = forLoop.getStmt().getAChild*() and
      ifCheck.getParent+() = forLoop and
      exists(EqualityOperation eq |
        eq = ifCheck.getCondition().getAChild*() and
        exists(Literal lit |
          lit = eq.getAnOperand() and
          lit.getValue().regexpMatch("['\"\\\\&|;`$<>]")
        )
      )
    )
  }
}

/**
* Configuration for tracking command injection vulnerabilities.
*/
module CommandInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof JavaScriptInputSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandExecutionSink
    or
    sink instanceof CStrToCommandSink
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof CommandInjectionSanitizer
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through string operations like strcat, strcpy
    exists(FunctionCall fc |
      (
        fc.getTarget().getName() = "strcat" or
        fc.getTarget().getName() = "strncat" or
        fc.getTarget().getName() = "strcpy" or
        fc.getTarget().getName() = "strncpy"
      ) and
      pred.asExpr() = fc.getArgument(1) and
      succ.asExpr() = fc.getArgument(0).(VariableAccess).getTarget().getAnAccess()
    )
    or
    // Track through string formatting functions
    exists(FunctionCall fc |
      (fc.getTarget().getName() = "sprintf" or fc.getTarget().getName() = "snprintf") and
      pred.asExpr() = fc.getArgument([2, 3, 4, 5]) and
      succ.asExpr() = fc.getArgument(0).(VariableAccess).getTarget().getAnAccess()
    )
    or
    // Track through string concatenation with + operator
    exists(AddExpr add |
      (
        add.getType().(PointerType).getBaseType() instanceof CharType or
        add.getType().getName().matches("%string%")
      ) and
      (
        pred.asExpr() = add.getLeftOperand() and
        succ.asExpr() = add
        or
        pred.asExpr() = add.getRightOperand() and
        succ.asExpr() = add
      )
    )
    or
    // Track through variable assignments
    exists(AssignExpr assign |
      pred.asExpr() = assign.getRValue() and
      succ.asExpr() = assign.getLValue()
    )
    or
    // Track through variable initialization
    exists(Variable var |
      var.getInitializer().getExpr() = pred.asExpr() and
      succ.asExpr() = var.getAnAccess()
    )
    or
    // Track through function calls (parameter passing)
    exists(FunctionCall call, Function f, int i |
      pred.asExpr() = call.getArgument(i) and
      f = call.getTarget() and
      exists(Parameter p |
        p = f.getParameter(i) and
        succ.asExpr() = p.getAnAccess()
      )
    )
    or
    // Critical: Track from a string to the command execution call when using c_str()
    exists(FunctionCall cstrCall, CommandExecutionCall execCall |
      // The string qualifier flows to c_str()
      pred.asExpr() = cstrCall.getQualifier() and
      // The c_str() call is an argument to the command execution
      execCall.getCommandArgument() = cstrCall and
      // The sink is the command execution call
      succ.asExpr() = execCall
    )
    or
    // Track from a string to the command execution call (direct case)
    exists(CommandExecutionCall execCall |
      // String flows to the command argument
      pred.asExpr() = execCall.getCommandArgument() and
      // The sink is the whole execution call
      succ.asExpr() = execCall
    )
  }
}

// Create the dataflow module by instantiating the configuration
module CommandInjectionFlow = TaintTracking::Global<CommandInjectionConfig>;

import CommandInjectionFlow::PathGraph

from 
  CommandInjectionFlow::PathNode source, 
  CommandInjectionFlow::PathNode sink, 
  string commandName,
  string sourceDesc
where 
  CommandInjectionFlow::flowPath(source, sink) and
  (
    // Get command name for CommandExecutionSink
    (sink.getNode() instanceof CommandExecutionSink and
    commandName = sink.getNode().(CommandExecutionSink).getCommandName())
    or
    // Get command name for CStrToCommandSink
    (sink.getNode() instanceof CStrToCommandSink and
    commandName = sink.getNode().(CStrToCommandSink).getCommandName())
  ) and
  // Provide better description for the source
  (
    // If source is a variable, use its name
    exists(Variable var |
      source.getNode().asExpr() = var.getAnAccess() and
      sourceDesc = var.getName()
    )
    or
    not exists(Variable var | source.getNode().asExpr() = var.getAnAccess()) and
    sourceDesc = "JavaScript input"
  )
select sink.getNode(), source, sink, 
  "Potential command injection in " + commandName + "() from $@.",
  source.getNode(), sourceDesc as description
  , sink.getLocation().getStartLine() as lineNumber
  , sink.getLocation().getFile().getRelativePath() as filePath