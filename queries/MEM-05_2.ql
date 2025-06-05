import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
* Identifies dangerous C-style string functions that assume NULL termination
*/
class NullTerminatedStringFunction extends Function {
  NullTerminatedStringFunction() {
    exists(string name | name = this.getName() |
      // String processing functions
      name = "strcpy" or name = "strncpy" or
      name = "strcat" or name = "strncat" or
      name = "strcmp" or name = "strncmp" or
      name = "strchr" or name = "strrchr" or
      name = "strstr" or
      name = "strlen" or
      // Formatting functions
      name = "sprintf" or name = "snprintf" or
      name = "vsprintf" or name = "vsnprintf" or
      // Other functions
      name = "strtok" or name = "atoi" or name = "atol" or name = "atof"
    )
  }
}

from Variable var, FunctionCall asCall, Expr cstrCall, FunctionCall stringFunc
where
  
  exists(Initializer init |
    var.getInitializer() = init and
    asCall.getParent*() = init and
    asCall.getTarget().getName() = "As"
  ) and
  
  // The variable is a std::string
  var.getType().getName() = "string" and
  
  exists(FunctionCall fcstr, VariableAccess va |
    va = fcstr.getQualifier() and
    va.getTarget() = var and
    cstrCall = fcstr
  ) and
  
  // The c_str() result flows to a C-style string function
  stringFunc.getTarget() instanceof NullTerminatedStringFunction and
  exists(Expr arg |
    arg = stringFunc.getAnArgument() and
    DataFlow::localExprFlow(cstrCall, arg)
  )

select stringFunc, "Using " + stringFunc.getTarget().getName() + 
                  "() on JavaScript string data from " + var.getName() + 
                  " can lead to vulnerabilities with embedded NULL bytes" as description
                  , stringFunc.getFile().getRelativePath() as filePath
                  , stringFunc.getLocation().getStartLine() as lineNumber