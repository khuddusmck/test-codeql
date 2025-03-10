/**
 * @name Data Exfiltration: Sensitive Data Flow to Network Call
 * @description Detects flows where data from process.env (a proxy for sensitive data) is passed to a network call (such as fetch), which may indicate a potential data exfiltration vulnerability.
 * @kind problem
 */
import javascript
import semmle.javascript.security.dataflow.DataFlow

// Custom configuration to define sensitive sources and sinks.
class DataExfiltrationConfig extends DataFlow::Configuration {
  DataExfiltrationConfig() { this = "DataExfiltrationConfig" }

  // Define sensitive sources – here, any access to process.env.
  override predicate isSource(DataFlow::Node source) {
    exists(MemberExpression me | 
      me.getQualifier() instanceof Identifier and 
      me.getQualifier().(Identifier).getName() = "process" and 
      me.getMemberName() = "env" and 
      source.asExpr() = me
    )
  }

  // Define sinks as the URL argument to network calls (e.g., fetch).
  override predicate isSink(DataFlow::Node sink) {
    exists(CallExpr call | 
      call.getCallee().getName() = "fetch" and 
      sink.asExpr() = call.getArgument(0)
    )
  }
}

// Query: look for a data flow from our sensitive source to our network sink.
from DataFlow::PathNode source, DataFlow::PathNode sink, CallExpr call
where DataFlow::localFlow(new DataExfiltrationConfig(), source, sink, call)
select call, "Potential data exfiltration vulnerability: sensitive data from process.env may be sent via a network call."
