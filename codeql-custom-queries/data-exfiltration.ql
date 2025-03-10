/**
 * @name Data Exfiltration: Sensitive Data Flow to Network Call
 * @description Detects flows where data derived from process.env is passed to a network call (e.g., fetch), which may indicate a potential data exfiltration vulnerability.
 * @kind problem
 */

import javascript
import semmle.javascript.security.dataflow.DataFlow

class DataExfiltrationConfig extends DataFlow::Configuration {
  DataExfiltrationConfig() { this = "DataExfiltrationConfig" }

  // Consider any expression whose code contains "process.env" as sensitive.
  override predicate isSource(DataFlow::Node source) {
    exists(Expr e |
      e = source.asExpr() and
      e.getCode().matches("%process.env%")
    )
  }

  // Consider the URL argument in fetch calls as a sink.
  override predicate isSink(DataFlow::Node sink) {
    exists(CallExpr call |
      call.getCallee().getName() = "fetch" and
      sink.asExpr() = call.getArgument(0)
    )
  }
}

// Look for a data flow from a sensitive source to a network sink.
from DataFlow::PathNode source, DataFlow::PathNode sink, CallExpr call
where DataFlow::localFlow(new DataExfiltrationConfig(), source, sink, call)
select call, "Potential data exfiltration vulnerability: sensitive data derived from process.env may be used in a network call."
