@main def main(cpgPath: String, outFile: String) = {
  importCpg(cpgPath)

  // Rules: [RuleId, CWE, FunctionName, Severity, Description]
  val rules = List(
    ("joern/cwe-120/strcpy", "CWE-120", "strcpy", "HIGH", "Buffer copy without bounds checking"),
    ("joern/cwe-120/strcat", "CWE-120", "strcat", "HIGH", "String concatenation without bounds checking"),
    ("joern/cwe-120/sprintf", "CWE-120", "sprintf", "HIGH", "Unbounded sprintf buffer write"),
    ("joern/cwe-120/gets", "CWE-120", "gets", "CRITICAL", "Extremely dangerous unbounded input function gets()"),
    ("joern/cwe-78/system", "CWE-78", "system", "CRITICAL", "OS command execution sink"),
    ("joern/cwe-78/popen", "CWE-78", "popen", "HIGH", "Pipe OS command execution sink"),
    ("joern/cwe-78/exec", "CWE-78", "execve", "HIGH", "Direct process execution sink"),
    ("joern/cwe-78/eval", "CWE-78", "eval", "CRITICAL", "Dynamic code evaluation sink"),
    ("joern/cwe-676/mktemp", "CWE-377", "mktemp", "MEDIUM", "Insecure temporary file creation")
  )

  val results = scala.collection.mutable.ListBuffer[String]()
  val params = cpg.method.parameter.l

  for ((ruleId, cwe, funcName, severity, desc) <- rules) {
    val matchingCalls = cpg.call.nameExact(funcName).l
    for (call <- matchingCalls) {
      val file = call.file.name.headOption.getOrElse("unknown")
      val line = call.lineNumber.getOrElse(0)
      val method = call.method.name
      val code = call.code.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ")
      
      // Check if reachable from any parameter
      var reachable = false
      try {
        if (params.nonEmpty && call.argument.nonEmpty) {
          reachable = call.argument.reachableBy(params).nonEmpty
        }
      } catch {
        case _: Throwable => reachable = false
      }

      val item = s"""{"rule_id":"$ruleId","cwe_id":"$cwe","title":"$desc ($funcName)","severity":"$severity","file":"$file","line":$line,"method":"$method","code":"$code","dataflow_reachable":$reachable}"""
      results += item
    }
  }

  val json = "[" + results.mkString(",\n") + "]"
  os.write.over(os.Path(outFile), json)
  println(s"JOERN_SUCCESS_FINDINGS:${results.size}")
}
