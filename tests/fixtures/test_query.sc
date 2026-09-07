@main def main(cpgPath: String, outFile: String) = {
  importCpg(cpgPath)
  val calls = cpg.call.map(_.name).toList
  println(s"CPG Calls detected: ${calls.size}")
  os.write.over(os.Path(outFile), s"""{"calls_count": ${calls.size}}""")
}
