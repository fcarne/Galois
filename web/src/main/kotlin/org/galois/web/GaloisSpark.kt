package org.galois.web

import spark.Spark.*
import java.net.URLDecoder
import java.nio.charset.Charset

fun main() {
    port(8080); // Spark will run on port 8080
    secure(
        URLDecoder.decode(object {}.javaClass.getResource("/deploy/galois.web.p12")!!.file, Charset.defaultCharset()),
        "qaFV6FUPwZ3KXH7vwSJNG3zs7CJAHqcz",
        null,
        null
    )
    staticFiles.location("/public"); // Static files
    get("/") { req, res -> res.redirect("index.html") }
}