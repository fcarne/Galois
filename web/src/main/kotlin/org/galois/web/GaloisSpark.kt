package org.galois.web

import spark.Spark.*

object GaloisSpark {
    @JvmStatic
    fun main(args: Array<String>) {
        get("/") { _, _ -> "Hello World" }
    }
}