package org.galois.web

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.galois.core.provider.GaloisJCE
import spark.ModelAndView
import spark.Spark.*
import spark.template.freemarker.FreeMarkerEngine
import java.net.URLDecoder
import java.nio.charset.Charset


fun main() {
    port(8080) // Spark will run on port 8080
    /*secure(
        URLDecoder.decode(object {}.javaClass.getResource("/deploy/galois.web.p12")!!.file, Charset.defaultCharset()),
        "qaFV6FUPwZ3KXH7vwSJNG3zs7CJAHqcz",
        null,
        null
    )*/
    staticFiles.location("/public") // Static files
    staticFiles.expireTime(0)

    get("/", { _, _ ->
        ModelAndView(emptyMap<String, Int>(), "../public/index.html")
    }, FreeMarkerEngine())

    get("/details") { _, res ->
        val mapper = jacksonObjectMapper()
        res.type("application/json");
        mapper.writeValueAsString(GaloisJCE.getDescription())
    }


}