package org.galois.core

import tech.tablesaw.api.Table
import java.io.ByteArrayOutputStream

fun main() {
    val datasetStream = object {}.javaClass.getResourceAsStream("/sample.csv")
    val dataset = Table.read().csv(datasetStream).retainColumns("age")

    val preWork = ByteArrayOutputStream()
    dataset.write().csv(preWork)
    println(dataset.print())
    println(preWork.size())

    dataset.concat(
        Table.read().csv(object {}.javaClass.getResourceAsStream("/sample.csv"))
            .retainColumns("ip-address", "workclass", "sex", "native-country")
    )

    val postWork = ByteArrayOutputStream()
    dataset.write().csv(postWork)
    println(dataset.print())
    println(postWork.size())
}