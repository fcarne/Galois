package org.galois.core

import org.galois.core.provider.GaloisJCE

fun main() {
    GaloisJCE.add()
    GaloisJCE.getDescription().forEach { println(it) }
}