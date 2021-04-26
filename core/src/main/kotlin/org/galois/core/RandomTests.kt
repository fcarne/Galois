package org.galois.core

import org.galois.core.provider.GaloisJCE

fun main() {
    providerAlgorithms()
}

fun providerAlgorithms() {
    GaloisJCE.add()
    GaloisJCE.supportedAlgorithms.forEach { println(it) }
}