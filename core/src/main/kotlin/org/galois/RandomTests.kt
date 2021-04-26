package org.galois

import org.galois.crypto.provider.GaloisJCE

fun main() {
    providerAlgorithms()
}

fun providerAlgorithms() {
    GaloisJCE.add()
    GaloisJCE.supportedAlgorithms.forEach { println(it) }
}