package org.galois

import org.galois.crypto.engine.EncryptionDetail
import org.galois.crypto.engine.EngineConfiguration
import org.galois.crypto.engine.Mode

class LocalEngineConfiguration(
    val input: String,
    val outputDir: String,
    outputFileName: String,
    mode: Mode,
    encryptionDetails: List<EncryptionDetail>
) : EngineConfiguration(outputFileName, mode, encryptionDetails)