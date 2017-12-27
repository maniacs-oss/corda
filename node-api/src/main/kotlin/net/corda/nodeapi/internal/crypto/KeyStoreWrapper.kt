package net.corda.nodeapi.internal.crypto

import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.read
import java.nio.file.Path
import java.security.KeyPair
import java.security.PublicKey
import java.security.cert.CertPath
import java.security.cert.Certificate

class KeyStoreWrapper(private val storePath: Path, private val storePassword: String) {
    private val keyStore = storePath.read { loadKeyStore(it, storePassword) }

    private fun createCertificate(serviceName: CordaX500Name, pubKey: PublicKey): CertPath {
        val clientCertPath = keyStore.getCertificateChain(X509Utilities.CORDA_CLIENT_CA)
        // Assume key password = store password.
        val clientCA = certificateAndKeyPair(X509Utilities.CORDA_CLIENT_CA)
        // Create new keys and store in keystore.
        val identityCert = X509Utilities.createCertificate(
                CertificateType.LEGAL_IDENTITY,
                clientCA.certificate,
                clientCA.keyPair,
                serviceName.x500Principal,
                pubKey)
        // TODO: X509Utilities.validateCertificateChain()
        return X509CertificateFactory().generateCertPath(identityCert, *clientCertPath)
    }

    fun signAndSaveNewKeyPair(serviceName: CordaX500Name, privateKeyAlias: String, keyPair: KeyPair) {
        val certPath = createCertificate(serviceName, keyPair.public)
        // Assume key password = store password.
        keyStore.addOrReplaceKey(privateKeyAlias, keyPair.private, storePassword.toCharArray(), certPath.certificates.toTypedArray())
        keyStore.save(storePath, storePassword)
    }

    // Delegate methods to keystore. Sadly keystore doesn't have an interface.
    fun containsAlias(alias: String) = keyStore.containsAlias(alias)

    fun getX509Certificate(alias: String) = keyStore.getX509Certificate(alias)

    fun getCertificateChain(alias: String): Array<out Certificate> = keyStore.getCertificateChain(alias)

    fun getCertificate(alias: String): Certificate = keyStore.getCertificate(alias)

    fun certificateAndKeyPair(alias: String): CertificateAndKeyPair = keyStore.getCertificateAndKeyPair(alias, storePassword)
}