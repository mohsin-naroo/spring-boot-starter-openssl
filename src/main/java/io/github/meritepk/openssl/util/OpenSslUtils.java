package io.github.meritepk.openssl.util;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JceInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.util.StringUtils;

public interface OpenSslUtils {

    String RSA = "RSA";
    String DSA = "DSA";
    String SHA256_WITH_RSA = "SHA256withRSA";
    String SHA256_WITH_DSA = "SHA256withDSA";
    String AES_256_CBC = "AES-256-CBC";
    String JKS = "JKS";
    String PKCS12 = "PKCS12";

    BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    static String encodePem(Object pemObject) {
        return encodePem(pemObject, "");
    }

    static String encodePem(Object pemObject, String password) {
        return encodePem(pemObject, password, AES_256_CBC);
    }

    static String encodePem(Object pemObject, String password, String algorithm) {
        try (StringWriter sw = new StringWriter(); JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            PEMEncryptor encryptor = null;
            if (StringUtils.hasText(password)) {
                encryptor = new JcePEMEncryptorBuilder(algorithm).setProvider(PROVIDER).build(password.toCharArray());
            }
            pw.writeObject(pemObject, encryptor);
            pw.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new IllegalStateException("OpenSslUtils.encodePem() error: " + e, e);
        }
    }

    static Object decodePem(String keyStr) {
        List<Object> objects = decodePem(keyStr, "");
        if (objects.isEmpty()) {
            return null;
        }
        return objects.get(0);
    }

    static List<Object> decodePem(String keyStr, String password) {
        ArrayList<Object> objects = new ArrayList<>();
        try (PEMParser pemParser = new PEMParser(new StringReader(keyStr))) {
            Object parsedKey = pemParser.readObject();
            if (parsedKey != null) {
                if (parsedKey instanceof PrivateKeyInfo value) {
                    objects.add(new JcaPEMKeyConverter().getPrivateKey(value));
                } else if (parsedKey instanceof PKCS8EncryptedPrivateKeyInfo value) {
                    objects.add(new JcaPEMKeyConverter().getPrivateKey(value.decryptPrivateKeyInfo(
                            new JceInputDecryptorProviderBuilder().setProvider(PROVIDER)
                                    .build(password.getBytes(Charset.defaultCharset())))));
                } else if (parsedKey instanceof PEMKeyPair value) {
                    objects.add(new JcaPEMKeyConverter().getKeyPair(value));
                } else if (parsedKey instanceof PEMEncryptedKeyPair value) {
                    objects.add(new JcaPEMKeyConverter()
                            .getKeyPair(value.decryptKeyPair(new BcPEMDecryptorProvider(password.toCharArray()))));
                } else if (parsedKey instanceof X509CertificateHolder value) {
                    objects.add(new JcaX509CertificateConverter().getCertificate(value));
                } else if (parsedKey instanceof SubjectPublicKeyInfo value) {
                    objects.add(new JcaPEMKeyConverter().getPublicKey(value));
                } else if (parsedKey instanceof PKCS10CertificationRequest value) {
                    objects.add(value);
                } else {
                    objects.add(parsedKey);
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("OpenSslUtils.decodePEM() error: " + e, e);
        }
        return objects;
    }

    static byte[] encodeStore(String type, String password, String alias, KeyPair keyPair,
            Certificate... certificates) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encodeStore(baos, type, password, List.of(alias),
                keyPair != null ? Map.of(alias, keyPair.getPrivate()) : Map.of(),
                certificates != null && certificates.length > 0 ? Map.of(alias, List.of(certificates)) : Map.of());
        return baos.toByteArray();
    }

    static void encodeStore(OutputStream output, String type, String password, List<String> aliases,
            Map<String, PrivateKey> privateKeys, Map<String, List<Certificate>> certificates) {
        try {
            KeyStore store;
            if (OpenSslUtils.PKCS12.equals(type)) {
                store = KeyStore.getInstance(OpenSslUtils.PKCS12);
            } else {
                store = KeyStore.getInstance(OpenSslUtils.JKS);
            }
            store.load(null, null);
            for (String alias : aliases) {
                PrivateKey privateKey = privateKeys.get(alias);
                if (privateKey != null) {
                    List<Certificate> certs = certificates.get(alias);
                    Certificate[] certsArray = new Certificate[] {};
                    if (certs != null && certs.size() > 0) {
                        certsArray = certs.toArray(new Certificate[certs.size()]);
                    }
                    store.setKeyEntry(alias, privateKey, "".toCharArray(), certsArray);
                } else {
                    List<Certificate> certs = certificates.get(alias);
                    if (certs != null) {
                        if (certs.size() == 1) {
                            store.setCertificateEntry(alias, certs.get(0));
                        } else if (certs.size() > 1) {
                            for (int i = 0; i < certs.size(); i++) {
                                store.setCertificateEntry(alias + "-" + i, certs.get(i));
                            }
                        }
                    }
                }
            }
            store.store(output, password.toCharArray());
            output.flush();
        } catch (Exception e) {
            throw new IllegalStateException("OpenSslUtils.encodeStore() error: " + e, e);
        }
    }

    static KeyStore decodeStore(InputStream input, String type, String password) {
        try {
            KeyStore store = KeyStore.getInstance(type);
            store.load(input, password.toCharArray());
            return store;
        } catch (Exception e) {
            throw new IllegalStateException("OpenSslUtils.encodePkcs12() error: " + e, e);
        }
    }

    static KeyPair generateKeyPair(String algo, int keysize) {
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance(algo);
            keygen.initialize(keysize);
            return keygen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("OpenSslUtils.generateKeyPairRsa() error: " + e, e);
        }
    }

    static PKCS10CertificationRequest generateCertificateRequest(String signAlgo, String subjectName,
            PublicKey subjectPublicKey, PrivateKey subjectPrivateKey) {
        try {
            X500Principal subject = new X500Principal(subjectName);
            ContentSigner contentSigner = new JcaContentSignerBuilder(signAlgo).build(subjectPrivateKey);
            PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(subject, subjectPublicKey)
                    .build(contentSigner);
            return csr;
        } catch (Exception e) {
            throw new IllegalStateException("OpenSslUtils.generateCertificateRequest() error: " + e, e);
        }
    }

    static X509Certificate generateCertificate(String signAlgo, String subjectName,
            PublicKey subjectPublicKey, String issuerName, PrivateKey issuerPrivateKey, int days, int... keyUsage) {
        try {
            X500Principal issuer = new X500Principal(issuerName);
            X500Principal subject = new X500Principal(subjectName);
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer,
                    BigInteger.valueOf(System.currentTimeMillis()), Date.valueOf(LocalDate.now()),
                    Date.valueOf(LocalDate.now().plusDays(days)), subject, subjectPublicKey);
            for (int i = 0; i < keyUsage.length; i++) {
                DEROctetString value = new DEROctetString(
                        new KeyUsage(keyUsage[i]).toASN1Primitive().getEncoded(ASN1Encoding.DER));
                builder.addExtension(new Extension(Extension.keyUsage, false, value));
            }
            ContentSigner signer = new JcaContentSignerBuilder(signAlgo).build(issuerPrivateKey);
            X509Certificate cer = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
            return cer;
        } catch (Exception e) {
            throw new IllegalStateException("OpenSslUtils.generateSelfSignedCertificate() error: " + e, e);
        }
    }
}
