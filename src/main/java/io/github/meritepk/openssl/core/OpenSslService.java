package io.github.meritepk.openssl.core;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.StringUtils;

import io.github.meritepk.openssl.util.OpenSslUtils;

@Service
public class OpenSslService {

    private static final String ERROR = "Error";

    public OpenSslInfo decode(InputStream input, String type, String password) {
        OpenSslInfo info = new OpenSslInfo(new ArrayList<>());
        try {
            if (OpenSslUtils.PKCS12.equals(type) || OpenSslUtils.JKS.equals(type)) {
                KeyStore store = OpenSslUtils.decodeStore(input, type, password);
                Enumeration<String> aliases = store.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    try {
                        Certificate certificate = store.getCertificate(alias);
                        if (certificate != null) {
                            addEntryInfo(info, specs(toEntryInfo(alias, certificate), certificate));
                        }
                        try {
                            Key key = store.getKey(alias, password.toCharArray());
                            if (key != null) {
                                addEntryInfo(info, specs(toEntryInfo(alias, key), key));
                            }
                        } catch (Exception e) {
                            Key key = store.getKey(alias, "".toCharArray());
                            if (key != null) {
                                addEntryInfo(info, toEntryInfo(alias, key));
                            }
                        }
                    } catch (Exception e) {
                        addEntryInfo(info, toEntryInfo(alias, e));
                    }
                }
            } else {
                try {
                    for (Object decoded : OpenSslUtils
                            .decodePem(new String(input.readAllBytes(), StandardCharsets.UTF_8), password)) {
                        addEntryInfo(info, toEntryInfo(null, decoded));
                    }
                } catch (Exception e) {
                    addEntryInfo(info, toEntryInfo(ERROR, e));
                }
            }
        } catch (Exception e) {
            addEntryInfo(info, toEntryInfo(ERROR, e));
        }
        return info;
    }

    private OpenSslEntryInfo specs(OpenSslEntryInfo info, Certificate certificate) {
        info.specs.put("type", certificate.getType());
        specs(info, certificate.getPublicKey());
        if (certificate instanceof X509Certificate x509) {
            specs(info, x509.getSubjectX500Principal().toString(), x509.getSigAlgName());
            long expiryMillis = x509.getNotAfter().getTime() - x509.getNotBefore().getTime();
            long expiryDays = TimeUnit.DAYS.convert(expiryMillis, TimeUnit.MILLISECONDS);
            info.specs.put("expiryCer", expiryDays);
        }
        return info;
    }

    private OpenSslEntryInfo specs(OpenSslEntryInfo info, PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            specs(info, key.getAlgorithm(), rsa.getModulus().bitLength());
        } else if (key instanceof DSAPublicKey dsa) {
            specs(info, key.getAlgorithm(), dsa.getParams().getP().bitLength());
        }
        return info;
    }

    private OpenSslEntryInfo specs(OpenSslEntryInfo info, Key key) {
        if (key instanceof RSAPrivateKey rsa) {
            specs(info, key.getAlgorithm(), rsa.getModulus().bitLength());
        } else if (key instanceof DSAPrivateKey dsa) {
            specs(info, key.getAlgorithm(), dsa.getParams().getP().bitLength());
        }
        return info;
    }

    private OpenSslEntryInfo specs(OpenSslEntryInfo info, String algo, int keySize) {
        info.specs.put("algo", algo);
        info.specs.put("keysize", keySize);
        return info;
    }

    private OpenSslEntryInfo specs(OpenSslEntryInfo info, String subject, String signAlgo) {
        info.specs.put("subjectCer", subject);
        info.specs.put("signAlgoCer", signAlgo);
        return info;
    }

    private String currentDateTime() {
        return LocalDateTime.now().toString().substring(0, 19);
    }

    public void encode(OutputStream output, OpenSslRequestInfo info) {
        try {
            ArrayList<String> aliases = new ArrayList<>();
            LinkedMultiValueMap<String, Certificate> certificates = new LinkedMultiValueMap<>();
            HashMap<String, PrivateKey> privateKeys = new HashMap<>();
            for (OpenSslEntryInfo entry : info.entries) {
                aliases.add(entry.alias);
                Object decoded = OpenSslUtils.decodePem(entry.value);
                if (decoded instanceof Certificate value) {
                    certificates.add(entry.alias, value);
                } else if (decoded instanceof PrivateKey value) {
                    privateKeys.put(entry.alias, value);
                } else if (decoded instanceof KeyPair value) {
                    privateKeys.put(entry.alias, value.getPrivate());
                }
            }
            OpenSslUtils.encodeStore(output, info.type, info.password, aliases, privateKeys, certificates);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public OpenSslInfo generateKeyPair(String algo, int keySize) {
        try {
            KeyPair keyPair = OpenSslUtils.generateKeyPair(algo, keySize);
            return fromEntryInfo(specs(toEntryInfo(null, keyPair), algo, keySize));
        } catch (Exception e) {
            return fromEntryInfo(toEntryInfo(ERROR, e));
        }
    }

    public OpenSslInfo generateCsr(String keyPairStr, String publicKeyStr, String privateKeyStr, String subject,
            String signAlgo) {
        try {
            PublicKey publicKey;
            PrivateKey privateKey;
            if (StringUtils.hasText(keyPairStr)) {
                KeyPair keyPair = (KeyPair) OpenSslUtils.decodePem(keyPairStr);
                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();
            } else {
                privateKey = (PrivateKey) OpenSslUtils.decodePem(privateKeyStr);
                publicKey = (PublicKey) OpenSslUtils.decodePem(publicKeyStr);
            }
            PKCS10CertificationRequest subjectCsr = OpenSslUtils.generateCertificateRequest(signAlgo, subject,
                    publicKey, privateKey);
            return fromEntryInfo(specs(specs(toEntryInfo(subject, subjectCsr), publicKey), subject, signAlgo));
        } catch (Exception e) {
            return fromEntryInfo(toEntryInfo(ERROR, e));
        }
    }

    public OpenSslInfo signCsr(String subjectCsrStr, String issuerCerStr, String issuerKeyPairStr,
            String issuerPrivateKeyStr, String signAlgo, int expiryDays) {
        try {
            PKCS10CertificationRequest subjectCsr = (PKCS10CertificationRequest) OpenSslUtils.decodePem(subjectCsrStr);
            PublicKey subjectPublicKey = new JcaPEMKeyConverter().getPublicKey(subjectCsr.getSubjectPublicKeyInfo());
            String subject = subjectCsr.getSubject().toString();
            X509Certificate issuerCer = (X509Certificate) OpenSslUtils.decodePem(issuerCerStr);
            String issuer = issuerCer.getSubjectX500Principal().toString();
            PrivateKey issuerPrivateKey;
            if (StringUtils.hasText(issuerKeyPairStr)) {
                KeyPair issuerKeyPair = (KeyPair) OpenSslUtils.decodePem(issuerKeyPairStr);
                issuerPrivateKey = issuerKeyPair.getPrivate();
            } else {
                issuerPrivateKey = (PrivateKey) OpenSslUtils.decodePem(issuerPrivateKeyStr);
            }
            if (expiryDays <= 0) {
                LocalDate now = LocalDate.now();
                expiryDays = now.lengthOfYear() - now.getDayOfYear() + 1;
            }
            X509Certificate subjectCer = OpenSslUtils.generateCertificate(signAlgo, subject, subjectPublicKey, issuer,
                    issuerPrivateKey, expiryDays);
            return fromEntryInfo(specs(toEntryInfo(subject, subjectCer), subjectCer));
        } catch (Exception e) {
            return fromEntryInfo(toEntryInfo(ERROR, e));
        }
    }

    public OpenSslInfo generateSelfSignCer(String keyPairStr, String publicKeyStr,
            String privateKeyStr, String subject, String signAlgo, int expiryDays) {
        try {
            PublicKey publicKey;
            PrivateKey privateKey;
            if (StringUtils.hasText(keyPairStr)) {
                KeyPair keyPair = (KeyPair) OpenSslUtils.decodePem(keyPairStr);
                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();
            } else {
                privateKey = (PrivateKey) OpenSslUtils.decodePem(privateKeyStr);
                publicKey = (PublicKey) OpenSslUtils.decodePem(publicKeyStr);
            }
            if (expiryDays <= 0) {
                LocalDate now = LocalDate.now();
                expiryDays = now.lengthOfYear() - now.getDayOfYear() + 1;
            }
            X509Certificate subjectCer = OpenSslUtils.generateCertificate(signAlgo, subject, publicKey, subject,
                    privateKey, expiryDays);
            return fromEntryInfo(specs(toEntryInfo(subject, subjectCer), subjectCer));
        } catch (Exception e) {
            return fromEntryInfo(toEntryInfo(ERROR, e));
        }
    }

    private OpenSslEntryInfo toEntryInfo(String alias, Throwable e) {
        Throwable cause = e.getCause();
        if (cause == null) {
            cause = e;
        }
        return new OpenSslEntryInfo(alias, ERROR, cause.toString(), currentDateTime(), null);
    }

    private OpenSslEntryInfo toEntryInfo(String alias, Object value) {
        return new OpenSslEntryInfo(alias, getType(value), OpenSslUtils.encodePem(value), currentDateTime(),
                new HashMap<>());
    }

    private String getType(Object value) {
        if (value instanceof PublicKey) {
            return "PublicKey";
        } else if (value instanceof PrivateKey) {
            return "PrivateKey";
        } else if (value instanceof KeyPair) {
            return "KeyPair";
        } else if (value instanceof Certificate) {
            return "Certificate";
        } else if (value instanceof PKCS10CertificationRequest) {
            return "CertificateRequest";
        } else if (value instanceof SecretKey) {
            return "SecretKey";
        }
        return getType(value.getClass());
    }

    private String getType(Class<? extends Object> clas) {
        Class<? extends Object> parent = clas.getSuperclass();
        if (parent == Object.class) {
            return clas.getSimpleName();
        }
        return getType(parent);
    }

    private OpenSslInfo addEntryInfo(OpenSslInfo info, OpenSslEntryInfo entryInfo) {
        info.entries().add(entryInfo);
        return info;
    }

    private OpenSslInfo fromEntryInfo(OpenSslEntryInfo entryInfo) {
        return addEntryInfo(new OpenSslInfo(new ArrayList<>()), entryInfo);
    }

    public record OpenSslInfo(List<OpenSslEntryInfo> entries) {
    }

    public record OpenSslEntryInfo(String alias, String type, String value, String createdAt,
            Map<String, Object> specs) {
    }

    public record OpenSslRequestInfo(String type, String password, List<OpenSslEntryInfo> entries) {
    }
}
