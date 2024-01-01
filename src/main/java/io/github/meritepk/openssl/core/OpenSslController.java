package io.github.meritepk.openssl.core;

import java.io.IOException;
import java.time.LocalDateTime;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import io.github.meritepk.openssl.util.OpenSslUtils;

@RestController
public class OpenSslController {

    private final OpenSslService service;

    public OpenSslController(OpenSslService service) {
        this.service = service;
    }

    @PostMapping("/api/v1/decode")
    public ResponseEntity<OpenSslService.OpenSslInfo> decode(
            @RequestParam("file") MultipartFile file,
            @RequestParam(name = "type", required = false) String type,
            @RequestParam(name = "password", required = false) String password) throws IOException {
        return ResponseEntity.ok(service.decode(file.getInputStream(), type, password));
    }

    @PostMapping("/api/v1/encode")
    public ResponseEntity<StreamingResponseBody> encode(
            @RequestBody OpenSslService.OpenSslRequestInfo requestInfo) throws IOException {
        String filename = LocalDateTime.now().toString();
        if (OpenSslUtils.PKCS12.equals(requestInfo.type())) {
            filename = filename.concat(".pfx");
        } else {
            filename = filename.concat(".jks");
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(out -> service.encode(out, requestInfo));
    }

    @PostMapping("/api/v1/keypair")
    public ResponseEntity<OpenSslService.OpenSslInfo> keypair(
            @RequestParam(name = "algo", defaultValue = OpenSslUtils.RSA) String algo,
            @RequestParam(name = "keysize", defaultValue = "2048") int keysize) {
        return ResponseEntity.ok(service.generateKeyPair(algo, keysize));
    }

    @PostMapping("/api/v1/csr")
    public ResponseEntity<OpenSslService.OpenSslInfo> csr(
            @RequestParam(name = "keyPair", required = false) String keyPairStr,
            @RequestParam(name = "publicKey", required = false) String publicKeyStr,
            @RequestParam(name = "privateKey", required = false) String privateKeyStr,
            @RequestParam(name = "subject") String subjectStr,
            @RequestParam(name = "signatureAlgorithm", defaultValue = OpenSslUtils.SHA256_WITH_RSA) String signAlgo) {
        return ResponseEntity.ok(service.generateCsr(keyPairStr, publicKeyStr, privateKeyStr, subjectStr, signAlgo));
    }

    @PostMapping("/api/v1/sign-csr")
    public ResponseEntity<OpenSslService.OpenSslInfo> signCsr(
            @RequestParam(name = "csr") String subjectCsrStr,
            @RequestParam(name = "issuerCertificate") String issuerCerStr,
            @RequestParam(name = "issuerPrivateKey", required = false) String issuerPrivateKeyStr,
            @RequestParam(name = "issuerKeyPair", required = false) String issuerKeyPairStr,
            @RequestParam(name = "signatureAlgorithm", defaultValue = OpenSslUtils.SHA256_WITH_RSA) String signAlgo,
            @RequestParam(name = "expiryDays", defaultValue = "0") int expiryDays) {
        return ResponseEntity.ok(service.signCsr(subjectCsrStr, issuerCerStr, issuerKeyPairStr, issuerPrivateKeyStr,
                signAlgo, expiryDays));
    }

    @PostMapping("/api/v1/self-sign-cer")
    public ResponseEntity<OpenSslService.OpenSslInfo> selfSignCer(
            @RequestParam(name = "keyPair", required = false) String keyPairStr,
            @RequestParam(name = "publicKey", required = false) String publicKeyStr,
            @RequestParam(name = "privateKey", required = false) String privateKeyStr,
            @RequestParam(name = "subject") String subjectStr,
            @RequestParam(name = "signatureAlgorithm", defaultValue = OpenSslUtils.SHA256_WITH_RSA) String signAlgo,
            @RequestParam(name = "expiryDays", defaultValue = "0") int expiryDays) {
        return ResponseEntity.ok(service.generateSelfSignCer(keyPairStr, publicKeyStr, privateKeyStr, subjectStr,
                signAlgo, expiryDays));
    }
}
