package com.webauthn4j.fido.server.config;

import com.webauthn4j.async.WebAuthnRegistrationAsyncManager;
import com.webauthn4j.async.metadata.*;
import com.webauthn4j.async.metadata.anchor.AggregatingTrustAnchorAsyncRepository;
import com.webauthn4j.async.metadata.anchor.MetadataBLOBBasedTrustAnchorAsyncRepository;
import com.webauthn4j.async.metadata.anchor.MetadataStatementsBasedTrustAnchorAsyncRepository;
import com.webauthn4j.async.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.apple.AppleAnonymousAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.none.NoneAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.packed.PackedAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.tpm.TPMAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.fido.server.service.CredentialRecordService;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import jakarta.enterprise.context.Dependent;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.stream.Stream;

@Dependent
public class AppConfig {

    @Singleton
    @Produces
    public ObjectConverter objectConverter(){
        return new ObjectConverter();
    }

    @Singleton
    @Produces
    public MetadataStatementsBasedTrustAnchorAsyncRepository metadataStatementsBasedTrustAnchorAsyncRepository(ObjectConverter objectConverter) {
        List<String> classpaths = listResources("/metadata/test-tools/");
        Stream<Path> paths = classpaths.stream().map(classpath -> {
            try {
                return Path.of(this.getClass().getResource(classpath).toURI());
            } catch (URISyntaxException e) {
                throw new IllegalStateException(e);
            }
        });
        MetadataStatementsAsyncProvider metadataStatementsAsyncProvider = new LocalFilesMetadataStatementsAsyncProvider(objectConverter, paths.toArray(Path[]::new));
        return new MetadataStatementsBasedTrustAnchorAsyncRepository(metadataStatementsAsyncProvider);
    }

    @Singleton
    @Produces
    public AggregatingTrustAnchorAsyncRepository aggregatingTrustAnchorAsyncRepository(MetadataStatementsBasedTrustAnchorAsyncRepository metadataStatementsBasedTrustAnchorAsyncRepository, MetadataBLOBBasedTrustAnchorAsyncRepository metadataBLOBBasedTrustAnchorAsyncRepository){
        return new AggregatingTrustAnchorAsyncRepository(metadataStatementsBasedTrustAnchorAsyncRepository, metadataBLOBBasedTrustAnchorAsyncRepository);
    }

    @Singleton
    @Produces
    MetadataBLOBBasedTrustAnchorAsyncRepository metadataBLOBBasedTrustAnchorAsyncRepository(ObjectConverter objectConverter){
        byte[] bytes = Base64Util.decode(
                "MIICaDCCAe6gAwIBAgIPBCqih0DiJLW7+UHXx/o1MAoGCCqGSM49BAMDMGcxCzAJ" +
                        "BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF" +
                        "IE1ldGFkYXRhIDMgQkxPQiBST09UIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG" +
                        "QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC" +
                        "VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh" +
                        "dGEgMyBCTE9CIFJPT1QgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ" +
                        "BgcqhkjOPQIBBgUrgQQAIgNiAASKYiz3YltC6+lmxhPKwA1WFZlIqnX8yL5RybSL" +
                        "TKFAPEQeTD9O6mOz+tg8wcSdnVxHzwnXiQKJwhrav70rKc2ierQi/4QUrdsPes8T" +
                        "EirZOkCVJurpDFbXZOgs++pa4XmjYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E" +
                        "BTADAQH/MB0GA1UdDgQWBBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAfBgNVHSMEGDAW" +
                        "gBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAKBggqhkjOPQQDAwNoADBlAjEA/xFsgri0" +
                        "xubSa3y3v5ormpPqCwfqn9s0MLBAtzCIgxQ/zkzPKctkiwoPtDzI51KnAjAmeMyg" +
                        "X2S5Ht8+e+EQnezLJBJXtnkRWY+Zt491wgt/AwSs5PHHMv5QgjELOuMxQBc=");
        X509Certificate mds3TestRootCertificate = CertificateUtil.generateX509Certificate(bytes);

        MetadataBLOBAsyncProvider[] fidoMDS3MetadataBLOBProviders = Stream.of(
                        "https://mds3.fido.tools/execute/b64f714dd9efc2f7011fff6a208e8c170776c326a623788838e43e8c06dd4a4f",
                        "https://mds3.fido.tools/execute/c344a84746f6a0978d34cd060e4fab6347f9e86b92cc2adc89e7891a419709c6",
                        "https://mds3.fido.tools/execute/1680c9d899447608dd28eeb5779b70c5bdbdb5daef284f90496fc661975d37df",
                        "https://mds3.fido.tools/execute/8c7f6fa6e2d058fdef324c2ee435ef4332b968ad8b5a8721717601c100bfb929",
                        "https://mds3.fido.tools/execute/a90169bef3866ae087e16b22371721eb9cf1411dab197111807013ef4d8d53ec")
                .map(url -> {
                    try{
                        FidoMDS3MetadataBLOBAsyncProvider fidoMDS3MetadataBLOBAsyncProvider = new FidoMDS3MetadataBLOBAsyncProvider(objectConverter, url, mds3TestRootCertificate);
                        fidoMDS3MetadataBLOBAsyncProvider.setRevocationCheckEnabled(true);
                        fidoMDS3MetadataBLOBAsyncProvider.provide().toCompletableFuture().get();
                        return fidoMDS3MetadataBLOBAsyncProvider;
                    }
                    catch (InterruptedException | ExecutionException | RuntimeException e){
                        Logger logger = LoggerFactory.getLogger(AppConfig.class);
                        logger.warn("Failed to provide metadataBLOB", e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toArray(MetadataBLOBAsyncProvider[]::new);
        return new MetadataBLOBBasedTrustAnchorAsyncRepository(fidoMDS3MetadataBLOBProviders);
    }

    @Singleton
    @Produces
    public CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier(AggregatingTrustAnchorAsyncRepository aggregatingTrustAnchorAsyncRepository){
        DefaultCertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier = new DefaultCertPathTrustworthinessAsyncVerifier(aggregatingTrustAnchorAsyncRepository);
        certPathTrustworthinessAsyncVerifier.setFullChainProhibited(true);
        return certPathTrustworthinessAsyncVerifier;
    }

    @Singleton
    @Produces
    public WebAuthnRegistrationAsyncManager webAuthnRegistrationAsyncManager(ObjectConverter objectConverter, CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier){
        return new WebAuthnRegistrationAsyncManager(
                Arrays.asList(
                        new PackedAttestationStatementAsyncVerifier(),
                        new FIDOU2FAttestationStatementAsyncVerifier(),
                        new AndroidKeyAttestationStatementAsyncVerifier(),
                        new AndroidSafetyNetAttestationStatementAsyncVerifier(),
                        new TPMAttestationStatementAsyncVerifier(),
                        new AppleAnonymousAttestationStatementAsyncVerifier(),
                        new NoneAttestationStatementAsyncVerifier()
                ),
                certPathTrustworthinessAsyncVerifier,
                new DefaultSelfAttestationTrustworthinessAsyncVerifier(),
                objectConverter
        );
    }

    @Singleton
    @Produces
    public CredentialRecordService credentialRecordService(){
        return new CredentialRecordService();
    }

    private List<String> listResources(String classpath){
        InputStream inputStream = getClass().getResourceAsStream(classpath);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        return bufferedReader.lines().map(line -> classpath + line ).toList();
    }

}
