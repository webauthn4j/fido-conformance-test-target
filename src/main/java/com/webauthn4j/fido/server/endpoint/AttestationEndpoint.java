package com.webauthn4j.fido.server.endpoint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.async.WebAuthnRegistrationAsyncManager;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.fido.server.service.CredentialRecordService;
import com.webauthn4j.fido.server.validator.ServerPublicKeyCredentialValidator;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Path("/webauthn/attestation")
public class AttestationEndpoint {

    private final ObjectConverter objectConverter;
    private final WebAuthnRegistrationAsyncManager webAuthnRegistrationAsyncManager;
    private final CredentialRecordService credentialRecordService;

    private final ServerPublicKeyCredentialValidator<ServerAuthenticatorAttestationResponse> serverPublicKeyCredentialValidator = new ServerPublicKeyCredentialValidator<>();
    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AttestationObjectConverter attestationObjectConverter;

    private final TypeReference<ServerPublicKeyCredential<ServerAuthenticatorAttestationResponse>> credentialTypeRef = new TypeReference<>() {};

    public AttestationEndpoint(ObjectConverter objectConverter, WebAuthnRegistrationAsyncManager webAuthnRegistrationAsyncManager, CredentialRecordService credentialRecordService) {
        this.objectConverter = objectConverter;
        this.webAuthnRegistrationAsyncManager = webAuthnRegistrationAsyncManager;
        this.credentialRecordService = credentialRecordService;
        this.collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        this.attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    }

    @Path("/options")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public String options(@Context HttpServletRequest httpServletRequest) throws IOException {
        HttpSession session = httpServletRequest.getSession();

        ServerPublicKeyCredentialCreationOptionsRequest serverRequest = objectConverter.getJsonConverter().readValue(httpServletRequest.getInputStream(), ServerPublicKeyCredentialCreationOptionsRequest.class);

        String username = serverRequest.getUsername();
        String displayName = serverRequest.getDisplayName();
        Challenge challenge = new DefaultChallenge();

        session.setAttribute("username", username);
        session.setAttribute("challenge", challenge.getValue());

        String userHandle;
        userHandle = serverRequest.getUsername();
        ServerPublicKeyCredentialUserEntity user = new ServerPublicKeyCredentialUserEntity(userHandle, username, displayName);
        String rpId = httpServletRequest.getServerName();

        List<ServerPublicKeyCredentialDescriptor> excludeCredentials =
                credentialRecordService.get(username).stream()
                        .map( credentialRecord -> new ServerPublicKeyCredentialDescriptor(Base64UrlUtil.encodeToString(credentialRecord.getAttestedCredentialData().getCredentialId()))).toList();

        ServerPublicKeyCredentialCreationOptionsResponse serverResponse = new ServerPublicKeyCredentialCreationOptionsResponse(
                new PublicKeyCredentialRpEntity(rpId, "fido-conformance-test-target"),
                user,
                Base64UrlUtil.encodeToString(challenge.getValue()),
                Arrays.asList(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.EdDSA)
                ),
                1000L,
                excludeCredentials,
                serverRequest.getAuthenticatorSelection(),
                serverRequest.getAttestation(),
                serverRequest.getExtensions());
        return objectConverter.getJsonConverter().writeValueAsString(serverResponse);
    }

    @Path("/result")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public String result(@Context HttpServletRequest httpServletRequest) throws IOException {
        HttpSession session = httpServletRequest.getSession();
        Challenge challenge = new DefaultChallenge((byte[]) session.getAttribute("challenge"));

        ServerPublicKeyCredential<ServerAuthenticatorAttestationResponse> publicKeyCredential = objectConverter.getJsonConverter().readValue(httpServletRequest.getInputStream(), credentialTypeRef);

        serverPublicKeyCredentialValidator.validate(publicKeyCredential);
        ServerAuthenticatorAttestationResponse serverAuthenticatorAttestationResponse = publicKeyCredential.getResponse();
        AttestationObject attestationObject = attestationObjectConverter.convert(serverAuthenticatorAttestationResponse.getAttestationObject());
        byte[] attestationObjectBytes = Base64UrlUtil.decode(serverAuthenticatorAttestationResponse.getAttestationObject());
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(serverAuthenticatorAttestationResponse.getClientDataJSON());
        byte[] collectedClientDataBytes = Base64UrlUtil.decode(serverAuthenticatorAttestationResponse.getClientDataJSON());
        RegistrationData registrationData = new RegistrationData(attestationObject, attestationObjectBytes, collectedClientData, collectedClientDataBytes, null, null);
        Origin origin = new Origin(httpServletRequest.getRequestURL().toString());
        ServerProperty serverProperty = new ServerProperty(origin, origin.getHost(), challenge, null);
        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, null, false, false);

        try{
            webAuthnRegistrationAsyncManager.getRegistrationDataAsyncVerifier().verify(registrationData, registrationParameters).toCompletableFuture().get();
        }
        catch (Exception e){
            return objectConverter.getJsonConverter().writeValueAsString(new ErrorResponse(e.getMessage()));
        }

        CredentialRecord credentialRecord =
                new CredentialRecordImpl(
                        attestationObject,
                        registrationData.getCollectedClientData(),
                        registrationData.getClientExtensions(),
                        registrationData.getTransports()
                );
        String username = (String) session.getAttribute("username");
        credentialRecordService.create(username, credentialRecord);
        return objectConverter.getJsonConverter().writeValueAsString(new AttestationResultSuccessResponse());
    }
}
