package com.webauthn4j.fido.server.service;

import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.util.HexUtil;

import java.util.*;

public class CredentialRecordService {

    private Map<String, List<CredentialRecord>> map = new HashMap<>();

    public void create(String username, CredentialRecord credentialRecord){
        map.computeIfAbsent(username, key -> new ArrayList<>());
        map.get(username).add(credentialRecord);
    }

    public List<CredentialRecord> get(String username){
        List<CredentialRecord> list = map.get(username);
        return list == null ? Collections.emptyList() : list;
    }

    public CredentialRecord getByCredentialId(byte[] credentialId){
        return map.entrySet()
                .stream()
                .flatMap( entry -> entry.getValue().stream())
                .filter(record -> Arrays.equals(record.getAttestedCredentialData().getCredentialId(), credentialId))
                .findFirst()
                .orElseThrow( ()-> new RuntimeException("Could not find credential record with ID " + HexUtil.encodeToString(credentialId)) );
    }

}
