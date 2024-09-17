# fido-conformance-test-target

This project is a target server to demonstrate that the async version of the webauthn4j library passes the FIDO Conformance test suites.

## Running the application in dev mode

You can run this fido-conformance-test-target with this command.

```shell script
./gradlew quarkusDev
```
Then, run the "FIDO2 Server - MDS3 Tests" of the [FIDO Conformance Tools](https://fidoalliance.org/certification/functional-certification/conformance/) to `http://localhost:8080/webauthn`.
