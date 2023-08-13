import express from "express";
import { exec } from 'child_process';
import path from 'path';
import { generateAuthenticationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import { isoBase64URL, isoUint8Array } from '@simplewebauthn/server/helpers';

const app = express();
const __dirname = path.dirname(new URL(import.meta.url).pathname);
const PORT = 3300;

const rpName = "webauthn-demo";
const rpId = "localhost";
const rpOrigin = "http://localhost:3300";

const getUserDetails = (email) => {
    return {
        id: email,
        name: email,
        displayName: email,
        savedMethods: [
            {
                id: "123",
                type: "public-key",
                transports: ["usb"],
                attachment: "platform",
            }
        ],
    };
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'dist')));

app.get("/status", (req, res) => {
    res.send("Hello, server is running");
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "dist/index.html"));
});

app.post("/generate-registration-options", (req, res) => {
    console.log("Request", req.body);
    const user = getUserDetails(req.body.email);
    console.log("User", user);

    const options = generateAuthenticationOptions({
        rpName,
        rpId,
        rpOrigin,
        userId: user.id,
        userName: user.name,
        timeout: 60000,
        attestationType: 'none',
        authenticatorSelection: {
            residentKey: 'discouraged',
        },
        excludeCredentials: user.savedMethods ? user.savedMethods.map(method => ({
            id: method.id,
            type: method.type,
            transports: method.transports,
        })) : [],
        authenticatorSelection: {
            residentKey: 'discouraged',
        },
        supportedAlgorithmIDs: [-7, -257],
    });

    res.send(options);
});

app.post("/verify-registration-response", async (req, res) => {
    const user = getUserDetails(req.body.email);

    const verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: req.body.challenge,
        expectedOrigin: rpOrigin,
        expectedRPID: rpId,
        requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
        const { credentialPublicKey, credentialID, counter } = registrationInfo;

        const existingDevice = user.savedMethods.find(device => isoUint8Array.areEqual(device.credentialID, credentialID));

        if (existingDevice) {
            existingDevice.counter = counter;
        } else {
            user.savedMethods.push({
                credentialID,
                credentialPublicKey,
                counter,
                transports: req.body.transports,
            });
        }
    }

    res.send(verification);
});

app.get("/login", (req, res) => {
    const user = getUserDetails(req.body.email);

    const options = generateAuthenticationOptions({
        timeout: 60000,
        allowCredentials: user.savedMethods.map(method => ({
            id: method.credentialID,
            type: 'public-key',
            transports: method.transports,
        })),
        userVerification: 'required',
        rpID: rpId,
    });

    res.send(options);
});

app.post("/verify-login-response", async (req, res) => {
    const user = getUserDetails(req.body.email);

    const bodyCredIDBuffer = isoBase64URL.toBuffer(req.body.id);

    let authenticator;
    for (const device of user.savedMethods) {
        if (isoUint8Array.areEqual(device.credentialID, bodyCredIDBuffer)) {
            authenticator = device;
            break;
        }
    }

    if (!authenticator) {
        return res.send({ verified: false, error: 'No authenticator found' });
    }

    let verification;
    try {
        verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: req.body.challenge,
            expectedOrigin: rpOrigin,
            expectedRPID: rpId,
            authenticator,
            requireUserVerification: true,
        });
    } catch (error) {
        return res.send({ verified: false, error: error.message });
    }

    const { verified, authenticationInfo } = verification;

    if (verified) {
        authenticator.counter = authenticationInfo.counter;
    }

    res.send(verification);
});

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "dist/dashboard.html"));
});

app.listen(PORT, () => {
    console.log("Server Listening on PORT:", PORT);

    // Run Parcel build and serve
    // exec based on the environment: development or production
    console.log('Running Parcel...', process.env.NODE_ENV)
    const execCommand = process.env.NODE_ENV === 'development' ? 'npx parcel start src/* --out-dir dist --public-url /' : 'npx parcel build src/* --out-dir dist --public-url ./';
    exec(execCommand, (error, stdout, stderr) => {
        const mode = process.env.NODE_ENV === 'development' ? 'serve' : 'build';
        if (error) {
            console.error(`Parcel ${mode} error: ${error}`);
            return;
        }
        console.log(`Parcel ${mode} stdout: ${stdout}`);
    });
});