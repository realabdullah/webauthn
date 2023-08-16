import express from "express";
import { exec } from 'child_process';
import path from 'path';
import { join } from 'node:path';
import {
    generateRegistrationOptions,
    generateAuthenticationOptions,
    verifyRegistrationResponse,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { isoBase64URL, isoUint8Array } from '@simplewebauthn/server/helpers';

import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'

const app = express();
const __dirname = path.dirname(new URL(import.meta.url).pathname);
const file = join(__dirname, 'db.json')
const PORT = 3300;

const rpName = "webauthn-demo";
const rpId = "localhost";
const rpOrigin = "http://localhost:3300";

// Configure lowdb to write data to JSON file
const adapter = new JSONFile(file)
const defaultData = { users: [] }
const db = new Low(adapter, defaultData)

// Read data from JSON file, this will set db.data content
// If JSON file doesn't exist, defaultData is used instead
await db.read()

const getUserDetails = (email) => db.data.users.find(user => user.email === email) || {};

app.use(express.json());
app.use(express.static(path.join(__dirname, 'dist')));

app.get("/status", (req, res) => {
    res.send("Hello, server is running");
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "dist/index.html"));
});

app.post("/generate-registration-options", async (req, res) => {
    const user = getUserDetails(req.body.email);

    const options = generateRegistrationOptions({
        rpName,
        rpId,
        rpOrigin,
        userID: req.body.email,
        userName: req.body.email,
        timeout: 60000,
        attestationType: 'none',
        authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'required',
        },
        excludeCredentials: user.savedMethods ? user.savedMethods.map(method => ({
            id: method.id,
            type: method.type,
            transports: method.transports,
        })) : [],
        supportedAlgorithmIDs: [-7, -257],
    });

    // save challenge for verification
    user.challenge = options.challenge;

    // save user
    if (!db.data.users.find(user => user.email === req.body.email)) {
        user.email = req.body.email;
        db.data.users.push(user);
        await db.write();
    }

    res.send(options);
});

app.post("/verify-registration-response", async (req, res) => {
    const user = getUserDetails(req.body.email);

    const verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: user.challenge,
        expectedOrigin: rpOrigin,
        expectedRPID: rpId,
        requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
        const { credentialPublicKey, credentialID, counter } = registrationInfo;

        const existingDevice = user.savedMethods ? user.savedMethods.find(method => isoUint8Array.areEqual(method.credentialID, credentialID)) : false;

        if (!existingDevice) {
            const newDevice = {
                credentialPublicKey,
                credentialID,
                counter,
                transports: req.body.response.transports,
            };

            if (!user.savedMethods) {
                user.savedMethods = [];
            }

            user.savedMethods.push(newDevice);
        }

        await db.write();
    }

    res.send(verification);
});

app.post("/login", async (req, res) => {
    const user = getUserDetails(req.body.email);

    if (!user.email) {
        return res.send({ error: 'User not found' });
    }

    const options = {
        timeout: 60000,
        allowCredentials: user.savedMethods.map(method => ({
            id: method.credentialID,
            type: "public-key",
            transports: method.transports,
        })),
        userVerification: 'required',
        rpID: rpId,
    };

    const options2 = generateAuthenticationOptions(options);

    // save challenge for verification
    user.challenge = options2.challenge;

    res.send(options2);
});

app.post("/verify-login-response", async (req, res) => {
    const user = getUserDetails(req.body.email);

    const bodyCredIDBuffer = isoBase64URL.toBuffer(req.body.rawId);

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
            expectedChallenge: user.challenge,
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

    await db.write();

    res.send(verification);
});

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "dist/dashboard.html"));
});

app.listen(PORT, () => {

    // Run Parcel build and serve
    exec("npx parcel build src/* --out-dir dist --public-url ./", (error, stdout, stderr) => {
        if (error) {
            console.error("Parcel build error: ", error);
            return;
        }
        console.log("Parcel build success: ", stdout);
    });
});