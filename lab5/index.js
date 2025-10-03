import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { compactDecrypt, importPKCS8} from 'jose';
import fs from 'fs';
import { webcrypto } from 'crypto';

globalThis.crypto = webcrypto;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const port = 3000;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const AUTH0_DOMAIN = "dev-qb7j7tdk0d5uihqt.us.auth0.com"
const AUDIENCE = "https://sslabs.ua.com"
const CLIENT_ID = "UeSaoR0ox5oFwZzs1OmmlvU9t6WrUU5E"
const CLIENT_SECRET = "qeWSXAOc8o1pHhy2YoG-39tnIqb8aKIWtyE9NbEjtvqmoihPBUp4DrG9hnxI_8KA"

let MAIN_TOKEN = ""

const privateKeyPem = fs.readFileSync('./private.pem', 'utf8');

async function decryptJwe(jweToken) {
    const privateKey = await importPKCS8(privateKeyPem, 'RSA-OAEP-256');
    const { plaintext } = await compactDecrypt(jweToken, privateKey);
    const decodedText = new TextDecoder().decode(plaintext);
    return decodedText;
}

const client = jwksClient({
    jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, (err, key) => {
        if (err) return callback(err);

        const signingKey = key.getPublicKey();

        callback(null, signingKey);
    });
}

function verifyToken(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(
            token,
            getKey,
            {
                audience: AUDIENCE,
                issuer: `https://${AUTH0_DOMAIN}/`,
                algorithms: ["RS256"]
            },
            (err, decoded) => {
                if (err) return reject(err);
                resolve(decoded);
            }
        );
    });
}

function IsTokenExpiringSoon(payload, seconds = 60) {
    try {
        if (!payload || !payload.exp) return true;

        const now = Math.floor(Date.now() / 1000);
        console.log("\nToken Life Time: ", payload.exp - now);
        return payload.exp - now < seconds;
    } catch (e) {
        return true;
    }
}

app.get('/', async (req, res) => {
    const access_token = req.headers['x-access-token'];
    const refresh_token = req.headers['x-refresh-token'];
    
    console.log("\naccess_token JWE: ", JSON.stringify(access_token, null, 2));

    if (access_token === "" || !access_token){
        return res.sendFile(path.join(__dirname, 'index.html'));
    }

    try {
        const jwt = await decryptJwe(access_token);
        console.log("\nJWT: ", JSON.stringify(jwt, null, 2));

        const payload = await verifyToken(jwt)
        console.log("\nPayload: ", JSON.stringify(payload, null, 2));

        if (IsTokenExpiringSoon(payload, 60)){
            const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({
                grant_type: 'refresh_token',
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                refresh_token
                }),
            });

            const data = await response.json();

            if (response.ok) {
                console.log("\nToken Refreshed:", JSON.stringify(data, null, 2));
                return res.json(data);
            }

            return res.sendFile(path.join(__dirname, 'index.html'));
        }

        const response = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, {
            headers: { Authorization: `Bearer ${jwt}` }
        });

        if (response.ok) {
            const userInfo = await response.json();
            console.log("\nUser info got:", JSON.stringify(userInfo, null, 2));
            return res.json({ userGreet: userInfo.name});
        }

        return res.sendFile(path.join(__dirname, 'index.html'));
    }
    catch (err) {
        console.log(`\n=======ERROR=======\n${err}\n==============`);
        return res.sendFile(path.join(__dirname, 'index.html'));
    }
})

// username: anton.rak050@gmail.com
// password: NewPass123

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'password',
                username,
                password,
                audience: AUDIENCE,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                scope: 'openid profile email offline_access'
            }),
        });

        const data = await response.json();

        if (response.ok) {
            console.log("\nUser Authorized:", JSON.stringify(data, null, 2));
            return res.json(data);
        }

        return res.status(401).send();
    } catch (err) {
        return res.status(500).json({ error: 'Failed to login user' });
    }
});

app.post('/api/register', async (req, res) => {
    const { username, pass } = req.body;

    try {
        if (MAIN_TOKEN === "" || IsTokenExpiringSoon(MAIN_TOKEN, 60)){
            const mainResponse = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client_id: CLIENT_ID,
                    client_secret: CLIENT_SECRET,
                    audience: `https://${AUTH0_DOMAIN}/api/v2/`,
                    grant_type: 'client_credentials'
                }),
            });

            const mainData = await mainResponse.json();

            if (mainResponse.ok) {
                MAIN_TOKEN = mainData.access_token;
                console.log("\nNew MAIN_TOKEN:", JSON.stringify(MAIN_TOKEN, null, 2));
            }
            else{
                return res.status(401).send();
            }
        }

        const response = await fetch(`https://${AUTH0_DOMAIN}/api/v2/users`, {
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${MAIN_TOKEN}`,
                'content-type': 'application/json' 
            },
            body: JSON.stringify({
                email: username,
                password: pass,
                connection: "Username-Password-Authentication",
                verify_email: false
            }),
        });

        const data = await response.json();

        if (response.ok) {
            console.log("\nUser Created:", JSON.stringify(data, null, 2));
            return res.json(data);
        }

        return res.status(401).send();
    } catch (err) {
        return res.status(500).json({ error: err });
    }
});

app.listen(port, () => {
    console.log(`============= Example app listening on port ${port} =============`)
})
