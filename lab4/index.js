import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';
import jwt from 'jsonwebtoken';

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

function IsTokenExpiringSoon(token, seconds = 60) {
    try {
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.exp) return true;

        const now = Math.floor(Date.now() / 1000);
        console.log("Token Life Time: ", decoded.exp - now);
        return decoded.exp - now < seconds;
    } catch (e) {
        return true;
    }
}

app.get('/', async (req, res) => {
    const access_token = req.headers['x-access-token'];
    const refresh_token = req.headers['x-refresh-token'];
    
    if (access_token === ""){
        return res.sendFile(path.join(__dirname, 'index.html'));
    }

    try {
        if (IsTokenExpiringSoon(access_token, 3480)){
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
                console.log("Token Refreshed:", JSON.stringify(data, null, 2));
                return res.json(data);
            }

            return res.sendFile(path.join(__dirname, 'index.html'));
        }

        const response = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        if (response.ok) {
            const userInfo = await response.json();
            console.log("User info got:", JSON.stringify(userInfo, null, 2));
            return res.json({ userGreet: userInfo.name});
        }

        return res.sendFile(path.join(__dirname, 'index.html'));
    }
    catch (err) {
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
            console.log("User Authorized:", JSON.stringify(data, null, 2));
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
                console.log("New MAIN_TOKEN:", JSON.stringify(MAIN_TOKEN, null, 2));
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
            console.log("User Created:", JSON.stringify(data, null, 2));
            return res.json(data);
        }

        return res.status(401).send();
    } catch (err) {
        return res.status(500).json({ error: err });
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
