import express from 'express';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const port = 3000;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

let clientRandom;
let serverRandom;
let sessionKey;

//------------------------------------------------------------------------------------------------------------------------------
const BufferToBase64 = buf => buf.toString('base64');
const Base64ToBuffer = s => Buffer.from(s, 'base64');

//------------------------------------------------------------------------------------------------------------------------------
function GenerateSessionKey(premasterBuffer, clientRandom, serverRandom) {
    return crypto.createHash('sha256')
        .update(Buffer.concat([premasterBuffer, Base64ToBuffer(clientRandom), Base64ToBuffer(serverRandom)]))
        .digest();
}

//------------------------------------------------------------------------------------------------------------------------------
function AesGcmEncrypt(sessionKey, plainText) {
    const initVector = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, initVector);
    const encryptText = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return { initVector: BufferToBase64(initVector), encryptText: BufferToBase64(Buffer.concat([encryptText, authTag]))};
}

//------------------------------------------------------------------------------------------------------------------------------
function AesGcmDecrypt(sessionKey, initVector_b64, encryptText_b64) {
    const initVector = Base64ToBuffer(initVector_b64);
    const encryptText = Base64ToBuffer(encryptText_b64);
    const bufLenght = encryptText.length

    const authTag = encryptText.slice(bufLenght - 16);
    const ciphertext = encryptText.slice(0, bufLenght - 16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, initVector);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8')
}

//------------------------------------------------------------------------------------------------------------------------------
app.get('/', (req, res) => {
    return res.sendFile(path.join(__dirname, 'index.html'));
});

//------------------------------------------------------------------------------------------------------------------------------
app.post('/hello', (req, res) => {
    clientRandom = req.body.clientRandom;
    if (!clientRandom) return res.status(400).json({ error: 'ClientRandom is empty' });
    console.log("\nClientRandom: ", clientRandom);

    serverRandom = crypto.randomBytes(32).toString('hex');
    console.log("\nServerRandom: ", serverRandom);

    return res.json({
        serverRandom: serverRandom,
        serverPublicKeyPem: publicKey
    });
});

//------------------------------------------------------------------------------------------------------------------------------
app.post('/premaster', (req, res) => {
    const {encryptPremasterBase64} = req.body;
    if (!encryptPremasterBase64) return res.status(400).json({ error: 'EncryptPremasterBase64 is empty' });

    try {
        const encryptPremaster = Base64ToBuffer(encryptPremasterBase64);
        const premaster = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        encryptPremaster
        );
        console.log("\nPremaster: ", premaster.toString('hex'));

        sessionKey = GenerateSessionKey(premaster, clientRandom, serverRandom);
        console.log("\nSessionKey: ", sessionKey.toString('hex'));

        console.log("\nMy ReadyPlain: server ready");
        const { initVector, encryptText} = AesGcmEncrypt(sessionKey, 'server ready');

        return res.json({ ready: { initVector, encryptText} });
    } catch (e) {
        console.error(`\n=========ERROR=========\n${e}\n==================`);
        return res.status(500).json({ error: "Failed in /premaster" });
    }
});

//------------------------------------------------------------------------------------------------------------------------------
app.post('/ready', (req, res) => {
  const clientReadyEncrypt = req.body.ready;
  if (!clientReadyEncrypt) return res.status(400).json({ error: 'Ready is empty' });

  try {
        const msg = AesGcmDecrypt(sessionKey, clientReadyEncrypt.initVector, clientReadyEncrypt.encryptText);
        console.log("\nClientReadyPlain: ", msg);

        const confirmPlain = 'connection confirm';
        const respons = AesGcmEncrypt(sessionKey, confirmPlain);
        console.log("\nMy ServerConfirmPlain: ", confirmPlain);

        return res.json({ confirm: respons });
    } catch (e) {
        console.error(`\n=========ERROR=========\n${e}\n==================`);
        return res.status(500).json({ error: "Failed in /ready" });
    }
});

//------------------------------------------------------------------------------------------------------------------------------
app.post('/send', (req, res) => {
    const messageEncrypt = req.body.messageEncrypt;
    if (!messageEncrypt) return res.status(400).json({ error: 'MessageEncrypt is empty' });

    try {
        const message = AesGcmDecrypt(sessionKey, messageEncrypt.initVector, messageEncrypt.encryptText);
        console.log(`\nInput Message: `, message);

        const answer = AesGcmEncrypt(sessionKey, message);
        res.json({ answer });
    } catch (e) {
        console.error(`\n=========ERROR=========\n${e}\n==================`);
        res.status(500).json({ error: "Failed in /send" });
    }
});

//------------------------------------------------------------------------------------------------------------------------------
app.post('/send/file', (req, res) => {
    const fileEncrypt = req.body.fileEncrypt;
    if (!fileEncrypt) return res.status(400).json({ error: 'FileEncrypt is empty' });

    try {
        const fileText = AesGcmDecrypt(sessionKey, fileEncrypt.initVector, fileEncrypt.encryptText);
        //console.log(`\nFile Message: `, fileText);

        const answer = AesGcmEncrypt(sessionKey, fileText);
        res.json({ answer });
    } catch (e) {
        console.error(`\n=========ERROR=========\n${e}\n==================`);
        res.status(500).json({ error: "Failed in /send" });
    }
});

//------------------------------------------------------------------------------------------------------------------------------
app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})