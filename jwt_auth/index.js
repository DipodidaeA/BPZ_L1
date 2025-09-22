import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';

const jwtSecretKey = 'secretkey';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const port = 3000;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';

app.use((req, res, next) => {
    console.log('\n=======================================================\n');
    const token = req.get(SESSION_KEY);

    if (token) {
        try {
            const decoded = jwt.verify(token, jwtSecretKey);
            req.session = decoded;
            console.log(`Valid token = ${JSON.stringify(decoded)}`);
        } catch (err) {
            console.log(`Invalid or expired token`);
            req.session = {};
        }
    } else {
        console.log('Have not token');
        req.session = {};
    }

    next();
});

app.get('/', (req, res) => {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    res.redirect('/');
});

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username',
    },
    {
        login: 'Login1',
        password: 'Password1',
        username: 'Username1',
    }
]

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find((user) => {
        if (user.login == login && user.password == password) {
            return true;
        }
        return false
    });

    if (user) {
        const payload = { 
            username: user.username,
            login: user.login 
        };

        const token = jwt.sign(payload, jwtSecretKey, { expiresIn: '1m' }); // токен на 1 годину

        console.log(`Create token = ${token}`);

        res.json({ token });
    }

    res.status(401).send();
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
