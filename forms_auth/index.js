import { v4 as uuidv4 } from 'uuid'; // для генерації унікальних ІД
import express from 'express'; // для створення web застосунку
import cookieParser from 'cookie-parser'; // для роботи з cookies у express
import onFinished from 'on-finished'; // виконує функцію після завершення HTTP відповіді
import bodyParser from 'body-parser'; // для парсингу тіла зпиту
import path from 'path'; // для роботи з шляхами до вайлів
import fs from 'fs';  // для роботи з файловою ситемою
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const port = 3000; // порт
const app = express(); // створення веб застосунку
app.use(bodyParser.json()); // парсинг тіла запиту JSON формату
app.use(bodyParser.urlencoded({ extended: true })); // парсинг форматованих даних з форму (extended: true - парсить вкладені об'єкти)
app.use(cookieParser()); // читає cookie з запиту

const SESSION_KEY = 'session'; // назва даних у cookie

class Session {
    #sessions = {}

    constructor() {
        try {
            // читаємо дані про сесії з файлу збережень сесій
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            // парсимо дані про сесії у список
            this.#sessions = JSON.parse(this.#sessions.trim());

            console.log(this.#sessions);
        } catch(e) {
            // створюємо новий список, якщо немає збережень
            this.#sessions = {};
        }
    }

    #storeSessions() {
        // зберігаємо список сесій у файл
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    // додати сесію
    set(key, value) {
        if (!value) {
            value = {};
        }
        this.#sessions[key] = value;
        this.#storeSessions(); // зберегти
    }

    // отримати дані сесії
    get(key) {
        return this.#sessions[key];
    }

    // створити нову сесію
    init(res) {
        const sessionId = uuidv4(); // генерація ІД сесії
        res.set('Set-Cookie', `${SESSION_KEY}=${sessionId}; HttpOnly`); // створення куку для сесії
        this.set(sessionId); // додати

        return sessionId;
    }

    // знищити сесію
    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
        res.set('Set-Cookie', `${SESSION_KEY}=; HttpOnly`);
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId;

    // отримання/створення сесії
    if (req.cookies[SESSION_KEY]) {
        sessionId = req.cookies[SESSION_KEY];
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    // збереження сесії піля відправки відповіді клієнту
    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    next();
});

app.get('/', (req, res) => {
    console.log(req.session);

    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
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
        req.session.username = user.username;
        req.session.login = user.login;

        res.json({ username: login });
    }

    res.status(401).send();
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
