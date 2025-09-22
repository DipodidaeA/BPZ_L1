const express = require('express') // для створення web застосунку
const app = express()   // створення веб застосунку
const port = 3000       // порт

// обробка будь яких http запитів
// повинен завжди надсилати res.send або res.end або next() перед виходом з функції
// req - об'єкт запиту, інформаціє про запит: URL, заголовки, тіло, параметри
// res - об'єкті відповіді, надсилання діних клієнту
// next() - функція яка передає управління наступному обробнику запитів в черзі
app.use((req, res, next) => {
    console.log('\n=======================================================\n');

    // отримання даних з заголовку 'Authorization'
    const authorizationHeader = req.get('Authorization');
    console.log('authorizationHeader', authorizationHeader);

    if (!authorizationHeader) {
        // відкри вікно для HTTP-авторизації, українська локалізація
        res.setHeader('WWW-Authenticate', 'Basic realm="Ukraine"');
        res.status(401); // статус неавторизований
        res.send('Unauthorized'); // надіслати повідомлення користувачу
        return; // повернення без next() щоб запит не пішов до інших обробників
    }

    // отримання логіну та паролю
    const authorizationBase64Part = authorizationHeader.split(' ')[1];

    // декодування з Base64
    const decodedAuthorizationHeader = Buffer.from(authorizationBase64Part, 'base64').toString('utf-8');
    console.log('decodedAuthorizationHeader', decodedAuthorizationHeader);

    const login = decodedAuthorizationHeader.split(':')[0];
    const password = decodedAuthorizationHeader.split(':')[1];
    console.log('Login/Password', login, password);

    if (login == 'Rak' && password == '123') {
        req.login = login; // додавання поля до запиту
        return next();      // передача запиту наступному обробнику (app.get('/', (req, res)=>{})
    }

    // якщо неправильні логін чи пароль
    res.setHeader('WWW-Authenticate', 'Basic realm="Ukraine"');
    res.status(401);
    res.send('Unauthorized');
});

// обробник Get запиту
// повинен завжди надсилати res.send або res.end перед виходом з функції
app.get('/', (req, res) => {
    res.send(`Hello ${req.login}`);
})

// запуск серверу
app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
