const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken')
const {verify} = require("jsonwebtoken");
const fs = require("fs");

const PORT = 3000;
const SECRET_FILE_PATH = './secret.txt';
const EXPIRES_IN = '3m';
const TOKEN_HEADER = 'Authorization';
const BLOCK_TIME_IN_MILLIS = 1 * 60 * 1000;

const PRIVATE_KEY = getSecret()

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username',
    },
    {
        login: 'Vlad',
        password: '1234',
        username: 'VladH',
    }
];

const loginHistory = {};

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use((req, res, next) => {
    let token = req.get(TOKEN_HEADER);
    if (token && isValid(token)) {
        req.username = getUsername(token);
    }
    next();
});

app.get('/', (req, res) => {
    if (req.username) {
        return res.json({
            username: req.username
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.post('/api/login', (req, res) => {
    const userAddress = req.socket.remoteAddress;
    updateUserStatus(userAddress)

    if (isUserBlocked(userAddress)) {
        console.log(`Unsuccessful attempt to login from address ${userAddress}`)
        increaseUnsuccessfulAttempts(userAddress)
        res.status(401).send();
        return;
    }
    const { login, password } = req.body;
    const user = users.find((user) => {
        return user.login === login && user.password === password;
    });

    if (user) {
        const token = sign({login: user.login})
        res.json({ token });
        return;
    }

    console.log(`Unsuccessful attempt to login from address ${userAddress}`)
    increaseUnsuccessfulAttempts(userAddress)
    res.status(401).send();
});

app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`)
})

function getSecret() {
    return fs.readFileSync(SECRET_FILE_PATH);
}

function sign(payload) {
    return jwt.sign(payload, PRIVATE_KEY, { expiresIn: EXPIRES_IN});
}

function isValid(token) {
    return verify(token, PRIVATE_KEY)
}

function getUsername(token) {
    const payload = verify(token, PRIVATE_KEY)
    if (!payload) {
        return null;
    }

    const user = users.find(user => user.login === payload.login);
    if (!user) {
        return null;
    }

    return user.username;
}

function isUserBlocked(userAddress) {
    return userAddress in loginHistory && loginHistory[userAddress].status === 'Blocked'
}

function updateUserStatus(userAddress) {
    let userHistory = loginHistory[userAddress]
    if (userAddress in loginHistory && userHistory.status === 'Blocked' && userHistory.blockedUntil < new Date()) {
        userHistory.status = 'Allowed'
        userHistory.unsuccessfulAttempts = 0
        userHistory.blockedUntil = null
    }
}

function increaseUnsuccessfulAttempts(userAddress) {
    if (!(userAddress in loginHistory)) {
        loginHistory[userAddress] = {status: 'Allowed', unsuccessfulAttempts: 1};
    } else {
        loginHistory[userAddress].unsuccessfulAttempts += 1;
    }

    if (loginHistory[userAddress].unsuccessfulAttempts > 3) {
        loginHistory[userAddress].status = 'Blocked'
        loginHistory[userAddress].blockedUntil = new Date(new Date().getTime() + BLOCK_TIME_IN_MILLIS)
        console.log(`User with address ${userAddress} is blocked until ${loginHistory[userAddress].blockedUntil}`)
    }
}
