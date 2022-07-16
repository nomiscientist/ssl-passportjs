const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const cookieSession = require('cookie-session');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');

require('dotenv').config();

const PORT = 7000;
const config = {
    ClientID: process.env.ClientID,
    ClientSecret: process.env.ClientSecret,
    Cookie_key1: process.env.Cookie_key1,
    Cookie_key2: process.env.Cookie_key2
}

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: config.ClientID,
    clientSecret: config.ClientSecret,
}

function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log('accesstoken:',accessToken);
    console.log('Google Profile: ', profile);
    done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    done(null, id);
});

const app = express();
app.use(helmet());

app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: ['config.Cookie_key1', 'config.Cookie_key2'],
}));

app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next) {
    const isLoggedIn = req.isAuthenticated() && req.user;
    if (!isLoggedIn) {
        return res.status(401).json({
            error: 'User must logged in.'
        });
    }
    next();
}

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
}), 
(req, res) => {
    console.log('Google Called us back.');
});

app.get('/auth/google', passport.authenticate('google', {
    scope: ['email']
}));

app.get('/auth/logout', (req, res) => {
    req.logout();
    return res.redirect('/');
 });

app.get('/failure', (req, res) => {
    return res.send('Failure logging in!');
});


app.get('/secret', checkLoggedIn, (req, res) => {
    return res.send('my secret is 66!');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

https.createServer(
    {
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem')
    }, app).listen(PORT, () => {
        console.log('Listening on 7000 ...');
    });