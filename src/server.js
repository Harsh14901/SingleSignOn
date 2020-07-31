import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import user from './routes/user';
import auth from './routes/auth';
import profile from './routes/profile';
import client from './routes/client';
import * as keys from './config/keys';

import { socialAuthenticate, linkSocial } from './utils/utils';

require('dotenv').config({
    path: `${__dirname}/../.env`,
});

const app = express();

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const FbStrategy = require('passport-facebook').Strategy;
const GithubStrategy = require('passport-github2').Strategy;

const googleStrategy = new GoogleStrategy(
    {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `https://auth.devclub.in/auth/google/callback`,
        passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, googleProfile, done) => {
        const token = req.cookies[keys.accessTokenName];
        const {
            sub: uid,
            family_name: lastname,
            given_name: firstname,
            email,
        } = googleProfile._json;
        try {
            const resp = await linkSocial(token, 'google', uid, email, done);
            return resp;
        } catch (error) {
            return socialAuthenticate(
                'google',
                done,
                uid,
                firstname,
                lastname,
                email
            );
        }
    }
);

const fbStrategy = new FbStrategy(
    {
        clientID: process.env.FACEBOOK_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
        callbackURL: `https://auth.devclub.in/auth/facebook/callback`,
        profileFields: ['id', 'displayName', 'email'],
        enableProof: true,
        passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, fbProfile, done) => {
        const token = req.cookies[keys.accessTokenName];
        const { id: uid, name: firstname, email } = fbProfile._json;
        try {
            const resp = await linkSocial(token, 'facebook', uid, email, done);
            return resp;
        } catch (error) {
            return socialAuthenticate(
                'facebook',
                done,
                uid,
                firstname,
                '',
                email
            );
        }
    }
);
const githubStrategy = new GithubStrategy(
    {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: `https://auth.devclub.in/auth/github/callback`,
        scope: ['user:email'],
        passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, githubProfile, done) => {
        const token = req.cookies[keys.accessTokenName];
        const { id: uid, name: firstname } = githubProfile._json;
        const email = githubProfile.emails[0].value;
        try {
            const resp = await linkSocial(token, 'github', uid, email, done);
            return resp;
        } catch (error) {
            return socialAuthenticate(
                'github',
                done,
                uid,
                firstname,
                '',
                email
            );
        }
    }
);

passport.use(googleStrategy);
passport.use(fbStrategy);
passport.use(githubStrategy);
app.use(passport.initialize());

app.use(cors());
app.use(cookieParser()); // pass a string inside function to encrypt cookies

app.set('view engine', 'ejs');
app.set('views', `${__dirname}/views`);
app.use(express.static(`${__dirname}/public`));

// Body Parser Middleware
// parse application/x-www-form-urlencoded (for ejs page requests)
app.use(bodyParser.urlencoded());
// parse json
app.use(bodyParser.json());

// export .env from previous folder

const db_url = process.env.DB_URL;

// Connect to database
mongoose
    .connect(db_url, {
        useNewUrlParser: true,
        useCreateIndex: true,
        useFindAndModify: false,
        useUnifiedTopology: true,
    })
    .then(() => {
        console.log('Connected to the database...');
    })
    .catch((err) => {
        console.log(err);
    });

// Root page
app.get('/', (req, res) => {
    res.render('index');
});

// middleware page used for redirecting and handeling the user token on our end
app.get('/redirecting', (req, res) => {
    const { serviceURL } = req.query;
    if (typeof serviceURL !== 'undefined' && serviceURL) {
        const finalServiceURL = `${serviceURL}`;
        return res.render('middleware', {
            serviceURL: finalServiceURL,
        });
    }
    res.render('middleware', {
        serviceURL,
    });
});

// About Page
app.get('/about', (req, res) => {
    res.render('about');
});

// Set Routes
app.use('/user', user);
app.use('/auth', auth);
app.use('/profile', profile);
app.use('/client', client);

const port = process.env.PORT;

app.listen(port, () => {
    console.log(`Server listening on ${port}!`);
});
