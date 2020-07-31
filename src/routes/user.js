/* eslint-disable import/named */
import express from 'express';
import bcrypt from 'bcryptjs';
import { createJWTCookie, sendVerificationEmail } from '../utils/utils';
import { refreshTokenName } from '../config/keys';
import { User } from '../models/user';

const router = express.Router();

router.get('/login', (req, res) => {
    /*
    TODO - 
        1. ADD A CHECK FOR THE CASE WHEN AUTH HAS FAILED AND 
        USER HAS BEEN REDIRECTED TO THE LOGIN PAGE
        PERHAPS PASS THE CORRESPONDING ERROR MESSAGE AND THEN RENDER PAGE
        OR THE URL QUERY CONTAINS THE SERVICE URL, YOU COULD REDIRECT TO THAT

        2. Create a utils function to check validity of serviceURLs
    */

    // make sure serviceURL already has `http://` prepended
    // this is the responsibility of the client server.
    const { serviceURL } = req.query;

    // We should pass the service URL as well to the login page.
    // we pass the error handeling data to page
    res.render('login', { message: '', error: false, serviceURL });
});

router.get('/register', (req, res) => {
    const { serviceURL } = req.query;
    res.render('register', { message: '', error: false, serviceURL });
});

router.post('/login', async (req, res, next) => {
    try {
        const { email, password, serviceURL, rememberme } = req.body;
        // try to find the user in the database
        const user = await User.findOne({ email });
        // this means user doesn't exists, so throw an error TODO: add correct status to return
        if (!user) {
            return res.render('login', {
                message: 'Not a registered email address',
                error: true,
                serviceURL,
            });
        }

        if (!user.isverified) {
            return res.render('login', {
                message:
                    'Your account is not verified. Can\'t login? <a href="/auth/email/verify" id="verify">Verify Email</a>',
                error: true,
                serviceURL,
            });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);

        // Incorrect password
        if (!isMatch) {
            return res.render('login', {
                message: 'Password seems to be incorrect',
                error: true,
                serviceURL,
            });
        }

        createJWTCookie(user, res);
        if (rememberme === 'true') {
            createJWTCookie(user, res, refreshTokenName);
        }

        if (typeof serviceURL !== 'undefined' && serviceURL) {
            // render homepage to store token and then redirect with serviceURL
            return res.redirect(`/redirecting?serviceURL=${serviceURL}`);
        }

        res.redirect(`/redirecting`);
    } catch (err) {
        next(err);
    }
});

router.post('/register', async (req, res) => {
    const {
        firstname,
        lastname,
        username,
        email,
        password,
        serviceURL,
    } = req.body;

    // TODO: ADD A USERNAME CHECK AS WELL, THAT ALSO HAS TO BE UNIQUE
    try {
        // try to find the user in the database
        let user = await User.findOne({ email });

        // User already exists
        if (user) {
            return res.render('register', {
                message: 'User already exists with same email',
                error: true,
                serviceURL,
            });
        }

        // Create a new user of type `User`
        user = new User({
            firstname,
            lastname,
            username,
            email,
            password,
            isverified: false,
        });

        // encrypt the password using bcrypt
        const salt = await bcrypt.genSalt(10); // which to use 10 or more than that

        // update the password to encrypted one
        user.password = await bcrypt.hash(user.password, salt);

        // Save the updated the user in database
        await user.save();
        sendVerificationEmail(user);
        res.render('register', {
            message: 'A verification email has been sent to your inbox!',
            error: false,
            serviceURL,
        });
    } catch (err) {
        console.log(err);
        res.render('register', {
            message: 'WHOOPS!! A server error occured, please try again later',
            error: true,
            serviceURL,
        });
    }
});

export default router;
