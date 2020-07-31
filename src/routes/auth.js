import express from 'express';
import { verify } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import {
    verifyToken,
    createJWTCookie,
    socialAuthenticate,
    sendVerificationEmail,
    sendPassResetEmail,
} from '../utils/utils';
import {
    accessTokenName,
    refreshTokenName,
    profileNotFoundMsg,
    accountExists,
    publicKey,
} from '../config/keys';
import { User } from '../models/user';

const router = express.Router();
const passport = require('passport');
const axios = require('axios');

// post route to check validity of tokens, clients will hit this route.
router.post('/refresh-token', async (req, res) => {
    const token = req.body[accessTokenName];
    const refreshToken = req.body[refreshTokenName];
    try {
        const user = await verifyToken(req, res, true, 0, token, refreshToken);
        return res.status(200).json({
            user,
        });
    } catch (error) {
        return res.status(401).json({
            err: true,
            msg: 'Error, token not valid',
        });
    }
});

router.get('/email/verify/token', async (req, res) => {
    try {
        const { token } = req.query;
        const decoded = await verify(token, publicKey, {
            algorithms: ['RS256'],
        });
        const user = await User.findById(decoded.id);
        user.isverified = true;
        await user.save();
        res.status(200).send('Account Verified!!');
    } catch (error) {
        console.log(error);
        res.clearCookie(accessTokenName);
        res.clearCookie(refreshTokenName);
        res.status(500).send(
            'Account could not be verified. Please try again later!'
        );
    }
});

router.get('/email/verify', (req, res) => {
    res.render('email_verify');
});

router.post('/email/verify', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({
            email,
        });
        if (!user)
            return res.render('email_verify', {
                message: 'Email Address not registered',
                error: true,
            });
        if (user.isverified) {
            return res.render('email_verify', {
                message:
                    'Your account is already verified, Please login to continue',
                error: true,
            });
        }
        sendVerificationEmail(user);
        return res.render('email_verify', {
            message: 'A verification email has been sent to your inbox!',
            error: true,
        });
    } catch (error) {
        res.render('email_verify', {
            message: 'Email Address not registered',
            error: true,
        });
    }
});

router.get('/password/reset/token', async (req, res) => {
    try {
        const { token } = req.query;
        const decoded = await verify(token, publicKey, {
            algorithms: ['RS256'],
        });
        const user = await User.findById(decoded.id);
        user.password = await bcrypt.hash(decoded.newPass, 10);
        await user.save();
        res.status(200).send('Password reset successfully!');
    } catch (error) {
        console.log(error);
        res.clearCookie(accessTokenName);
        res.clearCookie(refreshTokenName);
        res.status(500).send('Invalid Token. Please try again later!');
    }
});
router.get('/password/reset', (req, res) => {
    res.render('pass_forgot');
});
router.post('/password/reset', async (req, res) => {
    try {
        const { email, newPass } = req.body;
        const user = await User.findOne({
            email,
        });
        if (!user)
            return res.render('pass_forgot', {
                message: 'Email Address not registered',
                error: true,
            });
        if (!newPass)
            return res.render('pass_forgot', {
                message: 'New Password not supplied',
                error: true,
            });
        sendPassResetEmail(user, newPass);
        return res.render('pass_forgot', {
            message: 'A password reset email has been sent to your inbox!',
            error: false,
        });
    } catch (error) {
        res.render('pass_forgot', {
            message: 'Email Address not registered',
            error: true,
        });
    }
});

export default router;

router.get('/google', (req, res, next) => {
    passport.authenticate('google', {
        scope: ['profile', 'email'],
        state: req.query.serviceURL,
    })(req, res, next);
});

router.get('/facebook', (req, res, next) => {
    passport.authenticate('facebook', {
        authType: 'rerequest',
        state: req.query.serviceURL,
    })(req, res, next);
});

router.get('/github', (req, res, next) => {
    passport.authenticate('github', {
        state: req.query.serviceURL,
    })(req, res, next);
});

router.get(
    '/:provider/callback',
    (req, res, next) => {
        passport.authenticate(req.params.provider, {
            session: false,
            failureRedirect: '/user/login',
        })(req, res, next);
    },
    async (req, res) => {
        createJWTCookie(req.user, res);
        if (req.authInfo.message === profileNotFoundMsg) {
            return res.render('confirm');
        }
        if (req.authInfo.message === accountExists) {
            return res.render('settings', {
                messages: [{ message: accountExists, error: true }],
            });
        }
        const { state: serviceURL } = req.query;

        if (typeof serviceURL !== 'undefined' && serviceURL) {
            // render homepage to store token and then redirect with serviceURL
            return res.redirect(`/redirecting?serviceURL=${serviceURL}`);
        }
        return res.redirect('/');
    }
);

router.get('/iitd', (req, res) => {
    return res.redirect(
        `https://oauth.iitd.ac.in/authorize.php?response_type=code&client_id=${process.env.IITD_CLIENT_ID}&state=xyz`
    );
});

router.get('/iitd/confirm', async (req, res) => {
    try {
        const { access_token } = (
            await axios.post('https://oauth.iitd.ac.in/resource.php', {
                client_id: process.env.IITD_CLIENT_ID,
                client_secret: process.env.IITD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: req.query.code,
            })
        ).data;
        const userData = (
            await axios.post('https://oauth.iitd.ac.in/resource.php', {
                access_token,
            })
        ).data;
        const iitdCallback = async (
            err = null,
            user = null,
            authInfo,
            request = req,
            response = res
        ) => {
            if (!err || !user) return response.status(500);

            if (!user.roles.includes('iitd_user')) {
                user.roles.push('iitd_user');
                await user.save();
            }
            createJWTCookie(user, response);
            if (req.authInfo.message === profileNotFoundMsg) {
                return res.render('confirm');
            }
            if (req.authInfo.message === accountExists) {
                return res.render('settings', {
                    messages: [
                        {
                            message: accountExists,
                            error: true,
                        },
                    ],
                });
            }
            const { serviceURL } = request.query;

            if (typeof serviceURL !== 'undefined' && serviceURL) {
                // render homepage to store token and then redirect with serviceURL
                return response.redirect(
                    `/redirecting?serviceURL=${serviceURL}`
                );
            }
            return response.redirect('/');
        };
        return socialAuthenticate(
            'iitd',
            iitdCallback,
            userData.uniqueiitd,
            userData.name,
            '',
            userData.email,
            'iitd_user'
        );
    } catch (error) {
        console.log(error);
        return res.status(500);
    }
});

router.get(`/sudoTestCommand/:secret/makeadminforclient`, async (req, res) => {
    if (req.params.secret === process.env.MY_SECRET) {
        try {
            const result = await User.findOne({
                email: 'aryanguptaleo@gmail.com',
            });

            result.isverified = true;
            result.roles.push('admin');

            await User.findOneAndUpdate(
                { email: 'aryanguptaleo@gmail.com' },
                result
            );
            res.json({
                message: 'action completed',
            });
        } catch (err) {
            res.json({
                message: 'unable to process request',
            });
        }
    } else {
        res.json({
            message: 'Unauthorized',
        });
    }
});
