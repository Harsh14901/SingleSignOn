/* eslint-disable no-restricted-syntax */
/* eslint-disable no-await-in-loop */
/* eslint-disable import/named */
/* eslint-disable no-param-reassign */
import jwt, { verify } from 'jsonwebtoken';
import axios from 'axios';
import * as keys from '../config/keys';
import { User, SocialAccount, Role } from '../models/user';

const getUserPrivilege = (user) => {
    let privilege = 0;
    user.roles.forEach((role) => {
        if (keys.r2p[role]) privilege = Math.max(privilege, keys.r2p[role]);
    });
    return privilege;
};

const getRoleData = async (roles) => {
    // eslint-disable-next-line prefer-const
    let data = [];
    for (let index = 0; index < roles.length; index += 1) {
        const element = roles[index];
        const role = await Role.findOne({ name: element });
        data.push(role);
    }
    return data;
};

const createJWTCookie = (user, res, tokenName = keys.accessTokenName) => {
    const payload = {
        user: {
            id: user.id,
            email: user.email,
            firstname: user.firstname,
            lastname: user.lastname,
            username: user.username,
            roles: user.roles,
            privilege: getUserPrivilege(user),
            isverified: user.isverified,
        },
    };
    const exp =
        tokenName === keys.refreshTokenName ? keys.rememberTime : keys.expTime;
    // create a token
    const token = jwt.sign(payload, keys.privateKey, {
        expiresIn: exp, // in seconds
        issuer: keys.iss,
        algorithm: 'RS256',
    });

    // set the cookie with token with the same age as that of token
    res.cookie(tokenName, token, {
        maxAge: exp * 1000, // in milli seconds
        secure: true, // set to true if your using https
        httpOnly: true,
        sameSite: 'lax',
        domain: 'devclub.in',
    });
};

const verifyToken = async (
    req,
    res,
    verified = true,
    privilege = 0,
    token = null,
    refreshToken = null
) => {
    if (!token) token = req.cookies[keys.accessTokenName];
    if (!refreshToken) refreshToken = req.cookies[keys.refreshTokenName];
    let user;
    try {
        if (!token) {
            if (!refreshToken) throw jwt.JsonWebTokenError;

            const decoded = verify(refreshToken, keys.publicKey, {
                algorithms: ['RS256'],
            });
            user = await User.findById(decoded.user.id);

            // Extend the refresh token.
            createJWTCookie(user, res, keys.refreshTokenName);
        } else {
            const decoded = verify(token, keys.publicKey, {
                algorithms: ['RS256'],
            });
            user = await User.findById(decoded.user.id);
        }

        // The user is not yet verified or lacks the privileges
        if (
            (verified && !user.isverified) ||
            getUserPrivilege(user) < privilege
        )
            throw jwt.JsonWebTokenError;

        // Refresh the token cookie
        createJWTCookie(user, res);

        return user;
    } catch (err) {
        console.log(err);
        // I wasn't able to verify the token as it was invalid
        // clear the tokens
        res.clearCookie(keys.accessTokenName, {
            domain: 'devclub.in',
        });
        res.clearCookie(keys.refreshTokenName, {
            domain: 'devclub.in',
        });
        throw err;
    }
};

const sendVerificationEmail = async (user) => {
    try {
        const payload = {
            id: user.id,
            email: user.email,
        };
        const token = jwt.sign(payload, keys.privateKey, {
            expiresIn: 3600,
            issuer: keys.iss,
            algorithm: 'RS256',
        });
        await axios.post(process.env.MAILER_URL, {
            to: user.email,
            subject: 'Account Verification',
            html: `<h3>Click here to verify your account</h3>
              <p>
                  <a href = "http://localhost:8000/auth/email/verify/token/?token=${token}"> Click Here </a>
              </p>`,
            secret: process.env.MAILER_TOKEN,
        });
    } catch (error) {
        console.log(error);
    }
};
const sendPassResetEmail = async (user, newPass) => {
    try {
        const payload = {
            id: user.id,
            email: user.email,
            newPass,
        };
        const token = jwt.sign(payload, keys.privateKey, {
            expiresIn: 3600,
            issuer: keys.iss,
            algorithm: 'RS256',
        });
        await axios.post(process.env.MAILER_URL, {
            to: user.email,
            subject: 'Password Reset',
            html: `<h3>Click here to reset password for your account</h3>
              <p>
                  <a href = "http://localhost:8000/auth/password/reset/token/?token=${token}"> Click Here </a>
              </p>`,
            secret: process.env.MAILER_TOKEN,
        });
    } catch (error) {
        console.log(error);
    }
};

const matchUserRegex = (user, regex) => {
    let assign = true;
    for (const [field, regexp] of Object.entries(regex)) {
        if (user[field] && regexp) {
            const patt = new RegExp(regexp);
            if (!patt.test(user[field])) {
                assign = false;
                break;
            }
        } else if (regexp) {
            assign = false;
            break;
        }
    }
    return assign;
};

const assignRoleToUsers = async (role, del = false) => {
    const users = await User.find({});
    for (let index = 0; index < users.length; index += 1) {
        try {
            const user = users[index];
            const assign = matchUserRegex(user, role.regex);
            if (assign && !user.roles.includes(role.name)) {
                user.roles.push(role.name);
                await user.save();
            }

            if ((del || !assign) && user.roles.includes(role.name)) {
                // eslint-disable-next-line no-shadow
                const index = user.roles.findIndex((name) => {
                    return name === role.name;
                });
                user.roles.splice(index, 1);
                await user.save();
            }
        } catch (err) {
            console.log(err);
        }
    }
};

const makeid = (length, alpahnum_only = false) => {
    let result = '';
    const characters = !alpahnum_only
        ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,./;:?><[]{}|`~!@#$%^&*()-_=+'
        : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i += 1) {
        result += characters.charAt(
            Math.floor(Math.random() * charactersLength)
        );
    }
    return result;
};

const socialAuthenticate = async (
    provider,
    done,
    uid,
    firstname,
    lastname,
    email,
    role = 'external_user'
) => {
    try {
        let msg = '';
        // Find if the social account already exists or not
        const existingSocial = await SocialAccount.findOne({
            provider,
            uid,
        });

        // If social account exists then log in as the primary account of the social account.
        if (existingSocial) {
            console.log('Social account exists');
            const user = await User.findOne(existingSocial.primary_account);
            if (!user.isverified) msg = keys.profileNotFoundMsg;
            return done(null, user, { message: msg });
        }
        console.log(
            'No matching social account found for the user\nTrying to find if a user with same email exists or not ...'
        );

        // Find if a primary_account exists with the same email or not
        let primary_account = await User.findOne({ email });
        if (!primary_account) {
            console.log(
                'No user found with the given email address\nCreating user ....'
            );

            // No such account found hence create a DB entry for this user
            primary_account = await User.create({
                firstname,
                lastname,
                email,
                username: makeid(10),
                password: makeid(32),
                roles: [role],
            });
            msg = keys.profileNotFoundMsg;
        } else if (!primary_account.isverified) {
            msg = keys.profileNotFoundMsg;
            console.log('Found an unverified user with the same email address');
        } else {
            console.log('Found a user with the same email address');
        }
        console.log('Linking the social account with this user');

        // Create and link the new social account with the primary_accoun found/created in the steps above.
        await SocialAccount.create({
            provider,
            uid,
            email,
            primary_account,
        });

        return done(null, primary_account, {
            message: msg,
        });
    } catch (error) {
        console.log(error);
        return done(error);
    }
};

const linkSocial = async (token, provider, uid, email, done) => {
    const decoded = verify(token, keys.publicKey, {
        algorithms: ['RS256'],
    });

    const primary_account = await User.findById(decoded.user.id);
    if (!primary_account || !primary_account.isverified)
        throw jwt.JsonWebTokenError;
    if (await SocialAccount.findOne({ provider, uid }))
        return done(null, primary_account, { message: keys.accountExists });
    await SocialAccount.create({
        provider,
        uid,
        email,
        primary_account,
    });
    return done(null, primary_account);
};

export {
    makeid,
    createJWTCookie,
    verifyToken,
    socialAuthenticate,
    linkSocial,
    getUserPrivilege,
    getRoleData,
    assignRoleToUsers,
    sendVerificationEmail,
    sendPassResetEmail,
};
