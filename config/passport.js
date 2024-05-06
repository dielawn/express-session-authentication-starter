const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const connection = require('./database');
const User = connection.models.User;
const validPassword = require('../lib/passwordUtils').validPassword;

const customfields = {
    usernameField: 'uname',
    passwordField: 'pw'
};


const verifyCallback = (username, password, done) => {

    User.findOne({ username: username })
        .then((user) => {
            //no error, user undefined
            console.log(user)
            if (!user) { 
                return done(null, false) 
            } 

            const isValid = validPassword(password, user.hash, user.salt);
            console.log(isValid)
            if (isValid) {
                //no error, user is valid
                return done(null, user);
            } else {
                //no error, user not valid
                return done(null, false);
            }
        })
        .catch((err) => {
            done(err);
        });
};

const strategy = new LocalStrategy(customfields, verifyCallback);

passport.use(strategy);

passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser((userId, done) => {
    User.findById(userId)
        .then((user) => {
            done(null, user);
        })
        .catch(err => done(err))
});