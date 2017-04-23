const passport = require("passport");
const passportJWT = require("passport-jwt");
const ExtractJwt = passportJWT.ExtractJwt;
const Strategy = passportJWT.Strategy;
const models  = require('shoppingmall-db-model');
const config = require('./config.js');
const jwt = require("jwt-simple");
const params = {
  secretOrKey: config.jwt.jwtSecret,
  jwtFromRequest: ExtractJwt.fromAuthHeader()
};
module.exports = () => {
  const strategy = new Strategy(params, (payload, done) => {
    return models.user.findById(payload.id).then((user) => {
      if (user) {
        return done(null, user);
      } else {
        return done(new Error("User not found"), null);
      }
    });
  });

  passport.use(strategy);
  return {
    initialize() {
      return passport.initialize();
    },
    authenticate() {
      return passport.authenticate("jwt", { session: false });
    },
    secret() {
      return params.secretOrKey;
    },
    payload(userId){
      const payload = {
        id: userId
      };
      return {token: jwt.encode(payload, this.secret())};
    }
  };
};

