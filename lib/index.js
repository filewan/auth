const jwt = require('jsonwebtoken');
const User = require('../models/user');
const bcrypt = require('bcrypt');
const UnauthorizedError = require('./errors').UnauthorizedError;
const unless = require('express-unless');
const fs = require('fs');
const config = require('../config');
const crypto = require('crypto');

// const IntercomKey = 'JRVIXTqUi1AaOhCRVoM_V00gbtxJNqX4FEqaNbc5';


module.exports = (options) => {
  if (options === undefined) {
    throw new Error('options should be sent');
  }

  const middleware = (req, res, next) => { // eslint-disable-line consistent-return
    if (options.auth === true && options.verify === true) {
      return next(new UnauthorizedError('BadOptionsError',
      { message: 'Both `auth` and `verify` fields should not be set at the same time' }));
    } else if (!options.auth && !options.verify) {
      return next(new UnauthorizedError('BadOptionsError', { message: 'Atleast one of `auth` and `verify` fields should be set' }));
    }
    let token;
    try {
      token = req.body.token || req.query.token || req.headers['x-access-token'];
    } catch (err) {
      return next(new UnauthorizedError('TokenNotSentError', { message: 'No authorization token was sent' }));
    }
    if (options.auth === true) {
      const secret = fs.readFileSync(config.get('jwt:privateKey'));
      const expiresIn = options.expiresIn || 24 * 60 * 60; // 24 hours is default
        const { username, password } = req.body;
        User.findOne({ username },
          (err, user) => { // eslint-disable-line consistent-return
            if (err) {
              return next(err);
            } else if (!user) {
              req.auth = {
                success: false,
                message: 'Authentication failed. Username and password combination not found.',
              };
              return next();
            } else { // eslint-disable-line no-else-return
              bcrypt.compare(password, user.password)
                .then((equal) => { // eslint-disable-line consistent-return
                  if (equal === true) {
                    token = jwt.sign(user, secret, { expiresIn, algorithm: 'RS256' });
                    // IntercomHash = crypto.createHmac('sha256', IntercomKey).update(email);
                    req.auth = {
                      success: true,
                      message: 'Successfully signed token',
                      token,
                    //   IntercomToken: IntercomHash.digest('hex'),
                    };
                    return next();
                  } else { // eslint-disable-line no-else-return
                    req.auth = {
                      success: false,
                      message: 'Authentication failed. Username and password combination not found.',
                    };
                    return next();
                  }
                })
                .catch(e => next(e));
            }
          });
    } else if (options.verify === true) {
      const { secret } = options;
      if (token === undefined) {
        return next(new UnauthorizedError('TokenNotSentError', { message: 'No authorization token was sent' }));
      }
      jwt.verify(token, secret, { algorithms: ['RS256'] }, (err, decoded) => {
        if (!err) {
          req.verify = decoded;
          return next();
        } else { // eslint-disable-line no-else-return
          return next(new UnauthorizedError(err.name, { message: err }));
        }
      });
    }
  };

  middleware.UnauthorizedError = UnauthorizedError;
  middleware.unless = unless;
  return middleware;
};
