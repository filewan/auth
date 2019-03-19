const express = require('express');
const bcrypt = require('bcrypt'); // eslint-disable-line
const User = require('../../models/user');
const jwtAuth = require('../../lib');
const config = require('../../config');
const enforceContentType = require('enforce-content-type');
const fs = require('fs');

const router = new express.Router();
const publicKey = fs.readFileSync('config/jwtRS256.key.pub');

router.use(enforceContentType({
  type: 'application/json',
  force: true,
}));

router.post('/create', (req, res) => {
    console.log("request body:", req.body.username)
  bcrypt.hash(req.body.password, 10)
    .then(hash => new User({
      username: req.body.username,
      password: hash,
      role: req.body.role
    }), (err) => {
      throw err;
    })
    .then((user) => { // save
        console.log("user", user)
      user.save((err) => {
        if (err) {
          res.status(500).send(err);
        } else {
          res.json({ success: true });
        }
      });
    });
});

router.post('/login',
  jwtAuth({
    auth: true,
    expiresIn: config.get('jwt:expiry'),
  }),
  (req, res) => {
    res.json(req.auth);
  });

router.use(jwtAuth({
  verify: true,
  secret: publicKey,
}));

router.patch('/update/password', (req, res) => {
  const { password } = req.body.updates;
  const { username } = req.verify._doc; // eslint-disable-line no-underscore-dangle
  bcrypt.hash(password, 10)
    .then((hash) => {
      User.findOneAndUpdate({ username }, { $set: { password: hash } }, (err, doc) => {
        if (err) {
          res.status(500).json(err);
        } else {
          res.json({
            success: true,
            updated: doc,
          });
        }
      });
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// don't update password here
router.patch('/update', (req, res) => {
  const { updates } = req.body;
  const { password } = updates;
  if (password !== undefined) {
    res.status(400).json({ success: false, message: 'Invalid Request. Use /update/password to update password' });
  } else {
    const { username } = req.verify._doc; // eslint-disable-line no-underscore-dangle
    User.findOneAndUpdate({ username }, { $set: updates }, (err, doc) => {
      if (err) {
        res.status(500).json(err);
      } else {
        res.json({
          success: true,
          updated: doc,
        });
      }
    });
  }
});

router.delete('/delete', (req, res) => {
  const { username } = req.verify._doc; // eslint-disable-line no-underscore-dangle
  User.findOneAndRemove({ username }, (err, doc) => {
    if (err) {
      res.status(500).json(err);
    } else {
      res.json({
        success: true,
        deleted: doc,
      });
    }
  });
});

router.get('/all', (req, res) => {
  User.find({}, (err, users) => {
    res.json(users);
  });
});

router.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  // console.log(err);
  if (err.name === 'UnauthorizedError') {
    switch (err.code) {
      case 'TokenExpiredError':
        res.status(401).send('Token has expired');
        break;

      case 'JsonWebTokenError':
        res.status(401).send('Invalid Token');
        break;

      case 'BadOptionsError':
        res.status(401).send(err.message);
        break;

      case 'TokenNotSentError':
        res.status(401).send(err.message);
        break;

      default:
        res.status(401).send('Unauthorized Access');
        break;
    }
  }
});

module.exports = router;
