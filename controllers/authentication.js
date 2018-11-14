const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

//JWT
//encrypt: USER ID + SECRET STRING = JSON WEB TOKEN
//decrypt: JSON WEB TOKEN + SECRET STRING = USER ID

function tokenForUser(user) {
  const time = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: time }, config.secret);
}

exports.signin = (req, res, next) => {
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  console.log("post received: %s %s", email, password);

  if (!email || !password) {
    return res.status(422).send({ error: 'You must provide email and password'});
  }

  User.findOne({ email: email }, function(err, data) {
    if (err) { return next(err); }

    if (data) {
      return res.status(422).send({ error: 'Email in use' });
    }

    const user = new User({
      email: email,
      password: password
    });

    user.save(function(err) {
      if (err) { return next(err); }
      res.json({ token: tokenForUser(user) });
    });
  });
}
