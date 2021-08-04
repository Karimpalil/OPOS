import SYSTEMCONFIG from './systemconfig.js';

const JWT = require('jsonwebtoken');

const withCookieAuth = function (req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    res.status(401).send({error: 'Unauthorized: No token provided'});
  } else {
    JWT.verify(token, SYSTEMCONFIG.PWDHASH, function (err, decoded) {
      if (err) {
        res.status(401).send({error: 'Unauthorized: Invalid token'});
      } else {
        req.email = decoded.email;
        next();
      }
    });
  }
}
module.exports = withCookieAuth;