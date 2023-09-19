const jwt = require('jsonwebtoken');
const { AuthenticationError } = require('apollo-server-express');

// Set token secret and expiration date
const secret = 'mysecretsshhhhh';
const expiration = '2h';

module.exports = {
  // Middleware for authentication in GraphQL context
  authMiddleware: function ({ req }) {
    // Allows token to be sent via headers
    const token = req.headers.authorization || '';

    if (!token) {
      return;
    }

    try {
      // Verify token and get user data out of it
      const { data } = jwt.verify(token, secret, { maxAge: expiration });
      return { user: data };
    } catch (error) {
      throw new AuthenticationError('Invalid token');
    }
  },
  signToken: function ({ username, email, _id }) {
    const payload = { username, email, _id };
    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
  },
};
