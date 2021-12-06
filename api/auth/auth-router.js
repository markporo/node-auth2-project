const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!

const usersModel = require('../users/users-model')

const bcrypt = require('bcryptjs') //  i gues we aren't using jwt instead?!!
const jwt = require('jsonwebtoken');

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */



});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

  let { username, password } = req.body;
  usersModel.findBy({ username })
    .first()
    .then(user => {
      // bcrypt line - if (user and bcyrpt.compareSync(password, user, password))
      const token = generateToken(user);
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({
          "message": `${user.username} is back!`,
          token,
        })
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    })
});

function generateToken(user) {
  const payload = {
    subject: user.id, // sub property in header of the token; normally user id
    username: user.username,
    role_name: user.role_name,
    //...other data put here --never any sensitive information because
    //this token can be easily translated
  }
  const secret = JWT_SECRET  //'this sectret is how we sign the token only the server knows it';
  const options = {
    expiresIn: '24h', //1d
    // we can use many other options if we want
  }

  return jwt.sign(payload, secret, options)
}

module.exports = router;
