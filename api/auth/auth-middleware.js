const { JWT_SECRET } = require("../secrets"); // use this secret!
const usersModel = require('../users/users-model')
const jwt = require('jsonwebtoken')

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
  const token = req.headers.authorization
  if (!token) {
    return res.status(401).json({ "message": "Token required" })
  }
  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return res.status(401).json({ "message": "Token invalid" })
    } else {
      req.decodedToken = decodedToken
      next()
    }
  })
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  if (role_name === req.decodedToken.role_name) {
    next()
  } else {
    res.status(403).json({ "message": "This is not for you" })
  }
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
  if (!req.body.username) {
    res.status(401).json({ "message": "Invalid credentials" })
  } else if (req.body.username === '') {
    res.status(401).json({ "message": "Invalid credentials" })
  } else if (typeof req.body.username !== "string") {
    res.status(401).json({ "message": "Invalid credentials" })
  } else {
    try {
      const [user] = await usersModel.findBy({ username: req.body.username })
      if (!user) {
        res.status(401).json({ "message": "Invalid credentials" })
      } else {
        req.user = user; // this way we already have the the pasword on the 
        //request object when it comes time to compare it
        next()
      }
    } catch (err) {
      res.status(500).json({ "message": "An error happened in the DB" })
    }
  }
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
  if (!req.body.role_name || !req.body.role_name.trim()) {
    req.body.role_name = 'student'
    next()
  } else if (req.body.role_name.trim() === 'admin') {
    res.status(422).json({ "message": "Role name can not be admin" })
  } else if (req.body.role_name.trim().length > 32) {
    res.status(422).json({ message: "Role name can not be longer than 32 chars" })
  } else {
    req.body.role_name = req.body.role_name.trim()
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
