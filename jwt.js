const { Router } = require('express');
const jwt = require('jsonwebtoken');

Router.post('/login', (req, res) => {
    let { username, password } = req.body;

    Users.findBy({ username })
        .first()
        .then(user => {
            if (user && bcrypt.compareSync(password, user.password)) {
                const token = generateToken(user);

                res.status(200).json({
                    message: `Welcome ${user.username}!, here is your token...`, token
                })
            } else {
                res.status(401).json({ message: 'Invalid Credentials!' })
            }
        })
        .catch(error => {
            res.satus(500).json(error);
        })
})

function generateToken(user) {
    const payload = {
        subject: user.id,
        username: user.username
    }
    const options = {
        expiresIn: '30d'
    }

    return jwt.sign(payload, secrets.jwtSecret, options);

}