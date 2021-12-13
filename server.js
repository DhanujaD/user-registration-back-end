const express = require("express");
const Joi = require("joi");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors());

const PORT = 4000;
const SECRET = "MySecretKey";

let users = [];

app.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    if (!username) {
        res.status(400).send("Username is required");
    } else if (!password) {
        res.status(400).send("Password is required");
    }
    const user = getUserByUsername(username);

    if (!user) {
        res.status(400).send("Incorrect username");
    } else if (user.password !== password) {
        res.status(400).send("Incorrect password");
    }

    jwt.sign({ user }, SECRET, { expiresIn: "7200s" }, (error, token) => {
        res.status(200).json({ token, user });
    });
});

function verifyToken(req, res, next) {
    const bearerHeader = req.headers["authorization"];
    if (typeof bearerHeader === "undefined") {
        res.status(403).send("Unauthorized");
    } else {
        const token = bearerHeader.split(" ")[1];
        jwt.verify(token, SECRET, (error, authData) => {
            if (error) {
                res.status(403).send("Unauthorized");
            } else {
                const user = getUserByUsername(authData.user.username);
                if (user) {
                    req.authData = authData;
                    next();
                } else {
                    res.status(403).send("Unauthorized");
                }
            }
        });
    }
}

function authorizeUser(req, res, next) {
    const authUser = req.authData.user;
    if (authUser.role === "Admin" || authUser.id === parseInt(req.params.id)) {
        next();
    } else {
        res.status(403).send("Access Denied");
    }
}

app.get("/user", verifyToken, authorizeUser, (req, res) => {
    res.status(200).send(users);
});

app.get("/user/:id", verifyToken, authorizeUser, (req, res) => {
    const user = getUser(req.params.id);
    if (!user) {
        res.status(404).send("User not found");
    } else {
        res.status(200).send(user);
    }
});

app.post("/user", (req, res) => {
    let { error } = validateUser(req.body);

    if (error) {
        let errors = error.details.map((error) => error.message);
        res.status(400).send(errors.join(", "));
    } else {
        const usernameAlreadyExists =
            typeof getUserByUsername(req.body.username) !== "undefined";
        if (usernameAlreadyExists) {
            res.status(400).send("Username already exists");
        } else {
            const user = {
                id: users.length + 1,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                email: req.body.email,
                username: req.body.username,
                password: req.body.password,
                role: users.length === 0 ? "Admin" : "User",
            };
            users.push(user);
            res.status(201).send(user);
        }
    }
});

app.put("/user/:id", verifyToken, authorizeUser, (req, res) => {
    let user = getUser(req.params.id);
    if (!user) {
        res.status(404).send("User not found");
    }

    let { error } = validateUser(req.body);
    if (error) {
        let errors = error.details.map((error) => error.message);
        res.status(400).send(errors.join(", "));
    } else {
        user.firstName = req.body.firstName;
        user.lastName = req.body.lastName;
        user.email = req.body.email;
        user.password = req.body.password;
        res.status(200).send(user);
    }
});

app.delete("/user/:id", verifyToken, authorizeUser, (req, res) => {
    let user = getUser(req.params.id);
    if (!user) {
        res.status(404).send("User not found");
    }

    const index = users.indexOf(user);
    users.splice(index, 1);
    res.send(user);
});

function getUser(id) {
    if (id) {
        return users.find((u) => u.id === parseInt(id));
    }
}

function getUserByUsername(username) {
    return users.find((u) => u.username === username);
}

function validateUser(user) {
    const userSchema = Joi.object({
        id: Joi.number(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().email().required(),
        username: Joi.string().required(),
        password: Joi.string().required(),
    });

    return userSchema.validate(user);
}

app.listen(PORT, () => console.log(`Listening to port ${PORT}`));
