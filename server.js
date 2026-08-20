require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");

const db = require("./database");

const app = express();

const PORT = process.env.PORT || 3000;


// ,mid war

app.use(express.urlencoded({
extended: true
}));

app.use(express.json());

app.use(
session({
secret: process.env.SESSION_SECRET,

resave: false,

saveUninitialized: false,

cookie: {
httpOnly: true,
secure: false,
sameSite: "lax",

// 7 days
maxAge: 1000 * 60 * 60 * 24 * 7
}
})
);


// allow files inside public
app.use(express.static("public"));


// HOME SECT

app.get("/", (req, res) => {

res.sendFile(
__dirname + "/public/index.html"
);

});


// SIGN UP SECT

app.post("/signup", async (req, res) => {

const {
username,
email,
password
} = req.body;


// check existence

if (!username || !email || !password) {

return res.status(400).send(
"Please fill in all fields."
);

}


// req. sect

if (password.length < 8) {

return res.status(400).send(
"Password must be at least 8 characters."
);

}


try {

// check old acc

const existingUser = db.prepare(`
SELECT id
FROM users
WHERE email = ?
OR username = ?
`).get(email, username);


if (existingUser) {

return res.status(400).send(
"Username or email already exists."
);

}


// hash pswd

const passwordHash =
await bcrypt.hash(password, 12);


// make user

const result = db.prepare(`
INSERT INTO users
(
username,
email,
password_hash
)
VALUES (?, ?, ?)
`).run(
username,
email,
passwordHash
);


// make log sess

req.session.userId =
result.lastInsertRowid;


// go dash

res.redirect("/dashboard.html");

}

catch (error) {

console.error(error);

res.status(500).send(
"Something went wrong."
);

}

});


// log in sect

app.post("/login", async (req, res) => {

const {
email,
password
} = req.body;


if (!email || !password) {

return res.status(400).send(
"Email and password are required."
);

}


try {

// find user

const user = db.prepare(`
SELECT *
FROM users
WHERE email = ?
`).get(email);


if (!user) {

return res.status(401).send(
"Invalid email or password."
);

}


// git-only accs no passwords

if (!user.password_hash) {

return res.status(401).send(
"This account uses GitHub login."
);

}


// compare password w hash

const passwordCorrect =
await bcrypt.compare(
password,
user.password_hash
);


if (!passwordCorrect) {

return res.status(401).send(
"Invalid email or password."
);

}


// get session

req.session.userId = user.id;


// dashboard sect

res.redirect("/dashboard.html");

}

catch (error) {

console.error(error);

res.status(500).send(
"Something went wrong."
);

}

});


// get user sect

app.get("/api/me", (req, res) => {

if (!req.session.userId) {

return res.status(401).json({
loggedIn: false
});

}


const user = db.prepare(`
SELECT
id,
username,
email,
created_at
FROM users
WHERE id = ?
`).get(req.session.userId);


if (!user) {

return res.status(401).json({
loggedIn: false
});

}


res.json({
loggedIn: true,
user: user
});

});


// logout sect

app.post("/logout", (req, res) => {

req.session.destroy(() => {

res.clearCookie("connect.sid");

res.redirect("/");

});

});


// start server

app.listen(PORT, () => {

console.log("");
console.log("==============================");
console.log(" Website server is running!");
console.log("==============================");
console.log("");
console.log(
`Open http://localhost:${PORT}`
);
console.log("");

});
