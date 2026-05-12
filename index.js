require('./utils.js');
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const Joi = require("joi");
const mongoSanitizer = require('mongo-sanitizer').default;

const port = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const {database} = include('databaseConnection');
const userCollection = database.db(mongodb_user_database).collection('users');

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));
app.use(express.json());

app.use(mongoSanitizer(
    { replaceWith: '_'}
));

let mongoStore = new MongoStore({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (req.session.user_type != 'admin') {
        res.status(403);
        res.render('errorMessage', {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

// Routes (GET + POST + USE)
app.get('/', (req, res) => {
    const loggeduser = req.session.authenticated || false;
    res.render('index', {loggeduser: loggeduser, name: req.session.name});
});

app.get('/signup', (req, res) => {
    const errorMessage = req.session.errorMessage || null;
    req.session.errorMessage = null; // clear after reading
    res.render('signup');
});

app.post('/signingup', async (req,res) => {
    let name = req.body.name;
    let email = req.body.email;
    let password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().max(20).required(),
        password: Joi.string().max(20).required()
    });
	
	const validationResult = schema.validate({name, email, password});
	if (validationResult.error != null) {
        const message = validationResult.error.details[0].message;
        req.session.errorMessage = message;
        res.render('signup', {errorMessage: errorMessage});
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({name: name, email: email, password: hashedPassword, user_type: 'user'});
	console.log("Inserted user");

    req.session.name = name;
    req.session.email = email;

    loggeduser = true;

    req.session.loggeduser = loggeduser;
    res.redirect('/');
})

app.get('/login', (req, res) => {
    const errorMessage = req.session.errorMessage || null;
    req.session.errorMessage = null;
    res.render('login', {errorMessage: errorMessage});
});

app.post('/loggingin', async (req,res) => {
    let email = req.body.email;
    let password = req.body.password;

    const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
	}

	const result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1, user_type: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		req.session.errorMessage = "User not found";
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.email = email;
		req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		loggeduser = true;
        req.session.loggeduser = loggeduser;

        res.redirect('/');
		return;
	}
	else {
		req.session.errorMessage = "Incorrect password";
		res.redirect("/login");
		return;
	}
});

app.get('/members', sessionValidation, (req, res) => {
    res.render('animals');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({name: 1, email: 1, user_type: 1, _id: 1}).toArray();

    res.render("admin", {users: result});
});

app.get('/admin/promote/:email', sessionValidation, adminAuthorization, async (req, res) => {
    const email = req.params.email;
    await userCollection.updateOne({email: email}, {$set: {user_type: 'admin'}});
    res.redirect('/admin');
});

app.get('/admin/demote/:email', sessionValidation, adminAuthorization, async (req, res) => {
    const email = req.params.email;
    await userCollection.updateOne({email: email}, {$set: {user_type: 'user'}});
    res.redirect('/admin');
});

app.get('/logout', (req, res) => {
    loggeduser = false;
    req.session.destroy();
    res.redirect('/');
});

app.use(express.static('public'));

app.use((req,res) => {
    res.status(404);
    res.render('errorMessage', {error: "Page not found - 404"});
});

// Start Server

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});