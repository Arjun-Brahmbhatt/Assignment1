require("dotenv").config();

const PORT = process.env.PORT || 3000;
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const Joi = require("joi");

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
    }),
    cookie: {
      maxAge: 1000 * 60 * 60,
    },
    resave: false,
    saveUninitialized: false,
  }),
);

const client = new MongoClient(process.env.MONGODB_URI);
let db;

async function connectDB() {
  await client.connect();
  db = client.db();
  console.log("Connected to MongoDB");
}

connectDB();

app.get("/", (req, res) => {
  if (!req.session.user) {
    res.send(`
            <h1>Home</h1>
            <a href="/signup">Signup</a>
            <br>
            <a href="/login">Login</a>
        `);
  } else {
    res.send(`
            <h1>Hello ${req.session.user.name}</h1>
            <a href="/members">Members</a>
            <br>
            <a href="/logout">Logout</a>
        `);
  }
});

app.get("/signup", (req, res) => {
  res.send(`
        <h1>Signup</h1>

        <form method="POST" action="/signup">
            <input name="name" placeholder="Name">
            <br>
            <input name="email" placeholder="Email">
            <br>
            <input name="password" placeholder="Password">
            <br>
            <button>Signup</button>
        </form>
    `);
});

app.post("/signup", async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().required(),
    password: Joi.string().required(),
  });

  const validation = schema.validate(req.body);

  if (validation.error) {
    return res.send(`
            <p>Please fill in all fields.</p>
            <a href="/signup">Try again</a>
        `);
  }

  const hashedPassword = await bcrypt.hash(req.body.password, 10);

  await db.collection("users").insertOne({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  });

  req.session.user = {
    name: req.body.name,
  };

  res.redirect("/members");
});

app.get('/members', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    const images = [
        "Luffy_myGoat.jpg",
        "Luffy_myGoat2.jpg",
        "Yukti_Cat.jpg"
    ];

    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Hello ${req.session.user.name}</h1>
        <img src="/${randomImage}" width="300">
        <br>
        <a href="/logout">Logout</a>
    `);
});

app.get("/login", (req, res) => {
  res.send(`
        <h1>Login</h1>

        <form method="POST" action="/login">
            <input name="email" placeholder="Email">
            <br>
            <input name="password" placeholder="Password">
            <br>
            <button>Login</button>
        </form>
    `);
});

app.post("/login", async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().required(),
    password: Joi.string().required(),
  });

  const validation = schema.validate(req.body);

  if (validation.error) {
    return res.send(`
            <p>Please provide email and password.</p>
            <a href="/login">Try again</a>
        `);
  }

  const user = await db.collection("users").findOne({
    email: req.body.email,
  });

  if (!user) {
    return res.send(`
            <p>User and password not found.</p>
            <a href="/login">Try again</a>
        `);
  }

  const passwordMatch = await bcrypt.compare(req.body.password, user.password);

  if (!passwordMatch) {
    return res.send(`
            <p>Invalid password.</p>
            <a href="/login">Try again</a>
        `);
  }

  req.session.user = {
    name: user.name,
  };

  res.redirect("/members");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.use((req, res) => {
    res.status(404).send(`
        <h1>404 - Page Not Found</h1>
        <a href="/">Go Home</a>
    `);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
