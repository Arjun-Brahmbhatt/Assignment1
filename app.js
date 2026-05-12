require("dotenv").config();

const PORT = process.env.PORT || 3000;
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const Joi = require("joi");

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;

const app = express();

app.set("view engine", "ejs");

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

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user.user_type !== "admin") {
    return res.status(403).render("error", {
      message: "You are not authorized to view this page.",
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.render("index", {
    user: req.session.user,
  });
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().required(),
    password: Joi.string().required(),
  });

  const validation = schema.validate(req.body);

  if (validation.error) {
    return res.status(400).render("error", {
      message: "Please fill in all fields.",
    });
  }

  const hashedPassword = await bcrypt.hash(req.body.password, 10);

  await db.collection("users").insertOne({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
    user_type: "user",
  });

  req.session.user = {
    name: req.body.name,
    user_type: "user",
  };

  res.redirect("/members");
});

app.get("/members", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  const images = ["Luffy_myGoat.jpg", "Luffy_myGoat2.jpg", "Yukti_Cat.jpg"];

  res.render("members", {
    user: req.session.user,
    images: images,
  });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().required(),
    password: Joi.string().required(),
  });

  const validation = schema.validate(req.body);

  if (validation.error) {
    return res.status(400).render("error", {
      message: "Please provide email and password.",
    });
  }

  const user = await db.collection("users").findOne({
    email: req.body.email,
  });

  if (!user) {
    return res.status(400).render("error", {
      message: "User and password not found.",
    });
  }

  const passwordMatch = await bcrypt.compare(req.body.password, user.password);

  if (!passwordMatch) {
    return res.status(400).render("error", {
      message: "Invalid password.",
    });
  }

  req.session.user = {
    name: user.name,
    user_type: user.user_type,
  };

  res.redirect("/members");
});

app.get("/admin", requireLogin, requireAdmin, async (req, res) => {
  const users = await db.collection("users").find().toArray();

  res.render("admin", {
    users: users,
  });
});

app.get("/promote", requireLogin, requireAdmin, async (req, res) => {
  await db
    .collection("users")
    .updateOne({ email: req.query.email }, { $set: { user_type: "admin" } });

  res.redirect("/admin");
});

app.get("/demote", requireLogin, requireAdmin, async (req, res) => {
  await db
    .collection("users")
    .updateOne({ email: req.query.email }, { $set: { user_type: "user" } });

  res.redirect("/admin");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.use((req, res) => {
  res.status(404).render("404");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
