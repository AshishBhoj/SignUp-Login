const express = require("express");
const app = express();
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const session = require("express-session");
const flash = require("express-flash");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

// get config variaibles
dotenv.config();

// access config variable
process.env.TOKEN_SECRET;

const PORT = process.env.PORT || 8080;
const initializePassport = require("./passportConfig");
initializePassport(passport);

app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

app.get("/", (req, res) => {
  res.render("index.ejs");
});
app.get("/users/register", checkAuthenticated, (req, res) => {
  res.render("register.ejs");
});
app.get("/users/login", checkAuthenticated, (req, res) => {
  res.render("login.ejs");
});
app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
  console.log(req.isAuthenticated());
  res.render("dashboard", { user: req.user.name });
});
app.get("/users/changePassword", checkNotAuthenticated, (req, res) => {
  res.render("changePassword.ejs");
});
app.get("/users/userList", (req, res) => {
  pool.query(`SELECT * FROM usersdetails`, (err, results) => {
    if (err) throw err;
    console.log(results.rows);
    res.render("userlist", { userList: results.rows });
  });
});
app.get("/users/logout", (req, res) => {
  req.logOut();
  res.render("index.ejs", { message: "Logged out Successfully" });
});

app.post("/users/register", async (req, res) => {
  let { name, email, password, confirm_password } = req.body;
  console.log({ name, email, password, confirm_password });

  let errors = [];

  if (!name || !email || !password || !confirm_password) {
    errors.push({ message: "Please enter all feilds" });
  }
  if (password.length < 6) {
    errors.push({ message: "Password should be atleast 6 characters" });
  }
  if (password != confirm_password) {
    errors.push({ message: "Password do not match" });
  }
  if (errors.length > 0) {
    res.render("register", { errors, name, email, password, confirm_password });
  } else {
    hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    pool.query(
      `SELECT * FROM usersdetails
        WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
        }
        console.log(results.rows);

        if (results.rows.length > 0) {
          return res.render("register", {
            message: "Email already registered",
          });
        } else {
          pool.query(
            `INSERT INTO usersdetails (name, email,password) VALUES ($1, $2, $3)
            RETURNING id, password`,
            [name, email, hashedPassword],
            (err, results) => {
              if (err) throw err;
              console.log(results.rows);
              req.flash("success_msg", "You are now registered. Please log in");
              res.redirect("/users/login");
            }
          );
        }
      }
    );
  }
});

app.post(
  "/users/login",
  passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true,
  })
);
app.post("/users/changePassword", async (req, res) => {
  let { email, password, newPassword } = req.body;
  console.log({ email, password, newPassword });
  hashedNewPassword = await bcrypt.hash(newPassword, 10);
  console.log(hashedNewPassword);
  pool.query(
    `UPDATE usersdetails SET password = $1 WHERE email = $2`,
    [hashedNewPassword, email],
    (err, results) => {
      if (err) throw err;
      console.log(results.rows);
      req.flash("success_msg", "You password has been changed successfully");
      res.redirect("/users/dashboard");
    }
  );
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/users/dashboard");
  }
  next();
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/users/login");
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
