const express = require("express");
const passport = require("passport");
const router = express.Router();
const User = require("../models/User");
const nodemailer = require("nodemailer");

// Bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

router.get("/login", (req, res, next) => {
  res.render("auth/login", { message: req.flash("error") });
});

router.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/auth/login",
    failureFlash: true,
    passReqToCallback: true
  })
);

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const email = req.body.email;
  const confirmationCode = Math.floor(Math.random() * 1000000000);
  const password = req.body.password;
  if (username === "" || password === "" || email === "") {
    res.render("auth/signup", { message: "Indicate username and password" });
    return;
  }

  User.findOne({ username }, "username", (err, user) => {
    if (user !== null) {
      res.render("auth/signup", { message: "The username already exists" });
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);

    const newUser = new User({
      username,
      password: hashPass,
      email: email,
      confirmationCode: confirmationCode
    });

    newUser
      .save()
      .then(() => {
        res.redirect("/");
      })
      .catch(err => {
        res.render("auth/signup", { message: "Something went wrong" });
      });

    let transporter = nodemailer.createTransport({
      service: "GMAIL",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASS
      }
    });
    transporter
      .sendMail({
        from: '"Ironhack Project 👻" <myawesome@project.com>',
        to: email,
        subject: "Please confirm your email",
        text:
          "Please click here to verify your email address: http://localhost:3000/auth/confirm/THE-CONFIRMATION-CODE-OF-THE-USER",
        html: `<b>Please click <a href="http://localhost:3000/auth/confirm/THE-CONFIRMATION-CODE-OF-THE-USER">here</a> to verify your email address.</b>`
      })
      .then(info => res.render("/"))
      .catch(error => console.log(error));
  });
});

router.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

module.exports = router;
