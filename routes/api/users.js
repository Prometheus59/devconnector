const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const normalize = require("normalize-url");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");
const passport = require('passport');

// Load user model
const User = require("../../models/User");

// @router  GET api/users/test
// @desc    Tests users route
// @access  Public
router.get("/test", (req, res) => res.json({ msg: "Users Works" }));

// @router  GET api/users/register
// @desc    Register User
// @access  Public
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    let user = await User.findOne({ email });

    if (user) {
      return res.status(400).json({ email: "Email already exists" });
    }

    // Create new user
    const avatar = normalize(
      gravatar.url(email, {
        s: "200", // Size
        r: "pg", // rating
        d: "mm", // Default
      }),
      { forceHttps: true }
    );

    user = new User({
      // Sets name = req.body.name
      name,
      email,
      avatar,
      password,
    });

    // Encrypt Password

    const salt = await bcrypt.genSalt(10);

    user.password = await bcrypt.hash(password, salt);

    await user
      .save()
      .then((user) => res.json(user))
      .catch((err) => console.log(err));
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// @router  GET api/users/register
// @desc    Register User
// @access  Public
router.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  User.findOne({ email }).then((user) => {
    if (!user) {
      return res.status(404).json({ email: "User not found" });
    }

    // Check password
    bcrypt.compare(password, user.password).then((isMatch) => {
      if (isMatch) {
        // User Matched
        const payload = { id: user.id, name: user.name, avatar: user.avatar }; // create jwt payload
        // Sign token
        jwt.sign(
          payload,
          keys.secretOrKey,
          { expiresIn: 3600 },
          (err, token) => {
            res.json({
              success: true,
              token: "Bearer " + token,
            });
          }
        );
      } else {
        return res.status(400).json({ password: "Password Incorrect" });
      }
    });
  });
});

// @router  GET api/users/current
// @desc    Return current user
// @access  Private
router.get('/current', passport.authenticate('jwt', {session: false}), (req, res) => {
  res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email
  });
})

module.exports = router;
