const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const normalize = require("normalize-url");


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
        res.json({ msg: "Success" });
      } else {
        return res.status(400).json({ password: "Password Incorrect" });
      }
    });
  });
});

module.exports = router;
