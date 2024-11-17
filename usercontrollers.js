const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const Assignment = require("../models/assignmentModel");

const registerUser = async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ username, password: hashedPassword, role });
    await user.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(400).json({ message: "Error registering user", error });
  }
};

const loginUser = async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ token });
  } catch (error) {
    res.status(400).json({ message: "Error logging in", error });
  }
};

const uploadAssignment = async (req, res) => {
  try {
    const { userId, task, admin } = req.body;

    const assignment = new Assignment({ userId, task, admin });
    await assignment.save();

    res.status(201).json({ message: "Assignment uploaded successfully" });
  } catch (error) {
    res.status(400).json({ message: "Error uploading assignment", error });
  }
};

module.exports = { registerUser, loginUser, uploadAssignment };
