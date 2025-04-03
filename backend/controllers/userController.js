const userModel = require('../models/userModel');

const registerUser = async (req, res) => {
  const { name, email, phone, program } = req.body;

  // Check for missing fields
  if (!name || !email || !phone || !program) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  // Validate name (letters, spaces, hyphens)
  const nameRegex = /^[a-zA-Z\s-]+$/;
  if (!nameRegex.test(name)) {
    return res.status(400).json({ error: 'Name must contain only letters, spaces, or hyphens' });
  }

  // Validate email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  // Validate phone (10 digits)
  const phoneRegex = /^\d{10}$/;
  if (!phoneRegex.test(phone)) {
    return res.status(400).json({ error: 'Phone number must be 10 digits' });
  }

  // Validate program (ensure it’s one of the allowed values)
  const validPrograms = ['computer-science', 'engineering', 'business', 'arts', 'medicine'];
  if (!validPrograms.includes(program)) {
    return res.status(400).json({ error: 'Invalid program. Must be one of: computer-science, engineering, business, arts, medicine' });
  }

  try {
    const newUser = await userModel.createUser(name, email, phone, program);
    res.status(201).json(newUser);
  } catch (error) {
    console.error('Registration error:', error.message);
    if (error.message === 'Email already exists') {
      return res.status(409).json({ error: error.message });
    }
    res.status(500).json({ error: error.message });
  }
};

module.exports = { registerUser };