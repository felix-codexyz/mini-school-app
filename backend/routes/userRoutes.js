const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController'); // Change to non-destructuring import

router.post('/register', userController.registerUser);

module.exports = router;