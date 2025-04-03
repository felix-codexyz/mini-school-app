const { v4: uuidv4 } = require('uuid');
const { getDbConnection } = require('../config/aws');

let dbConnection = null;

const initializeDB = async () => {
  try {
    console.log('Initializing database...');
    dbConnection = await getDbConnection();
    await dbConnection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(15),
        program VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Database initialized');
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  }
};

const createUser = async (name, email, phone, program) => {
  try {
    console.log('Creating user with data:', { name, email, phone, program });
    if (!dbConnection) {
      await initializeDB();
    }
    const uniqueId = uuidv4();
    await dbConnection.execute(
      'INSERT INTO users (id, name, email, phone, program) VALUES (?, ?, ?, ?, ?)',
      [uniqueId, name, email, phone, program]
    );
    console.log('User created with ID:', uniqueId);
    return { id: uniqueId, name, email, phone, program };
  } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      throw new Error('Email already exists');
    }
    throw new Error(`Failed to create user: ${error.message}`);
  }
};

module.exports = { createUser, initializeDB };