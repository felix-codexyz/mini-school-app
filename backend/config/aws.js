const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');
const mysql = require('mysql2/promise');

const region = process.env.AWS_REGION || 'eu-west-3';
const secretsManagerClient = new SecretsManagerClient({ region });
const ssmClient = new SSMClient({ region });

const getDbConnection = async () => {
  try {
    console.log('Retrieving database credentials...');
    // Retrieve database password from Secrets Manager
    const secretArn = process.env.DB_SECRET_ARN;
    if (!secretArn || !secretArn.startsWith('arn:aws:secretsmanager:')) {
      throw new Error('Invalid DB_SECRET_ARN: Must be a valid Secrets Manager ARN');
    }
    console.log('Fetching secret from ARN:', secretArn);
    const secretCommand = new GetSecretValueCommand({ SecretId: secretArn });
    const secretResponse = await secretsManagerClient.send(secretCommand);
    const secret = JSON.parse(secretResponse.SecretString);
    const password = secret.password;
    const username = secret.username; // Ensure the secret contains the username

    // Retrieve database host, name, and user from Parameter Store
    console.log('Fetching Parameter Store values...');
    const hostParam = await ssmClient.send(
      new GetParameterCommand({ Name: process.env.PARAM_HOST_PATH, WithDecryption: true })
    );
    const dbNameParam = await ssmClient.send(
      new GetParameterCommand({ Name: process.env.PARAM_DB_NAME_PATH, WithDecryption: true })
    );
    const userParam = await ssmClient.send(
      new GetParameterCommand({ Name: process.env.PARAM_USER_PATH, WithDecryption: true })
    );

    const host = hostParam.Parameter.Value;
    const dbName = dbNameParam.Parameter.Value;
    const user = userParam.Parameter.Value || username; // Fallback to username from secret if not in Parameter Store

    console.log('Database credentials retrieved:', { host, dbName, user });

    // Create a MySQL connection
    const connection = await mysql.createConnection({
      host,
      user,
      password,
      database: dbName,
    });

    console.log('Database connection established');
    return connection;
  } catch (error) {
    console.error('Error establishing database connection:', error);
    throw error;
  }
};

module.exports = { getDbConnection };