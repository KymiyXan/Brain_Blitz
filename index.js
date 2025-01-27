const express = require('express');
//const mongoose = require('mongoose');
const bodyParser = require('body-parser');
require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');

const app = express();
const userRoutes = require('./routes/user');
const quizRoutes = require('./routes/quiz');
const categoryRoutes = require('./routes/category');

app.use(bodyParser.json());

app.use('/', userRoutes);
app.use('/api/quiz', quizRoutes);
app.use('/api/category', categoryRoutes);

const credentials = `${process.env.CERT_PEM}`

const client = new MongoClient('mongodb+srv://kymiyxander.8oaj4.mongodb.net/?authSource=%24external&authMechanism=MONGODB-X509&retryWrites=true&w=majority&appName=KymiyXander', {
  tlsCertificateKeyFile: credentials,
  serverApi: ServerApiVersion.v1
});

async function run() {
  try {
    await client.connect();
    const database = client.db("testDB");
    const collection = database.collection("testCol");
    const docCount = await collection.countDocuments({});
    console.log(docCount);
    // perform actions using client
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
