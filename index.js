const express = require('express');
const cors = require('cors');
require('dotenv').config();
const connectDB = require('./config/db');

const adminRoutes = require('./routes/admin');
const userRoutes = require('./routes/user');

const app = express();


app.use(express.json());
app.use(cors());


connectDB();
// Health check endpoint
app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});
app.use('/admin', adminRoutes);
app.use('/user', userRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));