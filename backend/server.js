require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}));

const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://vivekchaudhari3718:vivekchaudhari3718@cluster1.9qlun5j.mongodb.net/";

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    dbName: 'Signup'
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('MongoDB connection error:', err);
});



const authRoutes = require('./routes/auth');
const uploadRoutes = require('./routes/upload');
const projectRoutes = require('./routes/project');
app.use('/api/auth', authRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/project', projectRoutes);

app.get('/', (req, res) => {
    res.send('Backend is running');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
