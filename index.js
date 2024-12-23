const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors')
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');
const schoolRoutes = require('./routes/schools');

const app = express();
const PORT = 3002;
const DB_URI = 'mongodb+srv://senil_viradiya:Senil123@senil.oy4qh.mongodb.net/?retryWrites=true&w=majority&appName=Senil/multiTenantDB';

mongoose.connect(DB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

app.use(bodyParser.json());
app.use(cors());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/schools', schoolRoutes);

//for check status
app.get('/api/status',(req,res)=>{
    res.json({status: "API is up and running"})
})

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
