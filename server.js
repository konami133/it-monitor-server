// server.js (ฉบับอัปเกรด MongoDB)
require('dotenv').config(); // โหลดค่าจาก .env
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose'); // พระเอกของเรา

const app = express();
const port = process.env.PORT || 3000;

// --- 1. เชื่อมต่อ MongoDB ---
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- 2. สร้าง Schema (โครงสร้างข้อมูลที่จะเก็บ) ---
const deviceSchema = new mongoose.Schema({
    hostname: { type: String, required: true, unique: true }, // ชื่อเครื่องห้ามซ้ำ
    ip: String,
    os: String,
    cpu: String,
    ram: String,
    windows_update: String,
    last_seen: { type: Date, default: Date.now }
});

// สร้าง Model
const Device = mongoose.model('Device', deviceSchema);

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// --- Middleware Login (เหมือนเดิม) ---
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// --- API Login (เหมือนเดิม) ---
// ใน Production ควรเก็บ User ใน DB เช่นกัน แต่เพื่อความง่ายขอ Hardcode ไว้ก่อน
const users = { "admin": "password123" }; 
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (users[username] === password) {
        const token = jwt.sign({ username }, process.env.SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).send('Invalid Credentials');
    }
});

// --- API: รับข้อมูลจาก Agent (อัปเกรดใหม่) ---
app.post('/api/report', async (req, res) => {
    const data = req.body;
    
    try {
        // ค้นหาเครื่องเดิมจาก Hostname ถ้าเจอให้ Update ถ้าไม่เจอให้ Create ใหม่ (Upsert)
        await Device.findOneAndUpdate(
            { hostname: data.hostname }, // เงื่อนไขการหา
            { ...data, last_seen: new Date() }, // ข้อมูลที่จะอัปเดต
            { upsert: true, new: true } // Option: ถ้าไม่มีให้สร้างใหม่
        );
        
        console.log(`Updated status for: ${data.hostname}`);
        res.send('Data saved to MongoDB');
    } catch (error) {
        console.error(error);
        res.status(500).send('Database Error');
    }
});

// --- API: ดึงข้อมูล (อัปเกรดใหม่) ---
app.get('/api/devices', authenticateJWT, async (req, res) => {
    try {
        const devices = await Device.find(); // ดึงข้อมูลทั้งหมดจาก DB
        const now = new Date();

        // แปลงข้อมูลเพื่อคำนวณสถานะ Online/Offline
        const deviceList = devices.map(d => {
            // แปลง Mongoose Document เป็น Object ธรรมดา
            const device = d.toObject(); 
            
            const diff = (now - new Date(device.last_seen)) / 1000;
            device.status = diff > 120 ? 'offline' : 'online'; // 120 วินาที
            return device;
        });

        res.json(deviceList);
    } catch (error) {
        res.status(500).send('Error fetching devices');
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});