require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const port = process.env.PORT || 3000;

// 🔒 รหัสลับของคุณ (ตรงกับ Agent)
const AGENT_SECRET_KEY = "BCGE2643AMySuperSecretKey2025";

// ปลดล็อคให้รับรูปภาพขนาดใหญ่ได้ (50MB)
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());
app.use(express.static('public'));

// เชื่อมต่อ MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ DB Error:', err));

// โครงสร้างข้อมูล (Schema)
const deviceSchema = new mongoose.Schema({
    hostname: { type: String, required: true, unique: true },
    friendlyName: String,
    group: String,
    location: String,
    ip: String,
    public_ip: String,
    mac_address: String,
    location_city: String,
    isp: String,
    lat: Number,
    lon: Number,
    os: String,
    
    // ✅ เพิ่ม 2 ฟิลด์นี้
    cpu_temp: Number,  // เก็บอุณหภูมิ (องศา C)
    ram_type: String,  // เก็บชนิด RAM (DDR4)
    
    cpu: String,       
    ram: String,       
    cpu_model: String, 
    ram_total: String, 
    disk_info: String,
    last_update: String,
    serial_number: String,
    gpu: String,
    storage_model: String,
    last_seen: { type: Date, default: Date.now },
    pendingCommand: String,
    screenshot: String,
    isAlerted: { type: Boolean, default: false }
});

const Device = mongoose.model('Device', deviceSchema);

// Middleware ตรวจสอบ Login
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

// --- API ROUTES ---

// 1. Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === "admin" && password === "password123") {
        const token = jwt.sign({ username }, process.env.SECRET_KEY, { expiresIn: '12h' });
        res.json({ token });
    } else {
        res.status(401).send('Login Failed');
    }
});

// 2. รับรายงานจาก Agent (เช็ครหัสลับแล้ว)
app.post('/api/report', async (req, res) => {
    // 🔒 ตรวจรหัสลับจาก Agent
    const clientKey = req.headers['x-agent-secret'];
    if (clientKey !== AGENT_SECRET_KEY) {
        console.log(`🚫 Blocked unauthorized access from: ${req.ip}`);
        return res.status(403).json({ error: "Unauthorized" });
    }

    const data = req.body;
    try {
        const device = await Device.findOneAndUpdate(
            { hostname: data.hostname },
            { ...data, last_seen: new Date(), isAlerted: false },
            { upsert: true, new: true }
        );

        let responsePayload = { message: 'received' };
        if (device.pendingCommand) {
            responsePayload.command = device.pendingCommand;
            if(device.pendingCommand !== 'screenshot') {
                await Device.updateOne({ hostname: data.hostname }, { $unset: { pendingCommand: "" } });
            }
        }
        res.json(responsePayload);
    } catch (error) {
        console.error(error);
        res.status(500).send('Database Error');
    }
});

// 3. รับรูป Screenshot
app.post('/api/upload-screen', async (req, res) => {
    const { hostname, image } = req.body;
    try {
        await Device.updateOne(
            { hostname }, 
            { screenshot: image, $unset: { pendingCommand: "" } }
        );
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).send("Upload failed");
    }
});

// 4. ดึงข้อมูลแสดงหน้าเว็บ
app.get('/api/devices', authenticateJWT, async (req, res) => {
    try {
        const devices = await Device.find();
        const now = new Date();
        const deviceList = devices.map(d => {
            const dev = d.toObject();
            const diff = (now - new Date(dev.last_seen)) / 1000;
            dev.status = diff > 60 ? 'offline' : 'online';
            return dev;
        });
        res.json(deviceList);
    } catch (error) {
        res.status(500).send('Error');
    }
});

// 5. อัปเดตชื่อ/กลุ่ม
app.post('/api/devices/update', authenticateJWT, async (req, res) => {
    const { hostname, friendlyName, group, location } = req.body;
    await Device.updateOne({ hostname }, { friendlyName, group, location });
    res.json({ success: true });
});

// 6. สั่ง Command
app.post('/api/devices/command', authenticateJWT, async (req, res) => {
    const { hostname, command } = req.body;
    await Device.updateOne({ hostname }, { pendingCommand: command });
    res.json({ success: true });
});

// 7. ลบเครื่อง
app.delete('/api/devices/:hostname', authenticateJWT, async (req, res) => {
    const { hostname } = req.params;
    try {
        await Device.deleteOne({ hostname });
        res.json({ success: true });
    } catch (error) {
        res.status(500).send('Error');
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});