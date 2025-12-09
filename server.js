// server.js (Pro Version)
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const port = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error(err));

// 1. อัปเกรด Schema เพิ่มฟิลด์ใหม่
const deviceSchema = new mongoose.Schema({
    hostname: { type: String, required: true, unique: true },
    friendlyName: String, // ชื่อเรียกง่ายๆ เช่น "เครื่องบัญชี 1"
    group: String,        // แผนก เช่น "HR", "IT"
    location: String,     // ตำแหน่ง เช่น "ชั้น 2 โซน A"
    ip: String,
    os: String,
    cpu: String,
    ram: String,
    windows_update: String,
    last_seen: { type: Date, default: Date.now },
    pendingCommand: String // คำสั่งที่รอส่งให้เครื่องลูก (reboot, shutdown)
});

const Device = mongoose.model('Device', deviceSchema);

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

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

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    // Hardcode user ไว้ก่อน (ของจริงควรเก็บใน DB)
    if (username === "admin" && password === "password123") {
        const token = jwt.sign({ username }, process.env.SECRET_KEY, { expiresIn: '2h' });
        res.json({ token });
    } else {
        res.status(401).send('Login Failed');
    }
});

// 2. Agent Report (อัปเกรดให้ส่งคำสั่งกลับไปหา Agent)
app.post('/api/report', async (req, res) => {
    const data = req.body;
    try {
        // หาเครื่องและอัปเดตสถานะ
        const device = await Device.findOneAndUpdate(
            { hostname: data.hostname },
            { ...data, last_seen: new Date() },
            { upsert: true, new: true }
        );

        // เช็คว่ามีคำสั่งค้างอยู่ไหม?
        let responsePayload = { message: 'received' };
        if (device.pendingCommand) {
            console.log(`Sending command '${device.pendingCommand}' to ${device.hostname}`);
            responsePayload.command = device.pendingCommand;
            
            // ส่งคำสั่งแล้ว ให้ลบคำสั่งทิ้งทันที
            await Device.updateOne({ hostname: data.hostname }, { $unset: { pendingCommand: "" } });
        }

        res.json(responsePayload);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error');
    }
});

app.get('/api/devices', authenticateJWT, async (req, res) => {
    const devices = await Device.find();
    const now = new Date();
    const deviceList = devices.map(d => {
        const dev = d.toObject();
        const diff = (now - new Date(dev.last_seen)) / 1000;
        dev.status = diff > 120 ? 'offline' : 'online';
        return dev;
    });
    res.json(deviceList);
});

// 3. API สำหรับแก้ไขชื่อ/กลุ่ม (Edit Device)
app.post('/api/devices/update', authenticateJWT, async (req, res) => {
    const { hostname, friendlyName, group, location } = req.body;
    await Device.updateOne({ hostname }, { friendlyName, group, location });
    res.json({ success: true });
});

// 4. API สำหรับสั่ง Remote (Queue Command)
app.post('/api/devices/command', authenticateJWT, async (req, res) => {
    const { hostname, command } = req.body; // command: 'reboot' or 'shutdown'
    await Device.updateOne({ hostname }, { pendingCommand: command });
    res.json({ success: true, message: `Command ${command} queued for ${hostname}` });
});

app.listen(port, () => console.log(`Server running on port ${port}`));