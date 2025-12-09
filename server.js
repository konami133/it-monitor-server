// server.js (Final Version)
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const port = process.env.PORT || 3000;

// เพิ่ม limit เพื่อให้รับรูปภาพขนาดใหญ่ได้ (สำคัญมากสำหรับ Screenshot)
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());
app.use(express.static('public'));

mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error(err));

const deviceSchema = new mongoose.Schema({
    hostname: { type: String, required: true, unique: true },
    friendlyName: String,
    group: String,
    location: String,     
    ip: String,
    public_ip: String,    // เพิ่ม: IP จริง
    location_city: String,// เพิ่ม: เมือง
    isp: String,          // เพิ่ม: ผู้ให้บริการเน็ต
    lat: Number,          // เพิ่ม: ละติจูด
    lon: Number,          // เพิ่ม: ลองจิจูด
    os: String,
    cpu: String,
    ram: String,
    last_seen: { type: Date, default: Date.now },
    pendingCommand: String, // คำสั่งที่รอส่ง
    screenshot: String      // เก็บรูปภาพ Base64
});

const Device = mongoose.model('Device', deviceSchema);

// Middleware Login
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
    if (username === "admin" && password === "password123") {
        const token = jwt.sign({ username }, process.env.SECRET_KEY, { expiresIn: '12h' });
        res.json({ token });
    } else {
        res.status(401).send('Login Failed');
    }
});

// API: รับรายงานสถานะจาก Agent
app.post('/api/report', async (req, res) => {
    const data = req.body;
    try {
        const device = await Device.findOneAndUpdate(
            { hostname: data.hostname },
            { ...data, last_seen: new Date() },
            { upsert: true, new: true }
        );

        // เช็คว่ามีคำสั่งค้างไหม?
        let responsePayload = { message: 'received' };
        if (device.pendingCommand) {
            console.log(`Sending command '${device.pendingCommand}' to ${device.hostname}`);
            responsePayload.command = device.pendingCommand;
            // ถ้าเป็นคำสั่ง screenshot อย่าเพิ่งลบ รอรับรูปก่อน
            // แต่ถ้าเป็น reboot/shutdown ลบได้เลย
            if(device.pendingCommand !== 'screenshot') {
                await Device.updateOne({ hostname: data.hostname }, { $unset: { pendingCommand: "" } });
            }
        }
        res.json(responsePayload);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error');
    }
});

// API: รับรูป Screenshot (สำคัญ!)
app.post('/api/upload-screen', async (req, res) => {
    const { hostname, image } = req.body;
    console.log(`📸 Received screenshot from ${hostname}`);
    try {
        await Device.updateOne(
            { hostname }, 
            { 
                screenshot: image, 
                $unset: { pendingCommand: "" } // ได้รูปแล้ว ค่อยลบคำสั่งทิ้ง
            }
        );
        res.json({ success: true });
    } catch (error) {
        console.error("Upload error:", error);
        res.status(500).send("Upload failed");
    }
});

app.get('/api/devices', authenticateJWT, async (req, res) => {
    try {
        const devices = await Device.find();
        const now = new Date();
        const deviceList = devices.map(d => {
            const dev = d.toObject();
            const diff = (now - new Date(dev.last_seen)) / 1000;
            dev.status = diff > 120 ? 'offline' : 'online';
            return dev;
        });
        res.json(deviceList);
    } catch (error) {
        res.status(500).send('Error');
    }
});

app.post('/api/devices/update', authenticateJWT, async (req, res) => {
    const { hostname, friendlyName, group, location } = req.body;
    await Device.updateOne({ hostname }, { friendlyName, group, location });
    res.json({ success: true });
});

app.post('/api/devices/command', authenticateJWT, async (req, res) => {
    const { hostname, command } = req.body;
    await Device.updateOne({ hostname }, { pendingCommand: command });
    res.json({ success: true });
});

app.listen(port, () => console.log(`Server running on port ${port}`));