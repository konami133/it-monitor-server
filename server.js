require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const app = express();
const port = process.env.PORT || 10000;

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());
app.use(express.static('public'));

// ==========================================
// 1️⃣ USER SCHEMA (ต้องอยู่บนสุด! ห้ามย้าย)
// ==========================================
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'staff' },
    permissions: [String] 
});
const User = mongoose.model('User', userSchema);

// ==========================================
// 2️⃣ DEVICE SCHEMA (สเปคครบ + BSSID + Manual Geo)
// ==========================================
const deviceSchema = new mongoose.Schema({
    hostname: { type: String, required: true, unique: true },
    friendlyName: String,
    group: String,
    location: String,
    ip: String,
    public_ip: String,
    mac_address: String,
    connection_type: String, 
    
    // Hardware Specs
    brand: String, 
    model: String,
    os: String,            
    cpu_model: String,     
    gpu: String,           
    ram_total: String,     
    ram_type: String,      
    storage_model: String, 
    serial_number: String, 
    
    // Network & Location
    wifi_ssid: String, 
    wifi_bssid: String,
    isp: String, 
    location_city: String,
    lat: Number, 
    lon: Number,
    manual_geo: { type: Boolean, default: false },

    // Status
    cpu_temp: Number, cpu: String, ram: String, disk_info: String,
    last_update: String, last_seen: { type: Date, default: Date.now },
    pendingCommand: String, screenshot: String, isAlerted: { type: Boolean, default: false }
});
const Device = mongoose.model('Device', deviceSchema);

// ==========================================
// 3️⃣ สร้าง ADMIN (ถ้ายังไม่มี)
// ==========================================
async function initAdmin() {
    try {
        const count = await User.countDocuments();
        if (count === 0) {
            console.log("⚠️ No users found. Creating default admin...");
            const hashedPassword = await bcrypt.hash("password123", 10);
            await User.create({
                username: "admin",
                password: hashedPassword,
                role: "admin",
                permissions: ["manage_users", "delete_device", "control_device", "edit_device"]
            });
            console.log("👑 Created default Admin: admin / password123");
        }
    } catch (error) {
        console.error("❌ Init Admin Error:", error);
    }
}

// ==========================================
// 4️⃣ เชื่อมต่อ DB & เริ่ม Server
// ==========================================
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('✅ MongoDB Connected');
        initAdmin();
    })
    .catch(err => console.error('❌ DB Error:', err));

// ==========================================
// 5️⃣ API ROUTES (Login & Data)
// ==========================================

const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        jwt.verify(authHeader.split(' ')[1], process.env.SECRET_KEY, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    } else res.sendStatus(401);
};

const checkPerm = (perm) => {
    return (req, res, next) => {
        if (req.user.role === 'admin' || (req.user.permissions && req.user.permissions.includes(perm))) next();
        else res.status(403).json({ error: "Denied" });
    };
};

// 👉 Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ username: user.username, role: user.role, permissions: user.permissions, _id: user._id }, process.env.SECRET_KEY, { expiresIn: '12h' });
            res.json({ token, role: user.role, permissions: user.permissions });
        } else {
            res.status(401).send('Invalid Credentials');
        }
    } catch (e) { res.status(500).send('Error'); }
});

// 👉 Device Management
app.get('/api/devices', authenticateJWT, async (req, res) => {
    try {
        const devices = await Device.find();
        const now = new Date();
        res.json(devices.map(d => ({ ...d.toObject(), status: (now - new Date(d.last_seen)) / 1000 > 60 ? 'offline' : 'online' })));
    } catch (e) { res.status(500).send('Error'); }
});

app.post('/api/devices/update', authenticateJWT, checkPerm('edit_device'), async (req, res) => {
    const { hostname, friendlyName, group, location, lat, lon } = req.body;
    let updateFields = { friendlyName, group, location };
    if (lat && lon) { updateFields.lat = parseFloat(lat); updateFields.lon = parseFloat(lon); updateFields.manual_geo = true; }
    await Device.updateOne({ hostname }, updateFields);
    res.json({ success: true });
});

app.post('/api/devices/command', authenticateJWT, checkPerm('control_device'), async (req, res) => {
    await Device.updateOne({ hostname: req.body.hostname }, { pendingCommand: req.body.command });
    res.json({ success: true });
});

app.delete('/api/devices/:hostname', authenticateJWT, checkPerm('delete_device'), async (req, res) => {
    await Device.deleteOne({ hostname: req.params.hostname });
    res.json({ success: true });
});

// 👉 Agent Report
app.post('/api/report', async (req, res) => {
    if (req.headers['x-agent-secret'] !== "BCGE2643AMySuperSecretKey2025") return res.status(403).json({ error: "Unauthorized" });
    const data = req.body;
    try {
        const existing = await Device.findOne({ hostname: data.hostname });
        let finalData = { ...data, last_seen: new Date(), isAlerted: false };
        if (existing && existing.manual_geo) { delete finalData.lat; delete finalData.lon; delete finalData.location_city; }
        
        const device = await Device.findOneAndUpdate({ hostname: data.hostname }, finalData, { upsert: true, new: true });
        
        let resp = { message: 'ok' };
        if (device.pendingCommand) {
            resp.command = device.pendingCommand;
            if (device.pendingCommand !== 'screenshot') await Device.updateOne({ hostname: data.hostname }, { $unset: { pendingCommand: "" } });
        }
        res.json(resp);
    } catch (e) { res.status(500).send('Error'); }
});

app.post('/api/upload-screen', async (req, res) => {
    await Device.updateOne({ hostname: req.body.hostname }, { screenshot: req.body.image, $unset: { pendingCommand: "" } });
    res.json({ success: true });
});

// 👉 User Management
app.get('/api/users', authenticateJWT, checkPerm('manage_users'), async (req, res) => { res.json(await User.find({}, '-password')); });
app.post('/api/users', authenticateJWT, checkPerm('manage_users'), async (req, res) => {
    const { username, password, role, permissions } = req.body;
    await User.create({ username, password: await bcrypt.hash(password, 10), role, permissions });
    res.json({ success: true });
});
app.put('/api/users/:id', authenticateJWT, checkPerm('manage_users'), async (req, res) => {
    const { password, role, permissions } = req.body;
    const up = { role, permissions }; if(password) up.password = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(req.params.id, up);
    res.json({ success: true });
});
app.delete('/api/users/:id', authenticateJWT, checkPerm('manage_users'), async (req, res) => { await User.findByIdAndDelete(req.params.id); res.json({ success: true }); });

app.listen(port, () => { console.log(`🚀 Server running on port ${port}`); });