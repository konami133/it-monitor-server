require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // ✅ เพิ่มตัวเข้ารหัส

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());
app.use(express.static('public'));

mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('✅ MongoDB Connected');
        initAdmin(); // สร้าง Admin อัตโนมัติเมื่อเริ่มระบบ
    })
    .catch(err => console.error('❌ DB Error:', err));

// --- SCHEMAS ---

// 1. User Schema (ระบบสมาชิก)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'staff' }, // 'admin' or 'staff'
    // กำหนดสิทธิ์ละเอียด: manage_users, delete_device, control_device, edit_device
    permissions: [String] 
});
const User = mongoose.model('User', userSchema);

// 2. Device Schema (เหมือนเดิม เพิ่ม mac/ram_type/temp)
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
    cpu_temp: Number,  
    ram_type: String, 
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

// --- INITIALIZATION ---
async function initAdmin() {
    const count = await User.countDocuments();
    if (count === 0) {
        const hashedPassword = await bcrypt.hash("password123", 10);
        await User.create({
            username: "admin",
            password: hashedPassword,
            role: "admin",
            permissions: ["manage_users", "delete_device", "control_device", "edit_device"]
        });
        console.log("👑 Created default Admin: admin / password123");
    }
}

// --- MIDDLEWARE ---
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

// ตรวจสอบ Permission
const checkPermission = (requiredPerm) => {
    return (req, res, next) => {
        // Admin ทำได้ทุกอย่างเสมอ
        if (req.user.role === 'admin') return next();
        
        if (req.user.permissions && req.user.permissions.includes(requiredPerm)) {
            next();
        } else {
            res.status(403).json({ error: "Access Denied: Insufficient Permissions" });
        }
    };
};

// --- API ROUTES ---

// 1. Login (เปลี่ยนเป็นเช็ค DB)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
        // ส่ง Permissions ไปกับ Token ด้วย Frontend จะได้รู้ว่าต้องโชว์ปุ่มไหน
        const token = jwt.sign({ 
            username: user.username, 
            role: user.role,
            permissions: user.permissions 
        }, process.env.SECRET_KEY, { expiresIn: '12h' });
        
        res.json({ token, role: user.role, permissions: user.permissions });
    } else {
        res.status(401).send('Invalid Credentials');
    }
});

// --- DEVICE MANAGEMENT ---

// Get Devices (ทุกคนดูได้)
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
    } catch (error) { res.status(500).send('Error'); }
});

// Update (Edit Device) -> เช็ค permission 'edit_device'
app.post('/api/devices/update', authenticateJWT, checkPermission('edit_device'), async (req, res) => {
    const { hostname, friendlyName, group, location } = req.body;
    await Device.updateOne({ hostname }, { friendlyName, group, location });
    res.json({ success: true });
});

// Command (Reboot/Shutdown) -> เช็ค permission 'control_device'
app.post('/api/devices/command', authenticateJWT, checkPermission('control_device'), async (req, res) => {
    const { hostname, command } = req.body;
    await Device.updateOne({ hostname }, { pendingCommand: command });
    res.json({ success: true });
});

// Delete Device -> เช็ค permission 'delete_device'
app.delete('/api/devices/:hostname', authenticateJWT, checkPermission('delete_device'), async (req, res) => {
    try {
        await Device.deleteOne({ hostname: req.params.hostname });
        res.json({ success: true });
    } catch (error) { res.status(500).send('Error'); }
});

// Report from Agent (เหมือนเดิม)
app.post('/api/report', async (req, res) => {
    // 🔒 Agent Secret Key
    const AGENT_SECRET_KEY = "BCGE2643AMySuperSecretKey2025";
    const clientKey = req.headers['x-agent-secret'];
    if (clientKey !== AGENT_SECRET_KEY) return res.status(403).json({ error: "Unauthorized" });

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
            if(device.pendingCommand !== 'screenshot') await Device.updateOne({ hostname: data.hostname }, { $unset: { pendingCommand: "" } });
        }
        res.json(responsePayload);
    } catch (error) { res.status(500).send('DB Error'); }
});
app.post('/api/upload-screen', async (req, res) => {
    const { hostname, image } = req.body;
    await Device.updateOne({ hostname }, { screenshot: image, $unset: { pendingCommand: "" } });
    res.json({ success: true });
});


// --- USER MANAGEMENT (Admin Only) ---

// Get Users
app.get('/api/users', authenticateJWT, checkPermission('manage_users'), async (req, res) => {
    const users = await User.find({}, '-password'); // ไม่ส่ง password กลับไป
    res.json(users);
});

// Create User
app.post('/api/users', authenticateJWT, checkPermission('manage_users'), async (req, res) => {
    const { username, password, role, permissions } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, password: hashedPassword, role, permissions });
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// Update User (เปลี่ยน Password / Role / Permissions)
app.put('/api/users/:id', authenticateJWT, checkPermission('manage_users'), async (req, res) => {
    const { password, role, permissions } = req.body;
    const updateData = { role, permissions };
    if (password) {
        updateData.password = await bcrypt.hash(password, 10);
    }
    await User.findByIdAndUpdate(req.params.id, updateData);
    res.json({ success: true });
});

// Delete User
app.delete('/api/users/:id', authenticateJWT, checkPermission('manage_users'), async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});