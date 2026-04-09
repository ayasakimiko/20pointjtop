// server.js
const express = require("express");
const http = require("http");
const cors = require("cors");
const { initSocket } = require("./socket");
const { startCapture } = require("./capture");
const authRoutes = require("./routes/authRoutes"); // <-- 1. นำเข้า Auth Routes

const app = express();
app.use(cors());
app.use(express.json()); // <-- 2. สำคัญมาก! ต้องมีเพื่อให้ Express อ่านข้อมูล JSON จาก req.body ได้

// --- 3. ใช้งาน Routes ของระบบ Authentication ---
app.use("/api", authRoutes);

const server = http.createServer(app);

// 4. กำหนดค่าและเปิดใช้งาน Socket.io
const io = initSocket(server);

// 5. เริ่มการทำงานระบบดักจับ Packet และส่ง io instance เข้าไป
startCapture(io);

// 6. เริ่ม Server
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`🔐 Auth API ready at http://localhost:${PORT}/api`);
});