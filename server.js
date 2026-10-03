require("dotenv").config();
const express=require("express");
const http=require("http");
const path=require("path");
const crypto=require("crypto");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const multer=require("multer");
const {Pool}=require("pg");
const {Server}=require("socket.io");

const app=express();
const server=http.createServer(app);
const io=new Server(server,{maxHttpBufferSize:20*1024*1024});
const PORT=Number(process.env.PORT||10000);
const SECRET=process.env.JWT_SECRET||"CHANGE_ME";
const MAX_MB=Number(process.env.MAX_FILE_MB||15);
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?{rejectUnauthorized:false}:false});
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:MAX_MB*1024*1024}});

app.use(express.json({limit:"2mb"}));
app.use(express.static(path.join(__dirname,"public")));

const safeUser=u=>({id:u.id,email:u.email,username:u.username,bio:u.bio,avatar_url:u.avatar_url,role:u.role,created_at:u.created_at,last_seen:u.last_seen});
const tokenFor=u=>jwt.sign({id:u.id,email:u.email,role:u.role},SECRET,{expiresIn:"7d"});

function auth(req,res,next){
  const t=(req.headers.authorization||"").replace(/^Bearer\s+/i,"");
  if(!t)return res.status(401).json({error:"Login required"});
  try{req.user=jwt.verify(t,SECRET);next()}catch{res.status(401).json({error:"Session expired"})}
}
function admin(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error:"Admin only"});next()}

async function init(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,bio TEXT DEFAULT '',avatar_data BYTEA,avatar_mime TEXT,
  role TEXT NOT NULL DEFAULT 'user',created_at TIMESTAMPTZ DEFAULT NOW(),last_seen TIMESTAMPTZ DEFAULT NOW()
 );
 CREATE TABLE IF NOT EXISTS conversations(
  id SERIAL PRIMARY KEY,kind TEXT NOT NULL DEFAULT 'direct',name TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,created_at TIMESTAMPTZ DEFAULT NOW()
 );
 CREATE TABLE IF NOT EXISTS conversation_members(
  conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  role TEXT DEFAULT 'member',PRIMARY KEY(conversation_id,user_id)
 );
 CREATE TABLE IF NOT EXISTS messages(
  id SERIAL PRIMARY KEY,conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
  sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,body TEXT,created_at TIMESTAMPTZ DEFAULT NOW()
 );
 CREATE TABLE IF NOT EXISTS files(
  id SERIAL PRIMARY KEY,message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
  owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,size_bytes BIGINT NOT NULL,data BYTEA NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW()
 );
 CREATE TABLE IF NOT EXISTS live_rooms(
  id SERIAL PRIMARY KEY,code TEXT UNIQUE NOT NULL,name TEXT NOT NULL,
  host_id INTEGER REFERENCES users(id) ON DELETE SET NULL,active BOOLEAN DEFAULT TRUE,created_at TIMESTAMPTZ DEFAULT NOW()
 );
 CREATE INDEX IF NOT EXISTS msg_conv_idx ON messages(conversation_id,created_at);
 `);
 if(process.env.ADMIN_EMAIL&&process.env.ADMIN_PASSWORD){
   const email=process.env.ADMIN_EMAIL.toLowerCase();
   const x=await pool.query("SELECT id FROM users WHERE email=$1",[email]);
   if(!x.rowCount){
     const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD,12);
     let name="Admin";
     if((await pool.query("SELECT 1 FROM users WHERE username=$1",[name])).rowCount)name="Admin_"+crypto.randomBytes(3).toString("hex");
     await pool.query("INSERT INTO users(email,username,password_hash,role) VALUES($1,$2,$3,'admin')",[email,name,hash]);
     console.log("Admin account created");
   }
 }
}

app.get("/api/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true})}catch(e){res.status(500).json({ok:false,error:e.message})}});

app.post("/api/register",async(req,res)=>{
 try{
  const {email,username,password}=req.body;
  if(!email||!username||!password||password.length<8)return res.status(400).json({error:"Email, username and 8+ character password required"});
  const hash=await bcrypt.hash(password,12);
  const r=await pool.query("INSERT INTO users(email,username,password_hash) VALUES($1,$2,$3) RETURNING *",[email.trim().toLowerCase(),username.trim(),hash]);
  res.json({token:tokenFor(r.rows[0]),user:safeUser(r.rows[0])});
 }catch(e){res.status(400).json({error:e.code==="23505"?"Email or username already exists":e.message})}
});

app.post("/api/login",async(req,res)=>{
 const r=await pool.query("SELECT * FROM users WHERE email=$1",[String(req.body.email||"").trim().toLowerCase()]);
 if(!r.rowCount||!(await bcrypt.compare(String(req.body.password||""),r.rows[0].password_hash)))return res.status(401).json({error:"Invalid email or password"});
 await pool.query("UPDATE users SET last_seen=NOW() WHERE id=$1",[r.rows[0].id]);
 res.json({token:tokenFor(r.rows[0]),user:safeUser(r.rows[0])});
});

app.get("/api/me",auth,async(req,res)=>{
 const r=await pool.query("SELECT id,email,username,bio,avatar_url,role,created_at,last_seen FROM users WHERE id=$1",[req.user.id]);
 res.json({user:r.rows[0]});
});

app.put("/api/profile",auth,async(req,res)=>{
 try{
  const r=await pool.query(
   "UPDATE users SET username=COALESCE(NULLIF($1,''),username),bio=COALESCE($2,bio) WHERE id=$3 RETURNING id,email,username,bio,avatar_url,role,created_at,last_seen",
   [String(req.body.username||"").trim(),req.body.bio??null,req.user.id]
  );
  res.json({user:r.rows[0]});
 }catch(e){res.status(400).json({error:e.code==="23505"?"Username already exists":e.message})}
});

app.post("/api/profile/avatar",auth,upload.single("file"),async(req,res)=>{
 if(!req.file||!req.file.mimetype.startsWith("image/"))return res.status(400).json({error:"Image required"});
 await pool.query("UPDATE users SET avatar_data=$1,avatar_mime=$2,avatar_url=$3 WHERE id=$4",[req.file.buffer,req.file.mimetype,`/api/avatar/${req.user.id}`,req.user.id]);
 res.json({avatar_url:`/api/avatar/${req.user.id}`});
});
app.get("/api/avatar/:id",async(req,res)=>{
 const r=await pool.query("SELECT avatar_data,avatar_mime FROM users WHERE id=$1",[Number(req.params.id)]);
 if(!r.rowCount||!r.rows[0].avatar_data)return res.status(404).end();
 res.setHeader("Content-Type",r.rows[0].avatar_mime);res.send(r.rows[0].avatar_data);
});

app.get("/api/users",auth,async(req,res)=>{
 const r=await pool.query("SELECT id,username,bio,avatar_url,last_seen FROM users WHERE id<>$1 ORDER BY username",[req.user.id]);
 res.json({users:r.rows});
});

async function direct(a,b){
 const r=await pool.query(`
 SELECT c.id FROM conversations c
 JOIN conversation_members a ON a.conversation_id=c.id AND a.user_id=$1
 JOIN conversation_members b ON b.conversation_id=c.id AND b.user_id=$2
 WHERE c.kind='direct' LIMIT 1`,[a,b]);
 if(r.rowCount)return r.rows[0].id;
 const c=await pool.query("INSERT INTO conversations(kind) VALUES('direct') RETURNING id");
 await pool.query("INSERT INTO conversation_members(conversation_id,user_id) VALUES($1,$2),($1,$3)",[c.rows[0].id,a,b]);
 return c.rows[0].id;
}

app.post("/api/chats/direct",auth,async(req,res)=>{
 const id=await direct(req.user.id,Number(req.body.user_id));res.json({conversation_id:id});
});
app.get("/api/chats",auth,async(req,res)=>{
 const r=await pool.query(`
 SELECT c.id,c.kind,c.name,
 (SELECT body FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) last_message,
 COALESCE((SELECT MAX(created_at) FROM messages m2 WHERE m2.conversation_id=c.id),c.created_at) last_message_at
 FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id AND cm.user_id=$1
 ORDER BY last_message_at DESC`,[req.user.id]);
 res.json({chats:r.rows});
});
app.get("/api/chats/:id/messages",auth,async(req,res)=>{
 const id=Number(req.params.id);
 const ok=await pool.query("SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",[id,req.user.id]);
 if(!ok.rowCount&&req.user.role!=="admin")return res.status(403).json({error:"Not a member"});
 const r=await pool.query(`
 SELECT m.id,m.conversation_id,m.sender_id,m.body,m.created_at,u.username,
 f.id file_id,f.original_name,f.mime_type,f.size_bytes
 FROM messages m LEFT JOIN users u ON u.id=m.sender_id
 LEFT JOIN files f ON f.message_id=m.id WHERE m.conversation_id=$1 ORDER BY m.created_at ASC LIMIT 500`,[id]);
 res.json({messages:r.rows});
});
app.post("/api/chats/:id/messages",auth,upload.single("file"),async(req,res)=>{
 const id=Number(req.params.id);
 const ok=await pool.query("SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",[id,req.user.id]);
 if(!ok.rowCount)return res.status(403).json({error:"Not a member"});
 if(!req.body.body&&!req.file)return res.status(400).json({error:"Message or file required"});
 const m=await pool.query("INSERT INTO messages(conversation_id,sender_id,body) VALUES($1,$2,$3) RETURNING *",[id,req.user.id,req.body.body||null]);
 if(req.file)await pool.query("INSERT INTO files(message_id,owner_id,original_name,mime_type,size_bytes,data) VALUES($1,$2,$3,$4,$5,$6)",[m.rows[0].id,req.user.id,req.file.originalname,req.file.mimetype,req.file.size,req.file.buffer]);
 const full=await pool.query(`SELECT m.*,u.username,f.id file_id,f.original_name,f.mime_type,f.size_bytes FROM messages m LEFT JOIN users u ON u.id=m.sender_id LEFT JOIN files f ON f.message_id=m.id WHERE m.id=$1`,[m.rows[0].id]);
 io.to("chat:"+id).emit("message:new",full.rows[0]);
 res.json({message:full.rows[0]});
});

app.post("/api/groups",auth,async(req,res)=>{
 const name=String(req.body.name||"").trim();if(!name)return res.status(400).json({error:"Group name required"});
 const c=await pool.query("INSERT INTO conversations(kind,name,created_by) VALUES('group',$1,$2) RETURNING *",[name,req.user.id]);
 await pool.query("INSERT INTO conversation_members(conversation_id,user_id,role) VALUES($1,$2,'owner')",[c.rows[0].id,req.user.id]);
 res.json({group:c.rows[0]});
});
app.post("/api/groups/:id/members",auth,async(req,res)=>{
 const id=Number(req.params.id),uid=Number(req.body.user_id);
 const own=await pool.query("SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2 AND role IN('owner','admin')",[id,req.user.id]);
 if(!own.rowCount)return res.status(403).json({error:"Group admin required"});
 await pool.query("INSERT INTO conversation_members(conversation_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[id,uid]);
 res.json({ok:true});
});

app.post("/api/rooms",auth,async(req,res)=>{
 const code=crypto.randomBytes(4).toString("hex").toUpperCase();
 const r=await pool.query("INSERT INTO live_rooms(code,name,host_id) VALUES($1,$2,$3) RETURNING *",[code,String(req.body.name||"Live Room").trim(),req.user.id]);
 res.json({room:r.rows[0]});
});
app.get("/api/rooms",auth,async(req,res)=>{
 const r=await pool.query("SELECT r.*,u.username host_name FROM live_rooms r LEFT JOIN users u ON u.id=r.host_id WHERE r.active=true ORDER BY r.created_at DESC");
 res.json({rooms:r.rows});
});

app.get("/api/admin/users",auth,admin,async(req,res)=>{
 const r=await pool.query("SELECT id,email,username,bio,avatar_url,role,created_at,last_seen FROM users ORDER BY created_at DESC");res.json({users:r.rows});
});
app.get("/api/admin/messages",auth,admin,async(req,res)=>{
 const r=await pool.query(`SELECT m.id,m.body,m.created_at,m.conversation_id,u.username,u.email,f.id file_id,f.original_name,f.mime_type,f.size_bytes FROM messages m LEFT JOIN users u ON u.id=m.sender_id LEFT JOIN files f ON f.message_id=m.id ORDER BY m.created_at DESC LIMIT 1000`);
 res.json({messages:r.rows});
});
app.get("/api/admin/files",auth,admin,async(req,res)=>{
 const r=await pool.query(`SELECT f.id,f.original_name,f.mime_type,f.size_bytes,f.created_at,u.username,u.email FROM files f LEFT JOIN users u ON u.id=f.owner_id ORDER BY f.created_at DESC LIMIT 1000`);
 res.json({files:r.rows});
});
app.delete("/api/admin/users/:id",auth,admin,async(req,res)=>{
 if(Number(req.params.id)===req.user.id)return res.status(400).json({error:"Cannot delete yourself"});
 await pool.query("DELETE FROM users WHERE id=$1",[Number(req.params.id)]);res.json({ok:true});
});

app.get("/api/files/:id",auth,async(req,res)=>{
 const r=await pool.query("SELECT f.*,m.conversation_id FROM files f LEFT JOIN messages m ON m.id=f.message_id WHERE f.id=$1",[Number(req.params.id)]);
 if(!r.rowCount)return res.status(404).end();
 const f=r.rows[0];
 if(req.user.role!=="admin"){
   const ok=await pool.query("SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",[f.conversation_id,req.user.id]);
   if(!ok.rowCount)return res.status(403).json({error:"Not allowed"});
 }
 res.setHeader("Content-Type",f.mime_type);
 res.setHeader("Content-Disposition",`attachment; filename="${encodeURIComponent(f.original_name)}"`);
 res.send(f.data);
});

io.use((socket,next)=>{
 try{socket.user=jwt.verify(socket.handshake.auth?.token,SECRET);next()}catch{next(new Error("Unauthorized"))}
});
io.on("connection",socket=>{
 socket.on("chat:join",async id=>{
   const ok=await pool.query("SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",[Number(id),socket.user.id]);
   if(ok.rowCount||socket.user.role==="admin")socket.join("chat:"+Number(id));
 });
 socket.on("room:join",code=>socket.join("room:"+String(code)));
 socket.on("room:message",async d=>{
   const text=String(d.text||"").trim().slice(0,2000);if(!text)return;
   const r=await pool.query("SELECT id FROM live_rooms WHERE code=$1 AND active=true",[String(d.code)]);
   if(!r.rowCount)return;
   io.to("room:"+String(d.code)).emit("room:message",{username:socket.user.email,text,created_at:new Date().toISOString()});
 });
});

app.get("*",(req,res)=>{
 if(req.path.startsWith("/api/"))return res.status(404).json({error:"Not found"});
 res.sendFile(path.join(__dirname,"public","index.html"));
});

init().then(()=>server.listen(PORT,()=>console.log("ConnectChat running on "+PORT))).catch(e=>{console.error(e);process.exit(1)});
