require("dotenv").config();
const express=require("express"),cookieParser=require("cookie-parser"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),Database=require("better-sqlite3"),OpenAI=require("openai"),crypto=require("crypto"),path=require("path");
const app=express(); app.use(express.json({limit:"1mb"})); app.use(cookieParser());
const db=new Database("careerboost.db");
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,plan TEXT NOT NULL DEFAULT 'free',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS usage(user_id INTEGER PRIMARY KEY,generations INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,provider TEXT,provider_id TEXT,status TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
const secret=process.env.JWT_SECRET||"dev-change-me", model=process.env.OPENAI_MODEL||"gpt-5.6-luna";
const ai=process.env.OPENAI_API_KEY?new OpenAI({apiKey:process.env.OPENAI_API_KEY}):null;
const clean=(x,n=30000)=>String(x||"").trim().slice(0,n);
function token(u){return jwt.sign({id:u.id},secret,{expiresIn:"7d"})}
function auth(req,res,next){try{let t=req.cookies.tp_token;if(!t)throw 0;let p=jwt.verify(t,secret),u=db.prepare("SELECT id,email,plan FROM users WHERE id=?").get(p.id);if(!u)throw 0;req.user=u;next()}catch{res.status(401).json({error:"Please sign in."})}}
function session(res,u){res.cookie("tp_token",token(u),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:604800000})}

app.get("/api/health",(q,s)=>s.json({ok:true}));
app.post("/api/auth/signup",async(q,s)=>{let email=clean(q.body.email,160).toLowerCase(),pw=String(q.body.password||"");if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)||pw.length<8)return s.status(400).json({error:"Use a valid email and an 8+ character password."});try{let r=db.prepare("INSERT INTO users(email,password_hash) VALUES(?,?)").run(email,await bcrypt.hash(pw,12));db.prepare("INSERT INTO usage(user_id) VALUES(?)").run(r.lastInsertRowid);let u=db.prepare("SELECT id,email,plan FROM users WHERE id=?").get(r.lastInsertRowid);session(s,u);s.json({user:u})}catch{s.status(400).json({error:"That email is already registered."})}});
app.post("/api/auth/login",async(q,s)=>{let email=clean(q.body.email,160).toLowerCase(),pw=String(q.body.password||""),r=db.prepare("SELECT * FROM users WHERE email=?").get(email);if(!r||!(await bcrypt.compare(pw,r.password_hash)))return s.status(401).json({error:"Invalid email or password."});let u={id:r.id,email:r.email,plan:r.plan};session(s,u);s.json({user:u})});
app.post("/api/auth/logout",(q,s)=>{s.clearCookie("tp_token");s.json({ok:true})});
app.get("/api/me",auth,(q,s)=>{let u=db.prepare("SELECT id,email,plan FROM users WHERE id=?").get(q.user.id),x=db.prepare("SELECT generations FROM usage WHERE user_id=?").get(q.user.id);s.json({user:u,usage:x?.generations||0})});

const instructions={
resume:"Create an ATS-friendly resume using ONLY the supplied facts. Never invent employers, dates, degrees, skills or achievements. Use sections SUMMARY, SKILLS, EXPERIENCE, EDUCATION, PROJECTS, CERTIFICATIONS.",
cover:"Write a concise tailored cover letter using ONLY supplied facts and the job description. Never invent experience. Use placeholders for missing details.",
improve:"Improve the supplied resume for clarity, grammar, impact and job relevance without inventing facts. Return the improved resume and a short Changes made list.",
skills:"Compare the user's profile with the target job. Identify relevant existing strengths, missing/unclear skills and practical next steps. Do not claim the user has an unprovided skill."
};
app.post("/api/generate",auth,async(q,s)=>{if(!ai)return s.status(503).json({error:"Add OPENAI_API_KEY to your deployment Secrets."});let type=instructions[q.body.type]?q.body.type:"resume",input=clean(q.body.input);if(input.length<30)return s.status(400).json({error:"Please provide more information."});let u=db.prepare("SELECT generations FROM usage WHERE user_id=?").get(q.user.id);if(q.user.plan!=="pro"&&(u?.generations||0)>=5)return s.status(402).json({error:"Free limit reached. Upgrade to Pro."});try{let r=await ai.responses.create({model,instructions:instructions[type],input});db.prepare("UPDATE usage SET generations=generations+1 WHERE user_id=?").run(q.user.id);s.json({output:r.output_text||"No result returned."})}catch(e){console.error(e);s.status(500).json({error:"AI generation failed. Check your API key and model."})}});

function basic(){return Buffer.from(`${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`).toString("base64")}
app.post("/api/razorpay/subscription",auth,async(q,s)=>{if(!process.env.RAZORPAY_KEY_ID||!process.env.RAZORPAY_KEY_SECRET||!process.env.RAZORPAY_PLAN_ID)return s.status(503).json({error:"Razorpay is not configured yet."});try{let r=await fetch("https://api.razorpay.com/v1/subscriptions",{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Basic ${basic()}`},body:JSON.stringify({plan_id:process.env.RAZORPAY_PLAN_ID,total_count:12,customer_notify:1,notes:{user_id:String(q.user.id)}})}),d=await r.json();if(!r.ok)return s.status(400).json({error:d.error?.description||"Could not create subscription."});s.json({subscription:d,key_id:process.env.RAZORPAY_KEY_ID})}catch{s.status(500).json({error:"Payment service error."})}});
app.post("/api/razorpay/verify",auth,(q,s)=>{let {razorpay_payment_id:p,razorpay_subscription_id:i,razorpay_signature:g}=q.body;if(!p||!i||!g)return s.status(400).json({error:"Missing payment details."});let e=crypto.createHmac("sha256",process.env.RAZORPAY_KEY_SECRET||"").update(`${p}|${i}`).digest("hex");if(e.length!==g.length||!crypto.timingSafeEqual(Buffer.from(e),Buffer.from(g)))return s.status(400).json({error:"Payment verification failed."});db.prepare("UPDATE users SET plan='pro' WHERE id=?").run(q.user.id);db.prepare("INSERT INTO payments(user_id,provider,provider_id,status) VALUES(?,?,?,?)").run(q.user.id,"razorpay",i,"verified");s.json({ok:true})});

app.use(express.static(path.join(__dirname,"public")));app.get("*",(q,s)=>s.sendFile(path.join(__dirname,"public/index.html")));
app.listen(Number(process.env.PORT||3000),()=>console.log("AI Career Boost running"));
