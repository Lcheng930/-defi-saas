/**
 * DeFi 安全快评 SaaS — Express API 服务器
 * ============================================
 * 功能：
 *   1. 接收合约地址 → 调用 analyzer → 返回 JSON 结果
 *   2. API Key 认证（免费用户每天5次，付费用户无限）
 *   3. 速率限制
 *   4. 请求日志
 *   5. 用户注册/登录/升级
 *
 * 启动方式：
 *   node server.js
 *   ETHERSCAN_API_KEY=xxx PORT=3000 node server.js
 *
 * 部署：开箱即用 Vercel（vercel.json 已配置）
 * ============================================
 */

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// 引入 analyzer 引擎和用户系统
const { analyzeContract, toMarkdown } = require("../defi-security-api/analyzer.js");
const UserSystem = require("./users.js");

// ======================== 配置 ========================
const PORT = parseInt(process.env.PORT) || 3000;
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "admin-" + crypto.randomBytes(8).toString("hex");

// 速率限制配置
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1分钟窗口
const RATE_LIMIT_MAX_REQUESTS = 30;      // 每分钟最多30次（所有用户）

// ======================== Express 初始化 ========================
const app = express();

// 中间件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 静态文件服务（前端面板）
app.use(express.static(path.join(__dirname, "public")));

// CORS
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization");
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  next();
});

// ======================== 请求日志 ========================
app.use((req, res, next) => {
  const start = Date.now();
  const originalEnd = res.end;

  res.end = function (...args) {
    const elapsed = Date.now() - start;
    const logLine = [
      `[${new Date().toISOString()}]`,
      req.ip.replace("::ffff:", ""),
      req.method,
      req.originalUrl,
      res.statusCode,
      `${elapsed}ms`,
    ].join(" ");

    // 控制台输出
    console.log(logLine);

    // 写入日志文件（仅保留最近 1000 行）
    const logDir = path.join(__dirname, "logs");
    if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
    const logFile = path.join(logDir, "access.log");
    fs.appendFileSync(logFile, logLine + "\n");
    // 滚动日志：超过 2000 行则截断
    try {
      const lines = fs.readFileSync(logFile, "utf-8").split("\n").filter(Boolean);
      if (lines.length > 2000) {
        fs.writeFileSync(logFile, lines.slice(-1000).join("\n") + "\n");
      }
    } catch (_) {}

    return originalEnd.apply(this, args);
  };

  next();
});

// ======================== 速率限制 ========================
const rateLimitMap = new Map();

function rateLimiter(req, res, next) {
  const now = Date.now();
  const ip = req.ip;
  const windowStart = now - RATE_LIMIT_WINDOW_MS;

  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, []);
  }

  const requests = rateLimitMap.get(ip).filter((t) => t > windowStart);
  requests.push(now);
  rateLimitMap.set(ip, requests);

  res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX_REQUESTS);
  res.setHeader("X-RateLimit-Remaining", Math.max(0, RATE_LIMIT_MAX_REQUESTS - requests.length));

  if (requests.length > RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({
      error: "请求过于频繁，请稍后再试",
      retryAfter: Math.ceil(RATE_LIMIT_WINDOW_MS / 1000),
    });
  }

  next();
}

// 定期清理过期 IP 记录（每5分钟）
setInterval(() => {
  const now = Date.now();
  const cutoff = now - RATE_LIMIT_WINDOW_MS;
  for (const [ip, timestamps] of rateLimitMap) {
    const valid = timestamps.filter((t) => t > cutoff);
    if (valid.length === 0) {
      rateLimitMap.delete(ip);
    } else {
      rateLimitMap.set(ip, valid);
    }
  }
}, 5 * 60 * 1000);

// ======================== API Key 认证中间件 ========================

/**
 * 从请求中提取 API Key
 * 支持方式：Header X-API-Key、Query ?api_key=、Header Authorization Bearer
 */
function extractApiKey(req) {
  return (
    req.headers["x-api-key"] ||
    req.query.api_key ||
    (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")
      ? req.headers.authorization.slice(7)
      : null)
  );
}

/**
 * 认证中间件：验证 API Key 是否有效
 * 将用户信息挂载到 req.user
 */
async function authMiddleware(req, res, next) {
  const apiKey = extractApiKey(req);

  if (!apiKey) {
    return res.status(401).json({
      error: "缺少 API Key",
      hint: "请在 Header 中提供 X-API-Key，或注册获取免费 Key",
      registerUrl: "/api/auth/register",
    });
  }

  // 管理员 Key
  if (apiKey === ADMIN_API_KEY) {
    req.user = {
      email: "admin",
      apiKey: ADMIN_API_KEY,
      tier: "enterprise",
      quotaLimit: Infinity,
      quotaUsed: 0,
    };
    return next();
  }

  const user = await UserSystem.findByApiKey(apiKey);
  if (!user) {
    return res.status(403).json({
      error: "无效的 API Key",
      hint: "请检查 Key 是否正确，或重新注册",
    });
  }

  req.user = user;
  next();
}

/**
 * 可选认证：有 Key 就解析，没有也放行（用于公开接口）
 */
async function optionalAuth(req, res, next) {
  const apiKey = extractApiKey(req);
  if (apiKey) {
    const user = await UserSystem.findByApiKey(apiKey);
    if (user) {
      req.user = user;
    }
  }
  next();
}

// ======================== 全局速率限制 ========================
app.use("/api/", rateLimiter);

// ======================== API 路由 ========================

// --- 健康检查 ---
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    version: "2.0.0",
    timestamp: new Date().toISOString(),
    etherscanConfigured: !!ETHERSCAN_API_KEY,
  });
});

// --- 用户注册 ---
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "请提供有效的邮箱地址" });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ error: "密码至少6位" });
    }

    const existing = await UserSystem.findByEmail(email);
    if (existing) {
      return res.status(409).json({ error: "该邮箱已注册" });
    }

    const user = await UserSystem.createUser(email, password);

    res.status(201).json({
      message: "注册成功",
      user: {
        email: user.email,
        apiKey: user.apiKey,
        tier: user.tier,
        quotaLimit: user.quotaLimit,
        quotaReset: user.quotaReset,
      },
      tip: "请妥善保管你的 API Key，后续可在设置页面查看",
    });
  } catch (e) {
    console.error("注册失败:", e);
    res.status(500).json({ error: "注册失败，请稍后再试" });
  }
});

// --- 用户登录 ---
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "请输入邮箱和密码" });
    }

    const user = await UserSystem.verifyPassword(email, password);
    if (!user) {
      return res.status(401).json({ error: "邮箱或密码错误" });
    }

    res.json({
      message: "登录成功",
      user: {
        email: user.email,
        apiKey: user.apiKey,
        tier: user.tier,
        quotaLimit: user.quotaLimit,
        quotaUsed: user.quotaUsed,
        quotaReset: user.quotaReset,
        subscriptionExpiry: user.subscriptionExpiry,
      },
    });
  } catch (e) {
    console.error("登录失败:", e);
    res.status(500).json({ error: "登录失败，请稍后再试" });
  }
});

// --- 获取用户配额信息 ---
app.get("/api/user/quota", authMiddleware, async (req, res) => {
  const user = await UserSystem.findByApiKey(req.user.apiKey);
  if (!user) {
    return res.status(404).json({ error: "用户不存在" });
  }

  const quota = UserSystem.getQuotaInfo(user);

  res.json({
    email: user.email,
    tier: user.tier,
    apiKey: user.apiKey,
    ...quota,
    subscriptionExpiry: user.subscriptionExpiry,
    createdAt: user.createdAt,
  });
});

// --- 用户信息（需要认证） ---
app.get("/api/user/profile", authMiddleware, async (req, res) => {
  const user = await UserSystem.findByApiKey(req.user.apiKey);
  if (!user) {
    return res.status(404).json({ error: "用户不存在" });
  }

  res.json({
    email: user.email,
    tier: user.tier,
    apiKey: user.apiKey,
    subscriptionExpiry: user.subscriptionExpiry,
    createdAt: user.createdAt,
  });
});

// --- 订阅码激活（升级） ---
app.post("/api/user/upgrade", authMiddleware, async (req, res) => {
  try {
    const { code } = req.body;

    if (!code || typeof code !== "string" || code.trim().length < 8) {
      return res.status(400).json({ error: "请提供有效的订阅码" });
    }

    const result = await UserSystem.redeemCode(req.user.apiKey, code.trim());

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({
      message: "升级成功",
      tier: result.tier,
      subscriptionExpiry: result.subscriptionExpiry,
      newQuotaLimit: result.quotaLimit,
    });
  } catch (e) {
    console.error("升级失败:", e);
    res.status(500).json({ error: "升级处理失败，请联系客服" });
  }
});

// --- 核心：合约分析接口 ---
app.get("/api/analyze", optionalAuth, async (req, res) => {
  try {
    const address = req.query.address;
    const chain = req.query.chain || "ethereum";
    const format = req.query.format || "json";

    if (!address) {
      return res.status(400).json({
        error: "缺少 address 参数",
        example: "/api/analyze?address=0xdAC17F958D2ee523a2206206994597C13D831ec7",
      });
    }

    // 验证地址格式
    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return res.status(400).json({ error: "无效的合约地址格式" });
    }

    // 配额检查
    if (req.user) {
      const quotaInfo = UserSystem.getQuotaInfo(req.user);
      if (!quotaInfo.canUse) {
        return res.status(429).json({
          error: quotaInfo.message,
          upgradeUrl: "/pricing.html",
          quotaUsed: quotaInfo.used,
          quotaLimit: quotaInfo.limit,
        });
      }
    }

    // 执行分析
    const report = await analyzeContract(address, chain);

    // 记录配额消耗（仅认证用户）
    if (req.user) {
      await UserSystem.recordUsage(req.user.apiKey);
    }

    // 返回结果
    if (format === "markdown" || format === "md") {
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.send(toMarkdown(report));
    } else {
      res.json(report);
    }
  } catch (e) {
    console.error("分析失败:", e);
    res.status(500).json({
      error: "分析过程发生错误",
      detail: e.message,
    });
  }
});

// --- 批量分析（仅付费用户） ---
app.post("/api/analyze/batch", authMiddleware, async (req, res) => {
  if (req.user.tier === "free") {
    return res.status(403).json({
      error: "批量分析仅限付费用户使用",
      upgradeUrl: "/pricing.html",
    });
  }

  const { addresses } = req.body;
  if (!Array.isArray(addresses) || addresses.length === 0) {
    return res.status(400).json({ error: "请提供合约地址数组" });
  }
  if (addresses.length > 10) {
    return res.status(400).json({ error: "单次批量分析最多10个地址" });
  }

  const results = [];
  for (const addr of addresses) {
    try {
      const report = await analyzeContract(addr);
      results.push({ address: addr, success: true, data: report });
    } catch (e) {
      results.push({ address: addr, success: false, error: e.message });
    }
  }

  res.json({ total: addresses.length, results });
});

// --- 公开：定价页面 ---
app.get("/api/pricing", (req, res) => {
  res.json({
    plans: [
      {
        tier: "free",
        name: "免费版",
        price: "$0",
        queriesPerDay: 5,
        features: ["每天5次查询", "基础漏洞检测", "安全评分"],
      },
      {
        tier: "pro",
        name: "专业版",
        price: "$9.9/月",
        queriesPerDay: Infinity,
        features: ["无限查询", "API Key 接入", "Markdown 报告导出", "优先响应"],
      },
      {
        tier: "enterprise",
        name: "企业版",
        price: "$49/月",
        queriesPerDay: Infinity,
        features: ["专业版全部功能", "定制检测规则", "白标嵌入", "批量分析", "专属客服"],
      },
    ],
    payment: {
      method: "Gumroad 订阅码",
      description: "在 Gumroad 购买订阅后获得激活码，在网站激活即可",
      gumroadUrl: "https://gumroad.com/l/defi-security",
    },
  });
});

// --- 管理员：生成订阅码 ---
app.post("/api/admin/generate-codes", async (req, res) => {
  const apiKey = extractApiKey(req);
  if (apiKey !== ADMIN_API_KEY) {
    return res.status(403).json({ error: "需要管理员权限" });
  }

  const { count = 10, tier = "pro", months = 1 } = req.body;
  const codes = await UserSystem.generateSubscriptionCodes(count, tier, months);

  res.json({ codes });
});

// --- 管理员：仪表盘统计 ---
app.get("/api/admin/stats", async (req, res) => {
  const apiKey = extractApiKey(req);
  if (apiKey !== ADMIN_API_KEY) {
    return res.status(403).json({ error: "需要管理员权限" });
  }

  const stats = await UserSystem.getStats();
  res.json(stats);
});

// ======================== 前端页面路由 ========================

// SPA fallback：所有非 /api/ 的非静态请求返回 index.html
app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "接口不存在" });
  }
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ======================== 错误处理 ========================

app.use((err, req, res, _next) => {
  console.error("服务器错误:", err);
  res.status(500).json({
    error: "服务器内部错误",
    detail: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// ======================== 启动服务器 ========================

app.listen(PORT, () => {
  console.log("");
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║   🛡️  DeFi 安全快评 SaaS v2.0 已启动       ║");
  console.log(`║   地址: http://localhost:${PORT}              ║`);
  console.log(`║   管理 Key: ${ADMIN_API_KEY}  ║`);
  console.log("║                                              ║");
  console.log(`║   Etherscan API: ${ETHERSCAN_API_KEY ? "✅ 已配置" : "❌ 未配置"}                      ║`);
  console.log("╚══════════════════════════════════════════════╝");
  console.log("");
});

module.exports = app;
