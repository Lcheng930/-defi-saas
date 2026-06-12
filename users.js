/**
 * DeFi 安全快评 SaaS — 用户管理系统
 * ============================================
 * 功能：
 *   - JSON 文件存储（零依赖，不需要数据库）
 *   - 用户注册（邮箱 + API Key 生成）
 *   - 配额管理（免费 5次/天，付费无限）
 *   - API Key 验证
 *   - 订阅码生成与兑换
 *
 * 设计原则：
 *   - 纯内存缓存 + 文件持久化，读写分离
 *   - 所有操作异步化，不阻塞事件循环
 *   - 文件写入有去抖，避免频繁 IO
 * ============================================
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ======================== 配置 ========================
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const CODES_FILE = path.join(DATA_DIR, "codes.json");
const STATS_FILE = path.join(DATA_DIR, "stats.json");

// 免费用户每日配额
const FREE_DAILY_QUOTA = 5;

// ======================== 内存缓存 ========================
let usersCache = null;
let codesCache = null;
let statsCache = null;

// 文件写入去抖定时器
let saveTimer = null;
const SAVE_DEBOUNCE_MS = 2000; // 2秒内多次写入合并为一次

// ======================== 初始化 ========================

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function loadJsonFile(filePath, defaultValue) {
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(raw);
    }
  } catch (e) {
    console.error(`[Users] 读取 ${filePath} 失败:`, e.message);
  }
  return defaultValue;
}

function loadAllData() {
  ensureDataDir();
  usersCache = loadJsonFile(USERS_FILE, []);
  codesCache = loadJsonFile(CODES_FILE, []);
  statsCache = loadJsonFile(STATS_FILE, {
    totalAnalyses: 0,
    totalUsers: 0,
    totalRevenue: 0,
    dailyAnalyses: {},
  });
}

// 启动时加载
loadAllData();

// ======================== 持久化（去抖写入） ========================

function scheduleSave() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    saveAllData();
    saveTimer = null;
  }, SAVE_DEBOUNCE_MS);
}

function saveAllData() {
  try {
    ensureDataDir();
    fs.writeFileSync(USERS_FILE, JSON.stringify(usersCache, null, 2), "utf-8");
    fs.writeFileSync(CODES_FILE, JSON.stringify(codesCache, null, 2), "utf-8");
    fs.writeFileSync(STATS_FILE, JSON.stringify(statsCache, null, 2), "utf-8");
  } catch (e) {
    console.error("[Users] 数据持久化失败:", e.message);
  }
}

// ======================== 工具函数 ========================

/** 生成随机的 API Key */
function generateApiKey() {
  // 格式：dsa_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx（dsa = DeFi Security API）
  return "dsa_" + crypto.randomBytes(20).toString("hex");
}

/** 生成订阅码 */
function generateCode(tier) {
  const prefix = tier === "pro" ? "PRO" : "ENT";
  const random = crypto.randomBytes(6).toString("hex").toUpperCase();
  return `${prefix}-${random.slice(0, 4)}-${random.slice(4, 8)}-${random.slice(8, 12)}`;
}

/** 获取今日日期键 */
function todayKey() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/** 简单哈希密码（生产环境应使用 bcrypt） */
function hashPassword(password) {
  return crypto.createHash("sha256").update("defi_salt_" + password).digest("hex");
}

// ======================== 用户操作 ========================

/**
 * 创建新用户
 * @param {string} email - 邮箱
 * @param {string} password - 密码
 * @returns {object} 用户对象
 */
async function createUser(email, password) {
  const existing = usersCache.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (existing) {
    throw new Error("邮箱已注册");
  }

  const user = {
    id: crypto.randomBytes(8).toString("hex"),
    email: email.toLowerCase(),
    passwordHash: hashPassword(password),
    apiKey: generateApiKey(),
    tier: "free", // free | pro | enterprise
    quotaUsed: 0,
    quotaResetDate: todayKey(),
    createdAt: new Date().toISOString(),
    subscriptionExpiry: null,
    lastLoginAt: new Date().toISOString(),
  };

  usersCache.push(user);

  // 更新统计
  statsCache.totalUsers = usersCache.length;

  scheduleSave();
  return user;
}

/**
 * 根据 API Key 查找用户
 * @param {string} apiKey
 * @returns {object|null}
 */
async function findByApiKey(apiKey) {
  const user = usersCache.find((u) => u.apiKey === apiKey);
  if (!user) return null;

  // 检查配额日期是否过期，自动重置
  const today = todayKey();
  if (user.quotaResetDate !== today) {
    user.quotaUsed = 0;
    user.quotaResetDate = today;
    scheduleSave();
  }

  // 检查订阅是否过期
  if (user.tier !== "free" && user.subscriptionExpiry) {
    if (new Date(user.subscriptionExpiry) < new Date()) {
      user.tier = "free";
      user.subscriptionExpiry = null;
      scheduleSave();
    }
  }

  return user;
}

/**
 * 根据邮箱查找用户
 * @param {string} email
 * @returns {object|null}
 */
async function findByEmail(email) {
  return usersCache.find((u) => u.email.toLowerCase() === email.toLowerCase()) || null;
}

/**
 * 验证密码
 * @param {string} email
 * @param {string} password
 * @returns {object|null} 验证成功返回用户对象
 */
async function verifyPassword(email, password) {
  const user = await findByEmail(email);
  if (!user) return null;

  const hash = hashPassword(password);
  if (user.passwordHash !== hash) return null;

  // 更新最后登录时间
  user.lastLoginAt = new Date().toISOString();
  scheduleSave();

  return user;
}

// ======================== 配额管理 ========================

/**
 * 获取用户配额信息
 * @param {object} user
 * @returns {{ canUse: boolean, used: number, limit: number, message: string }}
 */
function getQuotaInfo(user) {
  // 付费用户无限
  if (user.tier !== "free") {
    return {
      canUse: true,
      used: user.quotaUsed,
      limit: Infinity,
      remaining: Infinity,
      message: "付费用户，无限配额",
    };
  }

  const today = todayKey();
  if (user.quotaResetDate !== today) {
    user.quotaUsed = 0;
    user.quotaResetDate = today;
    scheduleSave();
  }

  const used = user.quotaUsed || 0;
  const limit = FREE_DAILY_QUOTA;
  const remaining = Math.max(0, limit - used);

  return {
    canUse: remaining > 0,
    used,
    limit,
    remaining,
    message: remaining > 0
      ? `今日剩余 ${remaining}/${limit} 次查询`
      : `今日 ${limit} 次免费查询已用完，请明天再试或升级付费版`,
  };
}

/**
 * 记录一次 API 使用
 * @param {string} apiKey
 */
async function recordUsage(apiKey) {
  const user = usersCache.find((u) => u.apiKey === apiKey);
  if (!user) return;

  const today = todayKey();
  if (user.quotaResetDate !== today) {
    user.quotaUsed = 0;
    user.quotaResetDate = today;
  }

  user.quotaUsed = (user.quotaUsed || 0) + 1;

  // 统计
  statsCache.totalAnalyses = (statsCache.totalAnalyses || 0) + 1;
  if (!statsCache.dailyAnalyses) statsCache.dailyAnalyses = {};
  statsCache.dailyAnalyses[today] = (statsCache.dailyAnalyses[today] || 0) + 1;

  scheduleSave();
}

// ======================== 订阅码系统 ========================

/**
 * 生成一批订阅码
 * @param {number} count - 数量
 * @param {string} tier - pro | enterprise
 * @param {number} months - 有效月数
 * @returns {Array<{code: string, tier: string, months: number}>}
 */
async function generateSubscriptionCodes(count = 10, tier = "pro", months = 1) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = {
      code: generateCode(tier),
      tier,
      months,
      createdAt: new Date().toISOString(),
      used: false,
      usedBy: null,
      usedAt: null,
    };
    codes.push(code);
  }

  codesCache.push(...codes);
  scheduleSave();

  return codes.map((c) => ({
    code: c.code,
    tier: c.tier,
    months: c.months,
  }));
}

/**
 * 兑换订阅码
 * @param {string} apiKey - 用户 API Key
 * @param {string} codeStr - 订阅码
 * @returns {{ success: boolean, tier?: string, error?: string }}
 */
async function redeemCode(apiKey, codeStr) {
  const codeEntry = codesCache.find((c) => c.code === codeStr && !c.used);
  if (!codeEntry) {
    return { success: false, error: "订阅码无效或已被使用" };
  }

  const user = usersCache.find((u) => u.apiKey === apiKey);
  if (!user) {
    return { success: false, error: "用户不存在" };
  }

  // 计算到期时间
  const now = new Date();
  let expiryDate;

  if (user.tier === codeEntry.tier && user.subscriptionExpiry) {
    // 同级别续费：在现有到期时间基础上延长
    expiryDate = new Date(user.subscriptionExpiry);
    if (expiryDate < now) expiryDate = now;
    expiryDate.setMonth(expiryDate.getMonth() + codeEntry.months);
  } else {
    // 新级别或首次订阅：从今天开始
    expiryDate = new Date(now);
    expiryDate.setMonth(expiryDate.getMonth() + codeEntry.months);
  }

  // 更新用户
  user.tier = codeEntry.tier;
  user.subscriptionExpiry = expiryDate.toISOString();

  // 标记兑换码已使用
  codeEntry.used = true;
  codeEntry.usedBy = user.email;
  codeEntry.usedAt = new Date().toISOString();

  // 更新收入统计
  const price = codeEntry.tier === "pro" ? 9.9 : 49;
  statsCache.totalRevenue = (statsCache.totalRevenue || 0) + price * codeEntry.months;

  scheduleSave();

  return {
    success: true,
    tier: codeEntry.tier,
    subscriptionExpiry: expiryDate.toISOString(),
    quotaLimit: Infinity,
    months: codeEntry.months,
  };
}

/**
 * 获取所有未使用的订阅码
 * @returns {Array}
 */
async function getUnusedCodes() {
  return codesCache.filter((c) => !c.used);
}

// ======================== 统计 ========================

/**
 * 获取系统统计信息
 * @returns {object}
 */
async function getStats() {
  const today = todayKey();
  const freeUsers = usersCache.filter((u) => u.tier === "free").length;
  const proUsers = usersCache.filter((u) => u.tier === "pro").length;
  const enterpriseUsers = usersCache.filter((u) => u.tier === "enterprise").length;

  return {
    totalUsers: usersCache.length,
    freeUsers,
    proUsers,
    enterpriseUsers,
    totalAnalyses: statsCache.totalAnalyses || 0,
    todayAnalyses: (statsCache.dailyAnalyses && statsCache.dailyAnalyses[today]) || 0,
    totalRevenue: statsCache.totalRevenue || 0,
    activeSubscriptions: proUsers + enterpriseUsers,
    unusedCodes: codesCache.filter((c) => !c.used).length,
    generatedAt: new Date().toISOString(),
  };
}

// ======================== 导出 ========================

module.exports = {
  // 用户操作
  createUser,
  findByApiKey,
  findByEmail,
  verifyPassword,

  // 配额
  getQuotaInfo,
  recordUsage,

  // 订阅码
  generateSubscriptionCodes,
  redeemCode,
  getUnusedCodes,

  // 统计
  getStats,

  // 配置常量
  FREE_DAILY_QUOTA,
};
