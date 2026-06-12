/**
 * 订阅码生成工具
 * 用法：node scripts/generate-codes.js [数量] [级别] [月数]
 * 示例：node scripts/generate-codes.js 50 pro 1
 */

const path = require("path");
const UserSystem = require("../users.js");

async function main() {
  const args = process.argv.slice(2);
  const count = parseInt(args[0]) || 10;
  const tier = args[1] || "pro";
  const months = parseInt(args[2]) || 1;

  if (!["pro", "enterprise"].includes(tier)) {
    console.error("级别必须是 pro 或 enterprise");
    process.exit(1);
  }

  console.log(`正在生成 ${count} 个 ${tier} 订阅码（${months}个月）...\n`);

  const codes = await UserSystem.generateSubscriptionCodes(count, tier, months);

  console.log("========== 生成的订阅码 ==========");
  codes.forEach((c, i) => {
    console.log(`  ${String(i + 1).padStart(3, "0")}. ${c.code}  (${c.tier}, ${c.months}个月)`);
  });
  console.log(`\n共生成 ${codes.length} 个订阅码`);
  console.log("这些订阅码可在 Gumroad 上按个售卖，用户在网站输入后自动激活。");
}

main().catch(console.error);
