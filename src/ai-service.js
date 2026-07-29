/**
 * ai-service.js — 极风 AI 服务统一封装
 *
 * 支持 OpenAI 兼容协议（DeepSeek / 智谱GLM / Moonshot / OpenAI / 通义千问等）
 * 通过环境变量配置：
 *   AI_API_KEY   — API Key（必填才能启用真实 AI）
 *   AI_API_BASE  — 接口基址（默认 https://api.deepseek.com/v1）
 *   AI_MODEL     — 模型名（默认 deepseek-chat）
 *
 * 无 Key 时自动降级为本地规则引擎，保证服务不中断。
 */

const crypto = require('crypto');

const DEFAULT_BASE = 'https://api.deepseek.com/v1';
const DEFAULT_MODEL = 'deepseek-chat';
const TIMEOUT_MS = 25000;

/* ----------------- 配置 ----------------- */
function getConfig() {
  return {
    apiKey: process.env.AI_API_KEY || '',
    apiBase: (process.env.AI_API_BASE || DEFAULT_BASE).replace(/\/$/, ''),
    model: process.env.AI_MODEL || DEFAULT_MODEL,
    enabled: !!(process.env.AI_API_KEY && process.env.AI_API_KEY.trim()),
  };
}

/* ----------------- 内部工具 ----------------- */
function safeFetch(url, opts, timeout = TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const ctrl = setTimeout(() => reject(new Error('AI 请求超时')), timeout);
    fetch(url, opts)
      .then((r) => {
        clearTimeout(ctrl);
        resolve(r);
      })
      .catch((e) => {
        clearTimeout(ctrl);
        reject(e);
      });
  });
}

/**
 * 调用 OpenAI 兼容 /chat/completions
 * @param {Array<{role:string,content:string}>} messages
 * @param {object} opts {temperature, max_tokens, system}
 * @returns {Promise<{ok:boolean, content:string, usage?:object, raw?:object, error?:string}>}
 */
async function chat(messages, opts = {}) {
  const cfg = getConfig();
  const full = [];
  if (opts.system) {
    full.push({ role: 'system', content: opts.system });
  }
  full.push(...messages);

  if (!cfg.enabled) {
    return {
      ok: false,
      content: '',
      error: 'AI_SERVICE_NOT_CONFIGURED',
      message: '管理员尚未配置 AI API Key，降级为本地规则引擎。',
    };
  }

  try {
    const res = await safeFetch(`${cfg.apiBase}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${cfg.apiKey}`,
      },
      body: JSON.stringify({
        model: cfg.model,
        messages: full,
        temperature: opts.temperature ?? 0.6,
        max_tokens: opts.max_tokens ?? 1200,
        stream: false,
      }),
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      return { ok: false, content: '', error: `AI_HTTP_${res.status}`, message: txt.slice(0, 300) };
    }

    const data = await res.json();
    const content = data?.choices?.[0]?.message?.content ?? '';
    return {
      ok: true,
      content,
      usage: data.usage,
      raw: { model: data.model, id: data.id },
    };
  } catch (e) {
    return { ok: false, content: '', error: 'AI_NETWORK', message: e.message };
  }
}

/* ----------------- 业务场景 ----------------- */

/**
 * 客服：解答玩机文化 / 安装问题
 */
async function customerService(userMessage, history = [], context = {}) {
  const cfg = getConfig();
  const system = [
    '你是「极风工作室」官网的 AI 客服助手，名为极风智答。',
    '工作室专注于安卓玩机工具开发，代表作有「极风工具箱(JFToolbox)」与「极风环境检测(JifengEnvDetect)」。',
    '你的职责：',
    '1. 解答用户关于玩机文化、刷机、Magisk/KernelSU 模块、Xposed、root、救砖等技术问题；',
    '2. 指导用户下载与安装工作室的两款 APK；',
    '3. 解释环境检测的用途（如检测设备是否伪装、是否符合某些 App 的运行环境）；',
    '4. 回答关于工作室文化、开源精神、更新节奏等非技术问题。',
    '语气要求：专业、简洁、友好，中文回答，单条回复不超过 400 字。',
    '安全要求：',
    '- 不讨论绕过银行/支付类风控、不涉及违法用途；',
    '- 涉及刷机风险时必须提醒用户备份与免责声明；',
    '- 不泄露内部实现细节、密钥、管理员信息。',
  ].join('\n');

  const msgs = [];
  for (const h of history.slice(-6)) {
    msgs.push({ role: h.role === 'assistant' ? 'assistant' : 'user', content: h.content });
  }
  msgs.push({ role: 'user', content: userMessage });

  const r = await chat(msgs, { system, temperature: 0.5, max_tokens: 700 });
  if (!r.ok) {
    return fallbackCustomer(userMessage, context);
  }
  return { ok: true, content: r.content, model: r.raw?.model, usage: r.usage };
}

/**
 * 摘要：把 release notes 总结为简短公告
 */
async function summarizeRelease(repo, release) {
  const cfg = getConfig();
  const txt = [
    `仓库：${repo}`,
    `版本：${release.tag_name}`,
    `发布时间：${release.published_at}`,
    `标题：${release.name || release.tag_name}`,
    `更新内容：`,
    (release.body || '(无描述)').slice(0, 2500),
  ].join('\n');

  const system = [
    '你是极风工作室的发布编辑助手。请把 GitHub Release 的更新说明总结为一条中文公告。',
    '要求：',
    '1. 第一行给出 20 字以内的标题；',
    '2. 随后用 3-6 条要点列出本次更新亮点；',
    '3. 末尾标注来源版本号与发布时间；',
    '4. 全文不超过 300 字，使用 Markdown 列表格式。',
    '输出格式：',
    'TITLE: <标题>',
    'BODY:',
    '- 要点1',
    '- 要点2',
    '...',
    'SOURCE: <版本> @ <时间>',
  ].join('\n');

  const r = await chat([{ role: 'user', content: txt }], {
    system,
    temperature: 0.3,
    max_tokens: 500,
  });

  if (!r.ok) {
    // 降级：直接截取原文
    return fallbackSummary(release);
  }
  return parseSummary(r.content, release);
}

/**
 * 审核：判断用户提交内容是否违规
 * @returns {Promise<{verdict:'approve'|'reject'|'review', reason:string, confidence:number}>}
 */
async function moderate({ nickname = '', content = '', ip = '' } = {}) {
  const cfg = getConfig();
  if (!cfg.enabled) {
    // 无 AI 时使用关键词规则降级
    return ruleBasedModerate(content);
  }

  const system = [
    '你是内容安全审核 AI。判断用户提交的内容是否违规，输出 JSON。',
    '违规类别：垃圾广告、色情、赌博、暴力、政治敏感、人身攻击、违法信息、钓鱼链接。',
    '输出格式（严格 JSON）：',
    '{"verdict":"approve|reject|review","reason":"简短中文说明","confidence":0.0-1.0}',
    '- approve：内容安全；',
    '- reject：明确违规，应直接拦截；',
    '- review：疑似违规或不确定，转人工。',
  ].join('\n');

  const user = JSON.stringify({ nickname, content: String(content).slice(0, 800), ip });
  const r = await chat([{ role: 'user', content: user }], {
    system,
    temperature: 0.1,
    max_tokens: 200,
  });

  if (!r.ok) return ruleBasedModerate(content);

  const parsed = tryParseJson(r.content);
  if (parsed && ['approve', 'reject', 'review'].includes(parsed.verdict)) {
    return {
      verdict: parsed.verdict,
      reason: parsed.reason || 'AI 审核',
      confidence: Math.max(0, Math.min(1, Number(parsed.confidence) || 0.5)),
    };
  }
  return ruleBasedModerate(content);
}

/* ----------------- 降级实现 ----------------- */
function fallbackCustomer(msg) {
  const m = (msg || '').toLowerCase();
  if (/下载|安装|apk/.test(m)) {
    return {
      ok: true,
      content: '您可以在「极风工具箱」或「极风环境检测」页面点击「下载 APK」按钮，会自动获取最新版本。如果按钮显示准备中，请稍候几秒，系统正在向仓库请求最新资源。',
      fallback: true,
    };
  }
  if (/root|magisk|ksu|kernelsu/.test(m)) {
    return {
      ok: true,
      content: '玩机相关：刷入 Magisk 或 KernelSU 后，建议先在「极风环境检测」里跑一遍完整检测，确认环境伪装到位再使用目标 App。刷机有风险，请务必提前备份。',
      fallback: true,
    };
  }
  if (/环境检测|检测/.test(m)) {
    return {
      ok: true,
      content: '极风环境检测用于排查设备环境是否被某些 App 识别为风险设备，例如 root 状态、Magisk 模块、Xposed、应用列表等。检测结果仅供参考。',
      fallback: true,
    };
  }
  return {
    ok: true,
    content: '感谢联系极风工作室。AI 客服当前处于离线模式，您可以稍后再试，或在 GitHub 提 issue 联系作者。',
    fallback: true,
  };
}

function fallbackSummary(release) {
  const tag = release.tag_name || 'unknown';
  const name = release.name || tag;
  const body = (release.body || '').split('\n').filter((x) => x.trim()).slice(0, 6);
  const date = release.published_at ? new Date(release.published_at).toLocaleDateString('zh-CN') : '';
  return {
    title: `${name} 已发布`,
    body: body.length ? body.map((x) => `- ${x.replace(/^[-*]\s*/, '').slice(0, 80)}`).join('\n') : '- 本次更新内容详见仓库',
    source: `${tag} @ ${date}`,
    fallback: true,
  };
}

function ruleBasedModerate(content) {
  const c = String(content || '');
  const blacklist = ['色情', '赌博', '六合彩', '枪支', '代开发票', '办证', '黑产', '钓鱼'];
  const hit = blacklist.find((k) => c.includes(k));
  if (hit) {
    return { verdict: 'reject', reason: `命中敏感词：${hit}`, confidence: 0.85, fallback: true };
  }
  if (/https?:\/\//i.test(c) && c.length < 30) {
    return { verdict: 'review', reason: '内容过短且包含链接，需人工复核', confidence: 0.5, fallback: true };
  }
  return { verdict: 'approve', reason: '本地规则通过', confidence: 0.5, fallback: true };
}

/* ----------------- 解析工具 ----------------- */
function parseSummary(text, release) {
  const lines = String(text || '').split('\n');
  let title = '';
  let bodyStart = -1;
  let source = '';
  const bodyLines = [];
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i].trim();
    if (!title && /^TITLE\s*:/i.test(ln)) {
      title = ln.replace(/^TITLE\s*:\s*/i, '').trim();
    } else if (bodyStart < 0 && /^BODY\s*:?$/i.test(ln)) {
      bodyStart = i + 1;
    } else if (/^SOURCE\s*:/i.test(ln)) {
      source = ln.replace(/^SOURCE\s*:\s*/i, '').trim();
    } else if (bodyStart >= 0 && ln) {
      bodyLines.push(ln);
    }
  }
  if (!title) title = (release.name || release.tag_name || '版本更新') + ' 已发布';
  if (!bodyLines.length) bodyLines.push('- 详见仓库更新说明');
  if (!source) source = `${release.tag_name} @ ${release.published_at || ''}`;
  return { title, body: bodyLines.join('\n'), source };
}

function tryParseJson(s) {
  try {
    const m = String(s).match(/\{[\s\S]*\}/);
    if (!m) return null;
    return JSON.parse(m[0]);
  } catch (_) {
    return null;
  }
}

/* ----------------- 对外接口 ----------------- */
module.exports = {
  getConfig,
  chat,
  customerService,
  summarizeRelease,
  moderate,
  // 用于随机生成会话 id
  newSessionId: () => crypto.randomBytes(12).toString('hex'),
};
