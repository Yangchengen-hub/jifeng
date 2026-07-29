/**
 * 极风工作室 - WebSocket 实时同步系统
 * 实现管理端与官网的实时数据同步
 *
 * 注意：Vercel Serverless 环境下不能持有 WebSocket 长连接。
 * 本文件仅在本地开发或自建服务器模式下初始化真实连接；
 * Serverless 模式下所有 broadcast/send 调用会被安全跳过。
 */

const crypto = require('crypto');
const db = require('./db');

let WebSocketClass = null;
let wss = null;
let initialized = false;

// 客户端管理
const clients = new Map();
const adminClients = new Set();

// 消息类型
const MessageType = {
  ANNOUNCEMENT_NEW: 'announcement_new',
  ANNOUNCEMENT_UPDATE: 'announcement_update',
  ANNOUNCEMENT_DELETE: 'announcement_delete',
  SITE_STATUS_CHANGE: 'site_status_change',
  SERVICE_STATUS_CHANGE: 'service_status_change',
  SECURITY_ALERT: 'security_alert',
  SECURITY_EVENT: 'security_event',
  IP_BANNED: 'ip_banned',
  IP_UNBANNED: 'ip_unbanned',
  VISITOR_UPDATE: 'visitor_update',
  STATS_UPDATE: 'stats_update',
  DEVICE_INFO: 'device_info',
  HIGH_RISK_DEVICE: 'high_risk_device',
  HEARTBEAT: 'heartbeat',
  HEARTBEAT_ACK: 'heartbeat_ack',
  ADMIN_AUTH: 'admin_auth',
  ADMIN_MESSAGE: 'admin_message',
  BROADCAST: 'broadcast'
};

function initWebSocketTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      type TEXT DEFAULT 'info',
      priority INTEGER DEFAULT 0,
      visible INTEGER DEFAULT 1,
      created_by TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME
    );

    CREATE TABLE IF NOT EXISTS realtime_stats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      stat_key TEXT NOT NULL,
      stat_value TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS ws_clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id TEXT UNIQUE NOT NULL,
      client_type TEXT NOT NULL,
      ip TEXT,
      user_agent TEXT,
      connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
      disconnected_at DATETIME
    );

    CREATE INDEX IF NOT EXISTS idx_announcements_visible ON announcements(visible);
    CREATE INDEX IF NOT EXISTS idx_announcements_created ON announcements(created_at);
  `);
}

/**
 * 仅在本地/自建服务器下初始化。Vercel Serverless 下不要调用。
 */
function initWebSocketServer(server) {
  if (initialized) return wss;
  initialized = true;

  try {
    WebSocketClass = require('ws');
  } catch (e) {
    console.warn('[WebSocket] ws 模块未安装，跳过 WebSocket 初始化');
    return null;
  }

  initWebSocketTables();

  wss = new WebSocketClass.Server({
    server,
    path: '/ws',
    clientTracking: true,
    maxPayload: 1024 * 1024
  });

  console.log('[WebSocket] 服务器已启动');

  wss.on('connection', (ws, req) => {
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
               (req.connection && req.connection.remoteAddress) || '';

    const clientId = crypto.randomBytes(16).toString('hex');

    clients.set(clientId, {
      ws,
      type: 'visitor',
      ip,
      userAgent: req.headers['user-agent'],
      lastActivity: Date.now()
    });

    try {
      db.prepare(`
        INSERT INTO ws_clients (client_id, client_type, ip, user_agent)
        VALUES (?, ?, ?, ?)
      `).run(clientId, 'visitor', ip, req.headers['user-agent'] || '');
    } catch (e) {
      // 忽略
    }

    sendMessage(ws, {
      type: 'connected',
      clientId,
      serverTime: new Date().toISOString()
    });

    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        handleMessage(ws, clientId, message);
      } catch (_) {}
    });

    ws.on('close', () => {
      const client = clients.get(clientId);
      if (client) {
        if (client.type === 'admin') adminClients.delete(clientId);
        clients.delete(clientId);
        try {
          db.prepare(`
            UPDATE ws_clients SET disconnected_at = datetime('now')
            WHERE client_id = ?
          `).run(clientId);
        } catch (_) {}
        broadcastVisitorUpdate();
      }
    });

    ws.on('error', () => {});
  });

  setInterval(() => {
    const now = Date.now();
    for (const [clientId, client] of clients) {
      if (now - client.lastActivity > 60000) {
        try { client.ws.terminate(); } catch (_) {}
        clients.delete(clientId);
      } else {
        sendMessage(client.ws, { type: MessageType.HEARTBEAT });
      }
    }
  }, 30000);

  return wss;
}

function sendMessage(ws, message) {
  if (ws && ws.readyState === 1) {
    try {
      ws.send(JSON.stringify({ ...message, timestamp: new Date().toISOString() }));
    } catch (_) {}
  }
}

function handleMessage(ws, clientId, message) {
  const client = clients.get(clientId);
  if (!client) return;
  client.lastActivity = Date.now();

  switch (message.type) {
    case MessageType.HEARTBEAT_ACK: break;
    case MessageType.ADMIN_AUTH: handleAdminAuth(ws, clientId, message); break;
    case MessageType.DEVICE_INFO: handleDeviceInfo(clientId, message.data); break;
    case 'request_dynamic_path': handleDynamicPathRequest(client.ip); break;
    case MessageType.BROADCAST:
      if (client.type === 'admin') broadcastToVisitors(message.payload);
      break;
    default: break;
  }
}

function handleAdminAuth(ws, clientId, message) {
  const client = clients.get(clientId);
  if (client && message.token) {
    client.type = 'admin';
    adminClients.add(clientId);
    sendMessage(ws, { type: 'admin_auth_success', message: '管理员认证成功' });
  }
}

function handleDeviceInfo(clientId, deviceData) {
  const client = clients.get(clientId);
  if (!client) return;
  if (deviceData && deviceData.riskScore && deviceData.riskScore >= 50) {
    broadcastToAdmins({
      type: MessageType.HIGH_RISK_DEVICE,
      data: { ip: client.ip, clientId, riskScore: deviceData.riskScore, riskFactors: deviceData.riskFactors }
    });
  }
}

function handleDynamicPathRequest(ip) {
  try {
    const { createDynamicPathForIP } = require('./security-advanced');
    const path = createDynamicPathForIP(ip);
    console.log(`[WebSocket] 动态路径已生成: ${path} for ${ip}`);
  } catch (_) {}
}

function broadcastToVisitors(message) {
  for (const client of clients.values()) {
    if (client.type === 'visitor') sendMessage(client.ws, message);
  }
}

function broadcastToAdmins(message) {
  for (const client of clients.values()) {
    if (client.type === 'admin') sendMessage(client.ws, message);
  }
}

function broadcastVisitorUpdate() {
  const visitorCount = Array.from(clients.values()).filter(c => c.type === 'visitor').length;
  broadcastToAdmins({ type: MessageType.VISITOR_UPDATE, data: { onlineVisitors: visitorCount, timestamp: new Date().toISOString() } });
}

// ============ 公告管理 ============

function createAnnouncement(title, content, type = 'info', priority = 0, createdBy = null) {
  initWebSocketTables();
  const result = db.prepare(`
    INSERT INTO announcements (title, content, type, priority, created_by)
    VALUES (?, ?, ?, ?, ?)
  `).run(title, content, type, priority, createdBy);

  const announcement = {
    id: result.lastInsertRowid,
    title, content, type, priority,
    created_at: new Date().toISOString()
  };
  broadcastToVisitors({ type: MessageType.ANNOUNCEMENT_NEW, data: announcement });
  broadcastToAdmins({ type: MessageType.ANNOUNCEMENT_NEW, data: announcement });
  return announcement;
}

function updateAnnouncement(id, updates) {
  initWebSocketTables();
  const fields = [];
  const values = [];
  if (updates.title) { fields.push('title = ?'); values.push(updates.title); }
  if (updates.content) { fields.push('content = ?'); values.push(updates.content); }
  if (updates.type) { fields.push('type = ?'); values.push(updates.type); }
  if (updates.priority !== undefined) { fields.push('priority = ?'); values.push(updates.priority); }
  if (updates.visible !== undefined) { fields.push('visible = ?'); values.push(updates.visible ? 1 : 0); }
  fields.push("updated_at = datetime('now')");
  values.push(id);
  db.prepare(`UPDATE announcements SET ${fields.join(', ')} WHERE id = ?`).run(...values);

  const announcement = getAnnouncement(id);
  broadcastToVisitors({ type: MessageType.ANNOUNCEMENT_UPDATE, data: announcement });
  broadcastToAdmins({ type: MessageType.ANNOUNCEMENT_UPDATE, data: announcement });
  return announcement;
}

function deleteAnnouncement(id) {
  initWebSocketTables();
  db.prepare('DELETE FROM announcements WHERE id = ?').run(id);
  broadcastToVisitors({ type: MessageType.ANNOUNCEMENT_DELETE, data: { id } });
  broadcastToAdmins({ type: MessageType.ANNOUNCEMENT_DELETE, data: { id } });
}

function getAnnouncement(id) {
  initWebSocketTables();
  return db.prepare('SELECT * FROM announcements WHERE id = ?').get(id);
}

function getVisibleAnnouncements() {
  initWebSocketTables();
  return db.prepare(`SELECT * FROM announcements WHERE visible = 1 ORDER BY priority DESC, created_at DESC`).all();
}

function getAllAnnouncements() {
  initWebSocketTables();
  return db.prepare(`SELECT * FROM announcements ORDER BY created_at DESC`).all();
}

function broadcastSiteStatusChange(enabled) {
  broadcastToVisitors({ type: MessageType.SITE_STATUS_CHANGE, data: { enabled } });
  broadcastToAdmins({ type: MessageType.SITE_STATUS_CHANGE, data: { enabled } });
}
function broadcastServiceStatusChange(service, enabled) {
  broadcastToAdmins({ type: MessageType.SERVICE_STATUS_CHANGE, data: { service, enabled } });
}
function broadcastSecurityAlert(alert) {
  broadcastToAdmins({ type: MessageType.SECURITY_ALERT, data: alert });
}
function broadcastIPBanned(ip, reason) {
  broadcastToAdmins({ type: MessageType.IP_BANNED, data: { ip, reason, timestamp: new Date().toISOString() } });
}
function broadcastIPUnbanned(ip) {
  broadcastToAdmins({ type: MessageType.IP_UNBANNED, data: { ip, timestamp: new Date().toISOString() } });
}
function getOnlineStats() {
  return {
    totalClients: clients.size,
    visitors: Array.from(clients.values()).filter(c => c.type === 'visitor').length,
    admins: adminClients.size,
    uniqueIPs: new Set(Array.from(clients.values()).map(c => c.ip)).size
  };
}

module.exports = {
  initWebSocketServer,
  sendMessage,
  broadcastToVisitors,
  broadcastToAdmins,
  MessageType,
  createAnnouncement,
  updateAnnouncement,
  deleteAnnouncement,
  getAnnouncement,
  getVisibleAnnouncements,
  getAllAnnouncements,
  broadcastSiteStatusChange,
  broadcastServiceStatusChange,
  broadcastSecurityAlert,
  broadcastIPBanned,
  broadcastIPUnbanned,
  getOnlineStats,
  clients,
  adminClients
};
