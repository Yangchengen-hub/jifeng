/**
 * 极风工作室 - WebSocket 实时同步系统
 * 实现管理端与官网的实时数据同步
 */

const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');
const db = require('./db');

// WebSocket 服务器
let wss = null;

// 客户端管理
const clients = new Map(); // clientId -> { ws, type, ip, lastActivity }
const adminClients = new Set(); // 管理端 WebSocket 连接

// 消息类型
const MessageType = {
  // 公告相关
  ANNOUNCEMENT_NEW: 'announcement_new',
  ANNOUNCEMENT_UPDATE: 'announcement_update',
  ANNOUNCEMENT_DELETE: 'announcement_delete',
  
  // 系统状态
  SITE_STATUS_CHANGE: 'site_status_change',
  SERVICE_STATUS_CHANGE: 'service_status_change',
  
  // 安全事件
  SECURITY_ALERT: 'security_alert',
  SECURITY_EVENT: 'security_event',
  IP_BANNED: 'ip_banned',
  IP_UNBANNED: 'ip_unbanned',
  
  // 访问统计
  VISITOR_UPDATE: 'visitor_update',
  STATS_UPDATE: 'stats_update',
  
  // 设备信息
  DEVICE_INFO: 'device_info',
  HIGH_RISK_DEVICE: 'high_risk_device',
  
  // 心跳
  HEARTBEAT: 'heartbeat',
  HEARTBEAT_ACK: 'heartbeat_ack',
  
  // 管理
  ADMIN_AUTH: 'admin_auth',
  ADMIN_MESSAGE: 'admin_message',
  BROADCAST: 'broadcast'
};

// 初始化数据库表
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

initWebSocketTables();

// 初始化 WebSocket 服务器
function initWebSocketServer(server) {
  wss = new WebSocket.Server({ 
    server,
    path: '/ws',
    clientTracking: true,
    maxPayload: 1024 * 1024 // 1MB
  });
  
  console.log('[WebSocket] 服务器已启动');
  
  wss.on('connection', (ws, req) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
               req.connection.remoteAddress;
    
    const clientId = crypto.randomBytes(16).toString('hex');
    const clientType = 'visitor';
    
    // 注册客户端
    clients.set(clientId, {
      ws,
      type: clientType,
      ip,
      userAgent: req.headers['user-agent'],
      lastActivity: Date.now()
    });
    
    // 记录到数据库
    try {
      db.prepare(`
        INSERT INTO ws_clients (client_id, client_type, ip, user_agent)
        VALUES (?, ?, ?, ?)
      `).run(clientId, clientType, ip, req.headers['user-agent'] || '');
    } catch (e) {
      console.error('[WebSocket] 记录客户端失败:', e.message);
    }
    
    // 发送欢迎消息
    sendMessage(ws, {
      type: 'connected',
      clientId,
      serverTime: new Date().toISOString()
    });
    
    // 广播访客更新
    broadcastVisitorUpdate();
    
    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        handleMessage(ws, clientId, message);
      } catch (e) {
        console.error('[WebSocket] 解析消息失败:', e.message);
      }
    });
    
    ws.on('close', () => {
      const client = clients.get(clientId);
      if (client) {
        // 如果是管理端，从管理客户端集合移除
        if (client.type === 'admin') {
          adminClients.delete(clientId);
        }
        
        clients.delete(clientId);
        
        // 更新数据库
        db.prepare(`
          UPDATE ws_clients SET disconnected_at = datetime('now')
          WHERE client_id = ?
        `).run(clientId);
        
        // 广播访客更新
        broadcastVisitorUpdate();
      }
    });
    
    ws.on('error', (error) => {
      console.error('[WebSocket] 连接错误:', error.message);
    });
  });
  
  // 心跳检测
  setInterval(() => {
    const now = Date.now();
    for (const [clientId, client] of clients) {
      if (now - client.lastActivity > 60000) { // 60秒无响应
        client.ws.terminate();
        clients.delete(clientId);
      } else {
        sendMessage(client.ws, { type: MessageType.HEARTBEAT });
      }
    }
  }, 30000);
  
  return wss;
}

// 发送消息
function sendMessage(ws, message) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      ...message,
      timestamp: new Date().toISOString()
    }));
  }
}

// 处理接收的消息
function handleMessage(ws, clientId, message) {
  const client = clients.get(clientId);
  if (!client) return;
  
  // 更新活动时间
  client.lastActivity = Date.now();
  
  switch (message.type) {
    case MessageType.HEARTBEAT_ACK:
      // 心跳响应，更新活动时间
      break;
      
    case MessageType.ADMIN_AUTH:
      handleAdminAuth(ws, clientId, message);
      break;
      
    case MessageType.DEVICE_INFO:
      handleDeviceInfo(clientId, message.data);
      break;
      
    case 'request_dynamic_path':
      handleDynamicPathRequest(client.ip);
      break;
      
    case MessageType.BROADCAST:
      if (client.type === 'admin') {
        broadcastToVisitors(message.payload);
      }
      break;
      
    default:
      console.log('[WebSocket] 未知消息类型:', message.type);
  }
}

// 处理管理员认证
function handleAdminAuth(ws, clientId, message) {
  const { token } = message;
  
  // 验证 JWT token (这里简化处理，实际应验证 token)
  const client = clients.get(clientId);
  if (client && token) {
    client.type = 'admin';
    adminClients.add(clientId);
    
    sendMessage(ws, {
      type: 'admin_auth_success',
      message: '管理员认证成功'
    });
    
    console.log(`[WebSocket] 管理员已连接: ${client.ip}`);
  }
}

// 处理设备信息
function handleDeviceInfo(clientId, deviceData) {
  const client = clients.get(clientId);
  if (!client) return;
  
  // 存储设备信息
  const { saveDeviceFingerprint } = require('./security-advanced');
  if (saveDeviceFingerprint && deviceData.fingerprint) {
    saveDeviceFingerprint(client.ip, deviceData.fingerprint);
  }
  
  // 检查风险等级
  if (deviceData.riskScore && deviceData.riskScore >= 50) {
    // 高风险设备，通知管理端
    broadcastToAdmins({
      type: MessageType.HIGH_RISK_DEVICE,
      data: {
        ip: client.ip,
        clientId,
        riskScore: deviceData.riskScore,
        riskFactors: deviceData.riskFactors,
        fingerprint: deviceData.fingerprint
      }
    });
  }
}

// 处理动态路径请求
function handleDynamicPathRequest(ip) {
  const { createDynamicPathForIP } = require('./security-advanced');
  const { sendDynamicPath } = require('./email-service');
  
  if (createDynamicPathForIP) {
    const path = createDynamicPathForIP(ip);
    
    // 发送邮件
    if (sendDynamicPath) {
      sendDynamicPath(path, ip);
    }
    
    console.log(`[WebSocket] 动态路径已生成: ${path} for ${ip}`);
  }
}

// 广播给所有访客
function broadcastToVisitors(message) {
  for (const [clientId, client] of clients) {
    if (client.type === 'visitor') {
      sendMessage(client.ws, message);
    }
  }
}

// 广播给所有管理员
function broadcastToAdmins(message) {
  for (const [clientId, client] of clients) {
    if (client.type === 'admin') {
      sendMessage(client.ws, message);
    }
  }
}

// 广播访客更新
function broadcastVisitorUpdate() {
  const visitorCount = Array.from(clients.values())
    .filter(c => c.type === 'visitor').length;
  
  broadcastToAdmins({
    type: MessageType.VISITOR_UPDATE,
    data: {
      onlineVisitors: visitorCount,
      timestamp: new Date().toISOString()
    }
  });
}

// ============ 公告管理 ============

function createAnnouncement(title, content, type = 'info', priority = 0, createdBy = null) {
  const result = db.prepare(`
    INSERT INTO announcements (title, content, type, priority, created_by)
    VALUES (?, ?, ?, ?, ?)
  `).run(title, content, type, priority, createdBy);
  
  const announcement = {
    id: result.lastInsertRowid,
    title,
    content,
    type,
    priority,
    created_at: new Date().toISOString()
  };
  
  // 实时广播到所有客户端
  broadcastToVisitors({
    type: MessageType.ANNOUNCEMENT_NEW,
    data: announcement
  });
  
  broadcastToAdmins({
    type: MessageType.ANNOUNCEMENT_NEW,
    data: announcement
  });
  
  return announcement;
}

function updateAnnouncement(id, updates) {
  const fields = [];
  const values = [];
  
  if (updates.title) { fields.push('title = ?'); values.push(updates.title); }
  if (updates.content) { fields.push('content = ?'); values.push(updates.content); }
  if (updates.type) { fields.push('type = ?'); values.push(updates.type); }
  if (updates.priority !== undefined) { fields.push('priority = ?'); values.push(updates.priority); }
  if (updates.visible !== undefined) { fields.push('visible = ?'); values.push(updates.visible ? 1 : 0); }
  
  fields.push('updated_at = datetime(\'now\')');
  values.push(id);
  
  db.prepare(`UPDATE announcements SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  
  const announcement = getAnnouncement(id);
  
  // 实时广播更新
  broadcastToVisitors({
    type: MessageType.ANNOUNCEMENT_UPDATE,
    data: announcement
  });
  
  broadcastToAdmins({
    type: MessageType.ANNOUNCEMENT_UPDATE,
    data: announcement
  });
  
  return announcement;
}

function deleteAnnouncement(id) {
  db.prepare('DELETE FROM announcements WHERE id = ?').run(id);
  
  // 实时广播删除
  broadcastToVisitors({
    type: MessageType.ANNOUNCEMENT_DELETE,
    data: { id }
  });
  
  broadcastToAdmins({
    type: MessageType.ANNOUNCEMENT_DELETE,
    data: { id }
  });
}

function getAnnouncement(id) {
  return db.prepare('SELECT * FROM announcements WHERE id = ?').get(id);
}

function getVisibleAnnouncements() {
  return db.prepare(`
    SELECT * FROM announcements 
    WHERE visible = 1 
    ORDER BY priority DESC, created_at DESC
  `).all();
}

function getAllAnnouncements() {
  return db.prepare(`
    SELECT * FROM announcements 
    ORDER BY created_at DESC
  `).all();
}

// ============ 系统状态同步 ============

function broadcastSiteStatusChange(enabled) {
  broadcastToVisitors({
    type: MessageType.SITE_STATUS_CHANGE,
    data: { enabled }
  });
  
  broadcastToAdmins({
    type: MessageType.SITE_STATUS_CHANGE,
    data: { enabled }
  });
}

function broadcastServiceStatusChange(service, enabled) {
  broadcastToAdmins({
    type: MessageType.SERVICE_STATUS_CHANGE,
    data: { service, enabled }
  });
}

function broadcastSecurityAlert(alert) {
  broadcastToAdmins({
    type: MessageType.SECURITY_ALERT,
    data: alert
  });
}

function broadcastIPBanned(ip, reason) {
  broadcastToAdmins({
    type: MessageType.IP_BANNED,
    data: { ip, reason, timestamp: new Date().toISOString() }
  });
}

function broadcastIPUnbanned(ip) {
  broadcastToAdmins({
    type: MessageType.IP_UNBANNED,
    data: { ip, timestamp: new Date().toISOString() }
  });
}

// ============ 统计数据 ============

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
  
  // 公告
  createAnnouncement,
  updateAnnouncement,
  deleteAnnouncement,
  getAnnouncement,
  getVisibleAnnouncements,
  getAllAnnouncements,
  
  // 状态同步
  broadcastSiteStatusChange,
  broadcastServiceStatusChange,
  broadcastSecurityAlert,
  broadcastIPBanned,
  broadcastIPUnbanned,
  
  // 统计
  getOnlineStats,
  
  // 客户端管理
  clients,
  adminClients
};