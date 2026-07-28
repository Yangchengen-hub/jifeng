const db = require('./db');

function logAccess(req, res, next) {
  const startTime = req.startTime || Date.now();
  const ua = req.uaAnalysis || {};
  
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const responseTime = Date.now() - startTime;
    
    try {
      db.prepare(`
        INSERT INTO access_logs (
          ip, method, path, status_code, user_agent, referer, accept_language,
          browser, browser_version, os, os_version, device, device_type,
          is_mobile, is_bot, bot_name, response_time, request_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.ip,
        req.method,
        req.originalUrl || req.url,
        res.statusCode,
        req.headers['user-agent'] || '',
        req.headers['referer'] || '',
        req.headers['accept-language'] || '',
        ua.browser || 'Unknown',
        ua.browser_version || 'Unknown',
        ua.os || 'Unknown',
        ua.os_version || 'Unknown',
        ua.device || 'Unknown',
        ua.device_type || 'unknown',
        ua.is_mobile ? 1 : 0,
        ua.is_bot ? 1 : 0,
        ua.bot_name || null,
        responseTime,
        req.requestId
      );
    } catch (e) {
      console.error('[AccessLog] Failed to log:', e.message);
    }
    
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
}

function getAccessStats(hours = 24) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
  
  const totalVisits = db.prepare(
    'SELECT COUNT(*) as count FROM access_logs WHERE created_at >= ?'
  ).get(since).count;
  
  const uniqueVisitors = db.prepare(
    'SELECT COUNT(DISTINCT ip) as count FROM access_logs WHERE created_at >= ?'
  ).get(since).count;
  
  const botVisits = db.prepare(
    'SELECT COUNT(*) as count FROM access_logs WHERE created_at >= ? AND is_bot = 1'
  ).get(since).count;
  
  const blockedRequests = db.prepare(
    'SELECT COUNT(*) as count FROM security_events WHERE created_at >= ? AND blocked = 1'
  ).get(since).count;
  
  const pageViews = db.prepare(
    'SELECT path, COUNT(*) as views FROM access_logs WHERE created_at >= ? AND status_code = 200 GROUP BY path ORDER BY views DESC LIMIT 10'
  ).all(since);
  
  const topPages = db.prepare(`
    SELECT path, COUNT(*) as views, COUNT(DISTINCT ip) as visitors
    FROM access_logs 
    WHERE created_at >= ? AND method = 'GET' AND status_code = 200
    GROUP BY path 
    ORDER BY views DESC 
    LIMIT 10
  `).all(since);
  
  const osStats = db.prepare(`
    SELECT os, COUNT(*) as count, COUNT(DISTINCT ip) as visitors
    FROM access_logs 
    WHERE created_at >= ? AND is_bot = 0
    GROUP BY os 
    ORDER BY count DESC 
    LIMIT 10
  `).all(since);
  
  const browserStats = db.prepare(`
    SELECT browser, COUNT(*) as count, COUNT(DISTINCT ip) as visitors
    FROM access_logs 
    WHERE created_at >= ? AND is_bot = 0
    GROUP BY browser 
    ORDER BY count DESC 
    LIMIT 10
  `).all(since);
  
  const deviceStats = db.prepare(`
    SELECT 
      CASE 
        WHEN is_mobile = 1 THEN 'mobile'
        ELSE 'desktop'
      END as device_type,
      COUNT(*) as count,
      COUNT(DISTINCT ip) as visitors
    FROM access_logs 
    WHERE created_at >= ? AND is_bot = 0
    GROUP BY device_type
    ORDER BY count DESC
  `).all(since);
  
  const hourlyData = db.prepare(`
    SELECT 
      strftime('%Y-%m-%d %H:00:00', created_at) as hour,
      COUNT(*) as visits,
      COUNT(DISTINCT ip) as visitors,
      SUM(CASE WHEN is_bot = 1 THEN 1 ELSE 0 END) as bots
    FROM access_logs 
    WHERE created_at >= ?
    GROUP BY hour
    ORDER BY hour ASC
  `).all(since);
  
  return {
    totalVisits,
    uniqueVisitors,
    botVisits,
    blockedRequests,
    pageViews,
    topPages,
    osStats,
    browserStats,
    deviceStats,
    hourlyData
  };
}

function getRecentLogs(limit = 50, offset = 0) {
  return db.prepare(`
    SELECT * FROM access_logs 
    ORDER BY created_at DESC 
    LIMIT ? OFFSET ?
  `).all(limit, offset);
}

function getSecurityStats(hours = 24) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
  
  const byType = db.prepare(`
    SELECT type, severity, COUNT(*) as count
    FROM security_events 
    WHERE created_at >= ?
    GROUP BY type, severity
    ORDER BY count DESC
  `).all(since);
  
  const bySeverity = db.prepare(`
    SELECT severity, COUNT(*) as count
    FROM security_events 
    WHERE created_at >= ?
    GROUP BY severity
    ORDER BY count DESC
  `).all(since);
  
  const topBlockedIPs = db.prepare(`
    SELECT ip, COUNT(*) as blocks, MAX(created_at) as last_block
    FROM security_events 
    WHERE created_at >= ? AND blocked = 1
    GROUP BY ip
    ORDER BY blocks DESC
    LIMIT 10
  `).all(since);
  
  const recentEvents = db.prepare(`
    SELECT * FROM security_events 
    ORDER BY created_at DESC 
    LIMIT 50
  `).all();
  
  const totalBlocked = db.prepare(
    'SELECT COUNT(*) as count FROM security_events WHERE created_at >= ? AND blocked = 1'
  ).get(since).count;
  
  return {
    byType,
    bySeverity,
    topBlockedIPs,
    recentEvents,
    totalBlocked
  };
}

module.exports = {
  logAccess,
  getAccessStats,
  getRecentLogs,
  getSecurityStats
};
