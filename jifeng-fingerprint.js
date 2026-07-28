/**
 * 极风工作室 - 高级设备指纹收集系统
 * 收集详细设备信息用于安全分析和风险识别
 */

(function() {
  'use strict';
  
  // 设备指纹数据
  const fingerprint = {
    hash: null,
    canvasHash: null,
    webglHash: null,
    audioHash: null,
    fontsHash: null,
    screenInfo: {},
    timezone: null,
    language: null,
    plugins: [],
    hardwareInfo: {},
    browserFeatures: {},
    // 新增：扩展设备信息
    batteryInfo: {},
    networkInfo: {},
    sensorInfo: {},
    gpuInfo: {},
    storageInfo: {},
    mediaDevicesInfo: {},
    riskScore: 0,
    riskFactors: []
  };
  
  // 收集屏幕信息
  function collectScreenInfo() {
    return {
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelDepth: screen.pixelDepth,
      devicePixelRatio: window.devicePixelRatio || 1,
      orientation: screen.orientation ? screen.orientation.type : 'unknown'
    };
  }
  
  // 收集 Canvas 指纹
  function collectCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 280;
      canvas.height = 60;
      canvas.style.display = 'none';
      
      const ctx = canvas.getContext('2d');
      
      // 绘制测试图案
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('极风工作室 JIFENG', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('Fingerprint Canvas 1234', 4, 45);
      
      // 绘制圆形和线条
      ctx.globalCompositeOperation = 'multiply';
      ctx.beginPath();
      ctx.arc(50, 30, 25, 0, Math.PI * 2);
      ctx.fillStyle = '#ff6600';
      ctx.fill();
      ctx.beginPath();
      ctx.arc(100, 30, 25, 0, Math.PI * 2);
      ctx.fillStyle = '#0066ff';
      ctx.fill();
      
      // 获取数据 URL 并生成哈希
      const dataURL = canvas.toDataURL();
      return hashString(dataURL);
    } catch (e) {
      return 'canvas_error_' + e.message.length;
    }
  }
  
  // 收集 WebGL 指纹
  function collectWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      
      if (!gl) {
        return 'webgl_not_supported';
      }
      
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const webglInfo = {
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        unmaskedVendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown',
        unmaskedRenderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown',
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS),
        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        redBits: gl.getParameter(gl.RED_BITS),
        greenBits: gl.getParameter(gl.GREEN_BITS),
        blueBits: gl.getParameter(gl.BLUE_BITS),
        alphaBits: gl.getParameter(gl.ALPHA_BITS),
        depthBits: gl.getParameter(gl.DEPTH_BITS),
        stencilBits: gl.getParameter(gl.STENCIL_BITS)
      };
      
      return hashString(JSON.stringify(webglInfo));
    } catch (e) {
      return 'webgl_error_' + e.message.length;
    }
  }
  
  // 收集音频指纹
  function collectAudioFingerprint() {
    try {
      const audioContext = window.AudioContext || window.webkitAudioContext;
      if (!audioContext) {
        return 'audio_not_supported';
      }
      
      const context = new audioContext();
      const oscillator = context.createOscillator();
      const compressor = context.createDynamicsCompressor();
      const gain = context.createGain();
      
      oscillator.type = 'triangle';
      oscillator.frequency.setValueAtTime(10000, context.currentTime);
      
      gain.gain.setValueAtTime(100, context.currentTime);
      
      compressor.threshold.setValueAtTime(-50, context.currentTime);
      compressor.knee.setValueAtTime(40, context.currentTime);
      compressor.ratio.setValueAtTime(12, context.currentTime);
      compressor.attack.setValueAtTime(0, context.currentTime);
      compressor.release.setValueAtTime(0.25, context.currentTime);
      
      oscillator.connect(compressor);
      compressor.connect(gain);
      gain.connect(context.destination);
      
      oscillator.start(0);
      oscillator.stop(context.currentTime + 0.00001);
      
      const analyser = context.createAnalyser();
      const dataArray = new Float32Array(analyser.frequencyBinCount);
      analyser.getFloatFrequencyData(dataArray);
      
      context.close();
      
      return hashString(JSON.stringify({
        sampleRate: context.sampleRate,
        channelCount: context.destination.channelCount,
        dataArrayLength: dataArray.length
      }));
    } catch (e) {
      return 'audio_error_' + e.message.length;
    }
  }
  
  // 收集字体信息
  function collectFontsFingerprint() {
    const testFonts = [
      'Arial', 'Arial Black', 'Arial Narrow', 'Calibri', 'Cambria',
      'Cambria Math', 'Comic Sans MS', 'Consolas', 'Courier', 'Courier New',
      'Georgia', 'Helvetica', 'Impact', 'Lucida Console', 'Lucida Sans Unicode',
      'Microsoft Sans Serif', 'Palatino Linotype', 'Segoe UI', 'Tahoma',
      'Times', 'Times New Roman', 'Trebuchet MS', 'Verdana'
    ];
    
    const availableFonts = [];
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const h = document.getElementsByTagName('body')[0];
    const span = document.createElement('span');
    
    span.style.fontSize = testSize;
    span.innerHTML = testString;
    span.style.position = 'absolute';
    span.style.left = '-9999px';
    h.appendChild(span);
    
    const defaultWidth = span.offsetWidth;
    const defaultHeight = span.offsetHeight;
    
    for (const font of testFonts) {
      span.style.fontFamily = font;
      const width = span.offsetWidth;
      const height = span.offsetHeight;
      
      if (width !== defaultWidth || height !== defaultHeight) {
        availableFonts.push(font);
      }
    }
    
    h.removeChild(span);
    return hashString(availableFonts.join(','));
  }
  
  // 收集浏览器特性
  function collectBrowserFeatures() {
    return {
      cookiesEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,
      language: navigator.language,
      languages: navigator.languages ? navigator.languages.join(',') : '',
      platform: navigator.platform,
      userAgent: navigator.userAgent,
      webdriver: navigator.webdriver || false,
      pdfViewerEnabled: navigator.pdfViewerEnabled !== undefined ? navigator.pdfViewerEnabled : null,
      javaEnabled: navigator.javaEnabled ? navigator.javaEnabled() : false,
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      deviceMemory: navigator.deviceMemory || 0,
      maxTouchPoints: navigator.maxTouchPoints || 0,
      
      // 浏览器 API 支持
      serviceWorker: 'serviceWorker' in navigator,
      webWorker: typeof Worker !== 'undefined',
      webGL: !!window.WebGLRenderingContext,
      webGL2: !!window.WebGL2RenderingContext,
      webAudio: !!window.AudioContext || !!window.webkitAudioContext,
      webRTC: !!window.RTCPeerConnection,
      geolocation: 'geolocation' in navigator,
      indexedDB: !!window.indexedDB,
      localStorage: !!window.localStorage,
      sessionStorage: !!window.sessionStorage,
      
      // 触摸支持
      touchSupport: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
      
      // 时区
      timezoneOffset: new Date().getTimezoneOffset(),
      timezoneName: Intl.DateTimeFormat().resolvedOptions().timeZone,
      
      // 窗口特性
      outerWidth: window.outerWidth,
      outerHeight: window.outerHeight,
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight,
      screenX: window.screenX,
      screenY: window.screenY
    };
  }
  
  // 收集插件信息
  function collectPlugins() {
    const plugins = [];
    
    if (navigator.plugins) {
      for (let i = 0; i < navigator.plugins.length; i++) {
        const plugin = navigator.plugins[i];
        plugins.push({
          name: plugin.name,
          filename: plugin.filename,
          description: plugin.description,
          length: plugin.length
        });
      }
    }
    
    return plugins;
  }
  
  // 收集硬件信息
  function collectHardwareInfo() {
    return {
      cores: navigator.hardwareConcurrency || 'unknown',
      memory: navigator.deviceMemory || 'unknown',
      maxTouchPoints: navigator.maxTouchPoints || 0,
      connection: navigator.connection ? {
        effectiveType: navigator.connection.effectiveType,
        downlink: navigator.connection.downlink,
        rtt: navigator.connection.rtt,
        saveData: navigator.connection.saveData
      } : null
    };
  }
  
  // 简单的字符串哈希
  function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return 'fp_' + Math.abs(hash).toString(36);
  }

  // 收集电池状态信息（Battery API）
  async function collectBatteryInfo() {
    try {
      if (!navigator.getBattery) {
        return { supported: false };
      }
      const battery = await navigator.getBattery();
      const info = {
        supported: true,
        level: battery.level,
        charging: battery.charging,
        chargingTime: battery.chargingTime,
        dischargingTime: battery.dischargingTime,
        levelPercent: Math.round(battery.level * 100) + '%'
      };
      // 监听变化以更新
      battery.addEventListener('levelchange', () => {
        info.level = battery.level;
        info.levelPercent = Math.round(battery.level * 100) + '%';
      });
      battery.addEventListener('chargingchange', () => {
        info.charging = battery.charging;
      });
      return info;
    } catch (e) {
      return { supported: false, error: e.message };
    }
  }

  // 收集网络连接信息
  function collectNetworkInfo() {
    try {
      const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      if (!connection) {
        return { supported: false };
      }
      return {
        supported: true,
        effectiveType: connection.effectiveType,
        downlink: connection.downlink,
        rtt: connection.rtt,
        saveData: connection.saveData,
        type: connection.type || 'unknown',
        downlinkMax: connection.downlinkMax || null
      };
    } catch (e) {
      return { supported: false, error: e.message };
    }
  }

  // 检测传感器支持
  function collectSensorInfo() {
    const sensors = {
      supported: {},
      count: 0
    };
    const sensorTypes = [
      'Accelerometer',
      'Gyroscope',
      'LinearAccelerationSensor',
      'GravitySensor',
      'AbsoluteOrientationSensor',
      'RelativeOrientationSensor',
      'AmbientLightSensor',
      'Magnetometer',
      'ProximitySensor'
    ];
    sensorTypes.forEach(sensor => {
      const supported = sensor in window;
      sensors.supported[sensor] = supported;
      if (supported) sensors.count++;
    });
    // DeviceMotion / DeviceOrientation 事件支持
    sensors.deviceMotion = 'DeviceMotionEvent' in window;
    sensors.deviceOrientation = 'DeviceOrientationEvent' in window;
    return sensors;
  }

  // 收集 GPU 渲染器信息
  function collectGPUInfo() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) {
        return { supported: false };
      }
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const info = {
        supported: true,
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        unmaskedVendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown',
        unmaskedRenderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown',
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxViewportDims: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS) || []),
        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
        maxVaryingVectors: gl.getParameter(gl.MAX_VARYING_VECTORS),
        maxVertexUniformVectors: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
        maxFragmentUniformVectors: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
        extensions: gl.getSupportedExtensions ? gl.getSupportedExtensions() : []
      };
      // 识别 GPU 厂商类型
      const rendererLower = (info.unmaskedRenderer || '').toLowerCase();
      if (rendererLower.includes('nvidia')) info.gpuBrand = 'NVIDIA';
      else if (rendererLower.includes('amd') || rendererLower.includes('radeon')) info.gpuBrand = 'AMD';
      else if (rendererLower.includes('intel')) info.gpuBrand = 'Intel';
      else if (rendererLower.includes('apple')) info.gpuBrand = 'Apple';
      else if (rendererLower.includes('mali')) info.gpuBrand = 'ARM Mali';
      else if (rendererLower.includes('adreno')) info.gpuBrand = 'Qualcomm Adreno';
      else if (rendererLower.includes('powervr')) info.gpuBrand = 'PowerVR';
      else info.gpuBrand = 'unknown';
      return info;
    } catch (e) {
      return { supported: false, error: e.message };
    }
  }

  // 收集存储估算信息
  async function collectStorageInfo() {
    try {
      if (!navigator.storage || !navigator.storage.estimate) {
        return { supported: false };
      }
      const estimate = await navigator.storage.estimate();
      return {
        supported: true,
        quota: estimate.quota,
        usage: estimate.usage,
        usagePercent: estimate.quota > 0 ? Math.round((estimate.usage / estimate.quota) * 10000) / 100 : 0,
        quotaMB: estimate.quota ? Math.round(estimate.quota / 1024 / 1024) : 0,
        usageMB: estimate.usage ? Math.round(estimate.usage / 1024 / 1024) : 0,
        persistent: navigator.storage.persisted ? await navigator.storage.persisted() : null
      };
    } catch (e) {
      return { supported: false, error: e.message };
    }
  }

  // 收集媒体设备数量（摄像头、麦克风）
  async function collectMediaDevicesInfo() {
    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
        return { supported: false };
      }
      const devices = await navigator.mediaDevices.enumerateDevices();
      const info = {
        supported: true,
        total: devices.length,
        videoInputs: 0,
        audioInputs: 0,
        audioOutputs: 0,
        other: 0,
        devices: []
      };
      devices.forEach(device => {
        const entry = {
          kind: device.kind,
          label: device.label || '(未授权)',
          deviceId: device.deviceId ? hashString(device.deviceId) : null,
          groupId: device.groupId ? hashString(device.groupId) : null
        };
        info.devices.push(entry);
        if (device.kind === 'videoinput') info.videoInputs++;
        else if (device.kind === 'audioinput') info.audioInputs++;
        else if (device.kind === 'audiooutput') info.audioOutputs++;
        else info.other++;
      });
      return info;
    } catch (e) {
      return { supported: false, error: e.message };
    }
  }

  // 检测开发者工具是否打开（基于窗口尺寸异常）
  function detectDevTools() {
    const threshold = 200;
    const widthDiff = window.outerWidth - window.innerWidth;
    const heightDiff = window.outerHeight - window.innerHeight;
    // 常见 DevTools 高度差：底部/侧边
    const sideOpen = widthDiff > threshold;
    const bottomOpen = heightDiff > threshold;
    // 通过 Function.toString 长度变化的 trick 检测
    let debuggerHijack = false;
    try {
      const fn = function() {};
      fn.toString = function() {
        debuggerHijack = true;
        return '';
      };
      // eslint-disable-next-line no-console
      console.log('%c', fn);
      // 清理
      console.clear && console.clear();
    } catch (e) {}
    return {
      opened: sideOpen || bottomOpen || debuggerHijack,
      sideOpen: sideOpen,
      bottomOpen: bottomOpen,
      debuggerHijack: debuggerHijack,
      widthDiff: widthDiff,
      heightDiff: heightDiff
    };
  }

  // 检测自动化框架（Puppeteer, Selenium 等）
  function detectAutomationFrameworks() {
    const signals = {
      detected: false,
      frameworks: []
    };
    // 1. webdriver 标志
    if (navigator.webdriver === true) {
      signals.detected = true;
      signals.frameworks.push('webdriver');
    }
    // 2. Puppeteer 特征
    if (window.__puppeteer__ || window.callPhantom || window._phantom) {
      signals.detected = true;
      signals.frameworks.push('puppeteer/phantom');
    }
    // 3. Selenium 特征
    if (
      window._selenium ||
      window._Selenium_IDE_Recorder ||
      window.callSelenium ||
      document.__webdriver_evaluate ||
      document.__driver_evaluate ||
      document.__webdriver_unwrapped ||
      document.__fxdriver_unwrapped ||
      document.__selenium_unwrapped ||
      document.__driver_unwrapped
    ) {
      signals.detected = true;
      signals.frameworks.push('selenium');
    }
    // 4. 通过变量名检测常见自动化注入
    const autoKeys = ['$cdc_asdjflasutopfhvcZLmcfl_', '$wdc_', '__nightmare', '__playwright'];
    autoKeys.forEach(key => {
      if (key in window || key in document) {
        signals.detected = true;
        signals.frameworks.push(key);
      }
    });
    // 5. Chrome DevTools Protocol runtime evaluate 特征（部分 puppeteer 版本）
    if (typeof window.cdc_adoQpoasnfa76pfcZLmcfl_Array !== 'undefined' ||
        typeof window.cdc_adoQpoasnfa76pfcZLmcfl_Promise !== 'undefined' ||
        typeof window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol !== 'undefined') {
      signals.detected = true;
      signals.frameworks.push('chrome-devtools-protocol');
    }
    // 6. 异常的 permissions API 行为
    try {
      if (navigator.permissions && navigator.permissions.query) {
        // 某些自动化环境下 Notification.permission 与 permissions.query 不一致
        // 此处仅做标记，深度校验在 risk score 中
      }
    } catch (e) {}
    return signals;
  }

  // 检测虚拟机环境
  function detectVirtualMachine() {
    const signals = {
      detected: false,
      reasons: []
    };
    const ua = navigator.userAgent.toLowerCase();
    // 1. GPU 渲染器名称通常包含虚拟机标识
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          const renderer = (gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '').toLowerCase();
          const vmKeywords = ['swiftshader', 'llvmpipe', 'virtualbox', 'vmware', 'gallium', 'microsoft basic render', 'paravirtual'];
          vmKeywords.forEach(kw => {
            if (renderer.includes(kw)) {
              signals.detected = true;
              signals.reasons.push('gpu:' + kw);
            }
          });
        }
      }
    } catch (e) {}
    // 2. CPU 核心数异常少（常见 1 核虚拟机）
    if (navigator.hardwareConcurrency === 1) {
      signals.detected = true;
      signals.reasons.push('single_cpu_core');
    }
    // 3. 设备内存异常小
    if (navigator.deviceMemory && navigator.deviceMemory <= 1) {
      signals.detected = true;
      signals.reasons.push('low_memory:' + navigator.deviceMemory + 'GB');
    }
    // 4. 屏幕尺寸为常见虚拟机默认值（如 800x600 / 1024x768）
    const screenArea = screen.width + 'x' + screen.height;
    if (['800x600', '1024x768', '1152x864'].includes(screenArea)) {
      signals.detected = true;
      signals.reasons.push('vm_screen:' + screenArea);
    }
    // 5. 时区与系统语言不匹配（粗略判断）
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (tz === 'America/Los_Angeles' && ua.includes('windows') && navigator.language === 'en-US') {
        // 仅作为弱信号，不直接判定
      }
    } catch (e) {}
    return signals;
  }

  // 检测异常权限请求模式
  async function detectAbnormalPermissionPattern() {
    const result = {
      abnormal: false,
      reasons: []
    };
    try {
      if (!navigator.permissions || !navigator.permissions.query) {
        return result;
      }
      // 检查多种权限的状态是否异常
      const permissionNames = ['geolocation', 'notifications', 'camera', 'microphone', 'clipboard-read'];
      const states = {};
      for (const name of permissionNames) {
        try {
          const status = await navigator.permissions.query({ name });
          states[name] = status.state;
        } catch (e) {
          states[name] = 'unsupported';
        }
      }
      // 模式1：所有敏感权限都被授予（在自动化/虚拟机中常见，便于无人值守操作）
      const grantedCount = Object.values(states).filter(s => s === 'granted').length;
      if (grantedCount >= 4) {
        result.abnormal = true;
        result.reasons.push('too_many_granted_permissions');
      }
      // 模式2：notifications 权限与 Notification.permission 不一致
      if (states.notifications === 'granted' &&
          typeof Notification !== 'undefined' &&
          Notification.permission !== 'granted') {
        result.abnormal = true;
        result.reasons.push('notification_permission_inconsistent');
      }
      result.states = states;
    } catch (e) {
      result.error = e.message;
    }
    return result;
  }
  
  // 计算风险评分
  function calculateRiskScore(features) {
    let score = 0;
    const factors = [];

    // 检测自动化工具特征
    if (features.webdriver === true) {
      score += 40;
      factors.push('webdriver_detected');
    }

    // 检测无头浏览器
    if (navigator.userAgent.toLowerCase().includes('headless')) {
      score += 50;
      factors.push('headless_browser');
    }

    // 检测异常屏幕配置
    if (fingerprint.screenInfo.width === 0 || fingerprint.screenInfo.height === 0) {
      score += 30;
      factors.push('invalid_screen');
    }

    // 检测异常时区
    if (fingerprint.screenInfo.colorDepth < 24) {
      score += 10;
      factors.push('low_color_depth');
    }

    // 检测插件异常
    if (fingerprint.plugins.length === 0 && !navigator.userAgent.includes('Mobile')) {
      score += 15;
      factors.push('no_plugins');
    }

    // 检测语言不一致
    const browserLang = navigator.language;
    const systemLangs = navigator.languages ? navigator.languages[0] : '';
    if (systemLangs && browserLang && !systemLangs.startsWith(browserLang.split('-')[0])) {
      score += 20;
      factors.push('language_mismatch');
    }

    // 检测 Do Not Track
    if (navigator.doNotTrack === '1') {
      score += 5;
      factors.push('dnt_enabled');
    }

    // === 新增：开发者工具检测 ===
    if (fingerprint.devToolsInfo && fingerprint.devToolsInfo.opened) {
      score += 25;
      factors.push('devtools_open');
      if (fingerprint.devToolsInfo.debuggerHijack) {
        score += 10;
        factors.push('debugger_hijack');
      }
    }

    // === 新增：自动化框架检测 ===
    if (fingerprint.automationInfo && fingerprint.automationInfo.detected) {
      score += 45;
      fingerprint.automationInfo.frameworks.forEach(fw => {
        factors.push('automation_framework:' + fw);
      });
    }

    // === 新增：虚拟机环境检测 ===
    if (fingerprint.vmInfo && fingerprint.vmInfo.detected) {
      score += 35;
      factors.push('virtual_machine');
      fingerprint.vmInfo.reasons.forEach(r => {
        factors.push('vm_reason:' + r);
      });
    }

    // === 新增：异常权限请求模式检测 ===
    if (fingerprint.permissionInfo && fingerprint.permissionInfo.abnormal) {
      score += 30;
      fingerprint.permissionInfo.reasons.forEach(r => {
        factors.push('abnormal_permission:' + r);
      });
    }

    // === 新增：窗口尺寸与屏幕尺寸严重不一致（疑似模拟器） ===
    const sw = fingerprint.screenInfo.width || 0;
    const sh = fingerprint.screenInfo.height || 0;
    const ow = window.outerWidth || 0;
    const oh = window.outerHeight || 0;
    if (sw > 0 && sh > 0 && ow > 0 && oh > 0) {
      if (Math.abs(sw - ow) > 100 || Math.abs(sh - oh) > 100) {
        score += 10;
        factors.push('screen_window_size_mismatch');
      }
    }

    fingerprint.riskScore = score;
    fingerprint.riskFactors = factors;

    return { score, factors };
  }
  
  // 收集完整的设备指纹
  async function collectFingerprint() {
    try {
      fingerprint.screenInfo = collectScreenInfo();
      fingerprint.canvasHash = collectCanvasFingerprint();
      fingerprint.webglHash = collectWebGLFingerprint();
      fingerprint.audioHash = collectAudioFingerprint();
      fingerprint.fontsHash = collectFontsFingerprint();
      fingerprint.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
      fingerprint.language = navigator.language;
      fingerprint.plugins = collectPlugins();
      fingerprint.hardwareInfo = collectHardwareInfo();
      fingerprint.browserFeatures = collectBrowserFeatures();

      // === 新增：收集扩展设备信息 ===
      fingerprint.batteryInfo = await collectBatteryInfo();
      fingerprint.networkInfo = collectNetworkInfo();
      fingerprint.sensorInfo = collectSensorInfo();
      fingerprint.gpuInfo = collectGPUInfo();
      fingerprint.storageInfo = await collectStorageInfo();
      fingerprint.mediaDevicesInfo = await collectMediaDevicesInfo();

      // === 新增：风险检测信息收集 ===
      fingerprint.devToolsInfo = detectDevTools();
      fingerprint.automationInfo = detectAutomationFrameworks();
      fingerprint.vmInfo = detectVirtualMachine();
      fingerprint.permissionInfo = await detectAbnormalPermissionPattern();

      // 计算总哈希
      const combinedString = [
        fingerprint.canvasHash,
        fingerprint.webglHash,
        fingerprint.audioHash,
        fingerprint.fontsHash,
        fingerprint.screenInfo.width + 'x' + fingerprint.screenInfo.height,
        fingerprint.timezone,
        fingerprint.language,
        fingerprint.hardwareInfo.cores,
        fingerprint.gpuInfo.unmaskedRenderer || 'unknown',
        fingerprint.networkInfo.effectiveType || 'unknown'
      ].join('|');

      fingerprint.hash = hashString(combinedString);

      // 计算风险评分
      calculateRiskScore(fingerprint.browserFeatures);

      // === 自动调用封禁状态检查（不阻塞主流程） ===
      try {
        checkBanStatus().catch(err => {
          console.warn('封禁状态检查失败:', err);
        });
      } catch (e) {
        console.warn('checkBanStatus 调用异常:', e);
      }

      return fingerprint;
    } catch (e) {
      console.error('设备指纹收集失败:', e);
      return null;
    }
  }

  // 生成申诉表单 HTML 并挂载到页面
  function generateAppealForm(reason) {
    // 移除已存在的表单
    const existing = document.getElementById('jifeng-appeal-overlay');
    if (existing) existing.remove();

    const reasonText = reason || '您的设备已被系统识别为风险设备，可能被临时限制访问。';

    const overlay = document.createElement('div');
    overlay.id = 'jifeng-appeal-overlay';
    overlay.style.cssText = [
      'position:fixed',
      'top:0',
      'left:0',
      'width:100%',
      'height:100%',
      'background:rgba(0,0,0,0.6)',
      'z-index:999999',
      'display:flex',
      'align-items:center',
      'justify-content:center',
      'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif'
    ].join(';');

    const card = document.createElement('div');
    card.style.cssText = [
      'background:#fff',
      'border-radius:12px',
      'padding:32px',
      'width:90%',
      'max-width:480px',
      'box-shadow:0 8px 32px rgba(0,0,0,0.3)',
      'max-height:90vh',
      'overflow-y:auto'
    ].join(';');

    card.innerHTML = `
      <h2 style="margin:0 0 8px 0;color:#1a1a1a;font-size:22px;">设备申诉</h2>
      <p style="margin:0 0 20px 0;color:#666;font-size:14px;line-height:1.6;">${reasonText}</p>
      <form id="jifeng-appeal-form" style="display:flex;flex-direction:column;gap:14px;">
        <div>
          <label style="display:block;margin-bottom:6px;font-size:13px;color:#333;font-weight:600;">联系邮箱 <span style="color:#e53935;">*</span></label>
          <input type="email" name="email" required placeholder="your@email.com"
            style="width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;box-sizing:border-box;" />
        </div>
        <div>
          <label style="display:block;margin-bottom:6px;font-size:13px;color:#333;font-weight:600;">申诉理由 <span style="color:#e53935;">*</span></label>
          <textarea name="reason" required rows="5" placeholder="请详细描述您的申诉理由，例如：我是正常用户，未进行任何违规操作..."
            style="width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;resize:vertical;box-sizing:border-box;"></textarea>
        </div>
        <div>
          <label style="display:block;margin-bottom:6px;font-size:13px;color:#333;font-weight:600;">附加说明（可选）</label>
          <input type="text" name="extra" placeholder="例如：使用的网络环境、设备型号等"
            style="width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;box-sizing:border-box;" />
        </div>
        <div id="jifeng-appeal-message" style="min-height:20px;font-size:13px;"></div>
        <div style="display:flex;gap:10px;margin-top:6px;">
          <button type="submit" style="flex:1;padding:12px;background:#1976d2;color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;">提交申诉</button>
          <button type="button" id="jifeng-appeal-cancel" style="flex:1;padding:12px;background:#f5f5f5;color:#666;border:1px solid #ddd;border-radius:6px;font-size:14px;cursor:pointer;">取消</button>
        </div>
      </form>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    const form = card.querySelector('#jifeng-appeal-form');
    const messageEl = card.querySelector('#jifeng-appeal-message');
    const cancelBtn = card.querySelector('#jifeng-appeal-cancel');

    cancelBtn.addEventListener('click', () => {
      // 不允许直接关闭时显示提示
      messageEl.style.color = '#e53935';
      messageEl.textContent = '设备处于封禁状态，无法取消。请提交申诉。';
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(form);
      const payload = {
        email: formData.get('email'),
        reason: formData.get('reason'),
        extra: formData.get('extra'),
        fingerprint: fingerprint.hash,
        riskScore: fingerprint.riskScore,
        riskFactors: fingerprint.riskFactors,
        deviceInfo: getDeviceInfoForAdmin(),
        timestamp: Date.now()
      };

      const submitBtn = form.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.textContent = '提交中...';
      messageEl.style.color = '#666';
      messageEl.textContent = '正在提交申诉，请稍候...';

      try {
        const response = await fetch('/api/appeal/submit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok && (data.success !== false)) {
          messageEl.style.color = '#2e7d32';
          messageEl.textContent = data.message || '申诉已提交，我们将在 1-3 个工作日内审核并回复至您的邮箱。';
          submitBtn.textContent = '已提交';
          form.querySelectorAll('input,textarea').forEach(el => el.disabled = true);
        } else {
          throw new Error(data.message || '服务器返回错误');
        }
      } catch (err) {
        messageEl.style.color = '#e53935';
        messageEl.textContent = '申诉提交失败：' + (err.message || '网络错误') + '，请稍后重试。';
        submitBtn.disabled = false;
        submitBtn.textContent = '重新提交';
      }
    });

    return overlay;
  }

  // 检查当前设备是否被封禁
  async function checkBanStatus() {
    try {
      if (!fingerprint.hash) {
        // 指纹尚未就绪，等待主流程完成
        return { checked: false, reason: 'fingerprint_not_ready' };
      }
      const params = new URLSearchParams({
        fingerprint: fingerprint.hash,
        riskScore: fingerprint.riskScore
      });
      const response = await fetch('/api/appeal/check-ban?' + params.toString(), {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      const data = await response.json().catch(() => ({}));
      const result = {
        checked: true,
        banned: !!data.banned,
        reason: data.reason || null,
        banId: data.banId || null,
        expireAt: data.expireAt || null,
        raw: data
      };
      if (result.banned) {
        // 显示申诉页面
        const reasonText = result.reason
          ? '您的设备已被封禁。原因：' + result.reason + (result.expireAt ? '；解封时间：' + new Date(result.expireAt).toLocaleString() : '')
          : '您的设备已被封禁，请提交申诉以解除限制。';
        generateAppealForm(reasonText);
      }
      return result;
    } catch (e) {
      console.warn('封禁状态检查失败:', e);
      return { checked: false, error: e.message };
    }
  }

  // 返回格式化的设备信息，用于管理端树状图展示
  function getDeviceInfoForAdmin() {
    const ua = navigator.userAgent || '';
    // 简易解析 UA 中的设备品牌/型号/操作系统/浏览器
    const parser = parseUserAgent(ua);
    return {
      label: '设备信息',
      type: 'root',
      children: [
        {
          label: '基础信息',
          type: 'group',
          children: [
            { label: '指纹哈希', type: 'leaf', value: fingerprint.hash || '-' },
            { label: '设备品牌', type: 'leaf', value: parser.brand },
            { label: '设备型号', type: 'leaf', value: parser.model },
            { label: '操作系统', type: 'leaf', value: parser.os },
            { label: '操作系统版本', type: 'leaf', value: parser.osVersion },
            { label: '浏览器', type: 'leaf', value: parser.browser },
            { label: '浏览器版本', type: 'leaf', value: parser.browserVersion },
            { label: '是否移动端', type: 'leaf', value: parser.isMobile ? '是' : '否' },
            { label: 'User-Agent', type: 'leaf', value: ua }
          ]
        },
        {
          label: '屏幕信息',
          type: 'group',
          children: Object.entries(fingerprint.screenInfo || {}).map(([k, v]) => ({
            label: k, type: 'leaf', value: String(v)
          }))
        },
        {
          label: '硬件信息',
          type: 'group',
          children: [
            { label: 'CPU 核心数', type: 'leaf', value: String(fingerprint.hardwareInfo.cores ?? '-') },
            { label: '设备内存 (GB)', type: 'leaf', value: String(fingerprint.hardwareInfo.memory ?? '-') },
            { label: '最大触点数', type: 'leaf', value: String(fingerprint.hardwareInfo.maxTouchPoints ?? 0) }
          ]
        },
        {
          label: 'GPU 信息',
          type: 'group',
          children: fingerprint.gpuInfo && fingerprint.gpuInfo.supported ? [
            { label: 'GPU 品牌', type: 'leaf', value: fingerprint.gpuInfo.gpuBrand || 'unknown' },
            { label: '厂商', type: 'leaf', value: fingerprint.gpuInfo.unmaskedVendor },
            { label: '渲染器', type: 'leaf', value: fingerprint.gpuInfo.unmaskedRenderer },
            { label: '版本', type: 'leaf', value: fingerprint.gpuInfo.version },
            { label: '最大纹理尺寸', type: 'leaf', value: String(fingerprint.gpuInfo.maxTextureSize) },
            { label: '扩展数量', type: 'leaf', value: String((fingerprint.gpuInfo.extensions || []).length) }
          ] : [{ label: 'GPU', type: 'leaf', value: '不支持' }]
        },
        {
          label: '网络信息',
          type: 'group',
          children: fingerprint.networkInfo && fingerprint.networkInfo.supported ? [
            { label: '连接类型', type: 'leaf', value: fingerprint.networkInfo.effectiveType || '-' },
            { label: '下行带宽 (Mbps)', type: 'leaf', value: String(fingerprint.networkInfo.downlink ?? '-') },
            { label: '往返时延 (ms)', type: 'leaf', value: String(fingerprint.networkInfo.rtt ?? '-') },
            { label: '是否省流模式', type: 'leaf', value: fingerprint.networkInfo.saveData ? '是' : '否' },
            { label: '网络类型', type: 'leaf', value: fingerprint.networkInfo.type || '-' },
            { label: '最大下行', type: 'leaf', value: String(fingerprint.networkInfo.downlinkMax ?? '-') }
          ] : [{ label: 'Network API', type: 'leaf', value: '不支持' }]
        },
        {
          label: '电池信息',
          type: 'group',
          children: fingerprint.batteryInfo && fingerprint.batteryInfo.supported ? [
            { label: '电量', type: 'leaf', value: fingerprint.batteryInfo.levelPercent || '-' },
            { label: '是否充电', type: 'leaf', value: fingerprint.batteryInfo.charging ? '是' : '否' },
            { label: '充满剩余 (s)', type: 'leaf', value: String(fingerprint.batteryInfo.chargingTime ?? '-') },
            { label: '使用剩余 (s)', type: 'leaf', value: String(fingerprint.batteryInfo.dischargingTime ?? '-') }
          ] : [{ label: 'Battery API', type: 'leaf', value: '不支持' }]
        },
        {
          label: '存储信息',
          type: 'group',
          children: fingerprint.storageInfo && fingerprint.storageInfo.supported ? [
            { label: '配额 (MB)', type: 'leaf', value: String(fingerprint.storageInfo.quotaMB) },
            { label: '已用 (MB)', type: 'leaf', value: String(fingerprint.storageInfo.usageMB) },
            { label: '使用率 (%)', type: 'leaf', value: String(fingerprint.storageInfo.usagePercent) },
            { label: '是否持久化', type: 'leaf', value: fingerprint.storageInfo.persistent === null ? '-' : (fingerprint.storageInfo.persistent ? '是' : '否') }
          ] : [{ label: 'Storage API', type: 'leaf', value: '不支持' }]
        },
        {
          label: '媒体设备',
          type: 'group',
          children: fingerprint.mediaDevicesInfo && fingerprint.mediaDevicesInfo.supported ? [
            { label: '设备总数', type: 'leaf', value: String(fingerprint.mediaDevicesInfo.total) },
            { label: '摄像头数', type: 'leaf', value: String(fingerprint.mediaDevicesInfo.videoInputs) },
            { label: '麦克风数', type: 'leaf', value: String(fingerprint.mediaDevicesInfo.audioInputs) },
            { label: '扬声器数', type: 'leaf', value: String(fingerprint.mediaDevicesInfo.audioOutputs) }
          ] : [{ label: 'MediaDevices API', type: 'leaf', value: '不支持' }]
        },
        {
          label: '传感器支持',
          type: 'group',
          children: [
            { label: '支持传感器数', type: 'leaf', value: String(fingerprint.sensorInfo.count ?? 0) },
            ...Object.entries(fingerprint.sensorInfo.supported || {}).map(([k, v]) => ({
              label: k, type: 'leaf', value: v ? '支持' : '不支持'
            })),
            { label: 'DeviceMotion', type: 'leaf', value: fingerprint.sensorInfo.deviceMotion ? '支持' : '不支持' },
            { label: 'DeviceOrientation', type: 'leaf', value: fingerprint.sensorInfo.deviceOrientation ? '支持' : '不支持' }
          ]
        },
        {
          label: '浏览器指纹',
          type: 'group',
          children: [
            { label: 'Canvas 哈希', type: 'leaf', value: fingerprint.canvasHash || '-' },
            { label: 'WebGL 哈希', type: 'leaf', value: fingerprint.webglHash || '-' },
            { label: '音频哈希', type: 'leaf', value: fingerprint.audioHash || '-' },
            { label: '字体哈希', type: 'leaf', value: fingerprint.fontsHash || '-' },
            { label: '时区', type: 'leaf', value: fingerprint.timezone || '-' },
            { label: '语言', type: 'leaf', value: fingerprint.language || '-' },
            { label: '插件数', type: 'leaf', value: String((fingerprint.plugins || []).length) }
          ]
        },
        {
          label: '风险检测',
          type: 'group',
          children: [
            { label: '风险评分', type: 'leaf', value: String(fingerprint.riskScore) },
            { label: '风险因素', type: 'leaf', value: (fingerprint.riskFactors || []).join(', ') || '无' },
            { label: '开发者工具', type: 'leaf', value: fingerprint.devToolsInfo && fingerprint.devToolsInfo.opened ? '打开' : '未打开' },
            { label: '自动化框架', type: 'leaf', value: fingerprint.automationInfo && fingerprint.automationInfo.detected ? (fingerprint.automationInfo.frameworks.join(', ')) : '未检测到' },
            { label: '虚拟机环境', type: 'leaf', value: fingerprint.vmInfo && fingerprint.vmInfo.detected ? ('疑似 (' + fingerprint.vmInfo.reasons.join(', ') + ')') : '未检测到' },
            { label: '异常权限模式', type: 'leaf', value: fingerprint.permissionInfo && fingerprint.permissionInfo.abnormal ? ('异常 (' + fingerprint.permissionInfo.reasons.join(', ') + ')') : '正常' }
          ]
        }
      ]
    };
  }

  // 简易 UA 解析：返回设备品牌/型号/OS/浏览器
  function parseUserAgent(ua) {
    const result = {
      brand: 'unknown',
      model: 'unknown',
      os: 'unknown',
      osVersion: 'unknown',
      browser: 'unknown',
      browserVersion: 'unknown',
      isMobile: false
    };
    if (!ua) return result;
    const lower = ua.toLowerCase();
    result.isMobile = /mobile|android|iphone|ipod|windows phone/i.test(ua);

    // 操作系统
    if (/windows nt 10/.test(lower)) { result.os = 'Windows'; result.osVersion = '10/11'; }
    else if (/windows nt 6\.3/.test(lower)) { result.os = 'Windows'; result.osVersion = '8.1'; }
    else if (/windows nt 6\.2/.test(lower)) { result.os = 'Windows'; result.osVersion = '8'; }
    else if (/windows nt 6\.1/.test(lower)) { result.os = 'Windows'; result.osVersion = '7'; }
    else if (/windows/.test(lower)) { result.os = 'Windows'; }
    else if (/mac os x ([\d_]+)/.test(lower)) { result.os = 'macOS'; result.osVersion = RegExp.$1.replace(/_/g, '.'); }
    else if (/iphone os ([\d_]+)/.test(lower)) { result.os = 'iOS'; result.osVersion = RegExp.$1.replace(/_/g, '.'); result.brand = 'Apple'; result.model = 'iPhone'; }
    else if (/ipad/.test(lower)) { result.os = 'iPadOS'; result.brand = 'Apple'; result.model = 'iPad'; }
    else if (/android ([\d.]+)/.test(lower)) { result.os = 'Android'; result.osVersion = RegExp.$1; }
    else if (/linux/.test(lower)) { result.os = 'Linux'; }
    else if (/cros/.test(lower)) { result.os = 'ChromeOS'; }

    // 移动设备品牌/型号
    if (result.isMobile && result.os !== 'iOS') {
      if (/samsung|sm-|galaxy/i.test(ua)) { result.brand = 'Samsung'; const m = ua.match(/(sm-[a-z0-9]+)/i); if (m) result.model = m[1].toUpperCase(); }
      else if (/huawei|honor|hwbnd|hw-|jef-an00|jelly/i.test(ua)) { result.brand = 'Huawei'; }
      else if (/xiaomi|redmi|mi\s|mix/i.test(ua)) { result.brand = 'Xiaomi'; }
      else if (/oppo|cph|pctm/i.test(ua)) { result.brand = 'OPPO'; }
      else if (/vivo|v[0-9]{4}[a-z]*|i[qv]oo/i.test(ua)) { result.brand = 'vivo'; }
      else if (/pixel/i.test(ua)) { result.brand = 'Google'; result.model = 'Pixel'; }
    }

    // 浏览器
    if (/edg\/([\d.]+)/.test(lower)) { result.browser = 'Edge'; result.browserVersion = RegExp.$1; }
    else if (/chrome\/([\d.]+)/.test(lower) && !/chromium/.test(lower)) { result.browser = 'Chrome'; result.browserVersion = RegExp.$1; }
    else if (/firefox\/([\d.]+)/.test(lower)) { result.browser = 'Firefox'; result.browserVersion = RegExp.$1; }
    else if (/safari\/([\d.]+)/.test(lower) && /version\/([\d.]+)/.test(lower)) { result.browser = 'Safari'; result.browserVersion = RegExp.$1; }
    else if (/msie ([\d.]+)/.test(lower)) { result.browser = 'IE'; result.browserVersion = RegExp.$1; }
    else if (/trident\/.*rv:([\d.]+)/.test(lower)) { result.browser = 'IE'; result.browserVersion = RegExp.$1; }

    return result;
  }
  
  // 发送指纹到服务器
  async function sendFingerprint(ws) {
    const fp = await collectFingerprint();
    
    if (fp && ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: 'device_info',
        data: {
          fingerprint: fp,
          riskScore: fp.riskScore,
          riskFactors: fp.riskFactors
        }
      }));
    }
    
    return fp;
  }
  
  // 暴露到全局
  window.JiFengFingerprint = {
    collect: collectFingerprint,
    send: sendFingerprint,
    getRiskScore: () => fingerprint.riskScore,
    getRiskFactors: () => fingerprint.riskFactors,
    getData: () => fingerprint,
    // 新增：扩展功能
    generateAppealForm: generateAppealForm,
    checkBanStatus: checkBanStatus,
    getDeviceInfoForAdmin: getDeviceInfoForAdmin,
    // 新增：单独的检测器（便于外部按需调用）
    detectDevTools: detectDevTools,
    detectAutomationFrameworks: detectAutomationFrameworks,
    detectVirtualMachine: detectVirtualMachine,
    detectAbnormalPermissionPattern: detectAbnormalPermissionPattern
  };
  
  // 自动收集
  if (document.readyState === 'complete') {
    collectFingerprint();
  } else {
    window.addEventListener('load', collectFingerprint);
  }
  
})();