import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import {
  getAuth, signInWithEmailAndPassword, signOut, onAuthStateChanged,
  createUserWithEmailAndPassword, updateProfile,
  GoogleAuthProvider, signInWithPopup, signInWithRedirect, getRedirectResult,
  RecaptchaVerifier, signInWithPhoneNumber,
  PhoneAuthProvider, signInWithCredential,
  browserLocalPersistence, setPersistence
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import {
  getFirestore, collection, doc, setDoc, getDoc, getDocs,
  deleteDoc, query, where, orderBy, serverTimestamp, updateDoc, limit, addDoc,
  onSnapshot, increment, Timestamp
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";
import { firebaseConfig } from "./firebase/config.js";
import { IJRO_SEKTORLAR, IJRO_XODIMLAR } from "./data/ijro-default-data.js";

// ============================================================
// 🔧 FIREBASE CONFIG — o'zingizning config ni shu yerga qo'ying
// ============================================================
// Firebase config moved to ./firebase/config.js

// ============================================================

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Ensure session persists across browser tabs and reloads before any login/register call.
const authPersistenceReady = setPersistence(auth, browserLocalPersistence).catch((e) => {
  console.warn('Auth persistence sozlanmadi:', e);
});

// ===== SESSION TOKEN (1 hafta) =====
const SESSION_KEY = 'ijroda_session';
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days ms

function saveSession(uid) {
  try {
    localStorage.setItem(SESSION_KEY, JSON.stringify({ uid, ts: Date.now() }));
  } catch(e) {}
}
function clearSession() {
  try { localStorage.removeItem(SESSION_KEY); } catch(e) {}
}
function getSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw);
    if (Date.now() - s.ts > SESSION_TTL) { clearSession(); return null; }
    return s;
  } catch(e) { return null; }
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║          SAAS-LEVEL SECURITY MODULE v1.0                        ║
// ║  1. Rate Limiting     2. Device Tracking                        ║
// ║  3. Suspicious Login  4. Session Monitor                        ║
// ╚══════════════════════════════════════════════════════════════════╝
const Security = {
  MAX_LOGIN_ATTEMPTS : 5,
  LOGIN_WINDOW_MS    : 15 * 60 * 1000,
  MAX_OTP_ATTEMPTS   : 3,
  OTP_WINDOW_MS      : 60 * 60 * 1000,
  INACTIVITY_MS      : 30 * 60 * 1000,
  HEARTBEAT_MS       : 5  * 60 * 1000,
  SESSION_ID_KEY     : 'ijroda_sid',
  _heartbeatTimer    : null,
  _inactivityTimer   : null,
  _sessionId         : null,

  // ── 1. DEVICE FINGERPRINT ──────────────────────────────────────────
  async getDeviceId() {
    const stored = localStorage.getItem('ijroda_device_id');
    if (stored) return stored;
    let canvasHash = 'x';
    try {
      const c = document.createElement('canvas');
      const ctx = c.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#1a3f6e';
      ctx.fillText('Ijroda\uD83D\uDD10', 2, 2);
      ctx.fillStyle = 'rgba(255,99,33,0.5)';
      ctx.fillRect(100, 1, 80, 20);
      canvasHash = c.toDataURL().slice(-32);
    } catch(e) {}
    const raw = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
      Intl.DateTimeFormat().resolvedOptions().timeZone,
      navigator.hardwareConcurrency || 0,
      navigator.platform || '',
      canvasHash
    ].join('|');
    let hash = 0;
    for (let i = 0; i < raw.length; i++) {
      hash = ((hash << 5) - hash) + raw.charCodeAt(i);
      hash |= 0;
    }
    const deviceId = 'dev_' + Math.abs(hash).toString(36) + '_' + Date.now().toString(36);
    localStorage.setItem('ijroda_device_id', deviceId);
    return deviceId;
  },

  getDeviceName() {
    const ua = navigator.userAgent;
    let os = "Noma\u02BClum OS", browser = "Noma\u02BClum brauzer";
    if (/Windows NT 10/.test(ua))      os = 'Windows 10/11';
    else if (/Windows NT 6/.test(ua))  os = 'Windows 7/8';
    else if (/Android/.test(ua))       os = 'Android';
    else if (/iPhone|iPad/.test(ua))   os = 'iOS';
    else if (/Mac OS X/.test(ua))      os = 'macOS';
    else if (/Linux/.test(ua))         os = 'Linux';
    if (/Chrome\/(\d+)/.test(ua) && !/Edg/.test(ua) && !/OPR/.test(ua)) browser = 'Chrome';
    else if (/Firefox\//.test(ua))     browser = 'Firefox';
    else if (/Safari\//.test(ua) && !/Chrome/.test(ua)) browser = 'Safari';
    else if (/Edg\//.test(ua))         browser = 'Edge';
    else if (/OPR\//.test(ua))         browser = 'Opera';
    const isMobile = /Android|iPhone|iPad|Mobile/.test(ua);
    return browser + ' \u00B7 ' + os + (isMobile ? ' \uD83D\uDCF1' : ' \uD83D\uDDA5\uFE0F');
  },

  // ── 2. RATE LIMITING ───────────────────────────────────────────────
  async checkLoginRateLimit(identifier) {
    const key = 'rl_login_' + btoa(unescape(encodeURIComponent(identifier))).slice(0, 20);
    try {
      const raw = localStorage.getItem(key);
      const data = raw ? JSON.parse(raw) : { attempts: [], blockedUntil: 0 };
      if (data.blockedUntil && Date.now() < data.blockedUntil) {
        const remaining = Math.ceil((data.blockedUntil - Date.now()) / 60000);
        return { allowed: false, reason: '\uD83D\uDD12 Juda ko\u02BCp urinish. ' + remaining + ' daqiqadan so\u02BCng qaytadan urinib ko\u02BCring.' };
      }
      const cutoff = Date.now() - this.LOGIN_WINDOW_MS;
      data.attempts = (data.attempts || []).filter(t => t > cutoff);
      if (data.attempts.length >= this.MAX_LOGIN_ATTEMPTS) {
        data.blockedUntil = Date.now() + this.LOGIN_WINDOW_MS;
        localStorage.setItem(key, JSON.stringify(data));
        this._logSecurityEvent('login_rate_limited', { identifier, attempts: data.attempts.length });
        return { allowed: false, reason: '\uD83D\uDD12 ' + this.MAX_LOGIN_ATTEMPTS + ' ta muvaffaqiyatsiz urinish. 15 daqiqa blok.' };
      }
      return { allowed: true, _key: key, _data: data };
    } catch(e) { return { allowed: true }; }
  },

  recordLoginAttempt(identifier, success) {
    const key = 'rl_login_' + btoa(unescape(encodeURIComponent(identifier))).slice(0, 20);
    try {
      const raw = localStorage.getItem(key);
      const data = raw ? JSON.parse(raw) : { attempts: [], blockedUntil: 0 };
      if (success) { localStorage.removeItem(key); }
      else { data.attempts.push(Date.now()); localStorage.setItem(key, JSON.stringify(data)); }
    } catch(e) {}
  },

  async checkOtpRateLimit(phone) {
    const key = 'rl_otp_' + btoa(unescape(encodeURIComponent(phone))).slice(0, 20);
    try {
      const raw = localStorage.getItem(key);
      const data = raw ? JSON.parse(raw) : { attempts: [] };
      const cutoff = Date.now() - this.OTP_WINDOW_MS;
      data.attempts = data.attempts.filter(t => t > cutoff);
      if (data.attempts.length >= this.MAX_OTP_ATTEMPTS) {
        const oldest = data.attempts[0];
        const waitMin = Math.ceil((oldest + this.OTP_WINDOW_MS - Date.now()) / 60000);
        return { allowed: false, reason: '\uD83D\uDCF1 Bu raqamga soatiga ' + this.MAX_OTP_ATTEMPTS + ' ta SMS. ' + waitMin + ' daqiqa kuting.' };
      }
      data.attempts.push(Date.now());
      localStorage.setItem(key, JSON.stringify(data));
      return { allowed: true };
    } catch(e) { return { allowed: true }; }
  },

  // ── 3. DEVICE TRACKING ─────────────────────────────────────────────
  async registerDevice(uid) {
    try {
      const deviceId = await this.getDeviceId();
      const deviceRef = doc(db, 'security', uid, 'devices', deviceId);
      const snap = await getDoc(deviceRef);
      const deviceName = this.getDeviceName();
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (!snap.exists()) {
        await setDoc(deviceRef, { deviceId, deviceName, firstSeen: serverTimestamp(), lastSeen: serverTimestamp(), loginCount: 1, timezone: tz, trusted: false });
        return { isNewDevice: true, deviceName };
      } else {
        updateDoc(deviceRef, { lastSeen: serverTimestamp(), deviceName, loginCount: increment(1) }).catch(()=>{});
        return { isNewDevice: false, deviceName };
      }
    } catch(e) { return { isNewDevice: false, deviceName: this.getDeviceName() }; }
  },

  async getKnownDevices(uid) {
    try {
      const snaps = await getDocs(collection(db, 'security', uid, 'devices'));
      return snaps.docs.map(d => ({ id: d.id, ...d.data() }));
    } catch(e) { return []; }
  },

  async trustDevice(uid, deviceId) {
    try { await updateDoc(doc(db, 'security', uid, 'devices', deviceId), { trusted: true }); showToast('\u2705 Qurilma ishonchli deb belgilandi', 'success'); } catch(e) {}
  },

  async removeDevice(uid, deviceId) {
    try { await deleteDoc(doc(db, 'security', uid, 'devices', deviceId)); showToast('\uD83D\uDDD1\uFE0F Qurilma o\u02BCchirildi', 'info'); } catch(e) {}
  },

  // ── 4. SUSPICIOUS LOGIN DETECTION ─────────────────────────────────
  async analyzeSuspicion(uid, deviceResult) {
    const flags = [];
    const hour  = new Date().getHours();
    if (deviceResult.isNewDevice)
      flags.push({ type: 'new_device', level: 'warning', msg: '\uD83C\uDD95 Yangi qurilmadan kirish: ' + deviceResult.deviceName });
    if (hour >= 23 || hour <= 5)
      flags.push({ type: 'odd_hour', level: 'info', msg: '\uD83C\uDF19 Tun vaqtida kirish (' + hour + ':00)' });
    try {
      const userSnap = await getDoc(doc(db, 'users', uid));
      if (userSnap.exists()) {
        const savedTz = userSnap.data().lastTimezone;
        const currentTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        if (savedTz && savedTz !== currentTz)
          flags.push({ type: 'timezone_change', level: 'warning', msg: '\uD83C\uDF0D Mintaqa o\u02BCzgargan: ' + savedTz + ' \u2192 ' + currentTz });
        updateDoc(doc(db, 'users', uid), { lastTimezone: currentTz }).catch(()=>{});
      }
    } catch(e) {}
    try {
      const recentRef = query(collection(db, 'security', uid, 'login_events'), orderBy('ts', 'desc'), limit(2));
      const evSnap = await getDocs(recentRef);
      if (evSnap.docs.length >= 2) {
        const d0 = evSnap.docs[0].data().ts?.toMillis?.();
        const d1 = evSnap.docs[1].data().ts?.toMillis?.();
        if (d0 && d1 && (d0 - d1) < 60000)
          flags.push({ type: 'rapid_login', level: 'warning', msg: '\u26A1 1 daqiqada ikkinchi marta kirish' });
      }
    } catch(e) {}
    this._logLoginEvent(uid, flags);
    return flags;
  },

  async _logLoginEvent(uid, flags) {
    try {
      const deviceId = await this.getDeviceId();
      await addDoc(collection(db, 'security', uid, 'login_events'), {
        ts: serverTimestamp(), deviceId, deviceName: this.getDeviceName(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        flags: flags.map(f => f.type), suspicious: flags.some(f => f.level === 'warning')
      });
    } catch(e) {}
  },

  async _logSecurityEvent(type, data = {}) {
    try {
      await addDoc(collection(db, 'security_log'), {
        type, data, uid: auth.currentUser?.uid || 'anon',
        ts: serverTimestamp(), deviceId: localStorage.getItem('ijroda_device_id') || 'unknown'
      });
    } catch(e) {}
  },

  async showSuspicionAlerts(flags) {
    if (!flags || flags.length === 0) return;
    const warnings = flags.filter(f => f.level === 'warning');
    for (const f of warnings) {
      await new Promise(r => setTimeout(r, 400));
      showToast(f.msg, 'error');
    }
    for (const f of flags.filter(f => f.level === 'info')) {
      await new Promise(r => setTimeout(r, 600));
      showToast(f.msg, 'info');
    }
    if (warnings.length > 0) {
      const banner = document.getElementById('security-banner');
      const bannerMsgs = document.getElementById('security-banner-msgs');
      if (banner && bannerMsgs) {
        bannerMsgs.innerHTML = warnings.map(f => '<div class="sec-alert-item">\u26A0\uFE0F ' + f.msg + '</div>').join('');
        banner.style.display = 'block';
        setTimeout(() => { banner.style.display = 'none'; }, 12000);
      }
    }
  },

  // ── 5. SESSION MONITOR ─────────────────────────────────────────────
  async startSession(uid) {
    try {
      const deviceId = await this.getDeviceId();
      const sessionId = 'ses_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7);
      this._sessionId = sessionId;
      localStorage.setItem(this.SESSION_ID_KEY, sessionId);
      await setDoc(doc(db, 'security', uid, 'sessions', sessionId), {
        sessionId, deviceId, deviceName: this.getDeviceName(),
        startedAt: serverTimestamp(), lastActive: serverTimestamp(),
        active: true, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      });
      this._heartbeatTimer = setInterval(async () => {
        try { await updateDoc(doc(db, 'security', uid, 'sessions', sessionId), { lastActive: serverTimestamp() }); } catch(e) {}
      }, this.HEARTBEAT_MS);
      this._resetInactivityTimer(uid, sessionId);
      ['mousemove','keydown','touchstart','click','scroll'].forEach(evt => {
        document.addEventListener(evt, () => this._resetInactivityTimer(uid, sessionId), { passive: true });
      });
      this._watchForceLogout(uid, sessionId);
    } catch(e) { console.warn('Session start xatolik:', e); }
  },

  _resetInactivityTimer(uid, sessionId) {
    clearTimeout(this._inactivityTimer);
    this._inactivityTimer = setTimeout(async () => {
      showToast('\u23F0 30 daqiqa harakatsizlik. Xavfsizlik uchun chiqilmoqda...', 'info');
      await new Promise(r => setTimeout(r, 3000));
      window.doLogout?.();
    }, this.INACTIVITY_MS);
  },

  _watchForceLogout(uid, sessionId) {
    onSnapshot(doc(db, 'security', uid, 'sessions', sessionId), (snap) => {
      if (snap.exists() && snap.data().forceLogout === true) {
        showToast('\uD83D\uDD34 Boshqa qurilmadan chiqarildi!', 'error');
        setTimeout(() => window.doLogout?.(), 2000);
      }
    }, () => {});
  },

  async endSession(uid) {
    clearInterval(this._heartbeatTimer);
    clearTimeout(this._inactivityTimer);
    const sessionId = this._sessionId || localStorage.getItem(this.SESSION_ID_KEY);
    if (!sessionId || !uid) return;
    try { await updateDoc(doc(db, 'security', uid, 'sessions', sessionId), { active: false, endedAt: serverTimestamp() }); } catch(e) {}
    localStorage.removeItem(this.SESSION_ID_KEY);
    this._sessionId = null;
  },

  async getActiveSessions(uid) {
    try {
      const q = query(collection(db, 'security', uid, 'sessions'), where('active', '==', true), orderBy('lastActive', 'desc'), limit(20));
      const snaps = await getDocs(q);
      return snaps.docs.map(d => ({ id: d.id, ...d.data() }));
    } catch(e) { return []; }
  },

  async forceLogoutSession(uid, sessionId) {
    try {
      await updateDoc(doc(db, 'security', uid, 'sessions', sessionId), { forceLogout: true, active: false });
      showToast('\u2705 Session o\u02BCchirildi', 'success');
    } catch(e) { showToast('Xatolik: ' + e.message, 'error'); }
  },

  async getLoginHistory(uid, limitN = 20) {
    try {
      const q = query(collection(db, 'security', uid, 'login_events'), orderBy('ts', 'desc'), limit(limitN));
      const snaps = await getDocs(q);
      return snaps.docs.map(d => ({ id: d.id, ...d.data() }));
    } catch(e) { return []; }
  },

  // ── MAIN HOOK — onAuthStateChanged dan chaqiriladi ─────────────────
  async onSuccessfulLogin(uid) {
    try {
      const deviceResult = await this.registerDevice(uid);
      const flags        = await this.analyzeSuspicion(uid, deviceResult);
      await this.startSession(uid);
      setTimeout(() => this.showSuspicionAlerts(flags), 1500);
    } catch(e) { console.warn('Security post-login xatolik:', e); }
  }
};

window.Security = Security;

// Security panel loader
async function loadSecurityPanel() {
  const uid = currentUser?.uid; if (!uid) return;
  const container = document.getElementById('security-panel-content');
  if (!container) return;
  container.innerHTML = '<div style="color:var(--muted);padding:20px;">Yuklanmoqda...</div>';
  const [sessions, devices, history] = await Promise.all([
    Security.getActiveSessions(uid), Security.getKnownDevices(uid), Security.getLoginHistory(uid, 15)
  ]);
  const currentSid = Security._sessionId || localStorage.getItem(Security.SESSION_ID_KEY);
  const fmtTime = (ts) => {
    if (!ts) return '\u2014';
    const d = ts.toDate ? ts.toDate() : new Date(ts);
    return d.toLocaleString('uz-UZ',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'});
  };
  container.innerHTML = `
    <div class="card">
      <div class="card-title">\uD83D\uDCE1 Faol sessionlar (${sessions.length})</div>
      ${sessions.length===0?'<p style="color:var(--muted);font-size:13px;">Faol session topilmadi.</p>':sessions.map(s=>`
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px;">
          <div>
            <div style="font-weight:700;font-size:13px;color:var(--navy);">${escH(s.deviceName||'?')}
              ${s.id===currentSid?'<span style="background:var(--green-mid);color:#fff;font-size:10px;padding:2px 8px;border-radius:10px;margin-left:6px;">Bu qurilma</span>':''}
            </div>
            <div style="font-size:11px;color:var(--muted);">Boshlangan: ${fmtTime(s.startedAt)} &middot; So\u02BCnggi: ${fmtTime(s.lastActive)}</div>
            <div style="font-size:11px;color:var(--muted);">\uD83C\uDF0D ${escH(s.timezone||'?')}</div>
          </div>
          ${s.id!==currentSid
            ?`<button class="btn btn-danger btn-sm" onclick="Security.forceLogoutSession('${uid}','${s.id}').then(loadSecurityPanel)">\uD83D\uDD34 O\u02BCchirish</button>`
            :'<span style="font-size:11px;color:var(--green-mid);">\u2705 Joriy</span>'}
        </div>`).join('')}
    </div>
    <div class="card">
      <div class="card-title">\uD83D\uDDA5\uFE0F Qurilmalar (${devices.length})</div>
      ${devices.length===0?'<p style="color:var(--muted);font-size:13px;">Hali qurilma yo\u02BCq.</p>':devices.map(d=>`
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px;">
          <div>
            <div style="font-weight:700;font-size:13px;color:var(--navy);">${escH(d.deviceName||'?')}
              ${d.trusted?'<span style="background:var(--blue-mid);color:#fff;font-size:10px;padding:2px 7px;border-radius:10px;margin-left:5px;">\u2705 Ishonchli</span>':''}
            </div>
            <div style="font-size:11px;color:var(--muted);">Birinchi: ${fmtTime(d.firstSeen)} &middot; Login: ${d.loginCount||1}</div>
          </div>
          <div style="display:flex;gap:6px;">
            ${!d.trusted?`<button class="btn btn-outline btn-sm" onclick="Security.trustDevice('${uid}','${d.id}').then(loadSecurityPanel)">\u2705 Ishonchli</button>`:''}
            <button class="btn btn-danger btn-sm" onclick="Security.removeDevice('${uid}','${d.id}').then(loadSecurityPanel)">\uD83D\uDDD1\uFE0F</button>
          </div>
        </div>`).join('')}
    </div>
    <div class="card">
      <div class="card-title">\uD83D\uDCCB Kirish tarixi (so\u02BCnggi 15)</div>
      <div class="table-wrap" style="min-width:0;"><table style="min-width:500px;">
        <thead><tr><th>Vaqt</th><th>Qurilma</th><th>Mintaqa</th><th>Holat</th></tr></thead>
        <tbody>${history.length===0
          ?'<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:16px;">Tarix yo\u02BCq</td></tr>'
          :history.map(h=>`<tr>
            <td class="td-mono">${fmtTime(h.ts)}</td>
            <td style="font-size:12px;">${escH(h.deviceName||'?')}</td>
            <td style="font-size:11px;">${escH(h.timezone||'?')}</td>
            <td>${h.suspicious?'<span class="badge badge-fail">\u26A0\uFE0F Shubhali</span>':'<span class="badge badge-done">\u2705 Oddiy</span>'}
              ${(h.flags||[]).map(f=>'<span style="font-size:9px;color:var(--muted);display:block;">'+f+'</span>').join('')}
            </td>
          </tr>`).join('')}
        </tbody>
      </table></div>
    </div>
    <div class="card">
      <div class="card-title">\u23F1\uFE0F Rate Limit holati</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:13px;">
        <div style="padding:12px;background:var(--surface2);border-radius:8px;">
          <div style="font-weight:700;color:var(--navy);margin-bottom:4px;">Login urinishlari</div>
          <div style="color:var(--muted);">Max: ${Security.MAX_LOGIN_ATTEMPTS} ta / 15 daqiqa</div>
        </div>
        <div style="padding:12px;background:var(--surface2);border-radius:8px;">
          <div style="font-weight:700;color:var(--navy);margin-bottom:4px;">SMS OTP urinishlari</div>
          <div style="color:var(--muted);">Max: ${Security.MAX_OTP_ATTEMPTS} ta / soat</div>
        </div>
      </div>
    </div>`;
}
window.loadSecurityPanel = loadSecurityPanel;


// Global state
let currentUser = null;
let currentUserData = null;
let allDocs = [];
let filteredDocs = [];
let currentPage = 1;
const PAGE_SIZE = 50;
let recaptchaVerifier = null;
let phoneConfirmResult = null;
let pendingPhone = '';
let pendingAuthMethod = ''; // 'google' | 'phone'
let docsLoadedOnce = false;
let authStateResolved = false;
let lastActivatedUid = '';

async function activateAuthenticatedUser(user, userData = null) {
  currentUser = user;
  let data = userData;
  if (!data) {
    const snap = await getDoc(doc(db, 'users', user.uid));
    if (!snap.exists()) return false;
    data = snap.data();
  }

  currentUserData = data;
  if (currentUserData.blocked) {
    await signOut(auth);
    clearSession();
    hideLoading();
    showAuthScreen('login');
    showAuthErr('login-err', '⛔ Sizning akkauntingiz bloklangan. Admin bilan bog\'laning.');
    return true;
  }

  saveSession(user.uid);
  if (lastActivatedUid !== user.uid || !Security._sessionId) {
    lastActivatedUid = user.uid;
    Security.onSuccessfulLogin(user.uid).catch(console.warn);
  }
  updateDoc(doc(db, 'users', user.uid), {
    lastLogin: serverTimestamp(),
    lastAgent: navigator.userAgent.slice(0, 120)
  }).catch(console.error);

  hideLoading();
  showApp();
  window.showPanel?.('docs');
  loadUserDocs();
  return true;
}

// ===== HANDLE REDIRECT RESULT (Google redirect fallback) =====
getRedirectResult(auth).then(async (result) => {
  if (result && result.user) {
    // Redirect login succeeded — onAuthStateChanged will handle the rest
    showLoading('Google login muvaffaqiyatli...');
  }
}).catch((e) => {
  if (e.code !== 'auth/no-auth-event') {
    showVisibleAuthErr(friendlyGoogleAuthError(e));
  }
});

// ===== AUTH STATE =====
let _authInitialized = false;
onAuthStateChanged(auth, async (user) => {
  authStateResolved = true;
  if (user) {
    currentUser = user;
    try {
      const snap = await getDoc(doc(db, 'users', user.uid));
      if (snap.exists()) {
        await activateAuthenticatedUser(user, snap.data());
      } else {
        // New user needs profile completion.
        pendingAuthMethod = user.providerData?.[0]?.providerId === 'phone' ? 'phone' : 'google';
        hideLoading();
        showAuthScreen('complete-profile');
        if (user.displayName) {
          const parts = user.displayName.trim().split(' ');
          const fn = document.getElementById('cp-firstname');
          const ln = document.getElementById('cp-lastname');
          if (fn && parts[0]) fn.value = parts[0];
          if (ln && parts.length > 1) ln.value = parts.slice(1).join(' ');
        }
        const emailEl = document.getElementById('cp-email');
        if (emailEl && user.email) emailEl.value = user.email;
        const phoneEl = document.getElementById('cp-phone');
        if (phoneEl && user.phoneNumber) phoneEl.value = user.phoneNumber;
      }
    } catch(err) {
      console.error('Auth state error:', err);
      hideLoading();
      showAuthScreen('login');
      showAuthErr('login-err', 'Tizimga kirishda xatolik: ' + err.message);
    }
  } else {
    currentUser = null;
    currentUserData = null;
    lastActivatedUid = '';
    clearSession();
    hideLoading();
    showAuthScreen('login');
  }
  _authInitialized = true;
});

// Startup can run after DOMContentLoaded because app.js is imported by bootstrap.
function initAuthStartup() {
  initTheme();
  const hasSavedSession = !!getSession();
  if (hasSavedSession) {
    showLoading('Kirish tiklanmoqda...');
    setTimeout(() => {
      if (!authStateResolved && !_authInitialized) {
        hideLoading();
        showAuthScreen('login');
      }
    }, 5000);
  } else {
    setTimeout(() => {
      if (!authStateResolved) {
        hideLoading();
        showAuthScreen('login');
      }
    }, 800);
  }
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAuthStartup, { once: true });
} else {
  initAuthStartup();
}

// ===== SCREEN SWITCHER =====
function showAuthScreen(screen) {
  ['login','register','phone-verify','complete-profile','otp'].forEach(s => {
    const el = document.getElementById('auth-screen-' + s);
    if (el) el.style.display = 'none';
  });
  document.getElementById('auth-screen').style.display = 'flex';
  document.getElementById('app-screen').style.display = 'none';
  const target = document.getElementById('auth-screen-' + screen);
  if (target) target.style.display = 'block';
}
window.showAuthScreen = showAuthScreen;

function showAuthErr(id, msg) {
  const el = document.getElementById(id);
  if (el) el.textContent = msg;
}

function visibleAuthErrorId() {
  const registerPanel = document.getElementById('panel-register');
  return registerPanel && registerPanel.style.display !== 'none' ? 'reg-err' : 'login-err';
}

function showVisibleAuthErr(msg) {
  showAuthErr('login-err', msg);
  showAuthErr('reg-err', msg);
  showToast(msg, 'error');
}

function friendlyGoogleAuthError(e) {
  const host = location.hostname || '';
  const domainHint = host
    ? ` Firebase Console > Authentication > Settings > Authorized domains bo'limiga "${host}" domainini qo'shing.`
    : '';
  const msgs = {
    'auth/unauthorized-domain': 'Bu sayt domeni Firebase Google login uchun ruxsat etilmagan.' + domainHint,
    'auth/operation-not-allowed': 'Firebase Authentication ichida Google provider yoqilmagan. Sign-in method bo\'limidan Google ni Enable qiling.',
    'auth/popup-blocked': 'Popup bloklangan. Redirect orqali qayta uriniladi.',
    'auth/popup-closed-by-user': 'Google oynasi yopildi. Qaytadan urinib ko\'ring.',
    'auth/cancelled-popup-request': 'Google login bekor qilindi.',
    'auth/account-exists-with-different-credential': 'Bu email boshqa usulda ro\'yxatdan o\'tgan. Email/parol bilan kirib ko\'ring.',
    'auth/network-request-failed': 'Internet ulanishi xatoligi.'
  };
  return msgs[e?.code] || (e?.message ? 'Google login xatoligi: ' + e.message : 'Google login xatoligi.');
}

// ===== EMAIL/PASSWORD LOGIN =====
window.doLogin = async () => {
  const email = document.getElementById('login-email').value.trim();
  const pass  = document.getElementById('login-pass').value;
  const err   = document.getElementById('login-err');
  err.textContent = '';
  if (!email || !pass) { err.textContent = 'Email va parolni kiriting'; return; }

  // ── RATE LIMIT CHECK ──
  const rl = await Security.checkLoginRateLimit(email);
  if (!rl.allowed) { err.textContent = rl.reason; return; }

  try {
    await authPersistenceReady;
    showLoading('Kirish...');
    await signInWithEmailAndPassword(auth, email, pass);
    Security.recordLoginAttempt(email, true);  // muvaffaqiyatli — tozala
  } catch(e) {
    hideLoading();
    Security.recordLoginAttempt(email, false); // muvaffaqiyatsiz — sanab bor
    const msgs = {
      'auth/invalid-credential':    'Email yoki parol noto\'g\'ri',
      'auth/user-not-found':        'Bu email ro\'yxatdan o\'tmagan',
      'auth/wrong-password':        'Parol noto\'g\'ri',
      'auth/invalid-email':         'Email manzil noto\'g\'ri formatda',
      'auth/user-disabled':         '⛔ Akkaunt o\'chirilgan',
      'auth/too-many-requests':     '⚠️ Ko\'p urinish. Biroz kuting yoki parolni tiklang.',
      'auth/network-request-failed':'Internet ulanishi xatoligi. Qaytadan urinib ko\'ring.',
      'auth/quota-exceeded':        '⚠️ Kunlik limit tugadi. Ertaga urinib ko\'ring.',
    };
    err.textContent = msgs[e.code] || ('Xatolik: ' + e.message);
  }
};

// ===== TAB SWITCHER =====
window.switchAuthTab = (tab) => {
  const isRegister = tab === 'register';
  document.getElementById('panel-signin').style.display = isRegister ? 'none' : 'block';
  document.getElementById('panel-register').style.display = isRegister ? 'block' : 'none';
  document.getElementById('tab-signin').style.background = isRegister ? 'transparent' : 'var(--blue-mid)';
  document.getElementById('tab-signin').style.color = isRegister ? 'var(--muted)' : '#fff';
  document.getElementById('tab-register').style.background = isRegister ? 'var(--blue-mid)' : 'transparent';
  document.getElementById('tab-register').style.color = isRegister ? '#fff' : 'var(--muted)';
  // Clear errors
  document.getElementById('login-err').textContent = '';
  document.getElementById('reg-err').textContent = '';
};

// ===== EMAIL REGISTER =====
window.doEmailRegister = async () => {
  const firstName = document.getElementById('reg-firstname').value.trim();
  const lastName  = document.getElementById('reg-lastname').value.trim();
  const email     = document.getElementById('reg-email').value.trim();
  const password  = document.getElementById('reg-password').value;
  const dob       = document.getElementById('reg-dob').value;
  const gender    = document.getElementById('reg-gender').value;
  const phone     = document.getElementById('reg-phone-email').value.trim();
  const job       = document.getElementById('reg-job').value.trim();
  const org       = document.getElementById('reg-org').value.trim();
  const err       = document.getElementById('reg-err');
  err.textContent = '';

  // Validation
  if (!firstName)       { err.textContent = '⚠️ Ism kiritilmagan'; return; }
  if (!lastName)        { err.textContent = '⚠️ Familiya kiritilmagan'; return; }
  if (!email)           { err.textContent = '⚠️ Email kiritilmagan'; return; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { err.textContent = '⚠️ Email manzil noto\'g\'ri'; return; }
  if (!password || password.length < 6) { err.textContent = '⚠️ Parol kamida 6 ta belgi bo\'lishi kerak'; return; }
  if (!dob)             { err.textContent = '⚠️ Tug\'ilgan sana kiritilmagan'; return; }
  if (!gender)          { err.textContent = '⚠️ Jinsni tanlang'; return; }

  const fullName = firstName + ' ' + lastName;

  try {
    await authPersistenceReady;
    showLoading('Akkaunt yaratilmoqda...');
    const cred = await createUserWithEmailAndPassword(auth, email, password);
    const user = cred.user;

    // Update Firebase Auth profile
    await updateProfile(user, { displayName: fullName });

    // Save to Firestore
    await setDoc(doc(db, 'users', user.uid), {
      firstName, lastName, fullName,
      email,
      phone: phone || '',
      job: job || '',
      org: org || '',
      dob: dob || '',
      gender: gender || '',
      role: 'user',
      blocked: false,
      authMethod: 'email',
      createdAt: serverTimestamp(),
      lastLogin: serverTimestamp(),
      lastAgent: navigator.userAgent.slice(0, 120),
      photoURL: ''
    });

    await activateAuthenticatedUser(user, {
      firstName, lastName, fullName,
      email,
      phone: phone || '',
      job: job || '',
      org: org || '',
      dob: dob || '',
      gender: gender || '',
      role: 'user',
      blocked: false,
      authMethod: 'email',
      photoURL: ''
    });
  } catch(e) {
    hideLoading();
    const msgs = {
      'auth/email-already-in-use':    '⚠️ Bu email allaqachon ro\'yxatdan o\'tgan. Kirish tabiga o\'ting.',
      'auth/invalid-email':           '⚠️ Email manzil noto\'g\'ri formatda',
      'auth/weak-password':           '⚠️ Parol juda oddiy. Kamida 6 ta belgi kiriting.',
      'auth/network-request-failed':  '⚠️ Internet ulanishi xatoligi',
      'auth/too-many-requests':       '⚠️ Ko\'p urinish. Biroz kuting.',
    };
    err.textContent = msgs[e.code] || ('Xatolik: ' + e.message);
  }
};

window.doGoogleLogin = async () => {
  try {
    await authPersistenceReady;
    showAuthErr('login-err', '');
    showAuthErr('reg-err', '');
    showLoading('Google orqali kirish...');
    const provider = new GoogleAuthProvider();
    provider.addScope('email');
    provider.addScope('profile');
    provider.setCustomParameters({ prompt: 'select_account' });

    if (location.protocol === 'https:' && location.hostname.endsWith('github.io')) {
      await signInWithRedirect(auth, provider);
      return;
    }

    try {
      await signInWithPopup(auth, provider);
    } catch(popupErr) {
      if (popupErr.code === 'auth/popup-blocked') {
        showLoading('Popup bloklangan, redirect orqali urinilmoqda...');
        await signInWithRedirect(auth, provider);
        return;
      }
      if (popupErr.code === 'auth/popup-closed-by-user') {
        hideLoading();
        showAuthErr(visibleAuthErrorId(), 'Google oynasi yopildi. Qaytadan urinib ko\'ring.');
        return;
      }
      throw popupErr;
    }
  } catch(e) {
    hideLoading();
    showVisibleAuthErr(friendlyGoogleAuthError(e));
  }
};
// ===== PHONE AUTH =====
async function ensureRecaptcha() {
  try {
    if (recaptchaVerifier) {
      // Try to clear old one first
      try { recaptchaVerifier.clear(); } catch(e2) {}
      recaptchaVerifier = null;
    }
    recaptchaVerifier = new RecaptchaVerifier(auth, 'recaptcha-container', {
      size: 'invisible',
      callback: () => {},
      'expired-callback': () => { recaptchaVerifier = null; }
    });
    await recaptchaVerifier.render();
  } catch(e) {
    recaptchaVerifier = null;
    throw e;
  }
}

window.sendPhoneOTP = async () => {
  const raw = document.getElementById('reg-phone').value.trim();
  const err = document.getElementById('phone-err');
  err.textContent = '';
  if (!raw) { err.textContent = 'Telefon raqamini kiriting'; return; }

  // Format to E.164
  let phone = raw.replace(/[\s\-\(\)]/g,'');
  if (!phone.startsWith('+')) {
    if (phone.startsWith('8') && phone.length === 11) phone = '+7' + phone.slice(1);
    else if (phone.startsWith('998')) phone = '+' + phone;
    else if (phone.startsWith('0')) phone = '+998' + phone.slice(1);
    else phone = '+998' + phone;
  }
  if (!/^\+\d{10,15}$/.test(phone)) {
    err.textContent = 'Raqam noto\'g\'ri. Misol: +998 90 123 45 67'; return;
  }

  try {
    await authPersistenceReady;
    showLoading('Tekshirilmoqda...');

    // ── OTP RATE LIMIT ──
    const otpRl = await Security.checkOtpRateLimit(phone);
    if (!otpRl.allowed) { hideLoading(); err.textContent = otpRl.reason; return; }

    // Check if already registered
    const q = query(collection(db,'users'), where('phone','==',phone), limit(1));
    const snap = await getDocs(q);

    if (!snap.empty && snap.docs[0].data().blocked) {
      hideLoading();
      err.textContent = '⛔ Bu akkaunt bloklangan.'; return;
    }

    pendingPhone = phone;
    // Existing or new — send OTP either way
    showLoading('SMS kod yuborilmoqda...');
    await ensureRecaptcha();
    phoneConfirmResult = await signInWithPhoneNumber(auth, phone, recaptchaVerifier);
    hideLoading();

    if (!snap.empty) {
      // Existing user — straight to OTP
      document.getElementById('otp-phone-display').textContent = phone;
      showAuthScreen('otp');
    } else {
      // New user — collect profile first, then OTP
      pendingAuthMethod = 'phone';
      showAuthScreen('complete-profile');
      const phoneEl = document.getElementById('cp-phone');
      if(phoneEl){ phoneEl.value = phone; phoneEl.readOnly = true; }
      // We already sent OTP, so skip re-send in completeProfile
      window._otpAlreadySent = true;
      document.getElementById('otp-phone-display').textContent = phone;
    }
  } catch(e) {
    hideLoading();
    recaptchaVerifier = null;
    if (e.code === 'auth/too-many-requests') {
      err.textContent = '⚠️ Juda ko\'p urinish. Bir oz kuting.';
    } else if (e.code === 'auth/invalid-phone-number') {
      err.textContent = 'Telefon raqami noto\'g\'ri formatda.';
    } else if (e.code === 'auth/operation-not-allowed') {
      err.textContent = '⚠️ SMS autentifikatsiya Firebase Console da yoqilmagan!';
    } else {
      err.textContent = 'Xatolik: ' + (e.message || e.code);
    }
  }
};

window.resendOTP = async () => {
  const err = document.getElementById('otp-err');
  err.textContent = '';
  try {
    await authPersistenceReady;
    showLoading('Qayta yuborilmoqda...');
    recaptchaVerifier = null;
    await ensureRecaptcha();
    phoneConfirmResult = await signInWithPhoneNumber(auth, pendingPhone, recaptchaVerifier);
    hideLoading();
    showToast('Yangi kod yuborildi ✅', 'success');
  } catch(e) {
    hideLoading();
    err.textContent = 'Xatolik: ' + e.message;
  }
};

// ===== COMPLETE PROFILE (new Google / Phone user) =====
window.completeProfile = async () => {
  const firstName = document.getElementById('cp-firstname').value.trim();
  const lastName  = document.getElementById('cp-lastname').value.trim();
  const dob       = document.getElementById('cp-dob').value;
  const gender    = document.getElementById('cp-gender').value;
  const phone     = document.getElementById('cp-phone').value.trim();
  const email     = document.getElementById('cp-email').value.trim();
  const org       = document.getElementById('cp-org').value.trim();
  const err       = document.getElementById('cp-err');
  err.textContent = '';

  if (!firstName || !lastName)       { err.textContent = 'Ism va familiya majburiy'; return; }
  if (!dob)                          { err.textContent = 'Tug\'ilgan sana majburiy'; return; }
  if (!gender)                       { err.textContent = 'Jinsni tanlang'; return; }
  if (!phone && !email)              { err.textContent = 'Telefon yoki email kiritish shart'; return; }

  if (phone && !/^\+\d{10,15}$/.test(phone.replace(/\s/g,''))) {
    err.textContent = 'Telefon: +998901234567 formatida kiriting'; return;
  }
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    err.textContent = 'Email manzil noto\'g\'ri'; return;
  }

  const fullName = firstName + ' ' + lastName;

  if (pendingAuthMethod === 'phone') {
    try {
      if (!window._otpAlreadySent) {
        showLoading('SMS kod yuborilmoqda...');
        await ensureRecaptcha();
        phoneConfirmResult = await signInWithPhoneNumber(auth, pendingPhone, recaptchaVerifier);
        hideLoading();
      }
      window._otpAlreadySent = false;
      window._pendingProfile = { firstName, lastName, fullName, dob, gender, phone:pendingPhone, email, org, job:'' };
      document.getElementById('otp-phone-display').textContent = pendingPhone;
      showAuthScreen('otp');
    } catch(e) {
      hideLoading();
      recaptchaVerifier = null;
      err.textContent = 'SMS yuborishda xatolik: ' + e.message;
    }
  } else if (pendingAuthMethod === 'google' && currentUser) {
    try {
      showLoading('Saqlanmoqda...');
      await updateProfile(currentUser, { displayName: fullName });
      await setDoc(doc(db, 'users', currentUser.uid), {
        firstName, lastName, fullName, dob, gender,
        phone: phone||'', email: email||currentUser.email||'',
        org: org||'', job: '',
        role: 'user', blocked: false,
        authMethod: 'google',
        createdAt: serverTimestamp(),
        lastLogin: serverTimestamp(),
        lastAgent: navigator.userAgent.slice(0,120),
        photoURL: currentUser.photoURL||''
      });
      currentUserData = (await getDoc(doc(db,'users',currentUser.uid))).data();
      await activateAuthenticatedUser(currentUser, currentUserData);
    } catch(e) {
      hideLoading();
      err.textContent = 'Xatolik: ' + e.message;
    }
  }
};

async function savePhoneProfile(user) {
  const p = window._pendingProfile;
  if (!p) return;
  try {
    await updateProfile(user, { displayName: p.fullName });
    await setDoc(doc(db, 'users', user.uid), {
      firstName: p.firstName, lastName: p.lastName, fullName: p.fullName,
      dob: p.dob, gender: p.gender,
      phone: p.phone, email: p.email||'',
      org: p.org||'', job: p.job||'',
      role: 'user', blocked: false,
      authMethod: 'phone',
      createdAt: serverTimestamp(),
      lastLogin: serverTimestamp(),
      lastAgent: navigator.userAgent.slice(0,120),
      photoURL: ''
    });
    window._pendingProfile = null;
    currentUserData = (await getDoc(doc(db,'users',user.uid))).data();
    await activateAuthenticatedUser(user, currentUserData);
  } catch(e) {
    hideLoading();
    showToast('Profil saqlashda xatolik: ' + e.message, 'error');
  }
}

// ===== VERIFY OTP — handles both login and new registration =====
window.verifyOTP = async () => {
  const code = document.getElementById('otp-code').value.trim();
  const err  = document.getElementById('otp-err');
  err.textContent = '';
  if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
    err.textContent = '6 xonali raqamli kodni kiriting'; return;
  }
  try {
    showLoading('Tasdiqlash...');
    const result = await phoneConfirmResult.confirm(code);
    const user = result.user;
    if (window._pendingProfile) {
      // New user — save profile
      await savePhoneProfile(user);
    }
    // Existing user — onAuthStateChanged will call showApp()
  } catch(e) {
    hideLoading();
    err.textContent = 'Kod noto\'g\'ri yoki muddati o\'tgan. Qaytadan urinib ko\'ring.';
  }
};

window.doLogout = async () => {
  try {
    clearSession();
    // Security: session yopish
    if (currentUser?.uid) await Security.endSession(currentUser.uid).catch(()=>{});
    currentUser = null;
    currentUserData = null;
    allDocs = [];
    filteredDocs = [];
    await signOut(auth);
    showAuthScreen('login');
    // Clear any cached credential to prevent auto-login
    document.getElementById('login-email').value = '';
    document.getElementById('login-pass').value = '';
  } catch(e) {
    console.error('Logout error:', e);
    // Force UI reset even if signOut fails
    showAuthScreen('login');
  }
};

// ===== SUPER ADMIN: create user (old method kept for admin panel) =====
window.createUser = async () => {
  if (currentUserData?.role !== 'admin' && currentUserData?.role !== 'superadmin') {
    alert('Ruxsat yo\'q'); return;
  }
  const email = document.getElementById('new-email').value.trim();
  const pass  = document.getElementById('new-pass').value.trim();
  const name  = document.getElementById('new-name').value.trim();
  const role  = document.getElementById('new-role').value;
  const org   = document.getElementById('new-org').value.trim();
  if (!email || !pass || !name) { alert('Barcha maydonlarni to\'ldiring'); return; }
  try {
    showLoading('Foydalanuvchi yaratilmoqda...');
    const secondApp = initializeApp(firebaseConfig, 'secondary_' + Date.now());
    const secondAuth = getAuth(secondApp);
    const cred = await createUserWithEmailAndPassword(secondAuth, email, pass);
    await updateProfile(cred.user, { displayName: name });
    await setDoc(doc(db, 'users', cred.user.uid), {
      fullName: name, firstName: name, lastName: '', email, phone: '',
      role, org, blocked: false,
      authMethod: 'email',
      createdAt: serverTimestamp(),
      createdBy: currentUser.uid
    });
    await signOut(secondAuth);
    hideLoading();
    alert('✅ Foydalanuvchi yaratildi: ' + email);
    document.getElementById('new-email').value = '';
    document.getElementById('new-pass').value  = '';
    document.getElementById('new-name').value  = '';
    document.getElementById('new-org').value   = '';
    loadAllUsers();
  } catch(e) {
    hideLoading();
    alert('Xatolik: ' + e.message);
  }
};

// ===== COL MAP =====
let colMap = {
  docName:'', docNum:'', docDate:'', orgOutNum:'',
  fromOrg:'', resolution:'', taskText:'', executor:'',
  status:'', deadline:'', ourOutNum:'', docType:''
};

const COL_LABELS = {
  docName:'Hujjat nomi', docNum:'Hujjat raqami', docDate:'Hujjat sanasi',
  orgOutNum:'Tashkilot chiqish raqami', fromOrg:'Kimdan keldi',
  resolution:'Rezalyutsiya (Kimga)', taskText:'Topshiriq matni',
  executor:'Ijrochi', status:'Ijro holati', deadline:'Ijro muddati',
  ourOutNum:'Bizdan chiqish raqami', docType:'Hujjat turi'
};

const COL_KEYWORDS = {
  docName:['hujjat nomi','ҳужжат номи','хужжат номи','документ номи','номи','mavzu','қисқача мазмун','qisqacha mazmun','title','subject','name'],
  docNum:['kirish raqami','кириш рақами','кириш раками','hujjat raqami','ҳужжат рақами','хужжат раками','raqami','raqam','registratsiya raqami','ro\'yxat raqami','royxat raqami','number','num','№','номер'],
  docDate:['kiruvchi sana','кирувчи сана','hujjat sanasi','ҳужжат санаси','sana','келган сана','qabul qilingan sana','ro\'yxat sanasi','royxat sanasi','date','дата'],
  orgOutNum:['chiqish raqami','чиқиш рақами','чикиш раками','chiquvchi raqam','чиқувчи рақам','tashkilot chiqish','tashkilot raqami','yuboruvchi raqami','sender number','outgoing','исходящий номер'],
  fromOrg:['yuboruvchi','юборувчи','jo\'natuvchi','jonatuvchi','кимдан','kimdan','kimdan keldi','yuborgan','kelgan tashkilot','tashkilot nomi','tashkilot','manba','манба','idora','muassasa','from','sender','source','organization','организация','ташкилот'],
  resolution:['rezolyutsiya','rezalyutsiya','резолюция','kimga','kimga berildi','rahbar rezolyutsiyasi','резолюцияни имзолаган раҳбар','юқори турувчи орган топшириғи','resolution','addressed'],
  taskText:['topshiriq mazmuni','топшириқ мазмуни','topshiriq matni','ҳужжатнинг қисқача мазмуни','хужжатнинг кискача мазмуни','topshiriq','топшириқ','vazifa','ijro mazmuni','matn','mazmun','qisqacha mazmun','task','assignment','content'],
  executor:['asosiy ijrochi','асосий ижрочи','ijrochi','ижрочи','ijrochilar','ижрочилар','masul','mas\'ul','masul xodim','bajaruvchi','xodim','executor','исполнитель'],
  status:['topshiriq holati','топшириқ ҳолати','holat','status','ijro holati','ijro statusi','ijro natijasi','natija','bajarilishi','состояние','статус'],
  deadline:['bajarish muddati','бажариш муддати','muddat','ijro muddati','oxirgi muddat','deadline','due date','срок','срок исполнения','tugash'],
  ourOutNum:['bizdan','bizdan chiqish','ichki raqam','биздан чиқиш','ички рақам'],
  docType:['hujjat turi','ҳужжат тури','хужжат тури','topshiriq turi','топшириқ тури','tur','xat turi','type','тип','вид']
};

// ===== FIRESTORE DOCS =====
async function fetchAvailableDocs() {
  if(!currentUser) return [];
  const role = currentUserData?.role;
  const q = (role === 'admin' || role === 'superadmin')
    ? query(collection(db,'documents'), orderBy('createdAt','desc'))
    : query(collection(db,'documents'), where('userId','==', currentUser.uid), orderBy('createdAt','desc'));
  const snap = await getDocs(q);
  return snap.docs.map(d => ({ _id: d.id, ...d.data() }));
}

async function loadUserDocs() {
  showLoading("Ma'lumotlar yuklanmoqda...");
  try {
    allDocs = await fetchAvailableDocs();
    docsLoadedOnce = true;
    filteredDocs = [...allDocs];
    updateBadges();
    tashkilotlarCache = mergeTashkilotSources(tashkilotlarCache, buildTashkilotStatsFromDocs(allDocs));
    updateTashkilotlarBadge();
    persistTashkilotStatsFromDocs(allDocs, true);
    renderTable();
    buildStats();
    hideLoading();
  } catch(e) {
    hideLoading();
    console.error(e);
    showToast('Ma\'lumot yuklashda xatolik: ' + e.message, 'error');
  }
}

function normalizeOrgName(name) {
  return String(name||'')
    .replace(/[«»"']/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function orgKey(name) {
  return normalizeOrgName(name).toLowerCase();
}

function makeTashkilotLocalId(name) {
  const key = orgKey(name).replace(/[^a-z0-9а-яёёўқғҳъь]+/gi, '_').replace(/^_+|_+$/g, '');
  return 'org_' + (key || ('item_' + Date.now().toString(36)));
}

function getTashkilotRowId(t={}) {
  return t.row_id || t.local_id || (t.id ? `fs_${t.id}` : makeTashkilotLocalId(t.nom || ''));
}

function localTashkilotKey() {
  return `ijroda_tashkilotlar_${currentUser?.uid || 'guest'}`;
}

function ignoredTashkilotKey() {
  return `ijroda_tashkilotlar_ignored_${currentUser?.uid || 'guest'}`;
}

function readIgnoredTashkilotKeys() {
  try {
    const raw = localStorage.getItem(ignoredTashkilotKey());
    const arr = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(arr) ? arr : []);
  } catch(e) { return new Set(); }
}

function writeIgnoredTashkilotKeys(keys) {
  try {
    localStorage.setItem(ignoredTashkilotKey(), JSON.stringify([...keys]));
  } catch(e) { console.warn('Ignored tashkilotlar saqlanmadi:', e); }
}

function ignoreTashkilotName(name) {
  const key = orgKey(name);
  if(!key) return;
  const ignored = readIgnoredTashkilotKeys();
  ignored.add(key);
  writeIgnoredTashkilotKeys(ignored);
}

function unignoreTashkilotName(name) {
  const key = orgKey(name);
  if(!key) return;
  const ignored = readIgnoredTashkilotKeys();
  ignored.delete(key);
  writeIgnoredTashkilotKeys(ignored);
}

function readLocalTashkilotlar() {
  try {
    const raw = localStorage.getItem(localTashkilotKey());
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch(e) { return []; }
}

function writeLocalTashkilotlar(list=[]) {
  try {
    localStorage.setItem(localTashkilotKey(), JSON.stringify(list));
  } catch(e) { console.warn('Local tashkilotlar saqlanmadi:', e); }
}

function upsertLocalTashkilotlar(items=[]) {
  const merged = new Map(readLocalTashkilotlar().map(t => [orgKey(t.nom), t]));
  const ignored = readIgnoredTashkilotKeys();
  (items||[]).forEach(item => {
    const nom = normalizeOrgName(item.nom);
    if(!isValidOrgName(nom)) return;
    const key = orgKey(nom);
    if(ignored.has(key)) return;
    const old = merged.get(key) || {};
    const incomingCount = Number(item.hujjatlar_soni ?? item.count ?? 1);
    merged.set(key, {
      ...old,
      ...item,
      id: old.id || item.id || '',
      local_id: old.local_id || item.local_id || makeTashkilotLocalId(nom),
      row_id: old.row_id || item.row_id || (old.id || item.id ? `fs_${old.id || item.id}` : (old.local_id || item.local_id || makeTashkilotLocalId(nom))),
      nom,
      hujjatlar_soni: Math.max(Number(old.hujjatlar_soni||0), incomingCount),
      oxirgi_xat: item.oxirgi_xat || item.lastDate || old.oxirgi_xat || new Date().toLocaleDateString('uz-UZ'),
      auto_added: item.auto_added !== false,
      local_only: !item.id,
      updatedLocalAt: new Date().toISOString()
    });
  });
  const list = [...merged.values()].sort((a,b)=>(a.nom||'').localeCompare(b.nom||'', 'uz'));
  writeLocalTashkilotlar(list);
  return list;
}

function isValidOrgName(name) {
  const n = normalizeOrgName(name);
  if(n.length < 3) return false;
  if(/^[\d\s.,:/\\-]+$/.test(n)) return false;
  const bad = ['noma\'lum','nomalum','yo\'q','yoq','-','—'];
  return !bad.includes(n.toLowerCase());
}

function getOrgText(row={}) {
  const raw = row._raw || {};
  const direct = row.fromOrg || row.kimdan || row.tashkilot || row.organization ||
    raw['Kimdan keldi'] || raw['Kimdan'] || raw['Tashkilot'] || raw['Tashkilot nomi'] ||
    raw['Manba'] || raw['Юборувчи'] || raw['Отправитель'] || raw['Организация'] ||
    raw['Источник'] || raw['Кемдан'] || '';
  if(direct) return direct;
  const orgHeaderWords = ['kimdan','yuboruvchi',"jo'natuvchi",'jonatuvchi','tashkilot','manba','from','sender','source','отправитель','организация','источник','кемдан','юборувчи'];
  const foundKey = Object.keys(raw).find(k => {
    const nk = normalizeText(k);
    return orgHeaderWords.some(w => nk.includes(w));
  });
  return foundKey ? raw[foundKey] : '';
}

function buildTashkilotStatsFromDocs(rows=allDocs) {
  const map = new Map();
  const ignored = readIgnoredTashkilotKeys();
  (rows||[]).forEach(row => {
    const nom = normalizeOrgName(getOrgText(row));
    if(!isValidOrgName(nom)) return;
    const key = orgKey(nom);
    if(ignored.has(key)) return;
    const cur = map.get(key) || {
      id: '',
      local_id: makeTashkilotLocalId(nom),
      row_id: makeTashkilotLocalId(nom),
      nom,
      manzil: '',
      hujjatlar_soni: 0,
      oxirgi_xat: '',
      auto_added: true,
      from_docs: true
    };
    cur.hujjatlar_soni += 1;
    cur.oxirgi_xat = row.docDate || row.hujjat_sanasi || row.deadline || cur.oxirgi_xat;
    map.set(key, cur);
  });
  return map;
}

function mergeTashkilotSources(dbRows=[], docStats=buildTashkilotStatsFromDocs(), localRows=readLocalTashkilotlar()) {
  const merged = new Map();
  const ignored = readIgnoredTashkilotKeys();
  docStats.forEach((v,k)=>{ if(!ignored.has(k)) merged.set(k, {...v}); });
  [...(localRows||[]), ...(dbRows||[])].forEach(t => {
    const key = orgKey(t.nom);
    if(!key || ignored.has(key)) return;
    const fromDocs = merged.get(key);
    merged.set(key, {
      ...fromDocs,
      ...t,
      local_id: t.local_id || fromDocs?.local_id || makeTashkilotLocalId(t.nom),
      row_id: t.id ? `fs_${t.id}` : (t.row_id || t.local_id || fromDocs?.row_id || fromDocs?.local_id || makeTashkilotLocalId(t.nom)),
      hujjatlar_soni: Math.max(Number(t.hujjatlar_soni||0), Number(fromDocs?.hujjatlar_soni||0)),
      oxirgi_xat: t.oxirgi_xat || fromDocs?.oxirgi_xat || '',
      from_docs: !!fromDocs,
      auto_added: t.auto_added || !!fromDocs?.auto_added,
      local_only: !!t.local_only && !t.id
    });
  });
  return [...merged.values()].sort((a,b)=>(a.nom||'').localeCompare(b.nom||'', 'uz'));
}

async function syncTashkilotlarFromDocs(rows=[]) {
  const grouped = buildTashkilotStatsFromDocs(rows);
  if(!grouped.size) return;

  upsertLocalTashkilotlar([...grouped.values()].map(item => ({
    nom: item.nom,
    hujjatlar_soni: item.hujjatlar_soni,
    oxirgi_xat: item.oxirgi_xat,
    auto_added: true,
    from_docs: true
  })));
  tashkilotlarCache = mergeTashkilotSources(tashkilotlarCache, grouped);
  updateTashkilotlarBadge();
  if(document.getElementById('panel-tashkilotlar')?.classList.contains('active')) renderTashkilotlar();

  try {
    const snap = await getDocs(collection(db,'tashkilotlar'));
    const existing = new Map(snap.docs.map(d => [orgKey(d.data().nom), { id:d.id, ...d.data() }]));
    const ops = [];
    grouped.forEach(item => {
      const found = existing.get(orgKey(item.nom));
      if(found) {
        ops.push(updateDoc(doc(db,'tashkilotlar',found.id), {
          hujjatlar_soni: increment(item.hujjatlar_soni),
          oxirgi_xat: item.oxirgi_xat || found.oxirgi_xat || new Date().toLocaleDateString('uz-UZ'),
          updatedAt: serverTimestamp()
        }));
      } else {
        ops.push(addDoc(collection(db,'tashkilotlar'), {
          nom: item.nom,
          manzil: '',
          hujjatlar_soni: item.hujjatlar_soni,
          oxirgi_xat: item.oxirgi_xat || new Date().toLocaleDateString('uz-UZ'),
          auto_added: true,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp()
        }));
      }
    });
    await Promise.all(ops);
    updateTashkilotlarBadge();
    if(document.getElementById('panel-tashkilotlar')?.classList.contains('active')) await loadTashkilotlar();
  } catch(e) {
    console.warn('Tashkilotlarni avtomatik yangilashda xatolik:', e);
    tashkilotlarCache = mergeTashkilotSources(tashkilotlarCache, grouped);
    updateTashkilotlarBadge();
    if(document.getElementById('panel-tashkilotlar')?.classList.contains('active')) renderTashkilotlar();
    showToast('Tashkilotlar ro\'yxatga qo\'shildi. Server ruxsati bo\'lmasa ham lokal saqlandi.', 'info');
  }
}

async function persistTashkilotStatsFromDocs(rows=allDocs, silent=true) {
  const stats = buildTashkilotStatsFromDocs(rows);
  if(!stats.size) return;
  upsertLocalTashkilotlar([...stats.values()].map(item => ({
    nom: item.nom,
    hujjatlar_soni: item.hujjatlar_soni,
    oxirgi_xat: item.oxirgi_xat,
    auto_added: true,
    from_docs: true
  })));
  try {
    const snap = await getDocs(collection(db,'tashkilotlar'));
    const existing = new Map(snap.docs.map(d => [orgKey(d.data().nom), { id:d.id, ...d.data() }]));
    const ops = [];
    stats.forEach(item => {
      const found = existing.get(orgKey(item.nom));
      if(found) {
        const nextCount = Math.max(Number(found.hujjatlar_soni||0), Number(item.hujjatlar_soni||0));
        if(nextCount !== Number(found.hujjatlar_soni||0) || (!found.oxirgi_xat && item.oxirgi_xat)) {
          ops.push(updateDoc(doc(db,'tashkilotlar',found.id), {
            hujjatlar_soni: nextCount,
            oxirgi_xat: found.oxirgi_xat || item.oxirgi_xat || '',
            updatedAt: serverTimestamp()
          }));
        }
      } else {
        ops.push(addDoc(collection(db,'tashkilotlar'), {
          nom: item.nom,
          manzil: '',
          hujjatlar_soni: item.hujjatlar_soni,
          oxirgi_xat: item.oxirgi_xat || new Date().toLocaleDateString('uz-UZ'),
          auto_added: true,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp()
        }));
      }
    });
    if(ops.length) {
      await Promise.all(ops);
      if(!silent) showToast(`✅ ${ops.length} ta tashkilot hujjatlardan tiklandi`, 'success');
    } else if(!silent) {
      showToast('Tashkilotlar ro\'yxati allaqachon yangilangan', 'info');
    }
  } catch(e) {
    console.warn('Tashkilotlarni serverga tiklashda xatolik:', e);
    if(!silent) showToast('Serverga yozilmadi. Firestore rules ichida tashkilotlar ruxsatini tekshiring.', 'error');
  }
}

window.saveDocs = async (rows) => {
  showLoading(`${rows.length} ta hujjat saqlanmoqda...`);
  try {
    const batch = [];
    for(const row of rows) {
      const id = `${currentUser.uid}_${Date.now()}_${Math.random().toString(36).slice(2,7)}`;
      const data = {
        userId: currentUser.uid,
        userEmail: currentUser.email,
        userName: currentUserData?.fullName || currentUserData?.name || currentUser.email,
        userOrg: currentUserData?.org || '',
        createdAt: serverTimestamp(),
        ...row
      };
      batch.push(setDoc(doc(db,'documents',id), data));
    }
    await Promise.all(batch);
    await syncTashkilotlarFromDocs(rows);
    await loadUserDocs();
    showToast(`✅ ${rows.length} ta hujjat saqlandi!`, 'success');
  } catch(e) {
    hideLoading();
    showToast('Saqlashda xatolik: '+e.message, 'error');
  }
};

window.deleteDoc2 = async (id) => {
  if(!confirm('Bu hujjatni o\'chirmoqchimisiz?')) return;
  try {
    await deleteDoc(doc(db,'documents',id));
    allDocs = allDocs.filter(d=>d._id!==id);
    filteredDocs = filteredDocs.filter(d=>d._id!==id);
    renderTable();
    buildStats();
    showToast('Hujjat o\'chirildi','success');
  } catch(e) {
    showToast('Xatolik: '+e.message,'error');
  }
};

window.clearAllDocs = async () => {
  if(!confirm(`Barcha ${allDocs.length} ta hujjatni o'chirmoqchimisiz? Bu amalni qaytarib bo'lmaydi!`)) return;
  showLoading('O\'chirilmoqda...');
  try {
    await Promise.all(allDocs.map(d => deleteDoc(doc(db,'documents',d._id))));
    allDocs = [];
    filteredDocs = [];
    renderTable();
    buildStats();
    hideLoading();
    showToast('Barcha hujjatlar o\'chirildi','success');
  } catch(e) {
    hideLoading();
    showToast('Xatolik: '+e.message,'error');
  }
};

async function loadAllUsers() {
  const role = currentUserData?.role;
  if(role !== 'admin' && role !== 'superadmin') return;
  try {
    const snap = await getDocs(collection(db,'users'));
    adminUsersCache = snap.docs.map(d=>({id:d.id,...d.data()}));
    renderAdminUsers();
  } catch(e) {
    showToast('Foydalanuvchilar yuklanmadi: '+e.message,'error');
  }
}

function renderAdminUsers() {
  const role = currentUserData?.role;
  const q = ((document.getElementById('admin-user-search')?.value || document.getElementById('sa-search')?.value || '')).toLowerCase();
  const rf = document.getElementById('admin-role-filter')?.value || '';
  const sf = document.getElementById('admin-status-filter')?.value || '';
  const users = adminUsersCache.filter(u=>{
    const hay = `${u.fullName||u.name||''} ${u.email||''} ${u.phone||''} ${u.org||''} ${u.role||''}`.toLowerCase();
    if(q && !hay.includes(q)) return false;
    if(rf && (u.role||'user') !== rf) return false;
    if(sf==='blocked' && !u.blocked) return false;
    if(sf==='active' && u.blocked) return false;
    if(sf==='online' && !u.online) return false;
    return true;
  });
  const rows = users.map(u=>`
      <tr>
        <td>
          ${u.photoURL ? `<img src="${escH(u.photoURL)}" style="width:28px;height:28px;border-radius:50%;vertical-align:middle;margin-right:6px;">` : '<span style="display:inline-block;width:28px;height:28px;border-radius:50%;background:var(--border);vertical-align:middle;margin-right:6px;text-align:center;line-height:28px;font-size:12px;">👤</span>'}
          <b>${escH(u.fullName||u.name||'—')}</b>
          <div style="font-size:10px;color:${u.online?'var(--green-mid)':'var(--muted)'};">${u.online?'● online':'○ offline'}</div>
        </td>
        <td style="font-size:11px;">${escH(u.email||u.phone||'—')}</td>
        <td style="font-size:11px;">${escH(u.org||'—')}</td>
        <td><span class="badge ${u.role==='superadmin'?'badge-fail':u.role==='admin'?'badge-proc':(u.plan||u.subscription)==='premium'?'badge-done':'badge-wait'}">${escH(u.role||'user')}</span><div style="font-size:10px;color:var(--muted);">${escH(u.plan||u.subscription||'free')}</div></td>
        <td style="font-size:11px;color:var(--muted);">${escH(u.authMethod||'—')}</td>
        <td style="font-size:10px;color:var(--muted);">${u.lastLogin?.toDate ? u.lastLogin.toDate().toLocaleString('uz-UZ') : (u.lastSeenLocal||'—')}</td>
        <td><span class="badge ${u.blocked?'badge-fail':'badge-done'}">${u.blocked?'Bloklangan':'Faol'}</span></td>
        <td style="display:flex;gap:4px;flex-wrap:wrap;">
          ${role==='superadmin' ? `
            <button class="btn btn-sm ${u.blocked?'btn-success':'btn-danger'}" onclick="toggleBlock('${u.id}',${!!u.blocked})">${u.blocked?'✅ Ochish':'🚫 Bloklash'}</button>
            <select class="btn btn-sm btn-outline" onchange="changeRole('${u.id}',this.value)" style="padding:4px 6px;font-size:11px;">
              <option value="">Rol...</option><option value="user" ${u.role==='user'?'selected':''}>user</option><option value="admin" ${u.role==='admin'?'selected':''}>admin</option><option value="superadmin" ${u.role==='superadmin'?'selected':''}>superadmin</option>
            </select>
            <select class="btn btn-sm btn-outline" onchange="changePlan('${u.id}',this.value)" style="padding:4px 6px;font-size:11px;">
              <option value="free" ${(u.plan||u.subscription||'free')==='free'?'selected':''}>free</option><option value="premium" ${(u.plan||u.subscription)==='premium'?'selected':''}>premium</option><option value="admin" ${(u.plan||u.subscription)==='admin'?'selected':''}>admin</option>
            </select>` : ''}
          <button class="btn btn-sm btn-danger" onclick="deleteUser('${u.id}','${escH(u.email||u.phone||'')}')">O'chirish</button>
        </td>
      </tr>`).join('') || '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--muted);">Foydalanuvchi topilmadi</td></tr>';
  document.querySelectorAll('[data-users-tbody]').forEach(tbody=>tbody.innerHTML=rows);
  const countEl = document.getElementById('admin-users-count'); if(countEl) countEl.textContent = users.length;
}
window.renderAdminUsers = renderAdminUsers;
window.toggleBlock = async (uid, isBlocked) => {
  if(!confirm(isBlocked ? 'Blokdan chiqarilsinmi?' : 'Bu foydalanuvchini bloklash?')) return;
  try {
    await updateDoc(doc(db,'users',uid), { blocked: !isBlocked, updatedAt: serverTimestamp() });
    await writeAudit('user.block_toggle', { uid, blocked: !isBlocked });
    showToast(isBlocked ? '✅ Blok olib tashlandi' : '🚫 Foydalanuvchi bloklandi', 'success');
    loadAllUsers();
  } catch(e) { showToast('Xatolik: '+e.message,'error'); }
};

window.changeRole = async (uid, newRole) => {
  if(!newRole) return;
  const role = currentUserData?.role;
  if(role !== 'superadmin') { showToast('❌ Faqat Super Admin rol o\'zgartira oladi', 'error'); return; }
  if(uid === currentUser?.uid) { showToast('❌ O\'zingizning rolingizni o\'zgartira olmaysiz', 'error'); return; }
  if(!confirm(`Rolni "${newRole}" ga o'zgartirish?`)) return;
  try {
    await updateDoc(doc(db,'users',uid), { role: newRole, updatedAt: serverTimestamp() });
    await writeAudit('user.role_change', { uid, role: newRole });
    showToast('✅ Rol o\'zgartirildi','success');
    loadAllUsers();
  } catch(e) { showToast('Xatolik: '+e.message,'error'); }
};


window.changePlan = async (uid, plan) => {
  if(!isSuperAdmin()) { showToast('Faqat Super Admin tarif o\'zgartira oladi','error'); return; }
  try {
    await updateDoc(doc(db,'users',uid), { plan, subscription: plan, updatedAt: serverTimestamp() });
    await setDoc(doc(db,'subscriptions',uid), { uid, plan, status:'active', updatedAt: serverTimestamp(), updatedBy: currentUser?.uid||'' }, { merge:true });
    await writeAudit('subscription.change', { uid, plan });
    showToast('✅ Tarif yangilandi','success');
    loadAllUsers(); renderSaasConsole();
  } catch(e) { showToast('Tarif xatoligi: '+e.message,'error'); }
};window.deleteUser = async (uid, email) => {
  if(!confirm(`${email} foydalanuvchisini o'chirmoqchimisiz?\n\n⚠️ Eslatma: Bu faqat Firestore profilini o'chiradi. Firebase Auth akkauntini o'chirish uchun Firebase Console > Authentication bo'limiga o'ting.`)) return;
  await writeAudit('user.delete_profile', { uid, email });
  await deleteDoc(doc(db,'users',uid));
  showToast('Foydalanuvchi profili o\'chirildi (Auth emas)','success');
  loadAllUsers();
};

// ===== FILE UPLOAD — AUTO ANALYZE & SAVE =====
window.handleFile = (input) => {
  const file = input.files[0];
  if(!file) return;
  showLoading('Excel tahlil qilinmoqda...');
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const wb = XLSX.read(new Uint8Array(e.target.result), { type:'array', cellDates:true });
      const ws = wb.Sheets[wb.SheetNames[0]];
      const json = XLSX.utils.sheet_to_json(ws, { header:1, defval:'' });
      if(json.length < 2){ hideLoading(); showToast('Fayl bo\'sh yoki noto\'g\'ri format','error'); return; }

      // Find the real header row. Some Excel files have title/filter rows above the table.
      const headerRowIdx = detectExcelHeaderRow(json);
      const headers = makeUniqueHeaders(json[headerRowIdx].map(h=>String(h||'').trim()));
      const dataRows = json.slice(headerRowIdx+1).filter(r=>r.some(c=>c!==''&&c!==undefined));

      // Auto detect columns by header aliases + sample values, then let Gemini refine it.
      autoDetectCols(headers, dataRows);
      await refineExcelMappingWithGemini(headers, dataRows, file.name);
      normalizeExcelMapping(headers, dataRows);

      // Build preview info
      const detected = Object.entries(COL_LABELS)
        .filter(([k])=>colMap[k])
        .map(([k,l])=>`${l}: <b>${escH(colMap[k])}</b>`)
        .join(' · ');

      // Show preview panel before saving
      window._uploadHeaders = headers;
      window._uploadRows = dataRows;
      window._uploadFileName = file.name;
      hideLoading();
      showAutoPreview(file.name, dataRows.length, detected, headers);

    } catch(err) {
      hideLoading();
      showToast('Fayl o\'qishda xatolik: '+err.message,'error');
    }
  };
  reader.readAsArrayBuffer(file);
};

function showAutoPreview(fname, rowCount, detected, headers) {
  const panel = document.getElementById('panel-upload');
  // Show inline preview card
  let previewHtml = `
    <div class="card" id="auto-preview-card" style="border:2px solid var(--blue-mid);">
      <div class="card-title" style="color:var(--blue-mid);">✅ Fayl tahlil qilindi — avtomatik moslashtirish</div>
      <div style="background:var(--blue-light);border-radius:8px;padding:14px;margin-bottom:14px;font-size:12px;line-height:1.8;">
        <b>📄 Fayl:</b> ${escH(fname)}<br>
        <b>📊 Qatorlar:</b> ${rowCount} ta hujjat aniqlandi<br>
        <b>AI saralash:</b> ${escH(window._excelMappingSource || 'Local heuristic')} ${window._excelMappingNotes ? `<small style="color:var(--muted);">- ${escH(window._excelMappingNotes)}</small>` : ''}<br>
        <b>🔗 Moslashtirilgan ustunlar:</b> ${detected||'<i style="color:var(--muted)">Aniqlanmadi — barcha ustunlar saqlanadi</i>'}
      </div>
      <div style="font-size:12px;color:var(--muted);margin-bottom:14px;">
        Aniqlangan ustunlar: ${headers.map(h=>`<span style="background:var(--border);padding:2px 7px;border-radius:4px;margin:2px;display:inline-block;font-size:11px;">${escH(h)}</span>`).join('')}
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <button class="btn btn-success" onclick="autoSaveExcel()">💾 Hammasi qabul — Saqlash</button>
        <button class="btn btn-primary" onclick="showPanel('mapping')">🗺️ Ustunlarni o'zim moslashtiray</button>
        <button class="btn btn-outline" onclick="cancelAutoPreview()">✕ Bekor qilish</button>
      </div>
    </div>`;
  const existing = document.getElementById('auto-preview-card');
  if(existing) existing.remove();
  panel.insertAdjacentHTML('beforeend', previewHtml);
  // Also prepare mapping panel
  buildMappingUI(headers);
  document.getElementById('upload-preview').textContent = `${fname} — ${rowCount} ta qator`;
}

window.cancelAutoPreview = () => {
  const c = document.getElementById('auto-preview-card');
  if(c) c.remove();
  window._uploadHeaders=null; window._uploadRows=null;
  document.getElementById('fi').value='';
};

window.autoSaveExcel = async () => {
  const headers = window._uploadHeaders || [];
  const rows = window._uploadRows || [];
  if(!rows.length){ showToast('Ma\'lumot yo\'q','error'); return; }

  const c = document.getElementById('auto-preview-card');
  if(c) c.remove();

  const toSave = rows.map(row=>{
    const obj={};
    headers.forEach((h,i)=>{ obj[h]=row[i]!==undefined?row[i]:''; });
    // Mapped fields
    const mapped = {
      docName: getC(obj,'docName'),
      docNum:  getC(obj,'docNum'),
      docDate: fmtDate(getC(obj,'docDate')),
      orgOutNum: getC(obj,'orgOutNum'),
      fromOrg: getC(obj,'fromOrg'),
      resolution: getC(obj,'resolution'),
      taskText: getC(obj,'taskText'),
      executor: getC(obj,'executor'),
      status: getC(obj,'status'),
      deadline: fmtDate(getC(obj,'deadline')),
      ourOutNum: getC(obj,'ourOutNum'),
      docType: getC(obj,'docType'),
    };
    // Also store ALL original columns as _raw
    mapped._raw = obj;
    mapped._allCols = headers;
    mapped.source = detectSrc(mapped);
    return mapped;
  });
  await window.saveDocs(toSave);
  showPanel('docs');
};

function normHeaderText(value) {
  return normalizeText(value)
    .replace(/[№#]/g, ' raqam ')
    .replace(/[_\-./\\]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function makeUniqueHeaders(headers=[]) {
  const seen = new Map();
  return headers.map((h, idx) => {
    const base = String(h||'').trim() || `Ustun ${idx + 1}`;
    const key = base.toLowerCase();
    const count = (seen.get(key) || 0) + 1;
    seen.set(key, count);
    return count === 1 ? base : `${base} (${count})`;
  });
}

const EXACT_EXCEL_HEADER_MAP = {
  docName: ['Ҳужжат номи', 'Хужжат номи', 'Hujjat nomi'],
  docNum: ['Кириш рақами', 'Кириш раками', 'Kirish raqami', 'Ҳужжат рақами', 'Hujjat raqami'],
  docDate: ['Кирувчи сана', 'Kiruvchi sana', 'Келган сана', 'Ҳужжат санаси', 'Hujjat sanasi'],
  orgOutNum: ['Чиқиш рақами', 'Чикиш раками', 'Chiqish raqami', 'Чиқувчи рақам', 'Chiquvchi raqam'],
  fromOrg: ['Юборувчи', 'Yuboruvchi', 'Жўнатувчи', 'Jo\'natuvchi', 'Jonatuvchi', 'Кимдан', 'Manba'],
  docType: ['Ҳужжат тури', 'Хужжат тури', 'Hujjat turi', 'Топшириқ тури', 'Topshiriq turi'],
  taskText: ['Топшириқ мазмуни', 'Topshiriq mazmuni', 'Ҳужжатнинг қисқача мазмуни', 'Hujjatning qisqacha mazmuni', 'Қисқача мазмун'],
  executor: ['Асосий ижрочи', 'Asosiy ijrochi', 'Ижрочи', 'Ijrochi', 'Ижрочилар', 'Ijrochilar', 'Охирги ижрочи'],
  status: ['Топшириқ ҳолати', 'Topshiriq holati', 'Ijro holati', 'Holat', 'Status'],
  deadline: ['Бажариш муддати', 'Bajarish muddati', 'Ijro muddati', 'Muddat'],
  resolution: ['Юқори турувчи орган топшириғи', 'Yuqori turuvchi organ topshirig\'i', 'Резолюцияни имзолаган раҳбар', 'Rezolyutsiyani imzolagan rahbar'],
  ourOutNum: ['Биздан чиқиш рақами', 'Bizdan chiqish raqami', 'Ички рақам']
};

const EXCEL_FIELD_PRIORITY = [
  'docName', 'docNum', 'docDate', 'orgOutNum', 'fromOrg', 'docType',
  'taskText', 'executor', 'status', 'deadline', 'resolution', 'ourOutNum'
];

function findExactHeader(headers=[], aliases=[]) {
  const normalized = headers.map(h => ({ raw: h, norm: normHeaderText(h) }));
  for(const alias of aliases) {
    const target = normHeaderText(alias);
    const exact = normalized.find(item => item.norm === target);
    if(exact) return exact.raw;
  }
  for(const alias of aliases) {
    const target = normHeaderText(alias);
    const loose = normalized.find(item => item.norm && target && (item.norm.includes(target) || target.includes(item.norm)));
    if(loose) return loose.raw;
  }
  return '';
}

function applyExactExcelMapping(headers=[]) {
  Object.entries(EXACT_EXCEL_HEADER_MAP).forEach(([field, aliases]) => {
    const found = findExactHeader(headers, aliases);
    if(found) colMap[field] = found;
  });
}

function normalizeExcelMapping(headers=[], rows=[]) {
  const allowed = new Set(headers);
  applyExactExcelMapping(headers);

  const selected = {};
  const used = new Set();
  EXCEL_FIELD_PRIORITY.forEach(field => {
    const header = colMap[field];
    if(header && allowed.has(header) && !used.has(header)) {
      selected[field] = header;
      used.add(header);
    } else {
      selected[field] = '';
    }
  });

  EXCEL_FIELD_PRIORITY.forEach(field => {
    if(selected[field]) return;
    const candidates = headers
      .map((header, idx) => ({
        header,
        idx,
        score: inferFieldScore(header, (rows||[]).map(r => r?.[idx]), field)
      }))
      .filter(c => c.score >= 45 && !used.has(c.header))
      .sort((a,b) => b.score - a.score);
    if(candidates[0]) {
      selected[field] = candidates[0].header;
      used.add(candidates[0].header);
    }
  });

  Object.keys(colMap).forEach(field => { colMap[field] = selected[field] || ''; });
  return colMap;
}

function isLikelyDateValue(value) {
  if(value instanceof Date) return true;
  const s = String(value||'').trim();
  if(!s) return false;
  return /^(\d{1,2})[./-](\d{1,2})[./-](\d{2,4})$/.test(s) || /^\d{4}[./-]\d{1,2}[./-]\d{1,2}$/.test(s);
}

function isLikelyOrgValue(value) {
  const s = normHeaderText(value);
  if(!s || s.length < 5) return false;
  return /(vazirlik|vazirligi|hokimlik|hokimligi|boshqarma|boshqarmasi|qo'mita|qomita|qo‘mita|agentlik|departament|idora|muassasa|markaz|mchj|aj |aksiyadorlik|universitet|institut|organization|министер|хоким|управлен|организац|комитет|агентств|учрежден)/i.test(s);
}

function isLikelyStatusValue(value) {
  return normalizeDocStatus(String(value||'')).key !== 'unknown';
}

function inferFieldScore(header, values, key) {
  const h = normHeaderText(header);
  let score = 0;
  const aliases = COL_KEYWORDS[key] || [];
  aliases.forEach(alias => {
    const a = normHeaderText(alias);
    if(!a) return;
    if(h === a) score += 80;
    else if(h.includes(a) || a.includes(h)) score += 35;
  });
  const sample = (values||[]).filter(v => String(v||'').trim()).slice(0, 30);
  if(!sample.length) return score;
  const dateRatio = sample.filter(isLikelyDateValue).length / sample.length;
  const orgRatio = sample.filter(isLikelyOrgValue).length / sample.length;
  const statusRatio = sample.filter(isLikelyStatusValue).length / sample.length;
  const avgLen = sample.reduce((a,v)=>a+String(v||'').trim().length,0) / sample.length;

  if(key === 'fromOrg') score += orgRatio * 55;
  if(key === 'docDate' || key === 'deadline') score += dateRatio * 45;
  if(key === 'status') score += statusRatio * 55;
  if(key === 'taskText' && avgLen > 45) score += 24;
  if(key === 'docName' && avgLen > 18 && avgLen <= 90) score += 14;
  if(key === 'docNum' && sample.filter(v=>/^\s*[A-Za-zА-Яа-я0-9№#\/.-]{1,25}\s*$/.test(String(v))).length/sample.length > .6) score += 18;
  if(key === 'executor' && sample.filter(v=>String(v).trim().split(/\s+/).length <= 4 && /[A-Za-zА-Яа-я]/.test(String(v))).length/sample.length > .55) score += 12;
  return score;
}

function detectExcelHeaderRow(rows=[]) {
  let bestIdx = 0, bestScore = -1;
  const maxRows = Math.min(rows.length, 25);
  for(let i=0;i<maxRows;i++) {
    const row = rows[i] || [];
    const nonEmpty = row.filter(c=>String(c||'').trim()).length;
    if(nonEmpty < 2) continue;
    const aliasHits = row.reduce((sum, cell) => {
      const h = normHeaderText(cell);
      if(!h) return sum;
      const hit = Object.values(COL_KEYWORDS).flat().some(kw => {
        const a = normHeaderText(kw);
        return a && (h.includes(a) || a.includes(h));
      });
      return sum + (hit ? 1 : 0);
    }, 0);
    const nextRows = rows.slice(i+1, i+8);
    const valueSignals = row.reduce((sum, _cell, colIdx) => {
      const vals = nextRows.map(r=>r?.[colIdx]).filter(v=>String(v||'').trim());
      return sum + (vals.some(isLikelyDateValue) || vals.some(isLikelyOrgValue) || vals.some(isLikelyStatusValue) ? 1 : 0);
    }, 0);
    const score = nonEmpty + aliasHits * 8 + valueSignals * 2 - (row.filter(isLikelyDateValue).length * 3);
    if(score > bestScore) { bestScore = score; bestIdx = i; }
  }
  return bestIdx;
}

function autoDetectCols(headers, rows=[]) {
  Object.keys(colMap).forEach(k => colMap[k] = '');
  const candidates = [];
  headers.forEach((header, idx) => {
    const values = (rows||[]).map(r=>r?.[idx]);
    Object.keys(COL_KEYWORDS).forEach(key => {
      const score = inferFieldScore(header, values, key);
      if(score >= 18) candidates.push({ key, idx, header, score });
    });
  });
  candidates.sort((a,b)=>b.score-a.score);
  const usedFields = new Set();
  const usedCols = new Set();
  candidates.forEach(c => {
    if(usedFields.has(c.key) || usedCols.has(c.idx)) return;
    colMap[c.key] = headers[c.idx];
    usedFields.add(c.key);
    usedCols.add(c.idx);
  });
  normalizeExcelMapping(headers, rows);
}

async function refineExcelMappingWithGemini(headers=[], rows=[], fileName='') {
  let key = localStorage.getItem('GEMINI_API_KEY') || '';
  if(!key) {
    const shouldAsk = confirm('Excel ustunlarini Gemini AI yordamida chuqur saralash uchun API kalit kerak. Kalit kiritasizmi?\n\nKalit bo\'lmasa oddiy avtomatik analiz ishlaydi.');
    if(shouldAsk) {
      const entered = prompt('Google Gemini API kalitini kiriting (AIza...):\nhttps://aistudio.google.com/app/apikey');
      if(entered && entered.trim().startsWith('AIza')) {
        key = entered.trim();
        localStorage.setItem('GEMINI_API_KEY', key);
      }
    }
  }
  if(!key) {
    window._excelMappingSource = 'Local heuristic';
    return false;
  }

  const sampleRows = (rows||[]).slice(0, 18).map(row => {
    const obj = {};
    headers.forEach((h,i)=>{ obj[h] = row?.[i] instanceof Date ? fmtDate(row[i]) : String(row?.[i] ?? '').slice(0, 180); });
    return obj;
  });
  const fields = Object.keys(COL_LABELS).map(k => `${k}: ${COL_LABELS[k]}`).join('\n');
  const promptText = `Sen Excel import mapping ekspertsan. O'zbek/rus/ingliz aralash ustun nomlari va namunaviy qiymatlarga qarab qaysi Excel ustuni qaysi tizim maydoniga tegishli ekanini aniqlaysan.

Qoidalar:
- FAQAT quyidagi tizim maydonlarini ishlat: ${Object.keys(COL_LABELS).join(', ')}
- Qiymatlar faqat berilgan headers ichidagi ustun nomi bo'lsin yoki bo'sh string.
- "jo'natuvchi", "jonatuvchi", "jo‘natuvchi", "yuboruvchi", "kimdan", "tashkilot", "sender", "from" odatda fromOrg.
- Har bir Excel ustuni eng mos bitta maydonga tushsin.
- Noma'lum ustunlarni majburlab noto'g'ri joyga qo'yma; ular _raw ichida saqlanadi.
- Header nomi noaniq bo'lsa sampleRows qiymatlariga qarab xulosa qil.
- Jadvaldagi bosh/title qatorlar alohida maydon emas, ularni mappingga qo'shma.

Tizim maydonlari:
${fields}

Fayl: ${fileName}
Headers:
${JSON.stringify(headers, null, 2)}

Sample rows:
${JSON.stringify(sampleRows, null, 2)}

Javob FAQAT valid JSON:
{
  "mapping": {
    "docName": "",
    "docNum": "",
    "docDate": "",
    "orgOutNum": "",
    "fromOrg": "",
    "resolution": "",
    "taskText": "",
    "executor": "",
    "status": "",
    "deadline": "",
    "ourOutNum": "",
    "docType": ""
  },
  "confidence": 0,
  "notes": "qisqa izoh"
}`;

  const models = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];
  let lastError = '';
  for(const model of models) {
    try {
      const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text: promptText }] }],
          generationConfig: {
            temperature: 0.05,
            maxOutputTokens: 1800,
            responseMimeType: 'application/json'
          }
        })
      });
      if(!resp.ok) {
        const errData = await resp.json().catch(()=>({}));
        lastError = errData?.error?.message || `HTTP ${resp.status}`;
        if(resp.status === 404) continue;
        if(resp.status === 400 || resp.status === 403) localStorage.removeItem('GEMINI_API_KEY');
        throw new Error(lastError);
      }
      const data = await resp.json();
      const text = (data?.candidates?.[0]?.content?.parts || []).map(p=>p.text||'').join('\n').trim();
      const parsed = parseAIJson(text);
      const aiMap = parsed?.mapping || {};
      const allowedHeaders = new Set(headers);
      let applied = 0;
      Object.keys(COL_LABELS).forEach(field => {
        const h = String(aiMap[field] || '').trim();
        if(h && allowedHeaders.has(h)) {
          colMap[field] = h;
          applied++;
        }
      });
      window._excelMappingSource = `Gemini AI (${parsed?.confidence || '?'}%)`;
      window._excelMappingNotes = parsed?.notes || '';
      if(applied) showToast(`Gemini AI ${applied} ta ustunni saraladi`, 'success');
      return applied > 0;
    } catch(e) {
      lastError = e.message;
      console.warn('Gemini Excel mapping failed:', e);
    }
  }
  window._excelMappingSource = 'Local heuristic';
  if(lastError) showToast('Gemini mapping ishlamadi, oddiy analiz ishlatildi: ' + lastError, 'info');
  return false;
}

function buildMappingUI(headers) {
  const opts = ['<option value="">— Tanlanmagan —</option>',
    ...headers.map(h=>`<option value="${escH(h)}">${escH(h)}</option>`)].join('');
  document.getElementById('col-map-grid').innerHTML =
    Object.keys(COL_LABELS).map(key=>`
      <div class="col-map-row">
        <div class="col-map-label">${COL_LABELS[key]}</div>
        <select id="map-${key}" onchange="colMap['${key}']=this.value">
          ${opts.replace(`value="${escH(colMap[key]||'')}"`,`value="${escH(colMap[key]||'')}" selected`)}
        </select>
      </div>`).join('');
}

window.applyMappingAndSave = async () => {
  Object.keys(colMap).forEach(k=>{
    const el=document.getElementById('map-'+k);
    if(el) colMap[k]=el.value;
  });
  const headers = window._uploadHeaders || [];
  const rows = window._uploadRows || [];
  const toSave = rows.map(row=>{
    const obj={};
    headers.forEach((h,i)=>{ obj[h]=row[i]!==undefined?row[i]:''; });
    const mapped = {
      docName: getC(obj,'docName'),
      docNum:  getC(obj,'docNum'),
      docDate: fmtDate(getC(obj,'docDate')),
      orgOutNum: getC(obj,'orgOutNum'),
      fromOrg: getC(obj,'fromOrg'),
      resolution: getC(obj,'resolution'),
      taskText: getC(obj,'taskText'),
      executor: getC(obj,'executor'),
      status: getC(obj,'status'),
      deadline: fmtDate(getC(obj,'deadline')),
      ourOutNum: getC(obj,'ourOutNum'),
      docType: getC(obj,'docType')
    };
    mapped._raw = obj;
    mapped._allCols = headers;
    mapped.source = detectSrc(mapped);
    return mapped;
  });
  await window.saveDocs(toSave);
  showPanel('docs');
};

// Manual add
window.saveManualDoc = async () => {
  const get = id => document.getElementById(id)?.value?.trim()||'';
  const row = {
    docName: get('m-docName'), docNum: get('m-docNum'),
    docDate: get('m-docDate'), orgOutNum: get('m-orgOutNum'),
    fromOrg: get('m-fromOrg'), resolution: get('m-resolution'),
    taskText: get('m-taskText'), executor: get('m-executor'),
    status: get('m-status'), deadline: get('m-deadline'),
    ourOutNum: get('m-ourOutNum'), docType: get('m-docType'),
    source: ''
  };
  row.source = detectSrc(row);
  await window.saveDocs([row]);
  // clear form
  Object.keys(row).forEach(k=>{
    const el=document.getElementById('m-'+k);
    if(el) el.value='';
  });
  showPanel('docs');
};

// ===== FILTER =====
window.applyFilter = () => {
  const org = document.getElementById('f-org')?.value.trim().toLowerCase()||'';
  const df = document.getElementById('f-date-from')?.value||'';
  const dt = document.getElementById('f-date-to')?.value||'';
  const type = document.getElementById('f-type')?.value.toLowerCase()||'';
  const status = document.getElementById('f-status')?.value.toLowerCase()||'';
  const src = document.getElementById('f-src')?.value||'';
  const search = document.getElementById('f-search')?.value.toLowerCase()||'';

  const dfrom = df ? new Date(df) : null;
  const dto = dt ? new Date(dt+'T23:59:59') : null;

  filteredDocs = allDocs.filter(row=>{
    if(org && !normalizeText(getOrgText(row)).includes(org) && !(row.docName||'').toLowerCase().includes(org)) return false;
    if(src && row.source !== src) return false;
    if(type) { const t=((row.docType||'')+(row.docName||'')).toLowerCase(); if(!t.includes(type)) return false; }
    if(status && !statusMatches(row, status)) return false;
    if(dfrom||dto) {
      const d = parseDate(row.docDate)||parseDate(row.deadline);
      if(d){ if(dfrom&&d<dfrom)return false; if(dto&&d>dto)return false; }
    }
    if(search) {
      const txt = Object.values(row).join(' ').toLowerCase();
      if(!txt.includes(search)) return false;
    }
    return true;
  });
  currentPage=1;
  renderTable();
  showToast(`${filteredDocs.length} ta hujjat topildi`,'success');
};

window.clearFilter = () => {
  ['f-org','f-date-from','f-date-to','f-search'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  ['f-type','f-status','f-src','f-period'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  filteredDocs=[...allDocs]; currentPage=1; renderTable();
};

window.setPeriod = (val) => {
  const now=new Date(); let from=new Date(), to=new Date();
  if(val==='today'){from=new Date();}
  else if(val==='week'){from=new Date();from.setDate(from.getDate()-7);}
  else if(val==='month'){from=new Date(now.getFullYear(),now.getMonth(),1);}
  else if(val==='quarter'){const q=Math.floor(now.getMonth()/3);from=new Date(now.getFullYear(),q*3,1);}
  else if(val==='halfyear'){from=new Date(now.getFullYear(),now.getMonth()-6,1);}
  else if(val==='year'){from=new Date(now.getFullYear(),0,1);}
  else return;
  document.getElementById('f-date-from').value=from.toISOString().split('T')[0];
  document.getElementById('f-date-to').value=to.toISOString().split('T')[0];
};

// ===== RENDER TABLE =====
function renderTable() {
  updateBadges();
  const wrap=document.getElementById('table-wrap');
  const pageWrap=document.getElementById('pagination');
  if(!filteredDocs.length){
    wrap.innerHTML='<div class="empty-state"><div class="empty-icon">📭</div><h3>Hujjat topilmadi</h3><p>Fayl yuklang yoki filtrni o\'zgartiring</p></div>';
    pageWrap.innerHTML=''; return;
  }
  const totalPages=Math.ceil(filteredDocs.length/PAGE_SIZE);
  const pg=Math.min(currentPage,totalPages);
  const slice=filteredDocs.slice((pg-1)*PAGE_SIZE, pg*PAGE_SIZE);

  wrap.innerHTML=`<table>
    <thead><tr>
      <th>#</th><th>Manba</th><th>Hujjat nomi</th><th>Hujjat raqami</th>
      <th>Sana</th><th>Tashk. chiqish</th><th>Kimdan</th>
      <th>Rezalyutsiya</th><th>Topshiriq</th><th>Ijrochi</th>
      <th>Holat</th><th>Muddat</th><th>Bizdan chiqish</th>
      ${currentUserData?.role==='admin'?'<th>Foydalanuvchi</th>':''}
      <th></th>
    </tr></thead>
    <tbody>${slice.map((row,i)=>`<tr>
      <td class="td-num">${(pg-1)*PAGE_SIZE+i+1}</td>
      <td>${srcBadge(row.source)}</td>
      <td class="td-doc td-wrap">${escH(row.docName||'')}</td>
      <td class="td-mono td-narrow">${escH(row.docNum||'')}</td>
      <td class="td-narrow">${escH(row.docDate||'')}</td>
      <td class="td-mono td-narrow">${escH(row.orgOutNum||'')}</td>
      <td class="td-wrap">${escH(getOrgText(row))}</td>
      <td class="td-wrap">${escH(row.resolution||'')}</td>
      <td class="td-wrap">${escH(row.taskText||'')}</td>
      <td class="td-wrap">${escH(row.executor||'')}</td>
      <td>${stBadge(getStatusText(row))}</td>
      <td class="td-narrow">${escH(row.deadline||'')}</td>
      <td class="td-mono td-narrow">${escH(row.ourOutNum||'')}</td>
      ${currentUserData?.role==='admin'?`<td class="td-narrow" style="font-size:10px;">${escH(row.userName||row.userEmail||'')}</td>`:''}
      <td><button class="btn btn-sm btn-danger" onclick="deleteDoc2('${row._id}')">✕</button></td>
    </tr>`).join('')}</tbody>
  </table>`;

  const info=`<span>${(pg-1)*PAGE_SIZE+1}–${Math.min(pg*PAGE_SIZE,filteredDocs.length)} / ${filteredDocs.length} ta hujjat</span>`;
  const pages=Array.from({length:Math.min(totalPages,7)},(_,i)=>
    `<div class="page-btn ${i+1===pg?'active':''}" onclick="changePg(${i+1})">${i+1}</div>`).join('');
  pageWrap.innerHTML=`${info}<div class="page-btns">${pages}</div>`;
}

window.changePg = (p) => { currentPage=p; renderTable(); window.scrollTo({top:300,behavior:'smooth'}); };

// ===== STATS =====
function buildStats() {
  const el=document.getElementById('stats-content');
  if(!el) return;
  const data=allDocs;
  if(!data.length){ el.innerHTML='<div class="empty-state"><div class="empty-icon">📊</div><h3>Ma\'lumot yo\'q</h3></div>'; return; }

  const total=data.length;
  const statusCounts = getStatusCounts(data);
  const done=statusCounts.done;
  const proc=statusCounts.proc;
  const fail=statusCounts.fail;
  const srcs={VM:0,PF:0,VH:0,OTHER:0};
  data.forEach(r=>srcs[r.source||'OTHER']=(srcs[r.source||'OTHER']||0)+1);

  const orgCount={};
  data.forEach(r=>{ const o=normalizeOrgName(getOrgText(r))||'Noma\'lum'; orgCount[o]=(orgCount[o]||0)+1; });
  const topOrgs=Object.entries(orgCount).sort((a,b)=>b[1]-a[1]).slice(0,8);

  el.innerHTML=`
    <div class="stat-grid-5">
      <div class="stat-box blue"><div class="sv">${total}</div><div class="sl">Jami hujjat</div></div>
      <div class="stat-box green"><div class="sv">${done}</div><div class="sl">Bajarildi</div></div>
      <div class="stat-box yellow"><div class="sv">${proc}</div><div class="sl">Jarayonda</div></div>
      <div class="stat-box red"><div class="sv">${fail}</div><div class="sl">Bajarilmadi</div></div>
      <div class="stat-box navy"><div class="sv">${total>0?Math.round(done/total*100):0}%</div><div class="sl">Ijro foizi</div></div>
    </div>
    <div class="stats-two-col">
      <div class="card">
        <div class="card-title">🏢 Manba taqsimoti</div>
        ${[['VM','Vazirlar Mahkamasi','src-vm'],['PF','Prezident farmonlari','src-pf'],
           ['VH','Viloyat hokimligi','src-vh'],['OTHER','Boshqa','src-other']].map(([k,label,cls])=>`
          <div class="org-bar-row">
            <span class="src-tag ${cls}">${k}</span>
            <div class="org-bar-wrap">
              <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px;">
                <span>${label}</span><b>${srcs[k]||0}</b>
              </div>
              <div class="prog-bg"><div class="prog-fill" style="width:${total>0?Math.round((srcs[k]||0)/total*100):0}%;background:var(--blue-mid)"></div></div>
            </div>
          </div>`).join('')}
      </div>
      <div class="card">
        <div class="card-title">🏛️ Top tashkilotlar</div>
        ${topOrgs.map(([org,cnt],i)=>`
          <div class="org-bar-row" style="margin-bottom:10px;">
            <span style="font-size:11px;color:var(--muted);min-width:16px;font-family:'JetBrains Mono',monospace;">${i+1}</span>
            <div class="org-bar-wrap">
              <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px;">
                <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px;">${escH(org)}</span>
                <b style="color:var(--blue-mid);">${cnt}</b>
              </div>
              <div class="prog-bg"><div class="prog-fill" style="width:${topOrgs[0][1]>0?Math.round(cnt/topOrgs[0][1]*100):0}%"></div></div>
            </div>
          </div>`).join('')}
      </div>
    </div>`;
}

// ===== EXCEL EXPORT =====
window.exportExcel = (mode='filtered') => {
  const data = mode==='all' ? allDocs : filteredDocs;
  if(!data.length){ showToast("Ma'lumot yo'q!",'error'); return; }
  showLoading('Excel tayyorlanmoqda...');

  const rows=[['#','Manba','Hujjat nomi','Hujjat raqami','Hujjat sanasi',
    'Tashk. chiqish raqami','Kimdan keldi','Rezalyutsiya','Topshiriq',
    'Ijrochi','Ijro holati','Ijro muddati','Bizdan chiqish raqami',
    ...(currentUserData?.role==='admin'?['Foydalanuvchi','Tashkilot']:[])]];

  data.forEach((r,i)=>rows.push([i+1,r.source||'',r.docName||'',r.docNum||'',
    r.docDate||'',r.orgOutNum||'',getOrgText(r),r.resolution||'',
    r.taskText||'',r.executor||'',getStatusText(r),r.deadline||'',r.ourOutNum||'',
    ...(currentUserData?.role==='admin'?[r.userName||r.userEmail||'',r.userOrg||'']:[])]));

  const wb=XLSX.utils.book_new();
  const ws=XLSX.utils.aoa_to_sheet(rows);
  ws['!cols']=[{wch:4},{wch:6},{wch:32},{wch:14},{wch:12},{wch:18},{wch:26},
    {wch:26},{wch:36},{wch:22},{wch:14},{wch:12},{wch:18},{wch:24},{wch:20}];

  // Summary
  const total=data.length;
  const statusCounts = getStatusCounts(data);
  const done=statusCounts.done;
  const proc=statusCounts.proc;
  const fail=statusCounts.fail;
  const srcs={VM:0,PF:0,VH:0,OTHER:0};
  data.forEach(r=>srcs[r.source||'OTHER']=(srcs[r.source||'OTHER']||0)+1);
  const pct=v=>total>0?Math.round(v/total*100)+'%':'0%';

  const sumRows=[
    ['IJRODA HUJJATLARI TAHLIL HISOBOTI'],[''],
    ['Sana:',new Date().toLocaleDateString('uz-UZ')],
    ['Foydalanuvchi:', currentUserData?.name||currentUser.email],
    [''],['UMUMIY KO\'RSATKICHLAR','MIQDOR','FOIZ'],
    ['Jami hujjatlar',total,'100%'],
    ['Bajarildi',done,pct(done)],['Jarayonda',proc,pct(proc)],
    ['Bajarilmadi',fail,pct(fail)],[''],
    ['MANBA BO\'YICHA','',''],
    ['Vazirlar Mahkamasi (VM)',srcs.VM,pct(srcs.VM)],
    ['Prezident farmonlari (PF)',srcs.PF,pct(srcs.PF)],
    ['Viloyat hokimligi (VH)',srcs.VH,pct(srcs.VH)],
    ['Boshqa',srcs.OTHER,pct(srcs.OTHER)],
  ];
  const wsSum=XLSX.utils.aoa_to_sheet(sumRows);
  wsSum['!cols']=[{wch:36},{wch:12},{wch:10}];

  XLSX.utils.book_append_sheet(wb,ws,'Hujjatlar');
  XLSX.utils.book_append_sheet(wb,wsSum,'Xulosa');

  setTimeout(()=>{
    XLSX.writeFile(wb,`Ijroda_Hisobot_${new Date().toISOString().slice(0,10)}.xlsx`);
    hideLoading();
  },300);
};

// ===== HELPERS =====
function getC(row,key){
  const col=colMap[key];
  const v = col ? row[col] : '';
  if(!v&&v!==0) return '';
  if(v instanceof Date) return fmtDate(v);
  return String(v).trim();
}

function fmtDate(d){
  if(!d) return '';
  if(d instanceof Date){
    const dd=String(d.getDate()).padStart(2,'0');
    const mm=String(d.getMonth()+1).padStart(2,'0');
    return `${dd}.${mm}.${d.getFullYear()}`;
  }
  return String(d);
}


function normalizeText(s) {
  return String(s||'')
    .toLowerCase()
    .replace(/[ʻ‘’`´]/g, "'")
    .replace(/[ўӯ]/g, 'у')
    .replace(/ғ/g, 'г')
    .replace(/қ/g, 'к')
    .replace(/ҳ/g, 'х')
    .replace(/ё/g, 'е')
    .replace(/\s+/g, ' ')
    .trim();
}

function getStatusText(rowOrStatus) {
  if(rowOrStatus && typeof rowOrStatus === 'object') {
    const raw = rowOrStatus._raw || {};
    return rowOrStatus.status || rowOrStatus.holat || rowOrStatus.ijroHolati ||
      raw['Ijro holati'] || raw['Holat'] || raw['Статус'] || raw['Состояние'] ||
      raw['Состояние исполнения'] || raw['Ijro holati '] || '';
  }
  return rowOrStatus || '';
}

function normalizeDocStatus(rowOrStatus) {
  const text = normalizeText(getStatusText(rowOrStatus));
  if(!text) return { key:'unknown', label:'Noma\'lum', text:'' };

  const isFail =
    /(bajarilmadi|bajarilmagan|bajarilmasdan|ijro etilmadi|rad etildi|bekor qilindi|бажарилмади|бажарилмаган|ижро этилмади|невыполн|не выполн|не исполн|отклон|просроч|muddati o't|muddati ot|kechik|kechiktiril|муддати ўт|кечик)/i.test(text);
  if(isFail) return { key:'fail', label:'Bajarilmadi', text };

  const isDone =
    /(bajarildi|bajarilgan|bajarildi.|bajarilgan.|ijro etildi|ijro etilgan|ijrosi ta'?minlandi|ta'?minlangan|ijro qilindi|yakunlandi|tugatildi|ado etildi|бажарилди|бажарилган|ижро этилди|ижро этилган|якунланди|done|completed|complete|выполн|исполн|заверш|закрыт|готово)/i.test(text);
  if(isDone) return { key:'done', label:'Bajarildi', text };

  const isProc =
    /(jarayon|bajarilmoqda|ijroda|ko'rib chiqilmoqda|korib chiqilmoqda|nazoratda|ishlanmoqda|жараён|бажарилмоқда|ижрода|назоратда|pending|progress|in progress|в работе|на исполн|исполняется|рассмотр|ожидан|контрол)/i.test(text);
  if(isProc) return { key:'proc', label:'Jarayonda', text };

  const isNew = /(yangi|new|нов)/i.test(text);
  if(isNew) return { key:'new', label:'Yangi', text };

  return { key:'unknown', label:getStatusText(rowOrStatus), text };
}

function statusMatches(rowOrStatus, filter) {
  const f = normalizeDocStatus(filter).key;
  if(!filter || f === 'unknown') return !filter || normalizeText(getStatusText(rowOrStatus)).includes(normalizeText(filter));
  return normalizeDocStatus(rowOrStatus).key === f;
}

function getStatusCounts(data=[]) {
  const counts = { total:data.length, done:0, proc:0, fail:0, new:0, unknown:0 };
  data.forEach(row => {
    const key = normalizeDocStatus(row).key;
    if(counts[key] !== undefined) counts[key] += 1;
    else counts.unknown += 1;
  });
  return counts;
}

function parseDate(s){
  if(!s) return null;
  if(s instanceof Date) return s;
  const m=String(s).match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
  if(m) return new Date(m[3],m[2]-1,m[1]);
  const d=new Date(s); return isNaN(d)?null:d;
}

function detectSrc(row){
  const txt=((getOrgText(row)||'')+(row.docName||'')+(row.docType||'')).toLowerCase();
  if(txt.includes('vazirlar')||txt.includes('hukumat')) return 'VM';
  if(txt.includes('prezident')||txt.includes('farmon')||txt.includes('farmoyish')) return 'PF';
  if(txt.includes('viloyat')||txt.includes('hokimlik')) return 'VH';
  return 'OTHER';
}

function srcBadge(s){
  const m={VM:['src-vm','VM'],PF:['src-pf','PF'],VH:['src-vh','VH'],OTHER:['src-other','—']};
  const [cls,l]=(m[s]||m.OTHER);
  return `<span class="src-tag ${cls}">${l}</span>`;
}

function stBadge(st){
  if(!st) return '';
  const normalized = normalizeDocStatus(st);
  if(normalized.key==='done') return `<span class="badge badge-done">${escH(st)}</span>`;
  if(normalized.key==='proc') return `<span class="badge badge-proc">${escH(st)}</span>`;
  if(normalized.key==='fail') return `<span class="badge badge-fail">${escH(st)}</span>`;
  return `<span class="badge badge-new">${escH(st)}</span>`;
}

function updateBadges(){
  const el=document.getElementById('badge-docs');
  if(el) el.textContent=allDocs.length;
  const el2=document.getElementById('badge-filtered');
  if(el2) el2.textContent=filteredDocs.length;
}

function escH(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ===== PROFESSIONAL SAAS CORE =====
const SAAS_VERSION = '3.0.0-premium-saas';
const SAAS_COLLECTIONS = ['users','chats','messages','analytics','logs','subscriptions','reports','settings','aiUsage','aiLogs','documents','fishkalar'];
const DEFAULT_FEATURES = { aiChat:true, fileAnalysis:true, fishka:true, exports:true, voice:false, maintenance:false, providerPriority:['Gemini','Groq','OpenRouter'], freeHourlyLimit:20, premiumHourlyLimit:120 };
let appSettingsCache = { ...DEFAULT_FEATURES };
let adminUsersCache = [];

function isAdmin(){ return currentUserData?.role === 'admin' || currentUserData?.role === 'superadmin'; }
function isSuperAdmin(){ return currentUserData?.role === 'superadmin'; }
function userPlan(){ return currentUserData?.plan || currentUserData?.subscription || (isAdmin() ? 'admin' : 'free'); }
function getUsageLimit(){ return userPlan()==='premium' || isAdmin() ? Number(appSettingsCache.premiumHourlyLimit||120) : Number(appSettingsCache.freeHourlyLimit||20); }
function featureEnabled(name){ return !!appSettingsCache[name]; }
function nowIso(){ return new Date().toISOString(); }

async function writeAudit(action, meta={}) {
  try {
    await addDoc(collection(db,'logs'), { type:'audit', action, meta, uid: currentUser?.uid || '', userName: currentUserData?.fullName || currentUser?.email || '', role: currentUserData?.role || 'anon', createdAt: serverTimestamp(), createdAtLocal: nowIso() });
  } catch(e) { console.warn('audit skipped', e.message); }
}

async function writeAIRequestLog(data={}) {
  try {
    await addDoc(collection(db,'aiLogs'), { uid: currentUser?.uid || '', provider: data.provider || '', ok: !!data.ok, error: data.error || '', chars: data.chars || 0, tokensApprox: Math.ceil((data.chars || 0) / 4), model: data.model || '', createdAt: serverTimestamp(), createdAtLocal: nowIso() });
  } catch(e) { console.warn('ai log skipped', e.message); }
}

async function updatePresence(status='online') {
  if(!currentUser) return;
  try { await updateDoc(doc(db,'users',currentUser.uid), { online: status === 'online', lastSeen: serverTimestamp(), lastSeenLocal: nowIso(), userAgent: navigator.userAgent.slice(0,180) }); } catch(e) {}
}
window.addEventListener('beforeunload', () => { try { localStorage.setItem('ijroda_last_unload', nowIso()); } catch(e){} });

async function loadAppSettings() {
  try { const snap = await getDoc(doc(db,'settings','app')); appSettingsCache = snap.exists() ? { ...DEFAULT_FEATURES, ...snap.data() } : { ...DEFAULT_FEATURES }; }
  catch(e) { appSettingsCache = { ...DEFAULT_FEATURES }; }
  document.body.classList.toggle('maintenance-mode', !!appSettingsCache.maintenance);
  return appSettingsCache;
}

window.saveAppSettings = async () => {
  if(!isSuperAdmin()) { showToast('Faqat Super Admin sozlamalarni o\'zgartira oladi','error'); return; }
  const data = {
    aiChat: document.getElementById('set-aiChat')?.checked ?? true,
    fileAnalysis: document.getElementById('set-fileAnalysis')?.checked ?? true,
    fishka: document.getElementById('set-fishka')?.checked ?? true,
    exports: document.getElementById('set-exports')?.checked ?? true,
    maintenance: document.getElementById('set-maintenance')?.checked ?? false,
    freeHourlyLimit: Number(document.getElementById('set-freeLimit')?.value || 20),
    premiumHourlyLimit: Number(document.getElementById('set-premiumLimit')?.value || 120),
    announcement: sanitize(document.getElementById('set-announcement')?.value || '', 300),
    updatedAt: serverTimestamp(), updatedBy: currentUser?.uid || ''
  };
  await setDoc(doc(db,'settings','app'), data, { merge:true });
  appSettingsCache = { ...appSettingsCache, ...data };
  await writeAudit('settings.update', data);
  showToast('✅ SaaS sozlamalari saqlandi','success');
  renderSaasConsole();
};

function renderSettingsForm() {
  const el = document.getElementById('saas-settings-form');
  if(!el) return;
  el.innerHTML = `
    <div class="settings-grid">
      ${['aiChat','fileAnalysis','fishka','exports','maintenance'].map(k=>`<label class="toggle-row"><input type="checkbox" id="set-${k}" ${appSettingsCache[k]?'checked':''}> <span>${k}</span></label>`).join('')}
      <label class="field"><span>Free limit / soat</span><input id="set-freeLimit" type="number" min="1" value="${escH(appSettingsCache.freeHourlyLimit)}"></label>
      <label class="field"><span>Premium limit / soat</span><input id="set-premiumLimit" type="number" min="1" value="${escH(appSettingsCache.premiumHourlyLimit)}"></label>
      <label class="field wide"><span>Announcement</span><input id="set-announcement" value="${escH(appSettingsCache.announcement||'')}" placeholder="Tizim bo'yicha e'lon..."></label>
    </div>
    <button class="btn btn-primary" onclick="saveAppSettings()">💾 Sozlamalarni saqlash</button>`;
}

async function renderSaasConsole() {
  if(!isAdmin()) return;
  await loadAppSettings();
  renderSettingsForm();
  try {
    const [usersSnap, docsSnap, usageSnap, logsSnap, reportsSnap, subsSnap] = await Promise.all([ getDocs(collection(db,'users')), getDocs(collection(db,'documents')), getDocs(collection(db,'aiUsage')), getDocs(collection(db,'aiLogs')), getDocs(collection(db,'reports')), getDocs(collection(db,'subscriptions')) ]);
    const users = usersSnap.docs.map(d=>({id:d.id,...d.data()}));
    const usage = usageSnap.docs.map(d=>d.data());
    const logs = logsSnap.docs.map(d=>({id:d.id,...d.data()}));
    const totalAi = usage.reduce((s,d)=>s+(d.requests||0),0);
    const failed = logs.filter(l=>!l.ok).length;
    const online = users.filter(u=>u.online).length;
    const premium = users.filter(u=>(u.plan||u.subscription)==='premium').length;
    const set = (id,v)=>{ const e=document.getElementById(id); if(e)e.textContent=v; };
    set('saas-dau', users.filter(u=>u.lastSeen?.toDate && (Date.now()-u.lastSeen.toDate().getTime())<86400000).length);
    set('saas-online', online); set('saas-ai', totalAi); set('saas-failed', failed); set('saas-uploads', docsSnap.size); set('saas-premium', premium); set('saas-reports', reportsSnap.size); set('saas-subs', subsSnap.size);
    const health = document.getElementById('saas-health');
    if(health) health.innerHTML = `<div class="health-row ok"><b>Firebase</b><span>Operational</span></div><div class="health-row ${failed>5?'warn':'ok'}"><b>AI failures</b><span>${failed}</span></div><div class="health-row ok"><b>Collections</b><span>${SAAS_COLLECTIONS.length} mapped</span></div><div class="health-row ${appSettingsCache.maintenance?'warn':'ok'}"><b>Maintenance</b><span>${appSettingsCache.maintenance?'ON':'OFF'}</span></div>`;
    const logEl = document.getElementById('saas-ai-logs');
    if(logEl) logEl.innerHTML = logs.slice(-12).reverse().map(l=>`<tr><td>${escH(l.createdAtLocal||'—')}</td><td>${escH(l.provider||'—')}</td><td>${l.ok?'✅':'❌'}</td><td>${escH(l.error||'—')}</td><td>${l.tokensApprox||0}</td></tr>`).join('') || '<tr><td colspan="5">Loglar yo\'q</td></tr>';
  } catch(e) { console.error(e); }
}
window.renderSaasConsole = renderSaasConsole;

// ===== UI =====
function showApp(){
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app-screen').style.display='flex';
  const name = currentUserData?.fullName || currentUserData?.name || currentUser?.displayName || currentUser?.email || '';
  document.getElementById('user-name').textContent = name;
  const role = currentUserData?.role;
  document.getElementById('user-role').textContent =
    role==='superadmin' ? '🔴 Super Admin' : role==='admin' ? '🟠 Admin' : '🟢 Foydalanuvchi';
  const adminNav = document.getElementById('admin-nav');
  const superNav = document.getElementById('superadmin-nav');
  if(adminNav) adminNav.style.display = (role==='admin'||role==='superadmin') ? 'block' : 'none';
  if(superNav) superNav.style.display = (role==='superadmin') ? 'block' : 'none';
  if(role==='admin'||role==='superadmin') loadAllUsers();
  // Load chat list in background
  setTimeout(() => loadChatList(), 500);
}
window.showApp = showApp;

function showAuth(){
  document.getElementById('auth-screen').style.display='flex';
  document.getElementById('app-screen').style.display='none';
}

window.showPanel = (name) => {
  document.querySelectorAll('.panel').forEach(p => {
    p.classList.remove('active');
    p.style.display = '';
  });
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const p = document.getElementById('panel-' + name);
  if (p) {
    p.classList.add('active');
    // aichat needs flex display
    if (name === 'aichat') p.style.display = 'flex';
  }
  document.querySelectorAll('.nav-item').forEach(n => {
    if (n.dataset.panel === name) n.classList.add('active');
  });
  if (name === 'docs') renderTable();
  if (name === 'stats') buildStats();
  if (name === 'admin' || name === 'superadmin') { loadAllUsers(); loadSuperAdminStats(); }
  if (name === 'hisobot') initHisobotPanel();
  if (name === 'fishka') { initFishkaPanel(); updateApiKeyStatus(); }
  if (name === 'xodimlar') { loadSektorlar(); loadXodimlar(); }
  if (name === 'sektorlar') loadSektorlar();
  if (name === 'aichat') { loadChatList(); }
  if (name === 'providers') { renderProviderStatus(); }
  if (name === 'superadmin') { loadAdminAnalytics(); }
  if (name === 'muhim') { loadMuhimTopshiriqlar(); }
  if (name === 'tashkilotlar') { loadTashkilotlar(); }
  if (name === 'ai-hisobot-admin') { loadAiHisobotAdmin(); }
  window.scrollTo({ top: 0, behavior: 'smooth' });
};

function showLoading(txt='Yuklanmoqda...'){
  const el = document.getElementById('loading');
  const ltxt = document.getElementById('loading-txt');
  if(el){ el.style.display='flex'; el.style.opacity='1'; }
  if(ltxt) ltxt.textContent = txt;
}
window.showLoading = showLoading;
function hideLoading(){
  const el=document.getElementById('loading');
  if(!el) return;
  el.style.transition='opacity .2s';
  el.style.opacity='0';
  setTimeout(()=>{el.style.display='none';el.style.opacity='1';el.style.transition='';},200);
}
window.hideLoading = hideLoading;

function showToast(msg,type='info'){
  const t=document.createElement('div');
  t.className=`toast toast-${type}`;
  t.textContent=msg;
  document.getElementById('toast-container').appendChild(t);
  setTimeout(()=>t.classList.add('show'),10);
  setTimeout(()=>{ t.classList.remove('show'); setTimeout(()=>t.remove(),400); },3500);
}
window.showToast = showToast;

// Enter key support
document.addEventListener('keydown',e=>{
  if(e.key==='Enter' && document.getElementById('auth-screen')?.style.display!=='none') {
    const regPanel = document.getElementById('panel-register');
    if(regPanel && regPanel.style.display !== 'none') {
      window.doEmailRegister();
    } else {
      window.doLogin();
    }
  }
});

// ===== HISOBOT GENERATSIYA =====
// All possible columns including dynamic ones from Excel
const HISOBOT_BASE_COLS = [
  { key:'_num',    label:'№',                   always:true },
  { key:'source',  label:'Manba',               default:true },
  { key:'docName', label:'Hujjat nomi',         default:true },
  { key:'docNum',  label:'Hujjat raqami',       default:true },
  { key:'docDate', label:'Hujjat sanasi',       default:true },
  { key:'orgOutNum',label:'Tashkilot chiqish raqami', default:false },
  { key:'fromOrg', label:'Kimdan keldi',        default:true },
  { key:'resolution',label:'Rezalyutsiya (Kimga)',default:false },
  { key:'taskText',label:'Topshiriq matni',     default:false },
  { key:'executor',label:'Ijrochi',             default:true },
  { key:'status',  label:'Ijro holati',         default:true },
  { key:'deadline',label:'Ijro muddati',        default:true },
  { key:'ourOutNum',label:'Bizdan chiqish raqami',default:false },
  { key:'docType', label:'Hujjat turi',         default:false },
  { key:'userOrg', label:'Tashkilot',           default:false },
  { key:'userName',label:'Foydalanuvchi',       default:false },
];

let hisobotSelectedCols = new Set();
let hisobotExtraCols = []; // dynamic cols from _allCols

function initHisobotPanel() {
  // Collect extra cols from allDocs._allCols
  const extraSet = new Set();
  allDocs.forEach(d=>{
    if(Array.isArray(d._allCols)) d._allCols.forEach(c=>{
      if(c && !HISOBOT_BASE_COLS.some(b=>b.label===c||b.key===c)) extraSet.add(c);
    });
  });
  hisobotExtraCols = [...extraSet].map(c=>({ key:'_raw.'+c, label:c, default:false }));

  // Set defaults
  hisobotSelectedCols = new Set(HISOBOT_BASE_COLS.filter(c=>c.default||c.always).map(c=>c.key));
  renderHisobotChips();
}

function getAllHisobotCols() {
  return [...HISOBOT_BASE_COLS, ...hisobotExtraCols];
}

function renderHisobotChips() {
  const wrap = document.getElementById('hisobot-col-chips');
  if(!wrap) return;
  const all = getAllHisobotCols();
  wrap.innerHTML = all.map(col=>{
    const selected = hisobotSelectedCols.has(col.key);
    const always = col.always;
    return `<div class="hcol-chip ${selected?'hcol-chip-on':''} ${always?'hcol-chip-always':''}"
      data-key="${escH(col.key)}"
      style="cursor:${always?'default':'pointer'};">
      ${selected?'✓ ':''}${escH(col.label)}
    </div>`;
  }).join('');
  wrap.querySelectorAll('.hcol-chip:not(.hcol-chip-always)').forEach(el=>{
    const key = el.dataset.key;
    if(key) el.onclick = ()=>hisobotToggleCol(key);
  });
}

window.hisobotToggleCol = (key) => {
  if(hisobotSelectedCols.has(key)) hisobotSelectedCols.delete(key);
  else hisobotSelectedCols.add(key);
  renderHisobotChips();
};

window.hisobotSelectAll = () => {
  getAllHisobotCols().forEach(c=>hisobotSelectedCols.add(c.key));
  renderHisobotChips();
};

window.hisobotClearAll = () => {
  hisobotSelectedCols.clear();
  hisobotSelectedCols.add('_num'); // always keep №
  HISOBOT_BASE_COLS.filter(c=>c.always).forEach(c=>hisobotSelectedCols.add(c.key));
  renderHisobotChips();
};

window.setHisobotPeriod = (val) => {
  const now=new Date(); let from=new Date(), to=new Date();
  if(val==='today'){from=new Date();}
  else if(val==='week'){from=new Date();from.setDate(from.getDate()-7);}
  else if(val==='month'){from=new Date(now.getFullYear(),now.getMonth(),1);}
  else if(val==='quarter'){const q=Math.floor(now.getMonth()/3);from=new Date(now.getFullYear(),q*3,1);}
  else if(val==='halfyear'){from=new Date(now.getFullYear(),now.getMonth()-6,1);}
  else if(val==='year'){from=new Date(now.getFullYear(),0,1);}
  else return;
  document.getElementById('hr-date-from').value=from.toISOString().split('T')[0];
  document.getElementById('hr-date-to').value=to.toISOString().split('T')[0];
};

function getHisobotFilteredDocs() {
  const df = document.getElementById('hr-date-from')?.value||'';
  const dt = document.getElementById('hr-date-to')?.value||'';
  const status = (document.getElementById('hr-status')?.value||'').toLowerCase();
  const src = document.getElementById('hr-src')?.value||'';
  const org = (document.getElementById('hr-org')?.value||'').toLowerCase();
  const dfrom = df ? new Date(df) : null;
  const dto = dt ? new Date(dt+'T23:59:59') : null;
  return allDocs.filter(row=>{
    if(src && row.source !== src) return false;
    if(status && !statusMatches(row, status)) return false;
    if(org && !normalizeText(getOrgText(row)).includes(org)) return false;
    if(dfrom||dto){
      const d=parseDate(row.docDate)||parseDate(row.deadline);
      if(d){ if(dfrom&&d<dfrom)return false; if(dto&&d>dto)return false; }
    }
    return true;
  });
}

function getColValue(doc, key) {
  if(key==='_num') return '';
  if(key.startsWith('_raw.')) {
    const rawKey = key.slice(5);
    return doc._raw ? String(doc._raw[rawKey]||'') : '';
  }
  if(key==='source') {
    const m={VM:'Vazirlar Mahkamasi',PF:'Prezident farmonlari',VH:'Viloyat hokimligi',OTHER:'Boshqa'};
    return m[doc.source]||doc.source||'';
  }
  if(key==='fromOrg') return getOrgText(doc);
  if(key==='status') return getStatusText(doc);
  return String(doc[key]||'');
}

window.previewHisobot = () => {
  const docs = getHisobotFilteredDocs();
  const cols = getAllHisobotCols().filter(c=>hisobotSelectedCols.has(c.key));
  const wrap = document.getElementById('hisobot-table-wrap');
  const info = document.getElementById('hisobot-preview-info');
  const infoTxt = document.getElementById('hisobot-preview-txt');

  info.style.display='block';
  infoTxt.textContent = `${docs.length} ta hujjat, ${cols.length} ta ustun`;

  if(!docs.length){
    wrap.innerHTML='<div class="empty-state"><div class="empty-icon">📭</div><h3>Hujjat topilmadi</h3></div>';
    return;
  }
  const preview = docs.slice(0,50);
  wrap.innerHTML=`
    <div style="font-size:11px;color:var(--muted);margin-bottom:8px;">Ko'rinish: ${preview.length} ta (Excel'da hammasi)</div>
    <div class="table-wrap">
    <table>
      <thead><tr>${cols.map(c=>`<th>${escH(c.label)}</th>`).join('')}</tr></thead>
      <tbody>${preview.map((doc,i)=>`<tr>${cols.map(c=>`<td class="${c.key==='status'?'':''}">
        ${c.key==='_num'?i+1:c.key==='status'?stBadge(getColValue(doc,c.key)):escH(getColValue(doc,c.key))}
      </td>`).join('')}</tr>`).join('')}
      </tbody>
    </table></div>`;
};

window.generateHisobot = () => {
  const docs = getHisobotFilteredDocs();
  const cols = getAllHisobotCols().filter(c=>hisobotSelectedCols.has(c.key));
  if(!docs.length){ showToast('Hujjat topilmadi!','error'); return; }
  showLoading('Hisobot tayyorlanmoqda...');

  // Header row
  const headerRow = cols.map(c=>c.label);
  const dataRows = docs.map((doc,i)=>
    cols.map(c=>{
      if(c.key==='_num') return i+1;
      return getColValue(doc,c.key);
    })
  );

  // Summary sheet
  const total=docs.length;
  const statusCounts = getStatusCounts(docs);
  const done=statusCounts.done;
  const proc=statusCounts.proc;
  const fail=statusCounts.fail;
  const pct=v=>total>0?Math.round(v/total*100)+'%':'0%';
  const df=document.getElementById('hr-date-from')?.value||'—';
  const dt=document.getElementById('hr-date-to')?.value||'—';

  const sumRows=[
    ['IJRODA — HISOBOT'],[''],
    ['Sana:', new Date().toLocaleDateString('uz-UZ')],
    ['Davr:', `${df} — ${dt}`],
    ['Foydalanuvchi:', currentUserData?.name||currentUser?.email||''],
    [''],
    ['UMUMIY KO\'RSATKICHLAR','MIQDOR','FOIZ'],
    ['Jami',total,'100%'],
    ['Bajarildi',done,pct(done)],
    ['Jarayonda',proc,pct(proc)],
    ['Bajarilmadi',fail,pct(fail)],
  ];

  const wb=XLSX.utils.book_new();
  const ws=XLSX.utils.aoa_to_sheet([headerRow,...dataRows]);
  // Auto column width
  const colWidths=headerRow.map((h,ci)=>{
    const maxLen=Math.max(h.length,...dataRows.map(r=>String(r[ci]||'').length));
    return {wch:Math.min(Math.max(maxLen,8),50)};
  });
  ws['!cols']=colWidths;

  const wsSum=XLSX.utils.aoa_to_sheet(sumRows);
  wsSum['!cols']=[{wch:36},{wch:12},{wch:10}];

  XLSX.utils.book_append_sheet(wb,ws,'Hujjatlar');
  XLSX.utils.book_append_sheet(wb,wsSum,'Xulosa');

  const dateStr=new Date().toISOString().slice(0,10);
  setTimeout(()=>{
    XLSX.writeFile(wb,`Ijroda_Hisobot_${dateStr}.xlsx`);
    hideLoading();
    showToast(`✅ ${docs.length} ta hujjat, ${cols.length} ta ustun — yuklandi!`,'success');
  },300);
};

window.resetHisobot = () => {
  ['hr-date-from','hr-date-to','hr-org'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});
  ['hr-period','hr-status','hr-src'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});
  document.getElementById('hisobot-table-wrap').innerHTML='';
  document.getElementById('hisobot-preview-info').style.display='none';
  initHisobotPanel();
};

// ============================================================
// ===== XODIMLAR BAZASI =====
// ============================================================
let xodimlarCache = [];
let sektorlarCache = [];

async function loadXodimlar() {
  try {
    const snap = await getDocs(query(collection(db,'xodimlar'), orderBy('familiya')));
    xodimlarCache = snap.docs.map(d=>({id:d.id,...d.data()}));
    renderXodimlarTable();
  } catch(e) { showToast('Xodimlar yuklanmadi: '+e.message,'error'); }
}
window.loadXodimlar = loadXodimlar;

function renderXodimlarTable() {
  const tbody = document.getElementById('xodimlar-tbody');
  const cnt = document.getElementById('xodimlar-count');
  if(cnt) cnt.textContent = xodimlarCache.length;
  if(!tbody) return;
  if(!xodimlarCache.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--muted);">Xodimlar yo\'q. Qo\'shing ↑</td></tr>';
    return;
  }
  tbody.innerHTML = xodimlarCache.map(x=>`
    <tr>
      <td><b>${escH(x.familiya||'')} ${escH(x.ism||'')}</b><br><span style="font-size:10px;color:var(--muted);">${escH(x.lavozim||'')}</span></td>
      <td>${escH(x.sektor||'—')}</td>
      <td>${escH(x.email||'—')}</td>
      <td>${escH(x.telefon||'—')}</td>
      <td>${escH(x.kalit_sozlar||'—')}</td>
      <td><span class="badge ${x.faol!==false?'badge-done':'badge-fail'}">${x.faol!==false?'Faol':'Nofaol'}</span></td>
      <td style="display:flex;gap:4px;">
        <button class="btn btn-sm btn-outline" onclick="editXodim('${x.id}')">✏️</button>
        <button class="btn btn-sm btn-danger" onclick="deleteXodim('${x.id}')">🗑️</button>
      </td>
    </tr>`).join('');
}

window.saveXodim = async () => {
  const ism      = document.getElementById('x-ism').value.trim();
  const familiya = document.getElementById('x-familiya').value.trim();
  const lavozim  = document.getElementById('x-lavozim').value.trim();
  const sektor   = document.getElementById('x-sektor').value.trim();
  const email    = document.getElementById('x-email').value.trim();
  const telefon  = document.getElementById('x-tel').value.trim();
  const kalit    = document.getElementById('x-kalit').value.trim();
  const editId   = document.getElementById('x-edit-id').value;

  if(!ism||!familiya) { showToast('Ism va familiya majburiy','error'); return; }

  const data = {
    ism, familiya, lavozim, sektor, email, telefon,
    kalit_sozlar: kalit,
    faol: true,
    updatedAt: serverTimestamp()
  };

  try {
    showLoading('Saqlanmoqda...');
    if(editId) {
      await updateDoc(doc(db,'xodimlar',editId), data);
    } else {
      data.createdAt = serverTimestamp();
      await addDoc(collection(db,'xodimlar'), data);
    }
    hideLoading();
    showToast('✅ Xodim saqlandi','success');
    clearXodimForm();
    await loadXodimlar();
    updateFishkaBadge();
  } catch(e) { hideLoading(); showToast('Xatolik: '+e.message,'error'); }
};

window.editXodim = (id) => {
  const x = xodimlarCache.find(x=>x.id===id);
  if(!x) return;
  document.getElementById('x-ism').value      = x.ism||'';
  document.getElementById('x-familiya').value = x.familiya||'';
  document.getElementById('x-lavozim').value  = x.lavozim||'';
  document.getElementById('x-sektor').value   = x.sektor||'';
  document.getElementById('x-email').value    = x.email||'';
  document.getElementById('x-tel').value      = x.telefon||'';
  document.getElementById('x-kalit').value    = x.kalit_sozlar||'';
  document.getElementById('x-edit-id').value  = id;
  document.getElementById('x-form-title').textContent = '✏️ Xodimni tahrirlash';
  document.getElementById('x-ism').scrollIntoView({behavior:'smooth'});
};

window.deleteXodim = async (id) => {
  if(!confirm('Bu xodimni o\'chirmoqchimisiz?')) return;
  await deleteDoc(doc(db,'xodimlar',id));
  showToast('Xodim o\'chirildi','success');
  await loadXodimlar();
};

function clearXodimForm() {
  ['x-ism','x-familiya','x-lavozim','x-sektor','x-email','x-tel','x-kalit','x-edit-id'].forEach(id=>{
    const e=document.getElementById(id); if(e) e.value='';
  });
  const t=document.getElementById('x-form-title');
  if(t) t.textContent='➕ Yangi xodim qo\'shish';
}
window.clearXodimForm = clearXodimForm;

window.importXodimlarExcel = (input) => {
  const file = input.files[0]; if(!file) return;
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      showLoading('Excel o\'qilmoqda...');
      const wb = XLSX.read(new Uint8Array(e.target.result),{type:'array'});
      const ws = wb.Sheets[wb.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json(ws,{defval:''});
      let saved=0;
      for(const r of rows) {
        const ism = r['Ism']||r['ism']||r['ISM']||'';
        const familiya = r['Familiya']||r['familiya']||r['FAMILIYA']||'';
        if(!ism&&!familiya) continue;
        await addDoc(collection(db,'xodimlar'),{
          ism: String(ism).trim(),
          familiya: String(familiya).trim(),
          lavozim: String(r['Lavozim']||r['lavozim']||'').trim(),
          sektor: String(r['Sektor']||r['sektor']||r['Bo\'lim']||'').trim(),
          email: String(r['Email']||r['email']||'').trim(),
          telefon: String(r['Telefon']||r['telefon']||'').trim(),
          kalit_sozlar: String(r['Kalit so\'zlar']||r['kalit']||'').trim(),
          faol: true, createdAt: serverTimestamp()
        });
        saved++;
      }
      hideLoading();
      showToast(`✅ ${saved} ta xodim import qilindi`,'success');
      await loadXodimlar();
    } catch(e){ hideLoading(); showToast('Xatolik: '+e.message,'error'); }
  };
  reader.readAsArrayBuffer(file);
};

// ============================================================
// ===== IJRO.DOCX XODIMLAR VA SEKTORLAR DEFAULT IMPORT =====
// ============================================================
// IJRO default data moved to ./data/ijro-default-data.js


window.importIjroXodimlar = async () => {
  const btn = document.getElementById('btn-ijro-import');
  if(!btn) return;
  if(!confirm(`Ijro.docx va ZIP lavozim yo'riqnomalaridan ${IJRO_XODIMLAR.length} ta xodim/lavozim profili va ${IJRO_SEKTORLAR.length} ta sektor yuklanadi.\n\nMavjud xodimlar saqlanib qoladi, lekin topilgan dublikatlar yangi tahlil qilingan kalit so'zlar va manba hujjatlar bilan yangilanadi.\n\nDavom ettirilsinmi?`)) return;

  btn.disabled = true;
  btn.textContent = '⏳ Yuklanmoqda...';
  showLoading('Ijro.docx va ZIP lavozim yo\'riqnomalari ma\'lumotlari yuklanmoqda...');

  try {
    // 1. Import sektorlar
    let sektorSaved = 0;
    for (const s of IJRO_SEKTORLAR) {
      const existing = sektorlarCache.find(x => x.nom.trim().toLowerCase() === s.nom.trim().toLowerCase());
      if (!existing) {
        await addDoc(collection(db,'sektorlar'), { ...s, createdAt: serverTimestamp(), updatedAt: serverTimestamp() });
        sektorSaved++;
      }
    }
    await loadSektorlar();

    // 2. Import xodimlar / lavozim profillari
    let xodimSaved = 0, xodimUpdated = 0;
    for (const x of IJRO_XODIMLAR) {
      const existing = xodimlarCache.find(e =>
        e.familiya.trim().toLowerCase() === x.familiya.trim().toLowerCase() &&
        e.ism.trim().toLowerCase() === x.ism.trim().toLowerCase()
      );
      if (existing) {
        await updateDoc(doc(db,'xodimlar',existing.id), {
          ...x, faol: existing.faol !== false, updatedAt: serverTimestamp()
        });
        xodimUpdated++;
      } else {
        await addDoc(collection(db,'xodimlar'), {
          ...x, faol: true, createdAt: serverTimestamp(), updatedAt: serverTimestamp()
        });
        xodimSaved++;
      }
    }
    await loadXodimlar();

    hideLoading();
    btn.disabled = false;
    btn.textContent = '✅ Import qilindi!';
    setTimeout(()=>{ if(btn) btn.textContent = '📋 Ijro.docx + ZIP dan yuklash'; }, 3000);
    showToast(`✅ ${xodimSaved} xodim/profil qo'shildi, ${xodimUpdated} tasi yangilandi, ${sektorSaved} sektor qo'shildi.`, 'success');
  } catch(e) {
    hideLoading();
    btn.disabled = false;
    btn.textContent = '📋 Ijro.docx + ZIP dan yuklash';
    showToast('Xatolik: ' + e.message, 'error');
  }
};

// ============================================================
// ===== SEKTORLAR / BO'LIMLAR =====
// ============================================================
async function loadSektorlar() {
  try {
    const snap = await getDocs(query(collection(db,'sektorlar'), orderBy('nom')));
    sektorlarCache = snap.docs.map(d=>({id:d.id,...d.data()}));
    renderSektorlarList();
    updateSektorSelects();
  } catch(e) { showToast('Sektorlar yuklanmadi','error'); }
}
window.loadSektorlar = loadSektorlar;

function renderSektorlarList() {
  const wrap = document.getElementById('sektorlar-list');
  if(!wrap) return;
  if(!sektorlarCache.length) {
    wrap.innerHTML='<div style="color:var(--muted);font-size:13px;padding:12px;">Bo\'limlar yo\'q. Qo\'shing ↑</div>';
    return;
  }
  wrap.innerHTML = sektorlarCache.map(s=>`
    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border:1px solid var(--border);border-radius:8px;background:var(--surface);gap:10px;">
      <div>
        <b style="font-size:13px;">${escH(s.nom)}</b>
        ${s.tavsif ? `<div style="font-size:11px;color:var(--muted);margin-top:2px;">${escH(s.tavsif)}</div>` : ''}
        ${s.kalit_sozlar ? `<div style="font-size:11px;color:var(--blue-mid);margin-top:2px;">🔑 ${escH(s.kalit_sozlar)}</div>` : ''}
      </div>
      <div style="display:flex;gap:6px;">
        <button class="btn btn-sm btn-outline" onclick="editSektor('${s.id}')">✏️</button>
        <button class="btn btn-sm btn-danger" onclick="deleteSektor('${s.id}')">🗑️</button>
      </div>
    </div>`).join('');
}

function updateSektorSelects() {
  const opts = ['<option value="">— Sektor —</option>',
    ...sektorlarCache.map(s=>`<option value="${escH(s.nom)}">${escH(s.nom)}</option>`)].join('');
  ['x-sektor','fishka-sektor-filter'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.innerHTML=opts;
  });
}

window.saveSektor = async () => {
  const nom    = document.getElementById('s-nom').value.trim();
  const tavsif = document.getElementById('s-tavsif').value.trim();
  const kalit  = document.getElementById('s-kalit').value.trim();
  const editId = document.getElementById('s-edit-id').value;
  if(!nom) { showToast('Sektor nomi majburiy','error'); return; }
  const data = { nom, tavsif, kalit_sozlar: kalit, updatedAt: serverTimestamp() };
  try {
    showLoading('Saqlanmoqda...');
    if(editId) { await updateDoc(doc(db,'sektorlar',editId),data); }
    else { data.createdAt=serverTimestamp(); await addDoc(collection(db,'sektorlar'),data); }
    hideLoading(); showToast('✅ Sektor saqlandi','success');
    ['s-nom','s-tavsif','s-kalit','s-edit-id'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});
    await loadSektorlar();
  } catch(e){ hideLoading(); showToast('Xatolik: '+e.message,'error'); }
};

window.editSektor = (id) => {
  const s=sektorlarCache.find(x=>x.id===id); if(!s) return;
  document.getElementById('s-nom').value   = s.nom||'';
  document.getElementById('s-tavsif').value= s.tavsif||'';
  document.getElementById('s-kalit').value = s.kalit_sozlar||'';
  document.getElementById('s-edit-id').value=id;
};

window.deleteSektor = async (id) => {
  if(!confirm('Bu sektoni o\'chirmoqchimisiz?')) return;
  await deleteDoc(doc(db,'sektorlar',id));
  showToast('Sektor o\'chirildi','success');
  await loadSektorlar();
};

// ============================================================
// ===== FISHKA / REZOLUTSIYA — AI bilan =====
// ============================================================
let fishkaCache = [];

function initFishkaPanel() {
  loadFishkalar();
  // Load supporting data
  if(!xodimlarCache.length) loadXodimlar();
  if(!sektorlarCache.length) loadSektorlar();
  updateTashkilotlarBadge();
  // Show tip if no employees
  setTimeout(() => {
    const tip = document.getElementById('fishka-xodim-tip');
    if(tip) tip.style.display = xodimlarCache.length === 0 ? 'block' : 'none';
  }, 800);
}
window.initFishkaPanel = initFishkaPanel;

function updateFishkaBadge() {
  const el=document.getElementById('badge-fishka');
  if(el) el.textContent=fishkaCache.length;
}

async function loadFishkalar() {
  try {
    const snap = await getDocs(query(collection(db,'fishkalar'), orderBy('createdAt','desc')));
    fishkaCache = snap.docs.map(d=>({id:d.id,...d.data()}));
    renderFishkalar();
    updateFishkaBadge();
  } catch(e) { showToast('Fishkalar yuklanmadi','error'); }
}

function renderFishkalar() {
  const wrap = document.getElementById('fishka-list');
  if(!wrap) return;
  const filtered = fishkaCache.filter(f=>{
    const sf = (document.getElementById('fishka-sektor-filter')?.value||'');
    const st = (document.getElementById('fishka-status-filter')?.value||'');
    if(sf && f.sektor!==sf) return false;
    if(st && f.status!==st) return false;
    return true;
  });
  if(!filtered.length) {
    wrap.innerHTML='<div class="empty-state"><div class="empty-icon">🎯</div><h3>Fishkalar yo\'q</h3><p>Hujjat yuklang va AI tahlil qilsin</p></div>';
    return;
  }
  wrap.innerHTML = filtered.map(f=>`
    <div class="fishka-card ${f.status==='Bajarildi'?'fishka-done':f.status==='Kechikdi'?'fishka-late':''}">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;">
        <div style="flex:1;">
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px;">
            <span class="badge badge-proc" style="font-size:11px;">${escH(f.sektor||'—')}</span>
            ${f.xodim?`<span class="badge badge-done" style="font-size:11px;">👤 ${escH(f.xodim)}</span>`:''}
            <span class="badge ${f.status==='Bajarildi'?'badge-done':f.status==='Kechikdi'?'badge-fail':'badge-new'}">${escH(f.status||'Yangi')}</span>
            ${f.muddat?`<span style="font-size:11px;font-weight:700;color:${isMuddatKechikdi(f.muddat)?'var(--red-mid)':'var(--green-mid)'};">📅 ${escH(f.muddat)}</span>`:''}
          </div>
          <div style="font-weight:700;font-size:13px;margin-bottom:6px;">${escH(f.hujjat_nomi||'Noma\'lum hujjat')}</div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px;">${escH((f.ai_xulosa||'').slice(0,200))}${(f.ai_xulosa||'').length>200?'...':''}</div>
          ${f.rezolutsiya?`<div style="background:var(--blue-light);border-left:3px solid var(--blue-mid);padding:8px 12px;border-radius:0 6px 6px 0;font-size:12px;font-style:italic;">"${escH(f.rezolutsiya)}"</div>`:''}
        </div>
        <div style="display:flex;flex-direction:column;gap:6px;min-width:110px;">
          <select class="btn btn-sm btn-outline" onchange="changeFishkaStatus('${f.id}',this.value)" style="font-size:11px;">
            <option ${f.status==='Yangi'?'selected':''}>Yangi</option>
            <option ${f.status==='Jarayonda'?'selected':''}>Jarayonda</option>
            <option ${f.status==='Bajarildi'?'selected':''}>Bajarildi</option>
            <option ${f.status==='Kechikdi'?'selected':''}>Kechikdi</option>
          </select>
          <button class="btn btn-sm btn-danger" onclick="deleteFishka('${f.id}')">🗑️</button>
        </div>
      </div>
      <div style="font-size:10px;color:var(--muted);margin-top:8px;">
        📎 ${escH(f.fayl_nom||'—')} · 
        🕐 ${f.createdAt?.toDate?f.createdAt.toDate().toLocaleString('uz-UZ'):'—'}
      </div>
    </div>`).join('');
}

function isMuddatKechikdi(muddat) {
  if(!muddat) return false;
  const d = parseDate(muddat);
  return d && d < new Date();
}

window.filterFishkalar = () => renderFishkalar();

window.changeFishkaStatus = async (id, status) => {
  try {
    await updateDoc(doc(db,'fishkalar',id),{status, updatedAt:serverTimestamp()});
    const f=fishkaCache.find(x=>x.id===id); if(f) f.status=status;
    renderFishkalar();
    showToast('✅ Status yangilandi','success');
  } catch(e){ showToast('Xatolik: '+e.message,'error'); }
};

window.deleteFishka = async (id) => {
  if(!confirm('Bu fishkani o\'chirmoqchimisiz?')) return;
  await deleteDoc(doc(db,'fishkalar',id));
  fishkaCache = fishkaCache.filter(f=>f.id!==id);
  renderFishkalar();
  updateFishkaBadge();
  showToast('Fishka o\'chirildi','success');
};

// ===== AI TAHLIL — PDF / Word / Screenshot / Matn =====
window.handleFishkaFiles = (input) => {
  const files = Array.from(input.files || []);
  if(!files.length) return;
  if(files.length > 1) showToast(files.length + ' ta fayl qabul qilindi. Hozircha birinchi fayl tahlil qilinadi.','info');
  handleFishkaFile({ files:[files[0]] });
};

window.handleFishkaDrop = (event, zone) => {
  event.preventDefault();
  zone?.classList.remove('dragover');
  const files = event.dataTransfer?.files;
  if(!files?.length) return;
  handleFishkaFiles({ files });
};
window.handleFishkaFile = (input) => {
  const file = input.files[0]; if(!file) return;
  const ext = file.name.split('.').pop().toLowerCase();
  const imageExts = ['png','jpg','jpeg','webp'];

  if(ext === 'pdf') {
    showUploadProgress(file.name);
    readFileAsBase64(file).then(b64 => analyzeWithAI({ base64: b64, mimeType: 'application/pdf' }, 'file', file.name));
  } else if(imageExts.includes(ext)) {
    const mimeType = file.type || (ext === 'png' ? 'image/png' : ext === 'webp' ? 'image/webp' : 'image/jpeg');
    showUploadProgress(file.name);
    readFileAsBase64(file).then(b64 => analyzeWithAI({ base64: b64, mimeType }, 'file', file.name));
  } else if(['doc','docx'].includes(ext)) {
    showUploadProgress(file.name);
    readDocxAsText(file).then(text => analyzeWithAI(null, 'text', file.name, text));
  } else if(['txt','text'].includes(ext)) {
    showUploadProgress(file.name);
    readAsText(file).then(text => analyzeWithAI(null, 'text', file.name, text));
  } else {
    showToast('PDF, Word, screenshot yoki matn fayl yuklang','error');
  }
};

window.analyzeFishkaText = () => {
  const text = document.getElementById('fishka-text-input').value.trim();
  if(!text){ showToast('Matn kiriting','error'); return; }
  analyzeWithAI(null,'text','Qo\'lda kiritilgan matn',text);
};


function showUploadProgress(fileName) {
  const aiStatus = document.getElementById('fishka-ai-status');
  if(!aiStatus) return;
  aiStatus.style.display='block';
  aiStatus.innerHTML = `<div class="upload-progress"><b>${escH(fileName)}</b><div class="progress-bar"><span></span></div><small>Fayl o'qilmoqda va AI tahlilga tayyorlanmoqda...</small></div>`;
}function readFileAsBase64(file) {
  return new Promise((res,rej)=>{
    const r=new FileReader();
    r.onload=e=>res(e.target.result.split(',')[1]);
    r.onerror=rej;
    r.readAsDataURL(file);
  });
}

function readPdfAsBase64(file) {
  return readFileAsBase64(file);
}

function readDocxAsText(file) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = async (e) => {
      try {
        if (typeof mammoth !== 'undefined') {
          const result = await mammoth.extractRawText({ arrayBuffer: e.target.result });
          res(result.value || '');
        } else {
          res('[DOCX fayl o\'qildi, lekin matn ajratilmadi. Mammoth.js yuklanmagan.]');
        }
      } catch(err) { rej(err); }
    };
    r.onerror = rej;
    r.readAsArrayBuffer(file);
  });
}

function readAsText(file) {
  return new Promise((res,rej)=>{
    const r=new FileReader();
    r.onload=e=>res(e.target.result);
    r.onerror=rej;
    r.readAsText(file,'UTF-8');
  });
}

function parseAIJson(text) {
  if(!text) return null;
  const variants = [];
  const cleaned = String(text)
    .replace(/```json/gi, '')
    .replace(/```/g, '')
    .trim();
  variants.push(cleaned);

  const objectMatch = cleaned.match(/\{[\s\S]*\}/);
  if(objectMatch) variants.push(objectMatch[0]);

  for (const v of variants) {
    try {
      const parsed = JSON.parse(v);
      if(Array.isArray(parsed)) return parsed[0] || null;
      return parsed;
    } catch(e) {}
  }

  const pick = (keys) => {
    for (const key of keys) {
      const re = new RegExp('"?' + key + '"?\\s*[:：-]\\s*"?([^",\\n}]+)', 'i');
      const m = cleaned.match(re);
      if(m) return m[1].trim().replace(/["']/g, '');
    }
    return '';
  };

  const recovered = {
    sektor: pick(['sektor','bolim','bo\\W*lim']),
    xodim: pick(['xodim','ijrochi']),
    muddat: pick(['muddat','deadline']),
    muddat_asosi: pick(['muddat_asosi','asos']),
    xulosa: pick(['xulosa']),
    rezolutsiya: pick(['rezolutsiya','resolution']),
    hujjat_raqami: pick(['hujjat_raqami','raqam']),
    hujjat_sanasi: pick(['hujjat_sanasi','sana']),
    kimdan: pick(['kimdan','from','tashkilot']),
    ishonch: Number(pick(['ishonch','confidence'])) || 60
  };
  return Object.values(recovered).some(Boolean) ? recovered : null;
}

function normalizeAIResult(result) {
  const today = new Date();
  const d10 = fmtDate(addWorkDays(today, 10));
  const d12 = fmtDate(addWorkDays(today, 12));
  if(!result || typeof result !== 'object') return null;
  if(!result.muddat || !String(result.muddat).trim()) {
    result.muddat = d10;
    result.muddat_asosi = '10 ish kuni';
  }
  if(!result.muddat_asosi || !String(result.muddat_asosi).trim()) {
    result.muddat_asosi = 'hujjatdagi muddat yoki 10-12 ish kuni';
  }
  if(String(result.muddat_asosi).toLowerCase().includes('topilmadi')) {
    result.muddat_asosi = '10 ish kuni';
    result.muddat = result.muddat || d10;
  }
  // FIX #4: Preserve the actual AI ishonch value — only use fallback if truly absent
  const parsedIshonch = Number(result.ishonch);
  result.ishonch = (!isNaN(parsedIshonch) && parsedIshonch > 0) ? parsedIshonch : 70;
  result._fallback_12_ish_kuni = d12;
  return result;
}

async function analyzeWithAI(filePart, type, fileName, rawText='') {
  const aiStatus = document.getElementById('fishka-ai-status');
  if(aiStatus) {
    aiStatus.style.display='block';
    aiStatus.innerHTML='<div class="ai-loading">🤖 AI hujjatni chuqur tahlil qilmoqda...</div>';
  }

  // FIX #3: Ensure caches are loaded before building prompts
  if(!xodimlarCache.length) {
    try { await loadXodimlar(); } catch(e) { console.warn('Xodimlar yuklanmadi:', e); }
  }
  if(!sektorlarCache.length) {
    try { await loadSektorlar(); } catch(e) { console.warn('Sektorlar yuklanmadi:', e); }
  }

  // FIX #2: Calculate open task count per employee to avoid overloading one person
  const openTasksPerXodim = {};
  if(fishkaCache.length) {
    fishkaCache.forEach(f => {
      if(f.xodim && f.status !== 'Bajarildi') {
        openTasksPerXodim[f.xodim] = (openTasksPerXodim[f.xodim] || 0) + 1;
      }
    });
  }

  const xodimList = xodimlarCache.map(x=> {
    const fullName = `${x.familiya} ${x.ism}`;
    const openCount = openTasksPerXodim[fullName] || 0;
    const yuklamaText = openCount === 0 ? 'Yuklama: bo\'sh' : `Yuklama: ${openCount} ta ochiq topshiriq`;
    const hujjatlar = Array.isArray(x.biriktirilgan_hujjatlar)
      ? x.biriktirilgan_hujjatlar.join('; ')
      : (x.manba_hujjat || '');
    return `- ${fullName} | Lavozim: ${x.lavozim||'—'} | Sektor: ${x.sektor||'—'} | ${yuklamaText} | Biriktirilgan hujjatlar: ${hujjatlar||'—'} | Kalit so\'zlar: ${x.kalit_sozlar||'—'}`;
  }).join('\n');
  const sektorList = sektorlarCache.map(s=>
    `- ${s.nom} | Kalit so\'zlar: ${s.kalit_sozlar||'—'} | Tavsif: ${s.tavsif||'—'}`
  ).join('\n');
  const today = new Date();
  const todayStr = `${today.getDate().toString().padStart(2,'0')}.${(today.getMonth()+1).toString().padStart(2,'0')}.${today.getFullYear()}`;
  const deadline10 = addWorkDays(today,10);
  const deadline12 = addWorkDays(today,12);

  const systemPrompt = `Sen O'zbekiston davlat muassasasi uchun hujjat tahlil qiladigan AI yordamchisisan.
Vazifa: PDF, Word matni, screenshot/rasm yoki qo'lda kiritilgan matndan rasmiy topshiriqni chuqur tahlil qil.

Aniqlashing kerak:
1. Hujjat mazmuni qaysi SEKTOR/BO'LIMga tegishli.
2. Mavjud xodimlar ichidan eng mos IJROCHI kim.
   MUHIM QOIDA — YUKLAMANI MUVOZANATLASH:
   - Har xodimning "Yuklama" ko'rsatkichiga e'tibor ber.
   - Agar eng mos xodimda 5 va undan ko'p ochiq topshiriq bo'lsa, xuddi shu sektordagi kamroq yuklangan xodimni tanlashni ko'rib chiq.
   - "bo'sh" (0 ta) yoki kam topshiriqlı xodimlarni afzal ko'r — agar ularning kalit so'zlari ham mos bo'lsa.
   - Ishonch darajasi 80%+ bo'lsa ham, bir xodimga 5 tadan ortiq topshiriq yuklamaslik uchun alternativni ko'rib chiq.
3. MUDDAT: agar hujjatda aniq muddat, sana, "falon kungacha", "zudlik bilan", "3 kun ichida" kabi talab bo'lsa, shu asosda muddat qo'y. Agar muddat umuman topilmasa, murakkabroq/topshiriqli hujjatga 12 ish kuni (${fmtDate(deadline12)}), oddiy murojaat yoki standart xatga 10 ish kuni (${fmtDate(deadline10)}) qo'y.
4. Hujjatdan kimga tegishli ekanini, asosiy talabni, raqam/sana/tashkilotni imkon qadar ajrat.
5. Qisqa xulosa va rasmiy rezolutsiya yoz.

Bugungi sana: ${todayStr}

MAVJUD SEKTORLAR:
${sektorList||'(hali kiritilmagan)'}

MAVJUD XODIMLAR (Yuklama = joriy ochiq topshiriqlar soni):
${xodimList||'(hali kiritilmagan)'}

Javobni FAQAT valid JSON formatda ber. Markdown, izoh, qo'shimcha matn yozma:
{
  "sektor": "Sektor nomi",
  "xodim": "Familiya Ism",
  "muddat": "KK.OO.YYYY",
  "muddat_asosi": "hujjatda ko'rsatilgan",
  "xulosa": "2-3 jumlalik xulosa",
  "rezolutsiya": "Kimga, nima vazifa, qaysi muddatgacha bajarilishi rasmiy matni",
  "hujjat_raqami": "topilsa",
  "hujjat_sanasi": "topilsa KK.OO.YYYY",
  "kimdan": "topilsa tashkilot yoki shaxs",
  "ishonch": 85
}`;

  const instructionText = type === 'file' && filePart
    ? `${fileName} faylini ko'rib/OCR qilib tahlil qil. PDF yoki screenshot ichidagi barcha ko'rinadigan matn, jadval, muhr/sana va rezolutsiya belgilarini inobatga ol.`
    : `Quyidagi hujjat matnini tahlil qil:\n\n${rawText}`;

  const buildGeminiParts = () => {
    const parts = [{ text: systemPrompt }];
    if(type === 'file' && filePart?.base64) {
      parts.push({ inline_data: { mime_type: filePart.mimeType, data: filePart.base64 } });
    }
    parts.push({ text: instructionText });
    return parts;
  };

  const userContent = systemPrompt + '\n\n' + instructionText;

  const analyzeProviders = [
    {
      name: 'Gemini',
      getKey: () => localStorage.getItem('GEMINI_API_KEY') || '',
      call: async (key) => {
        const models = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];
        let lastGeminiError = '';
        for (const model of models) {
          const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
          const body = {
            contents: [{ role: 'user', parts: buildGeminiParts() }],
            generationConfig: {
              maxOutputTokens: 2200,
              temperature: 0.15,
              responseMimeType: 'application/json',
              responseSchema: {
                type: 'OBJECT',
                properties: {
                  sektor: { type: 'STRING' },
                  xodim: { type: 'STRING' },
                  muddat: { type: 'STRING' },
                  muddat_asosi: { type: 'STRING' },
                  xulosa: { type: 'STRING' },
                  rezolutsiya: { type: 'STRING' },
                  hujjat_raqami: { type: 'STRING' },
                  hujjat_sanasi: { type: 'STRING' },
                  kimdan: { type: 'STRING' },
                  ishonch: { type: 'NUMBER' }
                },
                required: ['sektor','xodim','muddat','muddat_asosi','xulosa','rezolutsiya','ishonch']
              }
            }
          };
          const resp = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
          if (!resp.ok) {
            const errData = await resp.json().catch(()=>({}));
            lastGeminiError = errData?.error?.message || `HTTP ${resp.status}`;
            if (resp.status === 404 && model !== models[models.length - 1]) continue;
            if (resp.status === 400 || resp.status === 403) { localStorage.removeItem('GEMINI_API_KEY'); }
            throw new Error(lastGeminiError);
          }
          const data = await resp.json();
          const text = (data?.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('\n').trim();
          if (!text) throw new Error('Bo\'sh javob');
          return text;
        }
        throw new Error(lastGeminiError || 'Gemini model topilmadi');
      }
    },
    {
      name: 'OpenRouter',
      getKey: () => localStorage.getItem('OPENROUTER_API_KEY') || '',
      call: async (key) => {
        if(type === 'file' && filePart?.base64) {
          throw new Error('OpenRouter fallback faqat matn uchun. PDF/screenshot uchun Gemini kalit kerak.');
        }
        const url = 'https://openrouter.ai/api/v1/chat/completions';
        const body = {
          model: 'mistralai/mistral-7b-instruct',
          messages: [{ role: 'user', content: userContent }],
          max_tokens: 1800,
          temperature: 0.2
        };
        const resp = await fetch(url, {
          method:'POST',
          headers:{'Authorization':'Bearer '+key,'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        const text = data?.choices?.[0]?.message?.content || '';
        if (!text) throw new Error('Bo\'sh javob');
        return text;
      }
    }
  ];

  let resultText = null;
  let usedProvider = null;
  let lastError = '';

  for (const ap of analyzeProviders) {
    const k = ap.getKey();
    if (!k) continue;
    try {
      if(aiStatus) aiStatus.innerHTML=`<div class="ai-loading">🤖 ${ap.name} AI hujjatni chuqur tahlil qilmoqda...</div>`;
      resultText = await ap.call(k);
      usedProvider = ap.name;
      break;
    } catch(e) {
      lastError = e.message;
      console.warn(`${ap.name} analyze failed:`, e.message);
    }
  }

  if (!resultText) {
    const geminiKey = localStorage.getItem('GEMINI_API_KEY');
    if (!geminiKey) {
      const k = prompt('🔑 Google Gemini API kalitini kiriting (AIza... bilan boshlanadi):\n\n👉 https://aistudio.google.com/app/apikey');
      if (k && k.trim().startsWith('AIza')) {
        localStorage.setItem('GEMINI_API_KEY', k.trim());
        updateApiKeyStatus();
        try {
          if(aiStatus) aiStatus.innerHTML='<div class="ai-loading">🤖 Gemini AI hujjatni chuqur tahlil qilmoqda...</div>';
          resultText = await analyzeProviders[0].call(k.trim());
          usedProvider = 'Gemini';
        } catch(e) { lastError = e.message; }
      }
    }
  }

  if (!resultText) {
    if(aiStatus) {
      aiStatus.innerHTML=`<div class="ai-error">❌ AI tahlil xatoligi: ${escH(lastError || 'API kalit topilmadi')}<br><small>Gemini API kalitini yangilang. PDF/screenshot tahlili uchun aynan Gemini kerak.</small></div>`;
      updateApiKeyStatus();
    }
    return;
  }

  let result = parseAIJson(resultText);
  result = normalizeAIResult(result);

  if(!result) {
    console.warn('AI raw response:', resultText);
    if(aiStatus) aiStatus.innerHTML=`<div class="ai-error">❌ AI javobini o'qishda xatolik. Qaytadan urinib ko'ring.<br><small>Javob JSON formatda kelmadi. Konsolda xom javob saqlandi.</small></div>`;
    return;
  }

  if(aiStatus) {
    aiStatus.style.display='block';
    aiStatus.innerHTML = `
      <div class="ai-result-card">
        <div class="ai-result-header">✅ ${usedProvider} AI tahlil tugadi — Ishonch: <b>${result.ishonch||'—'}%</b></div>
        <div class="ai-result-grid" style="grid-template-columns:repeat(3,1fr);">
          <div><span class="ai-label">📂 Sektor</span><span class="ai-val">${escH(result.sektor||'—')}</span></div>
          <div><span class="ai-label">👤 Ijrochi</span><span class="ai-val">${escH(result.xodim||'—')}</span></div>
          <div><span class="ai-label">📅 Muddat</span><span class="ai-val">${escH(result.muddat||'—')} <small style="color:var(--muted);">(${escH(result.muddat_asosi||'')})</small></span></div>
          <div><span class="ai-label">🏛️ Kimdan</span><span class="ai-val">${escH(result.kimdan||'—')}</span></div>
          <div><span class="ai-label">📋 Hujjat raqami</span><span class="ai-val">${escH(result.hujjat_raqami||'—')}</span></div>
          <div><span class="ai-label">📆 Hujjat sanasi</span><span class="ai-val">${escH(result.hujjat_sanasi||'—')}</span></div>
        </div>
        ${result.kimdan?`<div style="font-size:11px;background:#ecfdf5;border-radius:6px;padding:8px 12px;margin-bottom:10px;color:#065f46;">🏛️ "${escH(result.kimdan)}" tashkiloti avtomatik ro'yxatga qo'shiladi</div>`:''}
        <div class="ai-xulosa">${escH(result.xulosa||'')}</div>
        <div class="ai-rezolutsiya">"${escH(result.rezolutsiya||'')}"</div>
        <div style="display:flex;gap:10px;margin-top:12px;flex-wrap:wrap;">
          <button class="btn btn-success" onclick="saveFishka(${JSON.stringify(JSON.stringify(result))}, ${JSON.stringify(fileName)})">💾 Fishka sifatida saqlash</button>
          <button class="btn btn-primary" onclick="saveFishkaAndMuhim(${JSON.stringify(JSON.stringify(result))}, ${JSON.stringify(fileName)})">🚨 Muhim topshiriq sifatida ham qo'shish</button>
          <button class="btn btn-outline" onclick="document.getElementById('fishka-ai-status').innerHTML='';document.getElementById('fishka-ai-status').style.display='none'">✕ Yopish</button>
        </div>
      </div>`;
  }
}
// ===== API KEY MANAGEMENT =====
function updateApiKeyStatus() {
  // Gemini key status in Fishka panel
  const el = document.getElementById('api-key-status');
  if(el) {
    const key = localStorage.getItem('GEMINI_API_KEY');
    if(key) {
      el.textContent = 'Kiritilgan (...' + key.slice(-6) + ')';
      el.style.color = 'var(--green-mid)';
    } else {
      const orKey = localStorage.getItem('OPENROUTER_API_KEY');
      if (orKey) {
        el.textContent = 'OpenRouter (...' + orKey.slice(-6) + ')';
        el.style.color = 'var(--blue-mid)';
      } else {
        el.textContent = 'Kiritilmagan';
        el.style.color = 'var(--red-mid)';
      }
    }
  }
}

window.setApiKey = () => {
  const key = prompt('🔑 Google Gemini API kalitini kiriting (AIza... bilan boshlanadi):\n\n👉 Kalit olish: https://aistudio.google.com/app/apikey\n\nBu kalit localStorage da saqlanadi (sahifa yopilsa o\'chmaydi).\n\n💡 Yoki "AI Sozlamalar" bo\'limidan OpenRouter kalitini ham kiritishingiz mumkin.');
  if(!key) return;
  const trimmed = key.trim();
  if(!trimmed.startsWith('AIza')) {
    showToast('❌ Gemini kalit "AIza" bilan boshlanishi kerak!', 'error'); return;
  }
  localStorage.setItem('GEMINI_API_KEY', trimmed);
  showToast('✅ Gemini API kalit saqlandi', 'success');
  updateApiKeyStatus();
  renderProviderStatus();
};

window.clearApiKey = () => {
  localStorage.removeItem('GEMINI_API_KEY');
  showToast('Gemini API kalit o\'chirildi', 'info');
  updateApiKeyStatus();
  renderProviderStatus();
};

function addWorkDays(date, days) {
  let d = new Date(date); let added=0;
  while(added<days){ d.setDate(d.getDate()+1); if(d.getDay()!==0&&d.getDay()!==6) added++; }
  return d;
}

window.saveFishka = async (resultJson, fileName) => {
  try {
    const result = JSON.parse(resultJson);
    showLoading('Fishka saqlanmoqda...');
    await addDoc(collection(db,'fishkalar'),{
      hujjat_nomi: fileName,
      sektor: result.sektor||'',
      xodim: result.xodim||'',
      muddat: result.muddat||'',
      muddat_asosi: result.muddat_asosi||'',
      ai_xulosa: result.xulosa||'',
      rezolutsiya: result.rezolutsiya||'',
      ai_ishonch: result.ishonch||0,
      hujjat_raqami: result.hujjat_raqami||'',
      hujjat_sanasi: result.hujjat_sanasi||'',
      kimdan: result.kimdan||'',
      status: 'Yangi',
      createdBy: currentUser?.uid||'',
      createdByName: currentUserData?.fullName||'',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    });

    // ═══ AUTO TASHKILOT QO'SHISH ═══
    // Rezolutsiya olingan vaqt, xat qayerdan kelgan bo'lsa tashkilotlar listiga avtomatik qo'shamiz
    if (result.kimdan && result.kimdan.trim().length > 2) {
      await autoAddTashkilot(result.kimdan.trim(), fileName, result.hujjat_raqami||'', result.hujjat_sanasi||'');
    }

    hideLoading();
    showToast('✅ Fishka saqlandi!','success');
    document.getElementById('fishka-ai-status').innerHTML='';
    document.getElementById('fishka-file-input').value='';
    document.getElementById('fishka-text-input').value='';
    await loadFishkalar();
    showPanel('fishka');
  } catch(e){ hideLoading(); showToast('Saqlashda xatolik: '+e.message,'error'); }
};

// ═══ AUTO TASHKILOT QO'SHISH FUNKSIYASI ═══
async function autoAddTashkilot(orgName, hujjatNomi, hujjatRaqami, hujjatSanasi) {
  const before = tashkilotlarCache.length;
  await syncTashkilotlarFromDocs([{
    fromOrg: orgName,
    docName: hujjatNomi,
    docNum: hujjatRaqami,
    docDate: hujjatSanasi
  }]);
  if(tashkilotlarCache.length > before) {
    showToast(`🏛️ "${normalizeOrgName(orgName)}" tashkilotlar ro'yxatiga qo'shildi`, 'info');
  }
}

async function updateTashkilotlarBadge() {
  const el = document.getElementById('badge-tashkilotlar');
  if(!el) return;
  const derivedCount = buildTashkilotStatsFromDocs(allDocs).size;
  el.textContent = Math.max(tashkilotlarCache.length || 0, derivedCount || 0);
}

window.saveFishkaAndMuhim = async (resultJson, fileName) => {
  await saveFishka(resultJson, fileName);
  // Also create a muhim topshiriq entry
  try {
    const result = JSON.parse(resultJson);
    await addDoc(collection(db,'muhim_topshiriqlar'),{
      nom: result.rezolutsiya?.slice(0,80)||fileName||'Topshiriq',
      ijrochi: result.xodim||'',
      daraja: "o'rta",
      muddat: result.muddat ? (() => { const p=result.muddat.split('.'); return p.length===3?`${p[2]}-${p[1].padStart(2,'0')}-${p[0].padStart(2,'0')}`:result.muddat; })() : '',
      mazmun: result.xulosa||'',
      manba: result.kimdan||'',
      hujjat_raqam: result.hujjat_raqami||'',
      status:'Yangi', createdBy:currentUser?.uid||'',
      createdAt:serverTimestamp(), updatedAt:serverTimestamp()
    });
    showToast('✅ Muhim topshiriq ham qo\'shildi!','success');
    updateMuhimBadge();
  } catch(e) { console.warn('MuhimTopshiriq error:',e); }
};



// ╔══════════════════════════════════════════════════════════════╗
// ║   CHAT HISTORY — users/{uid}/chats/{chatId}/messages        ║
// ╚══════════════════════════════════════════════════════════════╝
let chatList = [];
let activeChatId = null;
let chatMessages = [];
let chatUnsub = null;

async function loadChatList() {
  if (!currentUser) return;
  try {
    const q = query(
      collection(db, `users/${currentUser.uid}/chats`),
      orderBy('updatedAt', 'desc'),
      limit(50)
    );
    const snap = await getDocs(q);
    chatList = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    renderChatList();
  } catch(e) { console.error('Chat load:', e); }
}

function renderChatList() {
  const el = document.getElementById('chat-list-wrap');
  if (!el) return;
  const search = (document.getElementById('chat-search')?.value || '').toLowerCase();
  const filtered = chatList.filter(c =>
    !search || (c.title || '').toLowerCase().includes(search)
  );

  if (!filtered.length) {
    el.innerHTML = `<div style="padding:20px;text-align:center;color:var(--muted);font-size:12px;">
      ${search ? 'Topilmadi' : 'Hali chat yo\'q.<br>Yangi suhbat boshlang ↑'}
    </div>`;
    return;
  }

  el.innerHTML = filtered.map(c => `
    <div class="chat-item ${c.id === activeChatId ? 'chat-item-active' : ''} ${c.pinned ? 'chat-item-pinned' : ''}"
         onclick="openChat('${c.id}')">
      <div style="display:flex;align-items:center;gap:6px;min-width:0;">
        ${c.pinned ? '<span style="font-size:11px;">📌</span>' : ''}
        <span class="chat-item-title">${escH(c.title || 'Yangi suhbat')}</span>
      </div>
      <div style="display:flex;align-items:center;gap:4px;flex-shrink:0;">
        <span style="font-size:10px;color:var(--muted);">${formatChatTime(c.updatedAt)}</span>
        <div class="chat-item-menu" onclick="event.stopPropagation();toggleChatMenu('${c.id}')">⋯</div>
      </div>
      <div class="chat-dropdown" id="cmenu-${c.id}" style="display:none;">
        <div onclick="renameChat('${c.id}')">✏️ Nomini o'zgartirish</div>
        <div onclick="pinChat('${c.id}', ${!!c.pinned})">${c.pinned ? '📌 Pinndan chiqarish' : '📌 Pin qilish'}</div>
        <div onclick="deleteChat('${c.id}')" style="color:var(--red-mid);">🗑️ O'chirish</div>
      </div>
    </div>`).join('');
}

function formatChatTime(ts) {
  if (!ts) return '';
  const d = ts.toDate ? ts.toDate() : new Date(ts);
  const now = new Date();
  const diff = now - d;
  if (diff < 60000) return 'hozir';
  if (diff < 3600000) return Math.floor(diff/60000) + ' min';
  if (diff < 86400000) return Math.floor(diff/3600000) + ' soat';
  return d.toLocaleDateString('uz-UZ');
}

window.openChat = async (chatId) => {
  activeChatId = chatId;
  renderChatList();
  if (chatUnsub) chatUnsub();

  const msgWrap = document.getElementById('chat-messages');
  if (msgWrap) msgWrap.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted);">Yuklanmoqda...</div>';

  chatUnsub = onSnapshot(
    query(collection(db, `users/${currentUser.uid}/chats/${chatId}/messages`), orderBy('createdAt')),
    (snap) => {
      chatMessages = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      renderChatMessages();
    }
  );
};

function renderChatMessages() {
  const wrap = document.getElementById('chat-messages');
  if (!wrap) return;
  if (!chatMessages.length) {
    wrap.innerHTML = `<div class="chat-empty">💬 Suhbatni boshlang...</div>`;
    return;
  }
  wrap.innerHTML = chatMessages.map(m => `
    <div class="msg-row ${m.role === 'user' ? 'msg-user' : 'msg-ai'}">
      <div class="msg-bubble ${m.role === 'user' ? 'msg-bubble-user' : 'msg-bubble-ai'}">
        <div class="msg-text">${m.role === 'ai' ? formatAIText(m.content) : escH(m.content)}</div>
        <div class="msg-time">${formatChatTime(m.createdAt)}</div>
      </div>
    </div>`).join('');
  wrap.scrollTop = wrap.scrollHeight;
}

function formatAIText(text) {
  return escH(text)
    .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
    .replace(/\*(.*?)\*/g, '<i>$1</i>')
    .replace(/`(.*?)`/g, '<code style="background:var(--border);padding:1px 5px;border-radius:3px;font-family:monospace;font-size:12px;">$1</code>')
    .replace(/\n/g, '<br>');
}

window.newChat = async () => {
  if (!currentUser) return;
  const chatRef = doc(collection(db, `users/${currentUser.uid}/chats`));
  await setDoc(chatRef, {
    title: 'Yangi suhbat',
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
    pinned: false,
    msgCount: 0
  });
  chatList.unshift({ id: chatRef.id, title: 'Yangi suhbat', pinned: false, updatedAt: Timestamp.now() });
  await openChat(chatRef.id);
  renderChatList();
  document.getElementById('chat-input')?.focus();
};

window.searchChats = () => renderChatList();

window.renameChat = async (chatId) => {
  toggleChatMenu(chatId);
  const chat = chatList.find(c => c.id === chatId);
  const name = prompt('Yangi nom:', chat?.title || 'Suhbat');
  if (!name) return;
  await updateDoc(doc(db, `users/${currentUser.uid}/chats/${chatId}`), { title: name });
  const c = chatList.find(x => x.id === chatId);
  if (c) c.title = name;
  renderChatList();
};

window.pinChat = async (chatId, isPinned) => {
  toggleChatMenu(chatId);
  await updateDoc(doc(db, `users/${currentUser.uid}/chats/${chatId}`), { pinned: !isPinned });
  const c = chatList.find(x => x.id === chatId);
  if (c) c.pinned = !isPinned;
  renderChatList();
};

window.deleteChat = async (chatId) => {
  toggleChatMenu(chatId);
  if (!confirm('Bu suhbatni o\'chirmoqchimisiz?')) return;
  await deleteDoc(doc(db, `users/${currentUser.uid}/chats/${chatId}`));
  chatList = chatList.filter(c => c.id !== chatId);
  if (activeChatId === chatId) {
    activeChatId = null;
    chatMessages = [];
    const wrap = document.getElementById('chat-messages');
    if (wrap) wrap.innerHTML = '<div class="chat-empty">💬 Suhbat tanlang...</div>';
  }
  renderChatList();
  showToast('Suhbat o\'chirildi', 'info');
};

window.toggleChatMenu = (chatId) => {
  document.querySelectorAll('.chat-dropdown').forEach(d => {
    if (d.id !== 'cmenu-' + chatId) d.style.display = 'none';
  });
  const el = document.getElementById('cmenu-' + chatId);
  if (el) el.style.display = el.style.display === 'block' ? 'none' : 'block';
};

document.addEventListener('click', (e) => {
  if (!e.target.closest('.chat-item-menu')) {
    document.querySelectorAll('.chat-dropdown').forEach(d => d.style.display = 'none');
  }
});

// ╔══════════════════════════════════════════════════════════════╗
// ║   AI CHAT — Streaming + Provider Fallback + Rate Limit      ║
// ╚══════════════════════════════════════════════════════════════╝

// AI Provider config — priority order
// Gemini: non-streaming (generateContent), OpenRouter: streaming fallback
const AI_PROVIDERS = [
  {
    name: 'Gemini', icon: '🟦', streaming: false, model: 'gemini-2.5-flash',
    getUrl: (key) => `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${key}`,
    getKey: () => localStorage.getItem('GEMINI_API_KEY') || '',
    buildBody: (messages) => ({ contents: messages.map(m => ({ role: m.role === 'ai' ? 'model' : 'user', parts: [{ text: m.content }] })), generationConfig: { maxOutputTokens: 2048, temperature: 0.7 } }),
    parseResponse: (data) => (data?.candidates?.[0]?.content?.parts || []).map(p=>p.text||'').join('\n'),
    headers: () => ({ 'Content-Type': 'application/json' })
  },
  {
    name: 'Groq', icon: '⚡', streaming: true, model: 'llama-3.1-70b-versatile',
    getUrl: () => 'https://api.groq.com/openai/v1/chat/completions',
    getKey: () => localStorage.getItem('GROQ_API_KEY') || '',
    buildBody: (messages) => ({ model: localStorage.getItem('GROQ_MODEL') || 'llama-3.1-70b-versatile', messages: messages.map(m => ({ role: m.role === 'ai' ? 'assistant' : 'user', content: m.content })), stream: true, max_tokens: 2048, temperature: 0.7 }),
    parseChunk: (line) => { try { if (line === 'data: [DONE]') return ''; const data = JSON.parse(line.replace(/^data: /, '')); return data?.choices?.[0]?.delta?.content || ''; } catch { return ''; } },
    headers: (key) => ({ 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' })
  },
  {
    name: 'OpenRouter', icon: '🔀', streaming: true, model: 'mistralai/mistral-7b-instruct',
    getUrl: () => 'https://openrouter.ai/api/v1/chat/completions',
    getKey: () => localStorage.getItem('OPENROUTER_API_KEY') || '',
    buildBody: (messages) => ({ model: localStorage.getItem('OPENROUTER_MODEL') || 'mistralai/mistral-7b-instruct', messages: messages.map(m => ({ role: m.role === 'ai' ? 'assistant' : 'user', content: m.content })), stream: true, max_tokens: 2048 }),
    parseChunk: (line) => { try { if (line === 'data: [DONE]') return ''; const data = JSON.parse(line.replace(/^data: /, '')); return data?.choices?.[0]?.delta?.content || ''; } catch { return ''; } },
    headers: (key) => ({ 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' })
  }
].sort((a,b)=> (appSettingsCache.providerPriority||DEFAULT_FEATURES.providerPriority).indexOf(a.name) - (appSettingsCache.providerPriority||DEFAULT_FEATURES.providerPriority).indexOf(b.name));

// Rate limiter — max 20 messages per hour per user
const RATE_LIMIT = { max: 20, windowMs: 3600000 };
function checkRateLimit() {
  const key = 'rl_' + (currentUser?.uid || 'anon');
  const raw = localStorage.getItem(key);
  const now = Date.now();
  let data = raw ? JSON.parse(raw) : { count: 0, windowStart: now };
  if (now - data.windowStart > RATE_LIMIT.windowMs) {
    data = { count: 0, windowStart: now };
  }
  const maxAllowed = getUsageLimit();
  if (data.count >= maxAllowed) {
    const remaining = Math.ceil((RATE_LIMIT.windowMs - (now - data.windowStart)) / 60000);
    return { allowed: false, remaining };
  }
  data.count++;
  localStorage.setItem(key, JSON.stringify(data));
  return { allowed: true, remaining: maxAllowed - data.count };
}

let _isStreaming = false;

window.sendChatMessage = async () => {
  const input = document.getElementById('chat-input');
  const text = input?.value?.trim();
  if (!text || _isStreaming) return;

  // Ensure a chat is open
  if (!activeChatId) await newChat();

  // Rate limit check
  const rl = checkRateLimit();
  if (!rl.allowed) {
    showToast(`⏳ Soatlik limit tugadi. ${rl.remaining} daqiqadan so'ng urinib ko'ring.`, 'error');
    return;
  }

  // Get API key — try providers in order
  let apiKey = '';
  let provider = null;
  for (const p of AI_PROVIDERS) {
    const k = p.getKey();
    if (k) { apiKey = k; provider = p; break; }
  }
  if (!provider) {
    // No API key set — guide user to settings
    const go = confirm('⚠️ AI API kalit topilmadi.\n\n"AI Sozlamalar" bo\'limiga o\'tib kalit kiritasizmi?\n\n(OK — sozlamalarga o\'tish, Bekor — yopish)');
    if (go) showPanel('providers');
    _isStreaming = false;
    document.getElementById('chat-send-btn')?.classList.remove('loading');
    return;
  }

  input.value = '';
  _isStreaming = true;
  document.getElementById('chat-send-btn')?.classList.add('loading');

  // Save user message
  const userMsg = {
    role: 'user',
    content: text,
    createdAt: serverTimestamp()
  };
  const userMsgRef = await addDoc(collection(db, `users/${currentUser.uid}/chats/${activeChatId}/messages`), userMsg);

  // Update chat metadata
  const isFirstMsg = chatMessages.filter(m=>m.role==='user').length === 0;
  const updateData = {
    updatedAt: serverTimestamp(),
    msgCount: increment(1)
  };
  if (isFirstMsg) {
    updateData.title = text.slice(0, 50) + (text.length > 50 ? '...' : '');
  }
  await updateDoc(doc(db, `users/${currentUser.uid}/chats/${activeChatId}`), updateData);
  const chatInList = chatList.find(c => c.id === activeChatId);
  if (chatInList && isFirstMsg) chatInList.title = updateData.title;
  renderChatList();

  // Build messages context (last 10)
  const context = chatMessages.slice(-10).map(m => ({ role: m.role, content: m.content }));
  context.push({ role: 'user', content: text });

  // Add typing indicator in UI
  const msgWrap = document.getElementById('chat-messages');
  const typingId = 'typing-' + Date.now();
  if (msgWrap) {
    const typingEl = document.createElement('div');
    typingEl.id = typingId;
    typingEl.className = 'msg-row msg-ai';
    typingEl.innerHTML = `<div class="msg-bubble msg-bubble-ai">
      <div class="msg-text" id="stream-text-${typingId}">
        <span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span>
      </div>
      <div style="font-size:10px;color:var(--muted);margin-top:4px;">${provider.icon} ${provider.name} javob yozmoqda...</div>
    </div>`;
    msgWrap.appendChild(typingEl);
    msgWrap.scrollTop = msgWrap.scrollHeight;
  }

  let fullResponse = '';
  let providerUsed = provider;
  let success = false;

  // Try providers in fallback order
  for (let pi = AI_PROVIDERS.indexOf(provider); pi < AI_PROVIDERS.length; pi++) {
    const p = AI_PROVIDERS[pi];
    const k = p.getKey();
    if (!k) continue;

    try {
      const headers = p.headers ? p.headers(k) : { 'Content-Type': 'application/json' };
      const resp = await fetch(p.getUrl(k), {
        method: 'POST',
        headers,
        body: JSON.stringify(p.buildBody(context))
      });

      if (!resp.ok) {
        const errText = await resp.text().catch(() => '');
        throw new Error(`HTTP ${resp.status}: ${errText.slice(0, 200)}`);
      }

      const streamEl = document.getElementById('stream-text-' + typingId);
      fullResponse = '';

      if (!p.streaming) {
        // Non-streaming (Gemini generateContent)
        const data = await resp.json();
        fullResponse = p.parseResponse(data);
        if (!fullResponse) throw new Error('Bo\'sh javob qaytarildi');
        if (streamEl) streamEl.innerHTML = formatAIText(fullResponse);
        if (msgWrap) msgWrap.scrollTop = msgWrap.scrollHeight;
      } else {
        // Streaming (OpenRouter)
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop(); // keep incomplete line
          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed === 'data: [DONE]') continue;
            if (trimmed.startsWith('data: ')) {
              const token = p.parseChunk(trimmed);
              if (token) {
                fullResponse += token;
                if (streamEl) streamEl.innerHTML = formatAIText(fullResponse) + '<span class="cursor-blink">▌</span>';
                if (msgWrap) msgWrap.scrollTop = msgWrap.scrollHeight;
              }
            }
          }
        }
        // Process remaining buffer
        if (buffer.trim() && buffer.trim() !== 'data: [DONE]' && buffer.trim().startsWith('data: ')) {
          const token = p.parseChunk(buffer.trim());
          if (token) fullResponse += token;
        }
        if (!fullResponse) throw new Error('Streaming javob bo\'sh qaytdi');
      }

      providerUsed = p;
      success = true;
      break;
    } catch(e) {
      console.warn(`${p.name} failed:`, e.message);
      if (pi < AI_PROVIDERS.length - 1) {
        // Try next provider that has a key
        let nextIdx = pi + 1;
        while (nextIdx < AI_PROVIDERS.length && !AI_PROVIDERS[nextIdx].getKey()) nextIdx++;
        if (nextIdx < AI_PROVIDERS.length) {
          const nextP = AI_PROVIDERS[nextIdx];
          const streamEl = document.getElementById('stream-text-' + typingId);
          if (streamEl) streamEl.innerHTML = `⚠️ ${p.name} ishlamadi. ${nextP.icon} ${nextP.name} ga o'tilmoqda...`;
        }
      }
    }
  }

  // Remove typing indicator
  document.getElementById(typingId)?.remove();
  _isStreaming = false;
  document.getElementById('chat-send-btn')?.classList.remove('loading');

  if (success && fullResponse) {
    // Save AI response to Firestore
    await addDoc(collection(db, `users/${currentUser.uid}/chats/${activeChatId}/messages`), {
      role: 'ai',
      content: fullResponse,
      provider: providerUsed.name,
      createdAt: serverTimestamp()
    });
    await updateDoc(doc(db, `users/${currentUser.uid}/chats/${activeChatId}`), {
      updatedAt: serverTimestamp(),
      msgCount: increment(1)
    });

    // Track AI usage for admin analytics
    trackAIUsage(fullResponse.length, providerUsed.name);
  } else if (!success) {
    const hasAnyKey = AI_PROVIDERS.some(p => p.getKey());
    if (!hasAnyKey) {
      showToast('❌ API kalit topilmadi. "AI Sozlamalar" bo\'limidan kalit kiriting.', 'error');
    } else {
      showToast('❌ AI javob bermadi. API limit yoki tarmoq xatoligi. Biroz kutib qaytadan urinib ko\'ring.', 'error');
    }
    renderChatMessages();
  }
};

// AI usage tracking
async function trackAIUsage(responseLen, providerName='') {
  if (!currentUser) return;
  try {
    const today = new Date().toISOString().slice(0, 10);
    const ref = doc(db, `aiUsage/${currentUser.uid}_${today}`);
    const snap = await getDoc(ref);
    if (snap.exists()) {
      await updateDoc(ref, { requests: increment(1), chars: increment(responseLen), tokensApprox: increment(Math.ceil(responseLen/4)), provider: providerName });
    } else {
      await setDoc(ref, {
        uid: currentUser.uid,
        date: today,
        requests: 1,
        chars: responseLen,
        tokensApprox: Math.ceil(responseLen/4),
        provider: providerName,
        createdAt: serverTimestamp()
      });
    }
  } catch(e) { /* non-critical */ }
}

// Enter key in chat
window.chatKeydown = (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    window.sendChatMessage();
  }
};

// ╔══════════════════════════════════════════════════════════════╗
// ║   ADMIN PANEL — User mgmt + AI usage + Analytics           ║
// ╚══════════════════════════════════════════════════════════════╝

window.loadAdminAnalytics = async () => {
  if (currentUserData?.role !== 'admin' && currentUserData?.role !== 'superadmin') return;
  try {
    // AI usage last 7 days
    const usageSnap = await getDocs(collection(db, 'aiUsage'));
    const usageData = usageSnap.docs.map(d => d.data());
    const totalRequests = usageData.reduce((s, d) => s + (d.requests || 0), 0);
    const totalChars = usageData.reduce((s, d) => s + (d.chars || 0), 0);

    const el = document.getElementById('admin-analytics');
    if (!el) return;
    el.innerHTML = `
      <div class="stat-grid-5" style="margin-bottom:0;">
        <div class="stat-box blue"><div class="sv">${totalRequests}</div><div class="sl">Jami AI so'rovlar</div></div>
        <div class="stat-box navy"><div class="sv">${Math.round(totalChars/1000)}K</div><div class="sl">Jami belgilar</div></div>
        <div class="stat-box green"><div class="sv">${usageData.length}</div><div class="sl">Faol kunlar</div></div>
      </div>`;
  } catch(e) { console.error(e); }
};

window.setProviderKey = (provider) => {
  const labels = {
    GEMINI: 'Gemini (AIza... bilan boshlanadi)',
    GROQ: 'Groq (gsk_... bilan boshlanadi)',
    OPENROUTER: 'OpenRouter (sk-or-... bilan boshlanadi)'
  };
  const hints = {
    GEMINI: '\n👉 Kalit olish: https://aistudio.google.com/app/apikey',
    GROQ: '\n👉 Kalit olish: https://console.groq.com/keys',
    OPENROUTER: '\n👉 Kalit olish: https://openrouter.ai/keys'
  };
  const key = prompt(`🔑 ${labels[provider] || provider} API kalitini kiriting:${hints[provider]||''}`);
  if (!key) return;
  const trimmed = key.trim();
  // Validate
  if (provider === 'GEMINI' && !trimmed.startsWith('AIza')) {
    showToast('❌ Gemini kalit "AIza" bilan boshlanishi kerak!', 'error'); return;
  }
  localStorage.setItem(provider + '_API_KEY', trimmed);
  showToast(`✅ ${provider} API kalit saqlandi`, 'success');
  renderProviderStatus();
  updateApiKeyStatus();
};

function renderProviderStatus() {
  const el = document.getElementById('provider-status');
  if (!el) return;
  el.innerHTML = AI_PROVIDERS.map((p, idx) => {
    const hasKey = !!p.getKey();
    const isFirst = idx === 0;
    return `<div style="display:flex;align-items:center;justify-content:space-between;padding:12px 14px;background:${hasKey?'var(--green-light)':'var(--red-light)'};border-radius:8px;margin-bottom:8px;border:1px solid ${hasKey?'#bbf7d0':'#fca5a5'};">
      <div>
        <span style="font-size:14px;">${p.icon}</span>
        <b style="margin-left:8px;">${p.name}</b>
        ${isFirst ? '<span style="font-size:10px;background:#dbeafe;color:#1e40af;padding:2px 6px;border-radius:4px;margin-left:6px;">Asosiy</span>' : '<span style="font-size:10px;background:#f3e8ff;color:#7c3aed;padding:2px 6px;border-radius:4px;margin-left:6px;">Fallback</span>'}
        <span style="font-size:11px;color:var(--muted);margin-left:8px;">${hasKey ? '✅ Kalit kiritilgan' : '❌ Kalit yo\'q'}</span>
      </div>
      <div style="display:flex;gap:6px;">
        <button class="btn btn-sm ${hasKey?'btn-outline':'btn-primary'}" onclick="setProviderKey('${p.name.toUpperCase()}')">
          ${hasKey ? '🔄 Yangilash' : '🔑 Kalit kiriting'}
        </button>
        ${hasKey ? `<button class="btn btn-sm btn-danger" onclick="localStorage.removeItem('${p.name.toUpperCase()}_API_KEY');renderProviderStatus();updateApiKeyStatus();showToast('Kalit o\\'chirildi','info')">✕</button>` : ''}
      </div>
    </div>`;
  }).join('');
}

// ╔══════════════════════════════════════════════════════════════╗
// ║   SECURITY — XSS protection already via escH               ║
// ║   Input sanitizer for Firestore writes                      ║
// ╚══════════════════════════════════════════════════════════════╝
function sanitize(str, maxLen = 2000) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen)
    .replace(/[<>]/g, '')   // basic XSS strip
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '');
}

// Extend doEmailRegister and completeProfile to sanitize inputs
const _origEmailRegister = window.doEmailRegister;
window.doEmailRegister = async function() {
  const fields = ['reg-firstname','reg-lastname','reg-email','reg-job','reg-org'];
  fields.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = sanitize(el.value);
  });
  return _origEmailRegister();
};

// ===== SUPER ADMIN STATS =====
async function loadSuperAdminStats() {
  try {
    const usersSnap = await getDocs(collection(db,'users'));
    const users = usersSnap.docs.map(d=>d.data());
    const total = users.length;
    const blocked = users.filter(u=>u.blocked).length;
    const admins = users.filter(u=>u.role==='admin'||u.role==='superadmin').length;
    const thirtyDaysAgo = new Date(); thirtyDaysAgo.setDate(thirtyDaysAgo.getDate()-30);
    const active = users.filter(u=>{
      if(!u.lastLogin?.toDate) return false;
      return u.lastLogin.toDate() > thirtyDaysAgo;
    }).length;

    const docsSnap = await getDocs(collection(db,'documents'));

    const set = (id,v)=>{ const e=document.getElementById(id); if(e)e.textContent=v; };
    set('sa-total-users', total);
    set('sa-active-users', active);
    set('sa-blocked-users', blocked);
    set('sa-total-docs', docsSnap.size);
    set('sa-admins', admins);

    // Auth method breakdown
    const methods = {};
    users.forEach(u=>{ const m=u.authMethod||'unknown'; methods[m]=(methods[m]||0)+1; });
    const saAuthEl = document.getElementById('sa-auth-stats');
    if(saAuthEl) {
      const icons = {google:'🟦 Google',phone:'📱 Telefon',email:'📧 Email',unknown:'❓ Noma\'lum'};
      saAuthEl.innerHTML = Object.entries(methods).map(([m,c])=>`
        <div class="stat-box blue" style="flex:1;min-width:100px;padding:12px;">
          <div class="sv" style="font-size:22px;">${c}</div>
          <div class="sl">${icons[m]||m}</div>
        </div>`).join('');
    }
  } catch(e) {
    console.error('SA stats error:', e);
  }
}

// ===== DARK MODE TOGGLE =====
function initTheme() {
  const saved = localStorage.getItem('ijroda_theme') || 'light';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeIcon(saved);
}
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('ijroda_theme', next);
  updateThemeIcon(next);
}
function updateThemeIcon(theme) {
  const icon = theme === 'dark' ? '☀️' : '🌙';
  const btn1 = document.getElementById('theme-toggle-btn');
  const btn2 = document.getElementById('auth-theme-btn');
  if(btn1) btn1.textContent = icon;
  if(btn2) btn2.textContent = icon;
}
window.toggleTheme = toggleTheme;
document.addEventListener('DOMContentLoaded', initTheme);

// ╔══════════════════════════════════════════════════════════════════╗
// ║   MUHIM TOPSHIRIQLAR MODULE                                      ║
// ╚══════════════════════════════════════════════════════════════════╝
let muhimCache = [];
let muhimSortKey = 'muddat';
let muhimSortDir = 'asc';

async function loadMuhimTopshiriqlar() {
  try {
    if(!xodimlarCache.length) await loadXodimlar();
    const snap = await getDocs(query(collection(db,'muhim_topshiriqlar'), orderBy('createdAt','desc')));
    muhimCache = snap.docs.map(d=>({id:d.id,...d.data()}));
    updateMuhimBadge();
    renderMuhimTopshiriqlar();
    populateMuhimIjrochi();
  } catch(e) { showToast('Yuklanmadi: '+e.message,'error'); }
}
window.loadMuhimTopshiriqlar = loadMuhimTopshiriqlar;

function updateMuhimBadge() {
  const el = document.getElementById('badge-muhim');
  if(el) el.textContent = muhimCache.filter(m=>m.status!=='Bajarildi').length;
}

function populateMuhimIjrochi() {
  const sel = document.getElementById('mt-ijrochi');
  if(!sel) return;
  const xodimlar = xodimlarCache.length ? xodimlarCache : [];
  sel.innerHTML = '<option value="">— Xodim tanlang —</option>' +
    xodimlar.map(x=>`<option value="${escH(x.familiya+' '+x.ism)}">${escH(x.familiya+' '+x.ism)} (${escH(x.sektor||'')})</option>`).join('');
}

function renderMuhimTopshiriqlar() {
  const el = document.getElementById('muhim-list');
  if(!el) return;
  const filterStatus = document.getElementById('mt-filter-status')?.value || '';
  let list = [...muhimCache];
  if(filterStatus) list = list.filter(m=>m.status===filterStatus);

  // Auto-update kechikdi status
  const today = new Date(); today.setHours(0,0,0,0);
  list = list.map(m => {
    if(m.status !== 'Bajarildi' && m.muddat) {
      const parts = m.muddat.split('-'); // date input gives YYYY-MM-DD
      const d = new Date(m.muddat);
      if(d < today) return {...m, status:'Kechikdi'};
    }
    return m;
  });

  // Sort
  const darajaOrder = {yuqori:0,"o'rta":1,past:2};
  list.sort((a,b) => {
    let va='', vb='';
    if(muhimSortKey==='muddat') { va=a.muddat||''; vb=b.muddat||''; }
    else if(muhimSortKey==='daraja') { va=darajaOrder[a.daraja]??1; vb=darajaOrder[b.daraja]??1; return muhimSortDir==='asc'?va-vb:vb-va; }
    else if(muhimSortKey==='status') { va=a.status||''; vb=b.status||''; }
    else if(muhimSortKey==='ijrochi') { va=a.ijrochi||''; vb=b.ijrochi||''; }
    else if(muhimSortKey==='manba') { va=a.manba||''; vb=b.manba||''; }
    return muhimSortDir==='asc' ? va.localeCompare(vb) : vb.localeCompare(va);
  });

  if(!list.length) {
    el.innerHTML='<div class="empty-state"><div class="empty-icon">🚨</div><h3>Muhim topshiriqlar yo\'q</h3></div>';
    return;
  }

  const darajaColors = {yuqori:'#dc2626',  "o'rta":'#d97706', past:'#16a34a'};
  const darajaLabels = {yuqori:'🔴 Yuqori', "o'rta":'🟡 O\'rta', past:'🟢 Past'};
  const statusColors = {Yangi:'#2563a8', Jarayonda:'#d97706', Bajarildi:'#16a34a', Kechikdi:'#dc2626'};

  el.innerHTML = list.map(m => {
    const daraja = m.daraja||"o'rta";
    const status = m.status||'Yangi';
    const muddatStr = m.muddat ? new Date(m.muddat).toLocaleDateString('uz-UZ') : '—';
    return `<div class="fishka-card" style="border-left:4px solid ${darajaColors[daraja]||'#2563a8'};">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
            <span style="font-weight:800;font-size:14px;">${escH(m.nom||'Topshiriq')}</span>
            <span style="font-size:11px;padding:2px 8px;border-radius:10px;background:${darajaColors[daraja]}20;color:${darajaColors[daraja]};font-weight:700;">${darajaLabels[daraja]}</span>
            <span style="font-size:11px;padding:2px 8px;border-radius:10px;background:${statusColors[status]}18;color:${statusColors[status]};font-weight:700;">${status}</span>
          </div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px;line-height:1.6;">${escH(m.mazmun||'')}</div>
          <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--text2);">
            <span>👤 ${escH(m.ijrochi||'—')}</span>
            <span>📅 Muddat: <b style="color:${status==='Kechikdi'?'#dc2626':'inherit'}">${muddatStr}</b></span>
            <span>🏛️ ${escH(m.manba||'—')}</span>
            ${m.hujjat_raqam?`<span>📋 ${escH(m.hujjat_raqam)}</span>`:''}
          </div>
        </div>
        <div style="display:flex;flex-direction:column;gap:6px;flex-shrink:0;">
          <select onchange="updateMuhimStatus('${m.id}',this.value)" style="padding:5px 8px;border:1px solid var(--border2);border-radius:7px;font-size:12px;outline:none;">
            <option ${status==='Yangi'?'selected':''}>Yangi</option>
            <option ${status==='Jarayonda'?'selected':''}>Jarayonda</option>
            <option ${status==='Bajarildi'?'selected':''}>Bajarildi</option>
            <option ${status==='Kechikdi'?'selected':''}>Kechikdi</option>
          </select>
          <button class="btn btn-sm btn-danger" onclick="deleteMuhimTopshiriq('${m.id}')">🗑️</button>
        </div>
      </div>
    </div>`;
  }).join('');
}
window.renderMuhimTopshiriqlar = renderMuhimTopshiriqlar;

window.saveMuhimTopshiriq = async () => {
  const nom = document.getElementById('mt-nom')?.value.trim();
  const ijrochi = document.getElementById('mt-ijrochi')?.value;
  const daraja = document.getElementById('mt-daraja')?.value||"o'rta";
  const muddat = document.getElementById('mt-muddat')?.value;
  const mazmun = document.getElementById('mt-mazmun')?.value.trim();
  const manba = document.getElementById('mt-manba')?.value.trim();
  const hujjat_raqam = document.getElementById('mt-hujjat-raqam')?.value.trim();
  if(!nom) { showToast('Topshiriq nomi kiritilmagan','error'); return; }
  if(!muddat) { showToast('Muddat kiritilmagan','error'); return; }
  showLoading('Saqlanmoqda...');
  try {
    await addDoc(collection(db,'muhim_topshiriqlar'),{
      nom, ijrochi:ijrochi||'', daraja, muddat, mazmun:mazmun||'',
      manba:manba||'', hujjat_raqam:hujjat_raqam||'',
      status:'Yangi', createdBy:currentUser?.uid||'',
      createdByName:currentUserData?.fullName||'',
      createdAt:serverTimestamp(), updatedAt:serverTimestamp()
    });
    hideLoading();
    showToast('✅ Muhim topshiriq qo\'shildi','success');
    clearMuhimForm();
    await loadMuhimTopshiriqlar();
  } catch(e) { hideLoading(); showToast('Xatolik: '+e.message,'error'); }
};

window.clearMuhimForm = () => {
  ['mt-nom','mt-muddat','mt-mazmun','mt-manba','mt-hujjat-raqam'].forEach(id=>{
    const e=document.getElementById(id); if(e)e.value='';
  });
  const sel=document.getElementById('mt-ijrochi'); if(sel)sel.value='';
  const dar=document.getElementById('mt-daraja'); if(dar)dar.value="o'rta";
};

window.updateMuhimStatus = async (id, status) => {
  try {
    await updateDoc(doc(db,'muhim_topshiriqlar',id),{status,updatedAt:serverTimestamp()});
    const idx = muhimCache.findIndex(m=>m.id===id);
    if(idx>=0) muhimCache[idx].status=status;
    updateMuhimBadge();
    showToast('✅ Holat yangilandi','success');
  } catch(e) { showToast('Xatolik: '+e.message,'error'); }
};

window.deleteMuhimTopshiriq = async (id) => {
  if(!confirm('Bu topshiriqni o\'chirmoqchimisiz?')) return;
  try {
    await deleteDoc(doc(db,'muhim_topshiriqlar',id));
    muhimCache = muhimCache.filter(m=>m.id!==id);
    updateMuhimBadge();
    renderMuhimTopshiriqlar();
    showToast('O\'chirildi','info');
  } catch(e) { showToast('Xatolik: '+e.message,'error'); }
};

window.sortMuhim = (key) => {
  if(muhimSortKey===key) muhimSortDir = muhimSortDir==='asc'?'desc':'asc';
  else { muhimSortKey=key; muhimSortDir='asc'; }
  // Update button styles
  ['muddat','daraja','status','ijrochi','manba'].forEach(k=>{
    const btn=document.getElementById('mt-sort-'+k);
    if(btn) btn.className='btn btn-sm '+(k===key?'btn-primary':'btn-outline');
  });
  renderMuhimTopshiriqlar();
};

window.setMuhimDir = (dir) => {
  muhimSortDir = dir;
  document.getElementById('mt-dir-asc')?.classList.toggle('active', dir==='asc');
  document.getElementById('mt-dir-desc')?.classList.toggle('active', dir==='desc');
  renderMuhimTopshiriqlar();
};

window.exportMuhimExcel = () => {
  if(!muhimCache.length) { showToast('Ma\'lumot yo\'q','error'); return; }
  const rows=[['#','Topshiriq','Ijrochi','Muhimlik','Holat','Muddat','Manba','Hujjat raqami','Mazmun']];
  muhimCache.forEach((m,i)=>rows.push([i+1,m.nom||'',m.ijrochi||'',m.daraja||'',m.status||'',m.muddat||'',m.manba||'',m.hujjat_raqam||'',m.mazmun||'']));
  const wb=XLSX.utils.book_new();
  const ws=XLSX.utils.aoa_to_sheet(rows);
  ws['!cols']=[{wch:4},{wch:30},{wch:20},{wch:10},{wch:12},{wch:12},{wch:24},{wch:14},{wch:40}];
  XLSX.utils.book_append_sheet(wb,ws,'Muhim Topshiriqlar');
  XLSX.writeFile(wb,`Muhim_Topshiriqlar_${new Date().toISOString().slice(0,10)}.xlsx`);
};

// ╔══════════════════════════════════════════════════════════════════╗
// ║   TASHKILOTLAR MODULE                                            ║
// ╚══════════════════════════════════════════════════════════════════╝
let tashkilotlarCache = [];

async function loadTashkilotlar() {
  let dbRows = [];
  if(currentUser && !docsLoadedOnce) {
    try {
      allDocs = await fetchAvailableDocs();
      docsLoadedOnce = true;
      filteredDocs = [...allDocs];
      updateBadges();
    } catch(e) {
      console.warn('Tashkilotlar uchun hujjatlar yuklanmadi:', e);
    }
  }
  try {
    const snap = await getDocs(query(collection(db,'tashkilotlar'), orderBy('nom')));
    dbRows = snap.docs.map(d=>({id:d.id,...d.data()}));
    upsertLocalTashkilotlar(dbRows.map(t=>({...t, local_only:false})));
  } catch(e) {
    console.warn('Tashkilotlar Firestore dan yuklanmadi:', e);
    if(!readLocalTashkilotlar().length && !buildTashkilotStatsFromDocs(allDocs).size) {
      showToast('Serverdagi tashkilotlar o\'qilmadi. Firestore rules ruxsatini tekshiring.', 'error');
    }
  }
  tashkilotlarCache = mergeTashkilotSources(dbRows, buildTashkilotStatsFromDocs(allDocs));
  persistTashkilotStatsFromDocs(allDocs, true);
  renderTashkilotlar();
  updateTashkilotlarBadge();
  populateAhbTashkilot();
}
window.loadTashkilotlar = loadTashkilotlar;

function renderTashkilotlar() {
  const tbody = document.getElementById('tashkilotlar-tbody');
  const cnt = document.getElementById('tashkilotlar-count');
  const search = (document.getElementById('tashkilotlar-search')?.value||'').toLowerCase();
  if(!tbody) return;
  let list = tashkilotlarCache;
  if(search) list = list.filter(t=>(t.nom||'').toLowerCase().includes(search));
  if(cnt) cnt.textContent = list.length;
  if(!list.length) {
    tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--muted);">Tashkilotlar yo\'q</td></tr>';
    return;
  }
  tbody.innerHTML = list.map((t,i)=>`
    <tr>
      <td class="td-num">${i+1}</td>
      <td><b>${escH(t.nom||'')}</b>
        ${t.auto_added?'<span style="font-size:10px;margin-left:6px;background:#dbeafe;color:#1d4ed8;padding:2px 6px;border-radius:4px;">auto</span>':''}
        ${t.from_docs?'<span style="font-size:10px;margin-left:4px;background:#dcfce7;color:#166534;padding:2px 6px;border-radius:4px;">hujjatdan</span>':''}
        ${t.local_only?'<span style="font-size:10px;margin-left:4px;background:#fef3c7;color:#92400e;padding:2px 6px;border-radius:4px;">lokal</span>':''}
      </td>
      <td>${escH(t.manzil||'—')}</td>
      <td style="font-weight:700;color:var(--blue-mid);">${t.hujjatlar_soni||0}</td>
      <td>${escH(t.oxirgi_xat||'—')}</td>
      <td style="font-size:11px;color:var(--muted);">${t.createdAt?.toDate ? t.createdAt.toDate().toLocaleDateString('uz-UZ') : '—'}</td>
      <td><button class="btn btn-sm btn-danger" title="O'chirish" onclick="deleteTashkilotByRowId('${encodeURIComponent(getTashkilotRowId(t))}')">X</button></td>
    </tr>`).join('');
}
window.renderTashkilotlar = renderTashkilotlar;

window.rebuildTashkilotlarFromDocs = async () => {
  if(!allDocs.length && currentUser) {
    try {
      showLoading('Hujjatlardan tashkilotlar olinmoqda...');
      allDocs = await fetchAvailableDocs();
      docsLoadedOnce = true;
      filteredDocs = [...allDocs];
      updateBadges();
      hideLoading();
    } catch(e) {
      hideLoading();
      showToast('Hujjatlar serverdan o\'qilmadi: '+e.message, 'error');
      return;
    }
  }
  if(!allDocs.length) {
    showToast('Avval hujjatlarni yuklang yoki Excel import qiling', 'error');
    return;
  }
  tashkilotlarCache = mergeTashkilotSources(tashkilotlarCache, buildTashkilotStatsFromDocs(allDocs));
  renderTashkilotlar();
  updateTashkilotlarBadge();
  await persistTashkilotStatsFromDocs(allDocs, false);
  await loadTashkilotlar();
};

window.addTashkilotManual = async () => {
  const nom = document.getElementById('tash-nom')?.value.trim();
  const manzil = document.getElementById('tash-manzil')?.value.trim();
  if(!nom) { showToast('Tashkilot nomi kiritilmagan','error'); return; }
  unignoreTashkilotName(nom);
  const exists = tashkilotlarCache.find(t=>orgKey(t.nom)===orgKey(nom));
  if(exists) { showToast('Bu tashkilot allaqachon mavjud','error'); return; }
  const localItem = {
    id:'',
    local_id: 'loc_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7),
    nom: normalizeOrgName(nom),
    manzil: manzil||'',
    hujjatlar_soni: 0,
    oxirgi_xat: '',
    auto_added: false,
    from_docs: false
  };
  localItem.row_id = localItem.local_id;
  upsertLocalTashkilotlar([localItem]);
  tashkilotlarCache = mergeTashkilotSources([...tashkilotlarCache, localItem], buildTashkilotStatsFromDocs(allDocs));
  renderTashkilotlar();
  updateTashkilotlarBadge();
  try {
    await addDoc(collection(db,'tashkilotlar'),{nom,manzil:manzil||'',hujjatlar_soni:0,oxirgi_xat:'',auto_added:false,createdAt:serverTimestamp(),updatedAt:serverTimestamp()});
    showToast('✅ Tashkilot qo\'shildi','success');
    document.getElementById('tash-nom').value='';
    document.getElementById('tash-manzil').value='';
    await loadTashkilotlar();
  } catch(e) {
    showToast('Serverga yozilmadi, lekin ro\'yxatda ko\'rsatildi. Firestore rules ruxsatini tekshiring.', 'info');
  }
};

window.deleteTashkilotByKey = async (encodedKey, id='') => {
  const key = decodeURIComponent(encodedKey || '');
  const item = tashkilotlarCache.find(t => orgKey(t.nom) === key || t.id === id);
  if(!item) { showToast('Tashkilot topilmadi', 'error'); return; }
  if(!confirm('Bu tashkilotni o\'chirmoqchimisiz?')) return;
  ignoreTashkilotName(item.nom);
  tashkilotlarCache = tashkilotlarCache.filter(t => orgKey(t.nom) !== key && t.id !== id);
  writeLocalTashkilotlar(readLocalTashkilotlar().filter(t => orgKey(t.nom) !== key && t.id !== id));
  renderTashkilotlar();
  updateTashkilotlarBadge();
  populateAhbTashkilot();

  if(!id) {
    showToast('Tashkilot ro\'yxatdan o\'chirildi', 'info');
    return;
  }

  try {
    await deleteDoc(doc(db,'tashkilotlar',id));
    showToast('O\'chirildi','info');
  } catch(e) {
    showToast('Serverdan o\'chirilmadi, lekin lokal ro\'yxatdan olib tashlandi: '+e.message,'info');
  }
};

window.deleteTashkilotByRowId = async (encodedRowId) => {
  const rowId = decodeURIComponent(encodedRowId || '');
  const item = tashkilotlarCache.find(t => getTashkilotRowId(t) === rowId);
  if(!item) { showToast('Tashkilot topilmadi', 'error'); return; }
  if(!confirm('Bu tashkilotni o\'chirmoqchimisiz?')) return;

  ignoreTashkilotName(item.nom);
  tashkilotlarCache = tashkilotlarCache.filter(t => getTashkilotRowId(t) !== rowId);
  writeLocalTashkilotlar(readLocalTashkilotlar().filter(t => getTashkilotRowId(t) !== rowId));
  renderTashkilotlar();
  updateTashkilotlarBadge();
  populateAhbTashkilot();

  if(!item.id) {
    showToast('Tashkilot ro\'yxatdan o\'chirildi', 'info');
    return;
  }

  try {
    await deleteDoc(doc(db,'tashkilotlar',item.id));
    showToast('O\'chirildi','info');
  } catch(e) {
    showToast('Serverdan o\'chirilmadi, lekin lokal ro\'yxatdan olib tashlandi: '+e.message,'info');
  }
};

window.deleteTashkilot = async (id) => {
  const item = tashkilotlarCache.find(t=>t.id===id);
  if(!item) { showToast('Tashkilot topilmadi', 'error'); return; }
  return window.deleteTashkilotByRowId(encodeURIComponent(getTashkilotRowId(item)));
};

window.exportTashkilotlarExcel = () => {
  if(!tashkilotlarCache.length){showToast('Ma\'lumot yo\'q','error');return;}
  const rows=[['#','Tashkilot nomi','Manzil','Hujjatlar soni','Oxirgi xat']];
  tashkilotlarCache.forEach((t,i)=>rows.push([i+1,t.nom||'',t.manzil||'',t.hujjatlar_soni||0,t.oxirgi_xat||'']));
  const wb=XLSX.utils.book_new();
  const ws=XLSX.utils.aoa_to_sheet(rows);
  ws['!cols']=[{wch:4},{wch:36},{wch:24},{wch:14},{wch:14}];
  XLSX.utils.book_append_sheet(wb,ws,'Tashkilotlar');
  XLSX.writeFile(wb,'Tashkilotlar_'+new Date().toISOString().slice(0,10)+'.xlsx');
};

// ╔══════════════════════════════════════════════════════════════════╗
// ║   AI HISOBOT ADMIN MODULE                                        ║
// ╚══════════════════════════════════════════════════════════════════╝
let ahbCache = [];
let ahbLastReport = null;
const DEFAULT_OUR_ORG_NAME = "Navoiy viloyati Qurilish va uy-joy kommunal xo'jaligi bosh boshqarmasi";

const AHB_EXPORT_COLS = [
  { key:'docName', label:'Hujjat nomi', aliases:['hujjat','nomi','hujjat nomi'] },
  { key:'docNum', label:'Hujjat raqami', aliases:['raqam','hujjat raqami'] },
  { key:'docDate', label:'Hujjat sanasi', aliases:['sana','hujjat sanasi'] },
  { key:'fromOrg', label:'Kimdan', aliases:['kimdan','tashkilot','manba'] },
  { key:'status', label:'Holat', aliases:['holat','status','ijro holati'] },
  { key:'deadline', label:'Muddat', aliases:['muddat','ijro muddati'] },
  { key:'executor', label:'Ijrochi', aliases:['ijrochi','xodim','bajaruvchi'] },
  { key:'resolution', label:'Rezalyutsiya', aliases:['rezalyutsiya','resolution','kimga'] },
  { key:'taskText', label:'Topshiriq', aliases:['topshiriq','vazifa','mazmun'] }
];

const AHB_OFFICIAL_COLS = [
  { key:'docName', label:'Hujjatning nomi', red:true },
  { key:'docReg', label:'Hujjat tartib raqami va qabul qilingan sana' },
  { key:'higherDecision', label:"Yuqori tashkilot rahbari (Vazir, rais)ning qarori (Buyruq, farmoyish va h.k) raqami, qabul qilingan sana" },
  { key:'inReg', label:"Hujjatni tashkilot devonxonasiga kirish sanasi, qayd etish raqami" },
  { key:'leaderResolutionDate', label:"Rahbar rezolyutsiyasi qo'yilgan sana", red:true },
  { key:'resolution', label:"Rezolyutsiya mazmuni (to'liq yozilsin)", red:true },
  { key:'acceptedDecision', label:"Qabul qilingan qaror (buyruq, farmoyish) tadbirlar №, sanasi" },
  { key:'acceptedDecisionExec', label:"Qabul qilingan qaror (buyruq, farmoyish) mazmuni, tegishli tashkilot hamda tashkilot dasturi va b.) tashkilot sana", red:true },
  { key:'ownDecision', label:"O'z qarorlari ijro yuzasidan tarqatma reyestri bo'yicha nazorat reestr №, sana", red:true },
  { key:'executionStatus', label:"Ijro holati, topshiriqlarning ijrosi qayday amalga oshirilgan, maqsadli ko'rsatkichlarga bajarilishi (Ijro holati qisqa, aniq va xronologik tartibda berilsin)", red:true },
  { key:'discussionStatus', label:"Ijro holati qachon, qayerda muhokama etildi, kimga nisbatan qanday intizomiy choralar ko'rildi" }
];

function getAhbExportCols(fieldsText='') {
  const requested = String(fieldsText||'').toLowerCase();
  if(!requested.trim()) return AHB_EXPORT_COLS;
  const cols = AHB_EXPORT_COLS.filter(c => c.aliases.some(a => requested.includes(a)));
  return cols.length ? cols : AHB_EXPORT_COLS;
}

function getAhbDocValue(doc, key) {
  if(key === 'fromOrg') return getOrgText(doc);
  if(key === 'status') return getStatusText(doc);
  return doc[key] || '';
}

function canonicalOrgName(name) {
  return normalizeText(name)
    .replace(/\b(mchj|ooo|llc|dukk|duk|uk|xtb|xalq ta'limi|bo'limi|boshqarmasi)\b/g, '')
    .replace(/[.,()"'`]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function parseAhbTashkilotlar(value='') {
  if(Array.isArray(value)) return value.map(normalizeOrgName).filter(Boolean);
  return String(value||'').split('||').map(normalizeOrgName).filter(Boolean);
}

function getSelectedAhbTashkilotlar() {
  const checks = Array.from(document.querySelectorAll('.ahb-org-check:checked'));
  if(document.getElementById('ahb-org-all')?.checked || !checks.length) return [];
  return checks.map(ch => ch.value).filter(Boolean);
}

function ahbOrgMatches(doc, selected=[]) {
  if(!selected.length) return true;
  const docOrg = canonicalOrgName(getOrgText(doc));
  if(!docOrg) return false;
  return selected.some(org => canonicalOrgName(org) === docOrg);
}

function getOurOrgName() {
  const org = normalizeOrgName(currentUserData?.org || '');
  if(org && !/maktabgacha|maktab ta'?lim/i.test(org)) return org;
  return DEFAULT_OUR_ORG_NAME;
}

function getAhbSelectedOrgTitle(selectedOrgs=[], docs=[]) {
  const clean = (selectedOrgs||[]).map(normalizeOrgName).filter(Boolean);
  if(clean.length === 1) return clean[0];
  if(clean.length > 1) return clean.join(', ');
  const uniqueFromDocs = [...new Map((docs||[])
    .map(d=>normalizeOrgName(getOrgText(d)))
    .filter(Boolean)
    .map(n=>[canonicalOrgName(n), n])
  ).values()];
  if(uniqueFromDocs.length === 1) return uniqueFromDocs[0];
  return '';
}

function getAhbOrgGroupTitle(doc={}, selectedOrgs=[]) {
  const docCanon = canonicalOrgName(getOrgText(doc));
  const matched = (selectedOrgs||[]).find(org => canonicalOrgName(org) === docCanon);
  return normalizeOrgName(matched || getOrgText(doc) || ahbGroupTitle(doc));
}

function getRawField(doc={}, aliases=[]) {
  const raw = doc._raw || {};
  const direct = aliases.find(a => doc[a] !== undefined && doc[a] !== '');
  if(direct) return doc[direct];
  for(const [k,v] of Object.entries(raw)) {
    const nk = normalizeText(k);
    if(aliases.some(a => nk.includes(normalizeText(a)))) return v;
  }
  return '';
}

function joinLines(...parts) {
  return parts
    .map(v => String(v||'').trim())
    .filter(Boolean)
    .join('\n');
}

function ahbOfficialValue(doc={}, key) {
  const docNum = doc.docNum || getRawField(doc, ['hujjat raqami','raqam','№','номер']);
  const docDate = doc.docDate || getRawField(doc, ['hujjat sanasi','sana','date','дата']);
  const orgOutNum = doc.orgOutNum || getRawField(doc, ['tashkilot chiqish','chiqish raqami','исходящий']);
  const ourOutNum = doc.ourOutNum || getRawField(doc, ['bizdan chiqish','kirish raqami','qayd raqami','qayd etish','наш номер','регистрац']);
  const deadline = doc.deadline || getRawField(doc, ['muddat','ijro muddati','срок']);
  const status = getStatusText(doc);
  const org = getOrgText(doc);
  const executor = doc.executor || getRawField(doc, ['ijrochi','bajaruvchi','исполнитель']);
  const task = doc.taskText || getRawField(doc, ['topshiriq','vazifa','mazmun','содержание']);
  const resolution = doc.resolution || getRawField(doc, ['rezolyutsiya','rezalyutsiya','resolution','kimga','кому']);

  const values = {
    docName: doc.docName || getRawField(doc, ['hujjat nomi','nomi','наименование']) || '—',
    docReg: joinLines(docNum, docDate) || '—',
    higherDecision: joinLines(getRawField(doc, ['yuqori tashkilot','rahbar qarori','buyruq','farmoyish','qaror']), docNum, docDate) || joinLines(docNum, docDate) || '—',
    inReg: joinLines(ourOutNum || orgOutNum, getRawField(doc, ['kirish sanasi','qabul sanasi']) || docDate) || '—',
    leaderResolutionDate: getRawField(doc, ['rezolyutsiya sanasi','rahbar rezolyutsiyasi','resolution date']) || docDate || '—',
    resolution: resolution || '—',
    acceptedDecision: joinLines(getRawField(doc, ['qabul qilingan qaror','qabul qilingan buyruq','tadbirlar']), orgOutNum, docDate) || '—',
    acceptedDecisionExec: joinLines(org, executor, deadline) || '—',
    ownDecision: joinLines(getRawField(doc, ['reyestr','reestr','tarqatma','nazorat reestr']), deadline || docDate) || '—',
    executionStatus: joinLines(status, task, executor ? `Ijrochi: ${executor}` : '') || '—',
    discussionStatus: getRawField(doc, ['muhokama','choralar','intizomiy','kimga nisbatan']) || 'Hisobotda mavjud maʼlumotlar asosida alohida muhokama/choralar qaydi topilmadi.'
  };
  return values[key] || '';
}

function ahbGroupTitle(doc={}) {
  const txt = normalizeText(`${doc.source||''} ${doc.docType||''} ${doc.docName||''} ${doc.docNum||''} ${getRawField(doc, ['hujjat turi','tur','type','hujjat raqami','raqam','qaror','farmon','farmoyish'])}`);
  if(txt.includes('qonun') || txt.includes('қонун')) return 'O‘zbekiston Respublikasi Qonunlari';
  if(txt.includes('farmon') || txt.includes('pf-') || txt.includes('пф-')) return 'O‘zbekiston Respublikasi Prezidentining Farmoni';
  if(txt.includes('qaror') || txt.includes('pq-') || txt.includes('пқ-') || txt.includes('пк-')) return 'O‘zbekiston Respublikasi Prezidentining Qarorlari';
  if(txt.includes('vazirlar') || txt.includes('vm') || txt.includes('hukumat')) return 'O‘zbekiston Respublikasi Vazirlar Mahkamasi hujjatlari';
  return 'Boshqa hujjatlar';
}

function buildAhbOfficialRows(docs=[], options={}) {
  const groups = new Map();
  const selectedOrgs = parseAhbTashkilotlar(options.selectedOrgs || []);
  const forcedGroupTitle = !selectedOrgs.length ? normalizeOrgName(options.groupTitle || '') : '';
  docs.forEach(doc => {
    const title = selectedOrgs.length ? getAhbOrgGroupTitle(doc, selectedOrgs) : (forcedGroupTitle || ahbGroupTitle(doc));
    if(!groups.has(title)) groups.set(title, []);
    groups.get(title).push(doc);
  });
  return [...groups.entries()].map(([title, groupDocs]) => ({
    title,
    rows: groupDocs.map((doc, i) => ({
      n: i + 1,
      values: AHB_OFFICIAL_COLS.map(col => ahbOfficialValue(doc, col.key))
    }))
  }));
}

function ahbOfficialStyles() {
  return `
    <style>
      @page { size: landscape; margin: 0.7cm; }
      .official-report{background:#1f1f1f;color:#fff;border-collapse:collapse;width:100%;font-family:"Times New Roman",serif;font-size:9px;table-layout:fixed;}
      .official-report th,.official-report td{border:1px solid #e5e7eb;padding:5px 4px;vertical-align:middle;text-align:center;white-space:pre-line;line-height:1.25;word-break:break-word;}
      .official-report th{font-weight:700;background:#242424;color:#fff;}
      .official-report .red{color:#ff4b4b;font-weight:700;}
      .official-report .group-row td{background:#2b2b2b;color:#fff;font-weight:700;text-align:center;font-size:11px;}
      .official-report .num{width:28px;}
      .official-report .doc-name{width:160px;}
      .official-report-wrap{overflow:auto;border:1px solid var(--border2);border-radius:8px;background:#1f1f1f;max-height:520px;}
      .official-note{font-size:12px;color:var(--muted);margin:8px 0 12px;}
    </style>`;
}

function buildAhbOfficialTableHtml(docs=[], options={}) {
  const groups = buildAhbOfficialRows(docs, options);
  const includeStyles = options.includeStyles !== false;
  const title = escH(options.title || 'AI Hisobot');
  const header = `
    <thead>
      <tr>
        <th class="num">T/r</th>
        ${AHB_OFFICIAL_COLS.map((col, i)=>`<th class="${col.red?'red':''} ${i===0?'doc-name':''}">${escH(col.label)}</th>`).join('')}
      </tr>
    </thead>`;
  const body = groups.map(group => `
    <tr class="group-row"><td colspan="${AHB_OFFICIAL_COLS.length + 1}">${escH(group.title)}</td></tr>
    ${group.rows.map(row => `
      <tr>
        <td class="num">${row.n}</td>
        ${row.values.map((v, i)=>`<td class="${AHB_OFFICIAL_COLS[i].red?'red':''}">${escH(v)}</td>`).join('')}
      </tr>`).join('')}
  `).join('');

  return `
    ${includeStyles ? ahbOfficialStyles() : ''}
    ${options.showTitle ? `<h2 style="font-family:'Times New Roman',serif;text-align:center;">${title}</h2>` : ''}
    <table class="official-report">
      ${header}
      <tbody>${body || `<tr><td colspan="${AHB_OFFICIAL_COLS.length + 1}">Ma'lumot topilmadi</td></tr>`}</tbody>
    </table>`;
}

function classifyAhbSummaryType(doc={}) {
  const txt = normalizeText(`${doc.source||''} ${doc.docType||''} ${doc.docName||''} ${doc.docNum||''} ${getRawField(doc, ['hujjat turi','tur','type','hujjat raqami','raqam','qaror','farmon','farmoyish','qonun'])}`);
  if(txt.includes('qonun') || txt.includes('қонун')) return 'law';
  if(txt.includes('vazirlar') || txt.includes('vm') || txt.includes('hukumat') || txt.includes('кабинет')) return 'vm';
  if(txt.includes('farmoyish')) return 'presidentOrder';
  if(txt.includes('farmon') || txt.includes('pf-') || txt.includes('пф-')) return 'presidentDecree';
  if(txt.includes('qaror') || txt.includes('pq-') || txt.includes('пқ-') || txt.includes('пк-')) return 'presidentDecision';
  if(doc.source === 'PF') return 'presidentDecree';
  if(doc.source === 'VM') return 'vm';
  return 'other';
}

function countAhbSummary(docs=[]) {
  const counts = { total: docs.length, law:0, presidentDecree:0, presidentDecision:0, presidentOrder:0, vm:0 };
  docs.forEach(doc => {
    const key = classifyAhbSummaryType(doc);
    if(counts[key] !== undefined) counts[key] += 1;
  });
  return counts;
}

function filterDocsByKeywords(docs=[], words=[]) {
  return docs.filter(doc => {
    const txt = normalizeText(`${doc.docName||''} ${doc.docType||''} ${doc.taskText||''} ${doc.resolution||''} ${getRawField(doc, ['mazmun','topshiriq','tavsif'])}`);
    return words.some(w => txt.includes(normalizeText(w)));
  });
}

function ahbSummaryDiscussionText(docs=[]) {
  const nums = docs.map(d => d.docNum || getRawField(d, ['raqam','номер'])).filter(Boolean).slice(0, 14);
  const base = docs.length
    ? `${docs.length} ta hujjat bo'yicha topshiriqlar ijrosi nazoratga olindi`
    : 'Hisobot davrida muhokama uchun hujjatlar topilmadi';
  return nums.length
    ? `${base}. Asos: ${nums.join(', ')} raqamli hujjatlar.`
    : `${base}.`;
}

function ahbSummaryRow(label, docs=[], roman='', options={}) {
  const c = countAhbSummary(docs);
  return {
    roman,
    label,
    counts: c,
    discussion: options.discussion || '',
    isSub: !!options.isSub
  };
}

function buildAhbSummaryRows(docs=[], options={}) {
  const ourOrg = options.ourOrg || getOurOrgName();
  return [
    ahbSummaryRow(`${ourOrg}da kirim qilingan hujjatlar`, docs, 'I'),
    ahbSummaryRow("Kirim qilingan hujjatlar bo'yicha ishlab chiqilgan", docs, 'II', { isSub:true }),
    ahbSummaryRow("Umumiy yig'ilish qarori", filterDocsByKeywords(docs, ["umumiy yig", "yig'ilish", "yig‘ilish"]), '', { isSub:true }),
    ahbSummaryRow("Rahbarning buyruqlari", filterDocsByKeywords(docs, ['buyruq', 'буйруқ', 'приказ']), '', { isSub:true }),
    ahbSummaryRow("Farmoyishlar", filterDocsByKeywords(docs, ['farmoyish', 'фармойиш', 'распоряж']), '', { isSub:true }),
    ahbSummaryRow("Tadbirlar", filterDocsByKeywords(docs, ['tadbir', 'чора-тадбир', 'мероприят']), '', { isSub:true }),
    ahbSummaryRow("Tegishli hujjatlar ijrosi bo'yicha maqsadli va kompleks o'rganishlar", filterDocsByKeywords(docs, ["o'rganish", "o‘rganish", 'monitoring', 'kompleks', 'maqsadli']), 'III'),
    { roman:'', label:'Shu jumladan:', counts:{total:'',law:'',presidentDecree:'',presidentDecision:'',presidentOrder:'',vm:''}, isSub:true },
    { roman:'IV', label:"Topshiriq ijrosi holati qachon, qayerda muhokama etildi, kimga nisbatan qanday intizomiy choralar ko'rildi.", discussion: ahbSummaryDiscussionText(docs), counts:null }
  ];
}

function buildAhbSummaryTableHtml(docs=[], options={}) {
  const ourOrg = options.ourOrg || getOurOrgName();
  const rows = buildAhbSummaryRows(docs, { ourOrg });
  const title = options.title || `${ourOrg}ga O'zbekiston Respublikasi Qonunlari, Prezident farmonlari, qarorlari, farmoyishlari va Vazirlar Mahkamasi qarorlari va farmoyishlarining ijrosi haqida`;
  const includeStyles = options.includeStyles !== false;
  return `
    ${includeStyles ? ahbOfficialStyles() : ''}
    <style>
      .summary-report-title{font-family:"Times New Roman",serif;text-align:center;color:#00a9ff;font-weight:700;font-size:20px;line-height:1.18;margin:6px 0 12px;}
      .summary-report-title span{display:block;letter-spacing:6px;}
      .summary-table{background:#242424;color:#fff;border-collapse:collapse;width:100%;font-family:"Times New Roman",serif;font-size:12px;table-layout:fixed;}
      .summary-table th,.summary-table td{border:1px solid #e5e7eb;padding:4px 6px;vertical-align:middle;white-space:pre-line;line-height:1.25;}
      .summary-table th{text-align:center;font-weight:700;}
      .summary-table .num{width:38px;text-align:center;font-weight:700;}
      .summary-table .label{text-align:left;font-weight:600;}
      .summary-table .count{text-align:center;font-weight:700;}
      .summary-table .red{color:#ff4b4b;}
      .summary-table .vertical{writing-mode:vertical-rl;transform:rotate(180deg);height:130px;white-space:normal;text-align:center;margin:auto;}
      .summary-table .section{font-size:16px;text-align:center;font-weight:700;}
      .summary-table .discussion{text-align:left;font-size:11px;}
    </style>
    <div class="summary-report-title">${escH(title)}<span>HISOBOT</span></div>
    <div style="text-align:right;color:#00a9ff;font-family:'Times New Roman',serif;margin:0 30px 14px 0;">2-jadval</div>
    <table class="summary-table">
      <thead>
        <tr>
          <th rowspan="2" class="num">T/r</th>
          <th rowspan="2" style="width:38%;">Hisobot davrida qabul qilingan hujjatlar<br><br><span style="font-size:16px;">O'z qarorlarini,<br>tadbirlarini ishlab chiqish,<br>maqsadli o'rganishlar</span></th>
          <th rowspan="2" style="width:70px;">Jami soni</th>
          <th colspan="5" class="red">Shu jumladan</th>
        </tr>
        <tr>
          <th><div class="vertical">O'zbekiston Respublikasi qonunlari</div></th>
          <th><div class="vertical">Prezident farmonlari</div></th>
          <th><div class="vertical">Prezident qarorlari</div></th>
          <th><div class="vertical">Prezident farmoyishlari</div></th>
          <th><div class="vertical">Vazirlar Mahkamasi qarorlari, farmoyishlari</div></th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(row => row.counts ? `
          <tr>
            <td class="section">${escH(row.roman)}</td>
            <td class="label ${row.isSub?'red':''}">${escH(row.label)}</td>
            <td class="count">${row.counts.total || ''}</td>
            <td class="count">${row.counts.law || ''}</td>
            <td class="count">${row.counts.presidentDecree || ''}</td>
            <td class="count">${row.counts.presidentDecision || ''}</td>
            <td class="count">${row.counts.presidentOrder || ''}</td>
            <td class="count">${row.counts.vm || ''}</td>
          </tr>` : `
          <tr>
            <td class="section">${escH(row.roman)}</td>
            <td class="label red">${escH(row.label)}</td>
            <td colspan="6" class="discussion">${escH(row.discussion)}</td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

async function loadAiHisobotAdmin() {
  try {
    await loadTashkilotlar();
    const snap = await getDocs(query(collection(db,'ai_hisobot_buyruqlar'), orderBy('createdAt','desc')));
    ahbCache = snap.docs.map(d=>({id:d.id,...d.data()}));
    renderAhbList();
  } catch(e) { showToast('Yuklanmadi: '+e.message,'error'); }
}
window.loadAiHisobotAdmin = loadAiHisobotAdmin;

function populateAhbTashkilot() {
  const wrap = document.getElementById('ahb-tashkilot-list');
  if(!wrap) return;
  const orgs = [...new Map(tashkilotlarCache
    .filter(t=>isValidOrgName(t.nom))
    .map(t=>[canonicalOrgName(t.nom), t.nom])
  ).values()].sort((a,b)=>a.localeCompare(b,'uz'));
  wrap.innerHTML = `
    <label class="ahb-org-row" style="display:flex;align-items:center;gap:8px;padding:6px 8px;border-bottom:1px solid var(--border);font-size:12px;">
      <input type="checkbox" id="ahb-org-all" checked onchange="toggleAhbOrgAll(this.checked)">
      <span>— Barchasi —</span>
    </label>
    ${orgs.length ? orgs.map(n=>`
      <label class="ahb-org-row" style="display:flex;align-items:center;gap:8px;padding:6px 8px;border-bottom:1px solid var(--border);font-size:12px;">
        <input type="checkbox" class="ahb-org-check" value="${escH(n)}" onchange="syncAhbOrgAllState()">
        <span>${escH(n)}</span>
      </label>`).join('') : '<div style="font-size:12px;color:var(--muted);padding:8px;">Tashkilotlar topilmadi. Avval hujjat yuklang yoki Tashkilotlar bo‘limida tiklang.</div>'}
  `;
}

window.toggleAhbOrgAll = (checked) => {
  document.querySelectorAll('.ahb-org-check').forEach(ch => ch.checked = false);
};

window.syncAhbOrgAllState = () => {
  const any = Array.from(document.querySelectorAll('.ahb-org-check')).some(ch => ch.checked);
  const all = document.getElementById('ahb-org-all');
  if(all) all.checked = !any;
};

function renderAhbList() {
  const el = document.getElementById('ahb-list');
  if(!el) return;
  if(!ahbCache.length) {
    el.innerHTML='<div class="empty-state"><div class="empty-icon">🤖</div><h3>Buyruqlar yo\'q</h3></div>';
    return;
  }
  el.innerHTML = ahbCache.map(b=>`
    <div class="fishka-card">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
        <div style="flex:1;">
          <div style="font-weight:800;font-size:14px;margin-bottom:4px;">${escH(b.nom||'Buyruq')}</div>
          <div style="font-size:12px;color:var(--muted);line-height:1.6;">
            🏛️ ${escH(parseAhbTashkilotlar(b.tashkilot).join(', ')||'Barcha')} &nbsp;|&nbsp; 
            📊 ${escH(b.tur||'excel')} &nbsp;|&nbsp; 
            📅 ${escH(b.davr||'month')} &nbsp;|&nbsp;
            📋 ${escH(b.status||'Barchasi')}
          </div>
          ${b.korstma?`<div style="font-size:11px;color:#5b21b6;margin-top:4px;font-style:italic;">AI ko'rsatma: ${escH(b.korstma)}</div>`:''}
          ${b.fields?`<div style="font-size:11px;color:#0f766e;margin-top:4px;">So'ralgan ma'lumotlar: ${escH(b.fields)}</div>`:''}
        </div>
        <div style="display:flex;gap:6px;flex-shrink:0;">
          <button class="btn btn-sm btn-primary" onclick="runAhbBuyruq(${JSON.stringify(JSON.stringify(b))})">▶ Bajarish</button>
          <button class="btn btn-sm btn-danger" onclick="deleteAhbBuyruq('${b.id}')">✕</button>
        </div>
      </div>
    </div>`).join('');
}

window.saveAiHisobotBuyruq = async () => {
  const nom = document.getElementById('ahb-nom')?.value.trim();
  if(!nom){showToast('Buyruq nomi kiritilmagan','error');return;}
  const selectedOrgs = getSelectedAhbTashkilotlar();
  const data = {
    nom, tashkilot:selectedOrgs.join('||'),
    tur:document.getElementById('ahb-tur')?.value||'excel',
    davr:document.getElementById('ahb-davr')?.value||'month',
    status:document.getElementById('ahb-status')?.value||'',
    fields:document.getElementById('ahb-fields')?.value.trim()||'',
    korstma:document.getElementById('ahb-korstma')?.value.trim()||'',
    createdBy:currentUser?.uid||'', createdAt:serverTimestamp()
  };
  try {
    showLoading('Saqlanmoqda...');
    await addDoc(collection(db,'ai_hisobot_buyruqlar'),data);
    hideLoading();
    showToast('✅ Buyruq saqlandi','success');
    clearAiHisobotForm();
    await loadAiHisobotAdmin();
  } catch(e){hideLoading();showToast('Xatolik: '+e.message,'error');}
};

window.clearAiHisobotForm = () => {
  ['ahb-nom','ahb-fields','ahb-korstma'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});
  ['ahb-tur','ahb-davr','ahb-status'].forEach(id=>{const e=document.getElementById(id);if(e)e.value=e.options?.[0]?.value||'';});
  document.querySelectorAll('.ahb-org-check').forEach(ch=>ch.checked=false);
  const all=document.getElementById('ahb-org-all'); if(all) all.checked=true;
};

window.deleteAhbBuyruq = async (id) => {
  if(!confirm('Bu buyruqni o\'chirmoqchimisiz?')) return;
  await deleteDoc(doc(db,'ai_hisobot_buyruqlar',id));
  ahbCache=ahbCache.filter(b=>b.id!==id);
  renderAhbList();
  showToast('O\'chirildi','info');
};

window.executeAiHisobotBuyruq = () => {
  const nom = document.getElementById('ahb-nom')?.value.trim();
  const tashkilot = getSelectedAhbTashkilotlar().join('||');
  const tur = document.getElementById('ahb-tur')?.value||'excel';
  const davr = document.getElementById('ahb-davr')?.value||'month';
  const status = document.getElementById('ahb-status')?.value||'';
  const fields = document.getElementById('ahb-fields')?.value.trim()||'';
  const korstma = document.getElementById('ahb-korstma')?.value.trim()||'';
  const fake = {nom:nom||'Hisobot',tashkilot,tur,davr,status,fields,korstma};
  runAhbBuyruq(JSON.stringify(fake));
};

window.runAhbBuyruq = async (buyruqJson) => {
  const b = JSON.parse(buyruqJson);
  const resultEl = document.getElementById('ahb-result');
  if(resultEl) { resultEl.style.display='block'; resultEl.innerHTML='<div class="ai-loading">🤖 AI hisobot tayyorlanmoqda...</div>'; }

  try {
    if(currentUser && !docsLoadedOnce) {
      allDocs = await fetchAvailableDocs();
      docsLoadedOnce = true;
      filteredDocs = [...allDocs];
      updateBadges();
    }
    // Filter docs based on command
    let docs = [...allDocs];
    const selectedOrgs = parseAhbTashkilotlar(b.tashkilot);
    if(selectedOrgs.length) docs = docs.filter(d=>ahbOrgMatches(d, selectedOrgs));
    if(b.status) docs = docs.filter(d=>statusMatches(d, b.status));

    // Davr filter
    const now = new Date();
    if(b.davr !== 'all') {
      const from = new Date();
      if(b.davr==='month') from.setMonth(from.getMonth()-1);
      else if(b.davr==='quarter') from.setMonth(from.getMonth()-3);
      else if(b.davr==='year') from.setFullYear(from.getFullYear()-1);
      docs = docs.filter(d => {
        if(!d.docDate) return true;
        const parts = d.docDate.split('.');
        if(parts.length===3) { const dt=new Date(parts[2],parts[1]-1,parts[0]); return dt>=from; }
        return true;
      });
    }

    const total = docs.length;
    const statusCounts = getStatusCounts(docs);
    const done = statusCounts.done;
    const proc = statusCounts.proc;
    const fail = statusCounts.fail;
    const selectedOrgTitle = getAhbSelectedOrgTitle(selectedOrgs, docs);
    const ourOrgName = getOurOrgName();

    // Build AI prompt
    const geminiKey = localStorage.getItem('GEMINI_API_KEY');
    let aiAnaliz = '';
    if(geminiKey) {
      const prompt = `Sen O'zbekiston davlat muassasasi uchun hujjat hisoboti tayyorlayotgan AI yordamchisisiz.

Hisobot buyrug'i: "${b.nom||'Hisobot'}"
Tashkilot filtri: ${selectedOrgs.length ? selectedOrgs.join(', ') : 'Barcha tashkilotlar'}
Davr: ${b.davr}
Holat filtri: ${b.status||'Barchasi'}
So'ralgan ma'lumotlar: ${b.fields||'Hujjat nomi, raqami, sanasi, tashkilot, holat, muddat, ijrochi, rezolyutsiya va topshiriq'}
${b.korstma?'Admin ko\'rsatmasi: '+b.korstma:''}

Hujjatlar statistikasi:
- Jami: ${total}
- Bajarildi: ${done} (${total?Math.round(done/total*100):0}%)
- Jarayonda: ${proc}
- Bajarilmadi: ${fail}

Hujjatlar ro'yxati (birinchi 30 ta):
${docs.slice(0,30).map((d,i)=>`${i+1}. ${d.docName||'—'} | ${getOrgText(d)||'—'} | ${getStatusText(d)||'—'} | Muddat: ${d.deadline||'—'} | Ijrochi: ${d.executor||'—'}`).join('\n')}

Iltimos, o'zbek tilida qisqa amaliy hisobot xulosasi yozing (3-5 jumlada). Asosiy muammolar, kechikkan topshiriqlar va tavsiyalarni bering. FAQAT matn yoz, JSON yoki kod yozma.`;

      try {
        const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${geminiKey}`,{
          method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({contents:[{role:'user',parts:[{text:prompt}]}],generationConfig:{maxOutputTokens:800,temperature:0.3}})
        });
        const data = await resp.json();
        aiAnaliz = (data?.candidates?.[0]?.content?.parts||[]).map(p=>p.text||'').join('').trim();
      } catch(e) { aiAnaliz = 'AI tahlil yuklanmadi.'; }
    }

    ahbLastReport = {
      docs,
      nom: b.nom || 'Hisobot',
      aiAnaliz,
      fields: b.fields || '',
      selectedOrgs,
      selectedOrgTitle,
      ourOrgName
    };
    window.ahbLastReport = ahbLastReport;

    if(resultEl) {
      const previewHtml = buildAhbOfficialTableHtml(docs.slice(0, 30), { title:b.nom||'Hisobot', includeStyles:true, groupTitle:selectedOrgTitle, selectedOrgs });
      const summaryPreviewHtml = buildAhbSummaryTableHtml(docs, { includeStyles:true, ourOrg:ourOrgName });
      resultEl.innerHTML = `<div class="card" style="border:2px solid var(--blue-mid);">
        <div class="card-title">📊 AI Hisobot: ${escH(b.nom||'Hisobot')}</div>
        <div class="stat-grid-5" style="margin:12px 0;">
          <div class="stat-box blue"><div class="sv">${total}</div><div class="sl">Jami</div></div>
          <div class="stat-box green"><div class="sv">${done}</div><div class="sl">Bajarildi</div></div>
          <div class="stat-box yellow"><div class="sv">${proc}</div><div class="sl">Jarayonda</div></div>
          <div class="stat-box red"><div class="sv">${fail}</div><div class="sl">Bajarilmadi</div></div>
          <div class="stat-box navy"><div class="sv">${total?Math.round(done/total*100):0}%</div><div class="sl">Foiz</div></div>
        </div>
        ${aiAnaliz?`<div style="background:#f5f0ff;border-left:4px solid #7c3aed;border-radius:0 8px 8px 0;padding:12px 16px;margin:12px 0;font-size:13px;line-height:1.7;color:#3b0764;"><b>🤖 AI Xulosa:</b><br>${escH(aiAnaliz)}</div>`:''}
        <div class="official-note">Rasmiy jadval ko'rinishi: previewda birinchi 30 ta qator ko'rsatiladi, Excel/Word faylida barcha qatorlar chiqadi.</div>
        <div class="official-report-wrap">${previewHtml}</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;">
          <button class="btn btn-success" onclick="exportCurrentAhbExcel()">📥 Excel yuklash</button>
          <button class="btn btn-outline" onclick="exportCurrentAhbWord()">📄 Word yuklash</button>
        </div>
        <div class="official-note" style="margin-top:18px;">Qo'shimcha 2-jadval yig'ma hisobot: hujjatlar turi bo'yicha umumiy sonlar.</div>
        <div class="official-report-wrap">${summaryPreviewHtml}</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;">
          <button class="btn btn-success" onclick="exportCurrentAhbSummaryExcel()">📥 2-jadval Excel</button>
          <button class="btn btn-outline" onclick="exportCurrentAhbSummaryWord()">📄 2-jadval Word</button>
        </div>
      </div>`;
    }
  } catch(e) {
    if(resultEl) resultEl.innerHTML=`<div class="ai-error">❌ Xatolik: ${escH(e.message)}</div>`;
  }
};

function safeFilePart(name) {
  return String(name||'Hisobot')
    .replace(/[\\/:*?"<>|]/g,'_')
    .replace(/\s+/g,'_')
    .slice(0,80) || 'Hisobot';
}

function resolveAhbDocs(input) {
  if(Array.isArray(input)) return input;
  if(typeof input === 'string') {
    try { return JSON.parse(input); } catch(e) { return []; }
  }
  return [];
}

window.exportCurrentAhbExcel = () => {
  const report = window.ahbLastReport || ahbLastReport;
  if(!report || !Array.isArray(report.docs)) {
    showToast('Avval AI hisobotni bajaring', 'error');
    return;
  }
  exportAhbExcel(report.docs, report.nom, report.aiAnaliz, report.fields, report);
};

window.exportCurrentAhbWord = () => {
  const report = window.ahbLastReport || ahbLastReport;
  if(!report || !Array.isArray(report.docs)) {
    showToast('Avval AI hisobotni bajaring', 'error');
    return;
  }
  exportAhbWord(report.docs, report.nom, report.aiAnaliz, report.fields, report);
};

window.exportCurrentAhbSummaryExcel = () => {
  const report = window.ahbLastReport || ahbLastReport;
  if(!report || !Array.isArray(report.docs)) {
    showToast('Avval AI hisobotni bajaring', 'error');
    return;
  }
  exportAhbSummaryExcel(report.docs, report.nom, report);
};

window.exportCurrentAhbSummaryWord = () => {
  const report = window.ahbLastReport || ahbLastReport;
  if(!report || !Array.isArray(report.docs)) {
    showToast('Avval AI hisobotni bajaring', 'error');
    return;
  }
  exportAhbSummaryWord(report.docs, report.nom, report);
};

window.exportAhbExcel = (docsInput, nom='Hisobot', aiAnaliz='', fields='', reportMeta={}) => {
  const docs = resolveAhbDocs(docsInput);
  if(!docs.length) { showToast('Hisobot uchun hujjat topilmadi','error'); return; }
  const statusCounts = getStatusCounts(docs);
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
    ${ahbOfficialStyles()}
    <style>
      body{font-family:"Times New Roman",serif;background:#fff;color:#111;}
      .summary{font-size:12px;margin:8px 0 14px;}
    </style>
  </head><body>
    <h2 style="text-align:center;">${escH(nom)}</h2>
    <div class="summary">
      Jami: ${docs.length} &nbsp; | &nbsp; Bajarildi: ${statusCounts.done} &nbsp; | &nbsp;
      Jarayonda: ${statusCounts.proc} &nbsp; | &nbsp; Bajarilmadi: ${statusCounts.fail}
    </div>
    ${aiAnaliz?`<div class="summary"><b>AI Xulosa:</b><br>${escH(aiAnaliz).replace(/\n/g,'<br>')}</div>`:''}
    ${buildAhbOfficialTableHtml(docs, { includeStyles:false, groupTitle:reportMeta.selectedOrgTitle || getAhbSelectedOrgTitle(reportMeta.selectedOrgs, docs), selectedOrgs:reportMeta.selectedOrgs || [] })}
  </body></html>`;
  const blob = new Blob([html],{type:'application/vnd.ms-excel;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'AI_Hisobot_'+safeFilePart(nom)+'_'+new Date().toISOString().slice(0,10)+'.xls';
  document.body.appendChild(a);
  a.click();
  setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  showToast('📥 Excel yuklandi','success');
};

window.exportAhbWord = (docsInput, nom='Hisobot', aiAnaliz='', fields='', reportMeta={}) => {
  const docs = resolveAhbDocs(docsInput);
  if(!docs.length) { showToast('Hisobot uchun hujjat topilmadi','error'); return; }
  const date = new Date().toLocaleDateString('uz-UZ');
  const statusCounts = getStatusCounts(docs);
  let html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
  ${ahbOfficialStyles()}
  <style>
    body{font-family:"Times New Roman",serif;font-size:11pt;margin:1.2cm;background:#fff;color:#111;}
    h1{font-size:14pt;text-align:center;margin-bottom:12px;}
    .ai-box{background:#f5f0ff;border-left:4px solid #7c3aed;padding:12px;margin:16px 0;font-style:italic;}
    .summary{font-size:11pt;margin:8px 0 14px;}
  </style>
  </head><body>
  <h1>📊 AI HISOBOT: ${escH(nom)}</h1>
  <p class="summary">Sana: ${date} | Jami: ${docs.length} | Bajarildi: ${statusCounts.done} | Jarayonda: ${statusCounts.proc} | Bajarilmadi: ${statusCounts.fail}</p>
  ${aiAnaliz?`<div class="ai-box"><b>🤖 AI Xulosa:</b><br>${escH(aiAnaliz).replace(/\n/g,'<br>')}</div>`:''}
  ${buildAhbOfficialTableHtml(docs, { includeStyles:false, groupTitle:reportMeta.selectedOrgTitle || getAhbSelectedOrgTitle(reportMeta.selectedOrgs, docs), selectedOrgs:reportMeta.selectedOrgs || [] })}
  </body></html>`;

  const blob = new Blob([html],{type:'application/msword'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'AI_Hisobot_'+safeFilePart(nom)+'_'+new Date().toISOString().slice(0,10)+'.doc';
  document.body.appendChild(a);
  a.click();
  setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  showToast('📄 Word yuklandi','success');
};

window.exportAhbSummaryExcel = (docsInput, nom='Hisobot', reportMeta={}) => {
  const docs = resolveAhbDocs(docsInput);
  if(!docs.length) { showToast('2-jadval uchun hujjat topilmadi','error'); return; }
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
    ${ahbOfficialStyles()}
  </head><body>
    ${buildAhbSummaryTableHtml(docs, { includeStyles:false, ourOrg:reportMeta.ourOrgName || getOurOrgName() })}
  </body></html>`;
  const blob = new Blob([html],{type:'application/vnd.ms-excel;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'AI_Hisobot_2_jadval_'+safeFilePart(nom)+'_'+new Date().toISOString().slice(0,10)+'.xls';
  document.body.appendChild(a);
  a.click();
  setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  showToast('📥 2-jadval Excel yuklandi','success');
};

window.exportAhbSummaryWord = (docsInput, nom='Hisobot', reportMeta={}) => {
  const docs = resolveAhbDocs(docsInput);
  if(!docs.length) { showToast('2-jadval uchun hujjat topilmadi','error'); return; }
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
    ${ahbOfficialStyles()}
    <style>body{font-family:"Times New Roman",serif;background:#fff;color:#111;margin:1.2cm;}</style>
  </head><body>
    ${buildAhbSummaryTableHtml(docs, { includeStyles:false, ourOrg:reportMeta.ourOrgName || getOurOrgName() })}
  </body></html>`;
  const blob = new Blob([html],{type:'application/msword'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'AI_Hisobot_2_jadval_'+safeFilePart(nom)+'_'+new Date().toISOString().slice(0,10)+'.doc';
  document.body.appendChild(a);
  a.click();
  setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  showToast('📄 2-jadval Word yuklandi','success');
};
