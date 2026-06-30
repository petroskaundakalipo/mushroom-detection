import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { AlertTriangle, BarChart3, Camera, CheckCircle2, Leaf, LockKeyhole, LogOut, Menu, Microscope, ShieldAlert, SlidersHorizontal, Sparkles, UserPlus, Users, X } from 'lucide-react';
import './styles.css';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';
const SESSION_KEY = 'mushroom-detector-session';

function loadSession() { try { return JSON.parse(localStorage.getItem(SESSION_KEY)) || null; } catch { return null; } }

function App() {
  const initialSession = loadSession();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [session, setSession] = useState(initialSession);
  const [page, setPage] = useState(initialSession ? 'app' : 'home');
  const [authMode, setAuthMode] = useState('login');
  const [authForm, setAuthForm] = useState({ name: '', email: '', password: '' });
  const [authErrors, setAuthErrors] = useState({});
  const [authStatus, setAuthStatus] = useState('idle');
  const [imageFile, setImageFile] = useState(null);
  const [imagePreview, setImagePreview] = useState('');
  const [result, setResult] = useState(null);
  const [errors, setErrors] = useState({});
  const [status, setStatus] = useState('idle');

  function saveSession(nextSession) { setSession(nextSession); nextSession ? localStorage.setItem(SESSION_KEY, JSON.stringify(nextSession)) : localStorage.removeItem(SESSION_KEY); }
  async function authedFetch(path, options = {}) { return fetch(`${API_BASE}${path}`, { ...options, headers: { ...(options.headers || {}), Authorization: `Bearer ${session?.token}` } }); }

  async function submitAuth(event) {
    event.preventDefault(); setAuthStatus('loading'); setAuthErrors({});
    try {
      const payload = authMode === 'register' ? authForm : { email: authForm.email, password: authForm.password };
      const response = await fetch(`${API_BASE}/api/auth/${authMode}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await response.json();
      if (!response.ok) { setAuthErrors(data.fields || { form: data.error || 'Authentication failed.' }); setAuthStatus('error'); return; }
      saveSession(data); setPage('app'); setAuthStatus('success'); setAuthForm({ name: '', email: '', password: '' }); setResult(null); setImageFile(null); setImagePreview(''); setErrors({});
    } catch { setAuthErrors({ form: `Could not reach Flask API at ${API_BASE}.` }); setAuthStatus('error'); }
  }

  async function logout() { if (session?.token) await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST', headers: { Authorization: `Bearer ${session.token}` } }).catch(() => {}); saveSession(null); setPage('home'); setResult(null); }
  function handleImage(event) { const file = event.target.files?.[0]; setErrors({}); setResult(null); if (!file) return; if (!file.type.startsWith('image/')) return setErrors({ form: 'Please choose a valid image file.' }); setImageFile(file); setImagePreview(URL.createObjectURL(file)); }

  async function submitPrediction(event) {
    event.preventDefault();
    if (!session?.token) return setErrors({ form: 'Please login or create an account before scanning.' });
    if (!imageFile) return setErrors({ form: 'Take or upload a mushroom photo first.' });
    setStatus('loading'); setErrors({}); setResult(null);
    const body = new FormData(); body.append('image', imageFile);
    try {
      const response = await authedFetch('/api/predict', { method: 'POST', body });
      const data = await response.json();
      if (!response.ok && data.prediction !== 'not_mushroom') { if (response.status === 401) saveSession(null); setErrors({ form: data.error || 'Scan failed.' }); setStatus('error'); return; }
      setResult(data); setStatus(data.prediction === 'not_mushroom' ? 'error' : 'success');
    } catch { setErrors({ form: `Could not reach Flask API at ${API_BASE}. Start the backend and try again.` }); setStatus('error'); }
  }

  return <>
    <header className="site-header"><button className="brand brand-button" onClick={() => setPage(session ? 'app' : 'home')}><span className="brand-mark"><Microscope size={24} /></span><span>Mushroom Detector</span></button><button className="menu-button" onClick={() => setMobileOpen(!mobileOpen)}>{mobileOpen ? <X /> : <Menu />}</button><nav id="site-nav" className={mobileOpen ? 'open' : ''}>{!session && <button onClick={() => setPage('home')}>Home</button>}{!session && <button onClick={() => { setAuthMode('login'); setPage('auth'); }}>Login</button>}{!session && <button onClick={() => { setAuthMode('register'); setPage('auth'); }}>Register</button>}{session && <button onClick={() => setPage('app')}>Detector</button>}{session && <button onClick={() => setPage('history')}>History</button>}{session?.user?.is_admin && <button onClick={() => setPage('admin')}>Admin</button>}{session && <button className="nav-logout" onClick={logout}><LogOut size={16} /> Logout</button>}</nav></header>
    {page === 'home' ? <Landing setPage={setPage} setAuthMode={setAuthMode} /> : page === 'auth' ? <AuthPage authMode={authMode} setAuthMode={setAuthMode} authForm={authForm} setAuthForm={setAuthForm} authErrors={authErrors} authStatus={authStatus} submitAuth={submitAuth} /> : page === 'admin' ? <AdminPage session={session} authedFetch={authedFetch} /> : page === 'history' ? <HistoryPage authedFetch={authedFetch} /> : <ScannerPage imageFile={imageFile} imagePreview={imagePreview} handleImage={handleImage} submitPrediction={submitPrediction} errors={errors} status={status} result={result} />}
  </>;
}

function AuthPage({ authMode, setAuthMode, authForm, setAuthForm, authErrors, authStatus, submitAuth }) { return <main className="auth-page"><section className="account-section auth-only"><form className="account-card" onSubmit={submitAuth}><div className="auth-tabs"><button type="button" className={authMode === 'login' ? 'active' : ''} onClick={() => setAuthMode('login')}><LockKeyhole size={17} /> Login</button><button type="button" className={authMode === 'register' ? 'active' : ''} onClick={() => setAuthMode('register')}><UserPlus size={17} /> Register</button></div>{authMode === 'register' && <label className="field"><span>Name</span><input value={authForm.name} onChange={(e) => setAuthForm({ ...authForm, name: e.target.value })} placeholder="Ada Forager" />{authErrors.name && <small className="field-error">{authErrors.name}</small>}</label>}<label className="field"><span>Email</span><input type="email" value={authForm.email} onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })} placeholder="you@example.com" />{authErrors.email && <small className="field-error">{authErrors.email}</small>}</label><label className="field"><span>Password</span><input type="password" value={authForm.password} onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })} placeholder="At least 8 characters" />{authErrors.password && <small className="field-error">{authErrors.password}</small>}</label>{authErrors.form && <p className="form-error">{authErrors.form}</p>}<button className="submit-button" disabled={authStatus === 'loading'}>{authStatus === 'loading' ? 'Please wait…' : authMode === 'register' ? 'Create account' : 'Login'}</button></form></section></main>; }
function ScannerPage({ imageFile, imagePreview, handleImage, submitPrediction, errors, status, result }) { return <main className="scanner-page"><section className="detector-section scanner-only"><div className="detector-layout"><form className="predictor-card scanner-card" onSubmit={submitPrediction}><label className="upload-zone"><input type="file" accept="image/png,image/jpeg,image/webp" capture="environment" onChange={handleImage} /><span className="upload-icon"><Camera /></span><strong>{imageFile ? imageFile.name : 'Take or upload mushroom photo'}</strong><small>Use a clear, close image with cap, stem, and underside visible when possible.</small></label>{imagePreview && <img className="image-preview" src={imagePreview} alt="Selected mushroom scan preview" />}{errors.form && <p className="form-error">{errors.form}</p>}<button className="submit-button" disabled={status === 'loading'}>{status === 'loading' ? 'Scanning image…' : 'Scan mushroom image'}</button></form><ResultPanel result={result} /></div></section></main>; }

function AdminPage({ session, authedFetch }) {
  const [data, setData] = useState(null); const [users, setUsers] = useState([]); const [predictions, setPredictions] = useState([]); const [threshold, setThreshold] = useState(85); const [error, setError] = useState('');
  async function loadAdmin() { try { const [s, u, p] = await Promise.all([authedFetch('/api/admin/summary'), authedFetch('/api/admin/users'), authedFetch('/api/admin/predictions')]); const sd = await s.json(); const ud = await u.json(); const pd = await p.json(); if (!s.ok) throw new Error(sd.error || 'Admin load failed.'); setData(sd); setUsers(ud.users || []); setPredictions(pd.predictions || []); setThreshold(sd.min_confidence); } catch (e) { setError(e.message); } }
  useEffect(() => { if (session?.user?.is_admin) loadAdmin(); }, []);
  async function saveThreshold() { const res = await authedFetch('/api/admin/settings', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ min_confidence: threshold }) }); const body = await res.json(); if (!res.ok) return setError(body.error || 'Could not save threshold.'); await loadAdmin(); }
  async function updateUser(id, patch) { const res = await authedFetch(`/api/admin/users/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) }); if (!res.ok) setError((await res.json()).error || 'User update failed.'); await loadAdmin(); }
  if (!session?.user?.is_admin) return <main className="scanner-page"><section className="admin-page"><p className="form-error">Admin access required.</p></section></main>;
  return <main className="admin-shell"><section className="admin-page"><div className="admin-heading"><div className="admin-title-row"><h1>Prediction operations</h1><p className="eyebrow"><BarChart3 size={16} /> Admin dashboard</p></div><p>Manage users, review scan history, adjust model confidence, and monitor prediction analytics.</p></div>{error && <p className="form-error">{error}</p>}{data && <div className="stats-grid"><article><Users /><span>Users</span><strong>{data.total_users}</strong><small>{data.active_users} active</small></article><article><Camera /><span>Predictions</span><strong>{data.total_predictions}</strong><small>Total scans</small></article><article><BarChart3 /><span>Avg confidence</span><strong>{data.average_confidence}%</strong><small>Across history</small></article><article><SlidersHorizontal /><span>Threshold</span><strong>{data.min_confidence}%</strong><small>Minimum accepted</small></article></div>}<div className="admin-grid"><section className="admin-card"><h2>Confidence score</h2><label className="field"><span>Minimum confidence</span><input type="number" min="50" max="99" value={threshold} onChange={(e) => setThreshold(e.target.value)} /></label><button className="submit-button" onClick={saveThreshold}>Save threshold</button></section><section className="admin-card"><h2>Prediction analytics</h2>{data?.by_prediction?.map((item) => <div className="analytics-row" key={item.prediction}><span>{title(item.prediction)}</span><strong>{item.count}</strong></div>)}</section></div><section className="admin-card"><h2>Users management</h2><div className="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Scans</th><th>Actions</th></tr></thead><tbody>{users.map((u) => <tr key={u.id}><td><strong>{u.name}</strong><small>{u.email}</small></td><td>{u.is_admin ? 'Admin' : 'User'}</td><td>{u.is_active ? 'Active' : 'Blocked'}</td><td>{u.prediction_count}</td><td><button onClick={() => updateUser(u.id, { is_active: !u.is_active })}>{u.is_active ? 'Block' : 'Activate'}</button>{u.id !== session.user.id && <button onClick={() => updateUser(u.id, { is_admin: !u.is_admin })}>{u.is_admin ? 'Remove admin' : 'Make admin'}</button>}</td></tr>)}</tbody></table></div></section><section className="admin-card"><h2>Prediction history</h2><div className="table-wrap"><table><thead><tr><th>When</th><th>User</th><th>Prediction</th><th>Confidence</th><th>Risk</th></tr></thead><tbody>{predictions.map((p) => <tr key={p.id}><td>{new Date(p.created_at).toLocaleString()}</td><td><strong>{p.user.name}</strong><small>{p.user.email}</small></td><td>{p.prediction === 'not_mushroom' ? 'Not Mushroom' : title(p.prediction)}</td><td>{p.confidence}%</td><td>{p.risk_level}</td></tr>)}</tbody></table></div></section></section></main>;
}

function Landing({ setPage, setAuthMode }) { return <main><section className="hero"><div className="hero-copy"><p className="eyebrow"><Sparkles size={16} /> Camera mushroom scanner</p><h1>Scan mushrooms before making risky choices.</h1><p className="hero-text">Mushroom Detector lets users capture or upload a mushroom/object image, then returns a protected computer-vision risk estimate with clear visual signals.</p><div className="hero-actions"><button className="primary-action" onClick={() => { setAuthMode('register'); setPage('auth'); }}>Create account</button><button className="secondary-action" onClick={() => { setAuthMode('login'); setPage('auth'); }}>Login</button></div></div><div className="specimen-board"><div className="scan-ring"><div className="mushroom-illustration"><span /></div></div><div className="metric-card top"><span>Input</span><strong>photo</strong></div><div className="metric-card bottom"><span>Availability</span><strong>Malawi only</strong></div><div className="trait-strip"><span>scan</span><span>analyze</span><span>score</span><span>explain</span></div></div></section><section className="signals-section"><article><Camera /><h3>Scan from phone</h3><p>Use the camera capture input to photograph a mushroom in the field or upload an existing image.</p></article><article><Microscope /><h3>Computer vision based</h3><p>The backend uses TensorFlow computer vision analysis to estimate mushroom risk.</p></article><article><ShieldAlert /><h3>Safety first</h3><p>Unknown wild mushrooms should be checked by a qualified mycologist.</p></article></section><section className="safety-band"><h2>Important safety note</h2><p>Mushroom poisoning can be fatal and many edible and poisonous species look similar. Never consume a wild mushroom because an app says it is edible.</p></section><footer className="landing-footer"><div><strong>Mushroom Detector</strong><p>Computer-vision mushroom/object scanning for Malawi. Educational use only.</p></div><nav><button onClick={() => { setAuthMode('login'); setPage('auth'); }}>Login</button><button onClick={() => { setAuthMode('register'); setPage('auth'); }}>Register</button></nav></footer></main>; }
function HistoryPage({ authedFetch }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    authedFetch('/api/history')
      .then((r) => r.json())
      .then((data) => { setHistory(data.history || []); setLoading(false); })
      .catch(() => { setError('Could not load history.'); setLoading(false); });
  }, []);

  const labelColor = (p) => p === 'edible' ? 'edible' : p === 'poisonous' ? 'poisonous' : 'not_mushroom';

  return <main className="scanner-page"><section className="history-page"><div className="history-heading"><h2>Scan history</h2><p>Your last 50 mushroom scans.</p></div>{loading && <p className="history-empty">Loading…</p>}{error && <p className="form-error">{error}</p>}{!loading && !error && history.length === 0 && <div className="history-empty"><ShieldAlert size={40} /><p>No scans yet. Go to the Detector to scan your first mushroom.</p></div>}{!loading && history.length > 0 && <div className="history-list">{history.map((item) => <div className={`history-card ${labelColor(item.prediction)}`} key={item.id}><div className="history-card-top"><span className={`history-badge ${labelColor(item.prediction)}`}>{item.prediction === 'not_mushroom' ? 'Not Mushroom' : title(item.prediction)}</span><span className="history-date">{new Date(item.created_at).toLocaleString()}</span></div><div className="history-card-meta"><span><strong>{item.confidence}%</strong> confidence</span><span><strong>{title(item.risk_level)}</strong> risk</span>{item.prediction !== 'not_mushroom' && <span>Edible <strong>{item.edible_probability}%</strong> · Poisonous <strong>{item.poisonous_probability}%</strong></span>}</div></div>)}</div>}</section></main>;
}

function ResultPanel({ result }) { return <aside className={`result-panel ${result?.prediction || ''}`}>{!result ? <div className="empty-result"><ShieldAlert size={44} /><h3>Awaiting scan</h3><p>Your prediction, confidence, visual signals, and top reasons will appear here after image analysis.</p></div> : <><p className="result-label">Prediction for {result.user?.name}</p><h3>{result.prediction === 'not_mushroom' ? 'Not Mushroom' : title(result.prediction)}</h3><div className={`probability ${result.prediction === 'not_mushroom' ? 'failed' : ''}`}><span style={{ width: result.prediction === 'not_mushroom' ? '100%' : `${result.poisonous_probability}%` }} /></div>{result.prediction !== 'not_mushroom' && <div className="probability-row"><span>Edible {result.edible_probability}%</span><span>Poisonous {result.poisonous_probability}%</span></div>}<div className="confidence"><strong>{result.confidence}%</strong><span>confidence · {result.risk_level} risk</span></div>{result.vision_signals && <dl className="vision-grid">{Object.entries(result.vision_signals).filter(([key]) => key !== 'image_size').map(([key, value]) => <div key={key}><dt>{title(key)}</dt><dd>{value}</dd></div>)}</dl>}<ul className="reason-list">{result.reasons.map((reason) => <li key={reason}>{result.prediction === 'edible' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}{reason}</li>)}</ul><p className="disclaimer">{result.disclaimer}</p></>}</aside>; }
function title(value) { return String(value).replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()); }
createRoot(document.getElementById('root')).render(<App />);
