import { useEffect, useState, type FormEvent, type InputHTMLAttributes, type ReactNode } from 'react'
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronRight,
  Eye,
  EyeOff,
  Fingerprint,
  FlaskConical,
  KeyRound,
  Mail,
  Plus,
  Shield,
  ShieldCheck,
  UserRound,
  UsersRound,
  X,
} from 'lucide-react'
import './auth.css'
import { enterApp, login as apiLogin, signupIndividual, signupOrganization } from '../api'

type Navigate = (path: string) => void
type AuthRole = 'individual' | 'organization'
type OrgRole = 'admin' | 'employee'
type Notice = { tone: 'success' | 'error' | 'info'; text: string }

function Field({ label, id, className = '', required = true, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string; id: string }) {
  return (
    <label className={'auth-field ' + className} htmlFor={id}>
      <span>{label}{!required && <small>Optional</small>}</span>
      <input id={id} required={required} {...props} />
    </label>
  )
}

function PasswordField({ label, id, value, onChange, autoComplete, required = true, minLength, hint }: {
  label: string
  id: string
  value: string
  onChange: (value: string) => void
  autoComplete: string
  required?: boolean
  minLength?: number
  hint?: string
}) {
  const [visible, setVisible] = useState(false)
  return (
    <label className="auth-field" htmlFor={id}>
      <span>{label}</span>
      <span className="auth-password-wrap">
        <input id={id} name={id} type={visible ? 'text' : 'password'} value={value} onChange={(event) => onChange(event.target.value)} autoComplete={autoComplete} required={required} minLength={minLength} />
        <button className="password-visibility" type="button" aria-label={visible ? 'Hide password' : 'Show password'} onClick={() => setVisible(!visible)}>
          {visible ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </span>
      {hint && <small className="auth-field-hint">{hint}</small>}
    </label>
  )
}

function PasswordStrength({ value }: { value: string }) {
  const checks = [value.length >= 8, /[A-Z]/.test(value), /[0-9]/.test(value), /[^A-Za-z0-9]/.test(value)]
  const score = checks.filter(Boolean).length
  const label = score < 2 ? 'Add more character variety' : score < 4 ? 'Getting stronger' : 'Strong password'
  return (
    <div className="password-strength" aria-live="polite">
      <div className="strength-bars" aria-label={`Password strength: ${score} of 4`}>
        {checks.map((passed, index) => <i className={passed ? 'is-filled' : ''} key={index} />)}
      </div>
      <span>{value ? label : 'Use 8+ characters'}</span>
    </div>
  )
}

function NoticeBox({ notice, onDismiss }: { notice: Notice; onDismiss?: () => void }) {
  const Icon = notice.tone === 'success' ? CheckCircle2 : notice.tone === 'error' ? Shield : Mail
  return (
    <div className={'auth-notice notice-' + notice.tone} role={notice.tone === 'error' ? 'alert' : 'status'}>
      <Icon size={16} />
      <span>{notice.text}</span>
      {onDismiss && <button type="button" aria-label="Dismiss message" onClick={onDismiss}><X size={14} /></button>}
    </div>
  )
}

function AuthBrand({ navigate }: { navigate: Navigate }) {
  return (
    <a className="auth-brand" href="/" onClick={(event) => { event.preventDefault(); navigate('/') }} aria-label="MCP-Sentinel home">
      <span className="auth-brand-icon"><ShieldCheck size={20} /></span>
      <span>MCP<span>·</span>SENTINEL</span>
    </a>
  )
}

function SecurityAside() {
  return (
    <aside className="auth-aside" aria-label="MCP-Sentinel security overview">
      <div className="auth-aside-grid" aria-hidden="true" />
      <div className="aside-topline"><span><i /> SECURITY BOUNDARY</span><span>01 / 03</span></div>
      <div className="aside-content">
        <div className="aside-emblem"><div className="emblem-orbit orbit-outer" /><div className="emblem-orbit orbit-inner" /><span><ShieldCheck size={34} /></span><i className="emblem-pulse pulse-one" /><i className="emblem-pulse pulse-two" /></div>
        <span className="aside-kicker">ACCESS WITH INTENTION</span>
        <h2>Every tool call.<br /><em>Under your control.</em></h2>
        <p>One clear security boundary between AI applications and the tools they can reach.</p>
        <div className="aside-flow" aria-label="Request, policy check, protected tool">
          <span><UserRound size={14} /> REQUEST</span><i><ChevronRight size={13} /></i>
          <span className="aside-flow-center"><Fingerprint size={14} /> SENTINEL</span><i><ChevronRight size={13} /></i>
          <span><KeyRound size={14} /> TOOL</span>
        </div>
      </div>
      <div className="aside-bottom"><span><FlaskConical size={14} /> ISOLATED TOOL VALIDATION</span><span>BUILT FOR MCP</span></div>
    </aside>
  )
}

function RoleChoice({ role, selected, icon, title, description, onClick }: {
  role: AuthRole
  selected: boolean
  icon: ReactNode
  title: string
  description: string
  onClick: (role: AuthRole) => void
}) {
  return (
    <button type="button" className={'auth-role-card ' + (selected ? 'is-selected' : '')} aria-pressed={selected} onClick={() => onClick(role)}>
      <span className="role-card-icon">{icon}</span><span className="role-card-copy"><strong>{title}</strong><small>{description}</small></span>
      <span className="role-card-check">{selected && <Check size={13} />}</span>
    </button>
  )
}

function ModeTabs({ mode, onChange }: { mode: 'login' | 'signup'; onChange: (mode: 'login' | 'signup') => void }) {
  return (
    <div className="auth-mode-tabs" role="tablist" aria-label="Authentication mode">
      <button type="button" role="tab" aria-selected={mode === 'login'} className={mode === 'login' ? 'is-active' : ''} onClick={() => onChange('login')}>Log in</button>
      <button type="button" role="tab" aria-selected={mode === 'signup'} className={mode === 'signup' ? 'is-active' : ''} onClick={() => onChange('signup')}>Create account</button>
    </div>
  )
}

function PrimaryButton({ children, loading = false, type = 'submit' }: { children: ReactNode; loading?: boolean; type?: 'submit' | 'button' }) {
  return <button className="auth-primary-button" type={type} disabled={loading}>{loading ? <><span className="button-spinner" /> Please wait</> : <>{children}<ArrowRight size={16} /></>}</button>
}

function SignupIndividual({ onSocial, onReturn }: { onSocial: (provider: string) => void; onReturn: () => void }) {
  void onReturn
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (password !== confirm) { setError('Passwords do not match.'); return }
    const data = Object.fromEntries(new FormData(event.currentTarget).entries())
    setError('')
    setLoading(true)
    try {
      await signupIndividual({ name: String(data.name ?? ''), email: String(data.email ?? ''), password, team: String(data.team ?? '') })
      enterApp()
    } catch (err) {
      setLoading(false)
      setError(err instanceof Error ? err.message : 'Could not create your account.')
    }
  }
  return (
    <form className="auth-form" onSubmit={handleSubmit}>
      <div className="auth-form-grid">
        <Field id="individual-name" name="name" label="Full name" placeholder="Jordan Lee" autoComplete="name" />
        <Field id="individual-email" name="email" label="Email address" type="email" placeholder="you@company.com" autoComplete="email" />
        <Field id="individual-team" name="team" label="Company or team" placeholder="Optional" required={false} autoComplete="organization" />
        <PasswordField id="individual-password" label="Password" value={password} onChange={setPassword} autoComplete="new-password" minLength={8} />
        <PasswordStrength value={password} />
        <PasswordField id="individual-confirm" label="Confirm password" value={confirm} onChange={setConfirm} autoComplete="new-password" minLength={8} />
      </div>
      {error && <p className="auth-inline-error" role="alert">{error}</p>}
      <PrimaryButton loading={loading}>Create account & continue</PrimaryButton>
      <div className="auth-divider"><span>or continue with</span></div>
      <div className="social-actions"><button type="button" onClick={() => onSocial('Google')}>Google</button><button type="button" onClick={() => onSocial('GitHub')}>GitHub</button></div>
      <p className="auth-microcopy">Your password is hashed and stored locally by MCP-Sentinel. Social sign-in connects to your identity provider.</p>
    </form>
  )
}

type EmployeeInvite = { name: string; email: string; role: string }

function OrganizationSignup({ onComplete, onReturn }: { onComplete: (text: string) => void; onReturn: () => void }) {
  const [step, setStep] = useState(0)
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [organizationData, setOrganizationData] = useState({ organization: '', organizationEmail: '', size: '', industry: '', region: '' })
  const [adminData, setAdminData] = useState({ adminName: '', adminEmail: '' })
  const [employees, setEmployees] = useState<EmployeeInvite[]>([{ name: '', email: '', role: 'Security analyst' }])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const steps = ['Organization', 'Admin account', 'Employees', 'Complete']
  const submitOrg = async (invites: EmployeeInvite[]) => {
    setError('')
    setLoading(true)
    try {
      await signupOrganization({ ...organizationData, ...adminData, password, employees: invites.filter((e) => e.email.trim()) })
      enterApp()
    } catch (err) {
      setLoading(false)
      setError(err instanceof Error ? err.message : 'Could not create your organization.')
    }
  }
  const continueStep = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const submitted = Object.fromEntries(new FormData(event.currentTarget).entries())
    if (step === 0) setOrganizationData({
      organization: String(submitted.organization ?? ''),
      organizationEmail: String(submitted.organizationEmail ?? ''),
      size: String(submitted.size ?? ''),
      industry: String(submitted.industry ?? ''),
      region: String(submitted.region ?? ''),
    })
    if (step === 1) setAdminData({ adminName: String(submitted.adminName ?? ''), adminEmail: String(submitted.adminEmail ?? '') })
    if (step === 1 && password !== confirm) { setError('Passwords do not match.'); return }
    setError('')
    if (step < 2) { setStep(step + 1); return }
    const invalidInvite = employees.some((employee) => (employee.name || employee.email) && (!employee.name.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(employee.email)))
    if (invalidInvite) { setError('Complete each employee name and enter a valid email, or remove the empty row.'); return }
    void submitOrg(employees)
  }
  void onComplete
  const updateEmployee = (index: number, key: keyof EmployeeInvite, value: string) => setEmployees((current) => current.map((employee, i) => i === index ? { ...employee, [key]: value } : employee))

  if (step === 3) return (
    <div className="auth-complete" role="status">
      <span className="complete-mark"><CheckCircle2 size={28} /></span>
      <span className="auth-eyebrow">ORGANIZATION READY</span>
      <h3>Workspace setup complete.</h3>
      <p>Your administrator account is ready in this prototype. Connect an authentication service to create accounts and send invitations.</p>
      <button type="button" className="auth-text-button" onClick={onReturn}>Return to sign in <ArrowRight size={14} /></button>
    </div>
  )

  return (
    <form className="auth-form org-signup-form" onSubmit={continueStep}>
      <div className="org-stepper" aria-label={`Step ${step + 1} of 4`}>
        {steps.map((label, index) => <div className={'org-step ' + (index < step ? 'is-done' : index === step ? 'is-current' : '')} key={label}><span>{index < step ? <Check size={12} /> : index + 1}</span><small>{label}</small></div>)}
      </div>
      {step === 0 && <>
        <div className="auth-form-grid">
          <Field id="org-name" name="organization" label="Organization name" placeholder="Northstar Security" autoComplete="organization" value={organizationData.organization} onChange={(event) => setOrganizationData((current) => ({ ...current, organization: event.target.value }))} />
          <Field id="org-email" name="organizationEmail" label="Organization email" type="email" placeholder="team@company.com" autoComplete="email" value={organizationData.organizationEmail} onChange={(event) => setOrganizationData((current) => ({ ...current, organizationEmail: event.target.value }))} />
          <label className="auth-field" htmlFor="org-size"><span>Organization size</span><select id="org-size" name="size" required value={organizationData.size} onChange={(event) => setOrganizationData((current) => ({ ...current, size: event.target.value }))}><option value="" disabled>Select team size</option><option>1–10</option><option>11–50</option><option>51–200</option><option>201–1,000</option><option>1,000+</option></select></label>
          <label className="auth-field" htmlFor="org-industry"><span>Industry</span><select id="org-industry" name="industry" required value={organizationData.industry} onChange={(event) => setOrganizationData((current) => ({ ...current, industry: event.target.value }))}><option value="" disabled>Select industry</option><option>Technology</option><option>Financial services</option><option>Healthcare</option><option>Government</option><option>Other</option></select></label>
          <Field className="field-full" id="org-region" name="region" label="Region or country" placeholder="United States" autoComplete="country-name" value={organizationData.region} onChange={(event) => setOrganizationData((current) => ({ ...current, region: event.target.value }))} />
        </div>
      </>}
      {step === 1 && <>
        <div className="step-context"><span className="role-card-icon"><ShieldCheck size={16} /></span><p>This first account will own the organization workspace and manage employee access.</p></div>
        <div className="auth-form-grid">
          <Field id="admin-name" name="adminName" label="Admin full name" placeholder="Jordan Lee" autoComplete="name" value={adminData.adminName} onChange={(event) => setAdminData((current) => ({ ...current, adminName: event.target.value }))} />
          <Field id="admin-email" name="adminEmail" label="Admin email" type="email" placeholder="jordan@company.com" autoComplete="email" value={adminData.adminEmail} onChange={(event) => setAdminData((current) => ({ ...current, adminEmail: event.target.value }))} />
          <PasswordField id="admin-password" label="Password" value={password} onChange={setPassword} autoComplete="new-password" minLength={8} />
          <PasswordField id="admin-confirm" label="Confirm password" value={confirm} onChange={setConfirm} autoComplete="new-password" minLength={8} />
          <PasswordStrength value={password} />
        </div>
      </>}
      {step === 2 && <>
        <p className="step-description">Invite teammates now, or skip this and add them later.</p>
        <div className="employee-invites">
          {employees.map((employee, index) => <div className="employee-invite-row" key={index}>
            <div className="invite-row-top"><span>EMPLOYEE {String(index + 1).padStart(2, '0')}</span>{employees.length > 1 && <button type="button" aria-label={`Remove employee ${index + 1}`} onClick={() => setEmployees((current) => current.filter((_, i) => i !== index))}><X size={14} /></button>}</div>
            <div className="invite-row-fields">
              <label className="auth-field"><span className="visually-hidden">Employee {index + 1} name</span><input aria-label={`Employee ${index + 1} name`} value={employee.name} onChange={(event) => updateEmployee(index, 'name', event.target.value)} placeholder="Full name" /></label>
              <label className="auth-field"><span className="visually-hidden">Employee {index + 1} email</span><input aria-label={`Employee ${index + 1} email`} type="email" value={employee.email} onChange={(event) => updateEmployee(index, 'email', event.target.value)} placeholder="Email address" /></label>
              <label className="auth-field"><span className="visually-hidden">Employee {index + 1} role</span><select aria-label={`Employee ${index + 1} role`} value={employee.role} onChange={(event) => updateEmployee(index, 'role', event.target.value)}><option>Security analyst</option><option>Developer</option><option>Viewer</option></select></label>
            </div>
          </div>)}
        </div>
        <button className="add-employee-button" type="button" onClick={() => setEmployees((current) => [...current, { name: '', email: '', role: 'Security analyst' }])}><Plus size={15} /> Add another employee</button>
      </>}
      {error && <p className="auth-inline-error" role="alert">{error}</p>}
      <div className="org-step-actions">
        {step > 0 && <button type="button" className="auth-back-button" onClick={() => { setError(''); setStep(step - 1) }}><ArrowLeft size={15} /> Back</button>}
        {step === 2 && <button type="button" className="auth-skip-button" onClick={() => void submitOrg([])}>Skip for now</button>}
        <PrimaryButton loading={loading}>{step === 2 ? 'Finish setup' : 'Continue'}</PrimaryButton>
      </div>
      <p className="auth-microcopy">The first account owns the workspace. Employees you add here are invited; set their password in the admin console so they can sign in.</p>
    </form>
  )
}

function LoginForm({ role, onError, onForgot }: { role: AuthRole; onError: (message: string) => void; onForgot: () => void }) {
  const [orgRole, setOrgRole] = useState<OrgRole>('admin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setLoading(true)
    try {
      await apiLogin(email, password)
      enterApp()
    } catch (err) {
      setLoading(false)
      onError(err instanceof Error ? err.message : 'Could not sign you in.')
    }
  }
  return (
    <form className="auth-form" onSubmit={submit}>
      {role === 'organization' && <div className="auth-subtabs" role="tablist" aria-label="Organization account type">
        <button type="button" role="tab" aria-selected={orgRole === 'admin'} className={orgRole === 'admin' ? 'is-active' : ''} onClick={() => setOrgRole('admin')}><ShieldCheck size={14} /> Admin</button>
        <button type="button" role="tab" aria-selected={orgRole === 'employee'} className={orgRole === 'employee' ? 'is-active' : ''} onClick={() => setOrgRole('employee')}><UsersRound size={14} /> Employee</button>
      </div>}
      <Field id="login-email" name="email" label={role === 'organization' ? (orgRole === 'admin' ? 'Admin email' : 'Employee email') : 'Email address'} type="email" placeholder="you@company.com" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
      <PasswordField id="login-password" label="Password" value={password} onChange={setPassword} autoComplete="current-password" />
      {role === 'individual' && <div className="login-options"><label><input type="checkbox" name="remember" /> Remember me</label><button type="button" className="auth-text-button" onClick={onForgot}>Forgot password?</button></div>}
      {role === 'organization' && <button type="button" className="auth-text-button forgot-org" onClick={onForgot}>Forgot password?</button>}
      <PrimaryButton loading={loading}>{role === 'organization' ? `Log in as ${orgRole}` : 'Log in'}</PrimaryButton>
    </form>
  )
}

const DEMO_LOGINS = [
  { label: 'Individual', email: 'you@demo.dev', note: 'full personal dashboard' },
  { label: 'Org admin', email: 'admin@northstar.dev', note: 'team console + access control' },
  { label: 'Org employee', email: 'analyst@northstar.dev', note: 'only assigned tools' },
]

function DemoAccounts({ onError }: { onError: (message: string) => void }) {
  const [busy, setBusy] = useState('')
  const signIn = async (email: string) => {
    setBusy(email)
    try {
      await apiLogin(email, 'sentinel')
      enterApp()
    } catch (err) {
      setBusy('')
      onError(err instanceof Error ? err.message : 'Could not sign in with this demo account.')
    }
  }
  return (
    <div className="demo-accounts" aria-label="Demo accounts">
      <span className="demo-accounts-title"><KeyRound size={12} /> Demo accounts · one-click sign in · password <code>sentinel</code></span>
      <div className="demo-accounts-list">
        {DEMO_LOGINS.map((acct) => (
          <button type="button" className="demo-account" key={acct.email} onClick={() => signIn(acct.email)} disabled={!!busy}>
            <span className="demo-account-role">{acct.label}</span>
            <code>{acct.email}</code>
            <small>{busy === acct.email ? 'Signing in…' : acct.note}</small>
            {busy === acct.email ? <span className="button-spinner" /> : <ArrowRight size={13} className="demo-account-go" />}
          </button>
        ))}
      </div>
    </div>
  )
}

export function AuthPage({ pathname, navigate }: { pathname: string; navigate: Navigate }) {
  const mode: 'login' | 'signup' = pathname.includes('/signup') ? 'signup' : 'login'
  const signupRole: AuthRole = pathname.includes('/organization') ? 'organization' : 'individual'
  const [loginRole, setLoginRole] = useState<AuthRole>('individual')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [forgotMode, setForgotMode] = useState(false)
  const [forgotEmail, setForgotEmail] = useState('')
  const [forgotSent, setForgotSent] = useState(false)

  useEffect(() => { setNotice(null); setForgotMode(false); setForgotSent(false) }, [pathname])

  const changeMode = (nextMode: 'login' | 'signup') => {
    setNotice(null)
    setForgotMode(false)
    navigate(nextMode === 'login' ? '/auth/login' : '/auth/signup')
  }
  const changeSignupRole = (role: AuthRole) => {
    setNotice(null)
    navigate(role === 'organization' ? '/auth/signup/organization' : '/auth/signup/individual')
  }
  const showNotice = (text: string, tone: Notice['tone'] = 'success') => setNotice({ text, tone })
  const startForgot = () => { setForgotMode(true); setForgotEmail(''); setForgotSent(false); setNotice(null) }

  return (
    <main className="auth-page">
      <div className="auth-page-header"><AuthBrand navigate={navigate} /><a className="back-home-link" href="/" onClick={(event) => { event.preventDefault(); navigate('/') }}><ArrowLeft size={14} /> Back to home</a></div>
      <div className="auth-layout">
        <section className="auth-panel" aria-labelledby="auth-heading">
          <div className="auth-panel-heading">
            <span className="auth-eyebrow"><i /> MCP-SENTINEL ACCESS</span>
            <h1 id="auth-heading">{forgotMode ? 'Reset your password' : mode === 'login' ? 'Welcome back.' : 'Create your account.'}</h1>
            <p>{forgotMode ? 'Enter your account email and we’ll prepare password reset instructions.' : mode === 'login' ? 'Sign in to continue to your secure workspace.' : 'Choose how you’ll use MCP-Sentinel.'}</p>
          </div>

          {!forgotMode && <ModeTabs mode={mode} onChange={changeMode} />}
          {notice && <NoticeBox notice={notice} onDismiss={() => setNotice(null)} />}

          {forgotMode ? (
            <form className="auth-form forgot-form" onSubmit={(event) => { event.preventDefault(); setForgotSent(true) }}>
              {forgotSent ? <NoticeBox notice={{ tone: 'info', text: 'If an account matches this email, reset instructions will be sent when email delivery is connected.' }} /> : <>
                <Field id="reset-email" name="email" label="Account email" type="email" placeholder="you@company.com" autoComplete="email" value={forgotEmail} onChange={(event) => setForgotEmail(event.target.value)} />
                <PrimaryButton>Send reset instructions</PrimaryButton>
              </>}
              <button type="button" className="auth-text-button back-to-login" onClick={() => setForgotMode(false)}><ArrowLeft size={14} /> Back to log in</button>
            </form>
          ) : mode === 'login' ? <>
            <div className="auth-role-switch" aria-label="Choose account type">
              <RoleChoice role="individual" selected={loginRole === 'individual'} icon={<UserRound size={17} />} title="Individual" description="Personal account" onClick={setLoginRole} />
              <RoleChoice role="organization" selected={loginRole === 'organization'} icon={<UsersRound size={17} />} title="Organization" description="Team workspace" onClick={setLoginRole} />
            </div>
            <LoginForm key={loginRole} role={loginRole} onError={(text) => showNotice(text, 'error')} onForgot={startForgot} />
            <DemoAccounts onError={(text) => showNotice(text, 'error')} />
          </> : <>
            <div className="auth-role-switch" aria-label="Choose signup type">
              <RoleChoice role="individual" selected={signupRole === 'individual'} icon={<UserRound size={17} />} title="Individual" description="For personal use" onClick={changeSignupRole} />
              <RoleChoice role="organization" selected={signupRole === 'organization'} icon={<UsersRound size={17} />} title="Organization" description="Create a team workspace" onClick={changeSignupRole} />
            </div>
            {signupRole === 'individual'
              ? <SignupIndividual key="individual-signup" onReturn={() => navigate('/auth/login')} onSocial={(provider) => showNotice(`${provider} sign-in will be available when authentication is connected.`, 'info')} />
              : <OrganizationSignup key="organization-signup" onComplete={(text) => showNotice(text, 'info')} onReturn={() => navigate('/auth/login')} />}
          </>}

          {!forgotMode && <p className="auth-switch-prompt">{mode === 'login' ? 'New to MCP-Sentinel?' : 'Already have an account?'} <button type="button" onClick={() => changeMode(mode === 'login' ? 'signup' : 'login')}>{mode === 'login' ? 'Create an account' : 'Log in'}</button></p>}
          <div className="auth-security-note"><Shield size={14} /><span>Passwords are hashed (PBKDF2); OIDC single sign-on can be connected for production.</span><span className="auth-security-dot" /></div>
        </section>
        <SecurityAside />
      </div>
      <footer className="auth-footer"><span>© MCP-SENTINEL · RESEARCH PROJECT</span><span>Secure access for AI tool workflows</span></footer>
    </main>
  )
}
