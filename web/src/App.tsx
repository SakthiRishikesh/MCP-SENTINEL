import { useEffect, useState } from 'react'
import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Check,
  Fingerprint,
  FlaskConical,
  GitBranch,
  KeyRound,
  LockKeyhole,
  Menu,
  Network,
  Radio,
  ScanLine,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
  Sun,
  Moon,
} from 'lucide-react'
import { WorkflowGraph } from './components/WorkflowGraph'
import { AuthPage } from './components/AuthPage'

function BrandMark() {
  return (
    <a className="brand-lockup" href="#overview" aria-label="MCP-Sentinel home">
      <span className="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 36 40" fill="none">
          <path d="M18 2.8 32 8v10.1c0 8.9-5.7 14.8-14 19.1C9.7 32.9 4 27 4 18.1V8L18 2.8Z" stroke="currentColor" strokeWidth="1.45" />
          <path d="M10.1 20.3h5.3l3-6.2 3.1 11.7 2.6-5.5h2.1" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
          <circle cx="10.1" cy="20.3" r="1.45" fill="currentColor" />
          <circle cx="26.2" cy="20.3" r="1.45" fill="currentColor" />
        </svg>
      </span>
      <span className="brand-type">MCP<span>·</span>SENTINEL</span>
    </a>
  )
}

function Navbar({ theme, onToggleTheme }: { theme: 'dark' | 'light'; onToggleTheme: () => void }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const items = [
    ['Overview', '#overview'],
    ['Workflow', '#workflow'],
    ['Capabilities', '#capabilities'],
    ['Architecture', '#architecture'],
  ]
  return (
    <header className="site-header">
      <nav className="navbar wrap" aria-label="Main navigation">
        <BrandMark />
        <div className={'nav-links ' + (menuOpen ? 'nav-open' : '')}>
          {items.map(([label, href]) => (
            <a key={label} href={href} onClick={() => setMenuOpen(false)}>{label}</a>
          ))}
          <a className="nav-mobile-cta" href="/auth" onClick={() => setMenuOpen(false)}>
            Login / Sign up <ArrowRight size={14} />
          </a>
        </div>
        <div className="nav-actions">
          <button className="theme-toggle" type="button" onClick={onToggleTheme} aria-label={'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' theme'} title={'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' theme'}>
            {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
          </button>
          <a className="nav-cta" href="/auth">Login / Sign up <ArrowRight size={14} /></a>
        </div>
        <button
          type="button"
          className="mobile-menu-button"
          aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'}
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen(!menuOpen)}
        >
          {menuOpen ? <X size={19} /> : <Menu size={19} />}
        </button>
      </nav>
    </header>
  )
}

function HeroSection() {
  return (
    <section className="hero-section" id="overview">
      <div className="hero-grid wrap">
        <div className="hero-copy" data-reveal>
          <div className="hero-eyebrow"><span className="eyebrow-pulse" /> ADAPTIVE SECURITY FOR MCP</div>
          <h1>Give AI tools access.<br /><span>Never give up control.</span></h1>
          <p className="hero-description">
            MCP-Sentinel is a proposed security boundary between LLMs and MCP tools—checking identity and permissions, inspecting tool calls, detecting prompt injection, and validating tools in isolation.
          </p>
          <div className="hero-actions">
            <a className="button-primary" href="#workflow">Explore the Workflow <ArrowRight size={15} /></a>
            <a className="button-secondary" href="#capabilities">Understand the Security Model <ArrowDownRight size={15} /></a>
          </div>
          <div className="hero-assurance"><span /> Identity &amp; RBAC <i /> Monitor tool calls <i /> Detect prompt injection <i /> Sandbox validation</div>
        </div>
        <div className="hero-art" aria-hidden="true" data-reveal>
          <div className="hero-art-orbit orbit-one" />
          <div className="hero-art-orbit orbit-two" />
          <div className="hero-node hero-node-core"><Shield size={29} strokeWidth={1.35} /><span>MCP-SENTINEL</span><small>POLICY BOUNDARY</small></div>
          <div className="hero-node hero-node-user"><Fingerprint size={16} /><span>IDENTITY</span></div>
          <div className="hero-node hero-node-tool"><Network size={16} /><span>TOOL CALL</span></div>
          <div className="hero-node hero-node-data"><LockKeyhole size={15} /><span>RESOURCE</span></div>
          <div className="hero-art-line art-line-one" />
          <div className="hero-art-line art-line-two" />
          <div className="hero-art-line art-line-three" />
          <div className="hero-art-signal signal-one" />
          <div className="hero-art-signal signal-two" />
          <div className="hero-art-status"><span className="status-indicator" /> REQUEST UNDER EVALUATION <span className="status-id">REQ–042</span></div>
          <div className="hero-art-note">TRUST IS A CONTINUOUS CHECK</div>
        </div>
      </div>
      <div className="hero-bottom-fade" />
    </section>
  )
}

const capabilityCards = [
  {
    icon: Fingerprint,
    index: '01',
    title: 'Verify Before Trust',
    name: 'Server & Tool Integrity',
    text: 'Compare registered server and tool information against approved versions. Identify unexpected definition changes, schema changes and capability expansion before they influence execution.',
    art: 'fingerprint-art',
  },
  {
    icon: FlaskConical,
    index: '02',
    title: 'Test in Isolation',
    name: 'Sandbox Validation',
    text: 'Test selected locally executable tools with synthetic data, dummy credentials and controlled resources to collect behavioural evidence before broader use.',
    art: 'sandbox-art',
  },
  {
    icon: GitBranch,
    index: '03',
    title: 'Understand the Sequence',
    name: 'Context-Aware Attack Detection',
    text: 'Examine how tool requests relate to previous actions, permissions and sensitive data. A sequence of individually legitimate calls may still violate policy.',
    art: 'sequence-art',
  },
  {
    icon: ShieldCheck,
    index: '04',
    title: 'Respond Adaptively',
    name: 'Risk-Based Enforcement',
    text: 'Use policy rules and changing security evidence to determine whether to allow, monitor, restrict, request approval or block a tool request.',
    art: 'response-art',
  },
]

function CapabilityArt({ kind }: { kind: string }) {
  if (kind === 'fingerprint-art') {
    return <div className="capability-art fingerprint-motif" aria-hidden="true"><div className="fingerprint-rings"><i /><i /><i /><i /><i /></div><span className="motif-dot" /><span className="motif-label">BASELINE MATCH</span><Check className="motif-check" size={14} /></div>
  }
  if (kind === 'sandbox-art') {
    return <div className="capability-art sandbox-motif" aria-hidden="true"><div className="sandbox-frame"><div className="sandbox-cube"><FlaskConical size={21} /></div><span className="sandbox-pip pip-a" /><span className="sandbox-pip pip-b" /><span className="sandbox-pip pip-c" /></div><span className="motif-label">ISOLATED ENVIRONMENT</span></div>
  }
  if (kind === 'sequence-art') {
    return <div className="capability-art sequence-motif" aria-hidden="true"><div className="sequence-path"><span /><span /><span /><span /></div><div className="sequence-caption"><b>READ</b><i /><b>ACCESS</b><i className="sequence-alert" /><b className="caption-alert">TRANSFER</b></div><ArrowRight className="sequence-arrow" size={13} /></div>
  }
  return <div className="capability-art response-motif" aria-hidden="true"><span className="response-center"><ShieldCheck size={19} /></span><span className="response-ring ring-a" /><span className="response-ring ring-b" /><span className="response-state state-allow">ALLOW</span><span className="response-state state-review">REVIEW</span><span className="response-state state-block">BLOCK</span><span className="response-state state-limit">LIMIT</span></div>
}

function Capabilities() {
  return (
    <section className="section capabilities-section" id="capabilities">
      <div className="wrap">
        <div className="section-heading" data-reveal>
          <div>
            <span className="section-kicker"><span>01</span> SECURITY CAPABILITIES</span>
            <h2>Trust is earned<br /><em>at every call.</em></h2>
          </div>
          <p>Protection that follows the request—from its declared identity to the behavior observed along the way.</p>
        </div>
        <div className="capability-grid">
          {capabilityCards.map((card) => {
            const Icon = card.icon
            return (
              <article className="capability-card" data-reveal key={card.index}>
                <div className="capability-card-top"><span className="capability-index">{card.index}</span><Icon size={17} strokeWidth={1.6} /></div>
                <CapabilityArt kind={card.art} />
                <div className="capability-card-copy">
                  <span className="capability-title">{card.title}</span>
                  <h3>{card.name}</h3>
                  <p>{card.text}</p>
                  {card.index === '02' && <p className="capability-clarification">Sandbox evidence can inform a decision; it cannot prove a tool is safe. Remote servers need other validation and runtime controls.</p>}
                </div>
              </article>
            )
          })}
        </div>
      </div>
    </section>
  )
}

const processSteps = [
  { icon: Fingerprint, num: '01', title: 'Establish trust', text: 'Identify the server, tool and requester, then compare the tool with its approved integrity baseline.' },
  { icon: ScanLine, num: '02', title: 'Evaluate the request', text: 'Validate inputs, permissions and the context in which the tool is being requested.' },
  { icon: ShieldAlert, num: '03', title: 'Enforce the decision', text: 'Apply configured policy before forwarding, with approval or restriction where required.' },
  { icon: Activity, num: '04', title: 'Monitor and learn', text: 'Inspect available behavior evidence, record decisions and inform future assessments.' },
]

function HowItWorks() {
  return (
    <section className="section how-section" id="architecture">
      <div className="wrap">
        <div className="how-heading" data-reveal>
          <div><span className="section-kicker"><span>02</span> THE CONTROL LOOP</span><h2>From request<br /><em>to response.</em></h2></div>
          <p>Every decision is made before a protected call is forwarded—and revisited as new evidence arrives.</p>
        </div>
        <div className="process-track" data-reveal>
          <div className="process-connector" />
          {processSteps.map((step) => {
            const Icon = step.icon
            return (
              <article className="process-step" key={step.num}>
                <div className="process-icon"><Icon size={18} strokeWidth={1.55} /><span>{step.num}</span></div>
                <div className="process-copy"><small>PHASE {step.num}</small><h3>{step.title}</h3><p>{step.text}</p></div>
              </article>
            )
          })}
        </div>
        <div className="architecture-note" data-reveal><span className="architecture-note-icon"><Radio size={15} /></span><p><strong>At the MCP boundary.</strong> The client must route protected calls through the gateway for its policy decisions to be enforced.</p><a href="#workflow">Explore the request path <ArrowRight size={13} /></a></div>
      </div>
    </section>
  )
}

function SecurityPrinciple() {
  return (
    <section className="principle-section">
      <div className="principle-aura" />
      <div className="wrap principle-wrap" data-reveal>
        <span className="section-kicker"><span>03</span> THE TRUST MODEL</span>
        <h2>Declared is not authorised.<br /><em>Authorised is not observed.</em></h2>
        <div className="principle-chain">
          <article className="principle-card">
            <span className="principle-card-icon"><Network size={16} /></span>
            <span className="principle-card-index">01 / CLAIM</span>
            <h3>Declared capability</h3>
            <p>What the tool says it can do.</p>
          </article>
          <div className="principle-link"><span /></div>
          <article className="principle-card">
            <span className="principle-card-icon"><KeyRound size={16} /></span>
            <span className="principle-card-index">02 / POLICY</span>
            <h3>Authorised capability</h3>
            <p>What the policy allows it to do.</p>
          </article>
          <div className="principle-link"><span /></div>
          <article className="principle-card">
            <span className="principle-card-icon"><Activity size={16} /></span>
            <span className="principle-card-index">03 / EVIDENCE</span>
            <h3>Observed behaviour</h3>
            <p>What available evidence indicates it does.</p>
          </article>
        </div>
        <p className="principle-conclusion">MCP-Sentinel is designed to identify mismatches between these views and use them as evidence for security decisions.</p>
        <p className="principle-limit">Visibility depends on the server, sandbox and runtime instrumentation available.</p>
      </div>
    </section>
  )
}

function ClosingSection({ onReplay }: { onReplay: () => void }) {
  return (
    <section className="closing-section">
      <div className="closing-aura" />
      <div className="wrap closing-content" data-reveal>
        <span className="section-kicker"><span>CONTINUOUS EVALUATION</span></span>
        <h2>Trust should be<br /><em>continuously evaluated.</em></h2>
        <p>Explore how MCP-Sentinel brings integrity checks, contextual security and adaptive enforcement together at the MCP boundary.</p>
        <div className="closing-actions">
          <button className="button-primary" type="button" onClick={onReplay}>Replay the Workflow <ArrowRight size={15} /></button>
          <a className="button-secondary" href="#overview">Back to Overview <ArrowUpRight size={14} /></a>
        </div>
        <div className="closing-footnote"><span className="tiny-shield"><ShieldCheck size={14} /></span> A research-oriented project for more accountable AI tool access.</div>
      </div>
    </section>
  )
}

function Footer() {
  return (
    <footer className="site-footer">
      <div className="wrap footer-main">
        <div className="footer-brand"><BrandMark /><p>An adaptive zero-trust security gateway for MCP-based AI applications.</p></div>
        <div className="footer-nav-group"><span>EXPLORE</span><a href="#overview">Overview</a><a href="#workflow">Workflow</a><a href="#capabilities">Capabilities</a><a href="#architecture">Architecture</a></div>
        <div className="footer-statement"><span>THE PRINCIPLE</span><p>Never trust a tool<br />just because it worked before.</p></div>
      </div>
      <div className="wrap footer-bottom"><span>© MCP-SENTINEL · RESEARCH PROJECT</span><span>Illustrative architecture · Features require implementation and evaluation.</span><a href="#overview">Back to top ↑</a></div>
    </footer>
  )
}

/** A small periwinkle glow that follows the pointer on desktop. Updates transform directly on
 *  pointer move (no React state, no rAF loop), and is disabled on touch / reduced-motion. */
function CursorGlow() {
  useEffect(() => {
    const fine = window.matchMedia('(pointer: fine)')
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)')
    if (!fine.matches || reduce.matches) return
    const el = document.createElement('div')
    el.className = 'cursor-glow'
    document.body.appendChild(el)
    let shown = false
    const move = (e: PointerEvent) => {
      el.style.transform = `translate3d(${e.clientX}px, ${e.clientY}px, 0)`
      if (!shown) { shown = true; el.style.opacity = '1' }
    }
    const hide = () => { shown = false; el.style.opacity = '0' }
    const over = (e: PointerEvent) => {
      const t = e.target as HTMLElement | null
      el.classList.toggle('is-active', !!(t && t.closest('a, button, input, select, textarea, [role="tab"], [tabindex]')))
    }
    window.addEventListener('pointermove', move, { passive: true })
    window.addEventListener('pointerover', over, { passive: true })
    document.addEventListener('pointerleave', hide)
    window.addEventListener('blur', hide)
    return () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerover', over)
      document.removeEventListener('pointerleave', hide)
      window.removeEventListener('blur', hide)
      el.remove()
    }
  }, [])
  return null
}

function App() {
  const [motionPreference, setMotionPreference] = useState(false)
  const [pathname, setPathname] = useState(window.location.pathname)
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = window.localStorage.getItem('mcp-sentinel-theme')
    if (saved === 'light' || saved === 'dark') return saved
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  })

  useEffect(() => {
    window.localStorage.setItem('mcp-sentinel-theme', theme)
  }, [theme])

  useEffect(() => {
    const syncPath = () => setPathname(window.location.pathname)
    window.addEventListener('popstate', syncPath)
    return () => window.removeEventListener('popstate', syncPath)
  }, [])

  const navigate = (path: string) => {
    if (window.location.pathname !== path) window.history.pushState({}, '', path)
    setPathname(path)
    window.scrollTo({ top: 0, behavior: motionPreference ? 'auto' : 'smooth' })
  }

  useEffect(() => {
    const fill = document.getElementById('scroll-progress-fill')
    if (!fill) return
    let frame = 0
    const update = () => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => {
        const scrollable = document.documentElement.scrollHeight - window.innerHeight
        const progress = scrollable > 0 ? window.scrollY / scrollable : 0
        fill.style.transform = 'scaleX(' + Math.min(1, Math.max(0, progress)) + ')'
      })
    }
    update()
    window.addEventListener('scroll', update, { passive: true })
    window.addEventListener('resize', update, { passive: true })
    return () => {
      cancelAnimationFrame(frame)
      window.removeEventListener('scroll', update)
      window.removeEventListener('resize', update)
    }
  }, [])

  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)')
    const reduced = query.matches
    const sync = () => setMotionPreference(query.matches)
    setMotionPreference(reduced)
    query.addEventListener('change', sync)
    const elements = Array.from(document.querySelectorAll<HTMLElement>('[data-reveal]'))
    if (reduced || !('IntersectionObserver' in window)) {
      elements.forEach((element) => element.classList.add('is-visible'))
    } else {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible')
            observer.unobserve(entry.target)
          }
        })
      }, { threshold: 0.13 })
      elements.forEach((element) => observer.observe(element))
      return () => { observer.disconnect(); query.removeEventListener('change', sync) }
    }
    return () => query.removeEventListener('change', sync)
  }, [])

  useEffect(() => {
    const onVis = () => document.body.classList.toggle('page-hidden', document.hidden)
    document.addEventListener('visibilitychange', onVis)
    return () => document.removeEventListener('visibilitychange', onVis)
  }, [])

  const replay = () => {
    document.getElementById('workflow')?.scrollIntoView({ behavior: motionPreference ? 'auto' : 'smooth' })
  }

  if (pathname.startsWith('/auth')) {
    return (
      <div className="app-shell" data-theme={theme}>
        <CursorGlow />
        <div className="ambient-backdrop" aria-hidden="true"><span className="aurora aurora-one" /><span className="aurora aurora-two" /><span className="aurora aurora-three" /><span className="background-grain" /></div>
        <AuthPage pathname={pathname} navigate={navigate} />
      </div>
    )
  }

  return (
    <div className="app-shell" data-theme={theme}>
      <CursorGlow />
      <div className="scroll-progress" aria-hidden="true"><span id="scroll-progress-fill" /></div>
      <div className="ambient-backdrop" aria-hidden="true"><span className="aurora aurora-one" /><span className="aurora aurora-two" /><span className="aurora aurora-three" /><span className="background-grain" /></div>
      <Navbar theme={theme} onToggleTheme={() => setTheme((current) => current === 'dark' ? 'light' : 'dark')} />
      <main>
        <HeroSection />
        <section className="workflow-section section" id="workflow">
          <div className="wrap">
            <div className="workflow-intro" data-reveal>
              <div><span className="section-kicker"><span>00</span> MCP SECURITY PATH</span><h2>One boundary.<br /><em>Two-way protection.</em></h2></div>
              <div className="workflow-intro-aside">
                <span className="proposed-tag"><span /> PROPOSED CONTROL PLANE</span>
                <p>Tool requests pass through MCP-Sentinel for identity checks, call monitoring, injection detection, and sandbox validation. Inspected results return to the LLM through the same boundary.</p>
              </div>
            </div>
            <WorkflowGraph />
          </div>
        </section>
        <Capabilities />
        <HowItWorks />
        <SecurityPrinciple />
        <ClosingSection onReplay={replay} />
      </main>
      <Footer />
    </div>
  )
}

export default App
