import { useState } from 'react'
import {
  Activity,
  BrainCircuit,
  ChevronDown,
  Fingerprint,
  FlaskConical,
  ShieldCheck,
  ScanSearch,
  type LucideIcon,
} from 'lucide-react'
import { DetailedFlowchart } from './DetailedFlowchart'

type Guard = {
  id: string
  index: string
  title: string
  description: string
  detail: string
  icon: LucideIcon
}

const guards: Guard[] = [
  {
    id: 'identity',
    index: '01',
    title: 'Identity & RBAC',
    description: 'Verify who is asking and what they can access.',
    detail: 'Check trusted identity claims, roles, scopes, and request context before a tool call reaches a protected server.',
    icon: Fingerprint,
  },
  {
    id: 'monitoring',
    index: '02',
    title: 'Tool-call monitoring',
    description: 'Inspect each request, decision, and returned result.',
    detail: 'Keep an explainable trace of tool calls and apply configured policy to arguments and results at the MCP boundary.',
    icon: Activity,
  },
  {
    id: 'injection',
    index: '03',
    title: 'Prompt-injection detection',
    description: 'Flag hostile instructions in tool content and context.',
    detail: 'Treat tool output as untrusted input, identify instruction-like content, and pass findings into the configured policy decision.',
    icon: ScanSearch,
  },
  {
    id: 'sandbox',
    index: '04',
    title: 'Sandbox validation',
    description: 'Test selected tools in an isolated environment.',
    detail: 'Use synthetic data, dummy credentials, and controlled resources to collect behavioral evidence before broader use.',
    icon: FlaskConical,
  },
]

function SecurityGateway({ selected, onSelect }: { selected: string; onSelect: (id: string) => void }) {
  return (
    <section className="architecture-node gateway-node" aria-labelledby="gateway-title">
      <div className="architecture-node-heading">
        <span className="architecture-icon"><ShieldCheck size={19} /></span>
        <div>
          <span className="architecture-overline">POLICY BOUNDARY</span>
          <h3 id="gateway-title">MCP-Sentinel</h3>
        </div>
        <span className="gateway-live"><i /> ACTIVE</span>
      </div>
      <div className="gateway-guards" aria-label="MCP-Sentinel security controls">
        {guards.map((guard) => {
          const Icon = guard.icon
          const active = selected === guard.id
          return (
            <button
              className={'gateway-guard ' + (active ? 'is-selected' : '')}
              key={guard.id}
              type="button"
              aria-pressed={active}
              onClick={() => onSelect(guard.id)}
            >
              <span className="guard-icon"><Icon size={16} strokeWidth={1.8} /></span>
              <span className="guard-copy"><strong>{guard.title}</strong><small>{guard.description}</small></span>
              <span className="guard-index">{guard.index}</span>
            </button>
          )
        })}
      </div>
      <div className="gateway-foot"><span className="gateway-foot-pulse" /> CHECK EVERY CALL <span>·</span> LEAST PRIVILEGE</div>
    </section>
  )
}

function CommunicationArrows() {
  return (
    <div className="architecture-connector" aria-label="Two-way communication between MCP-Sentinel and the LLM">
      <svg className="connector-desktop" viewBox="0 0 240 144" role="img" aria-label="Request flows from the LLM to MCP-Sentinel; policy decisions and inspected results return to the LLM">
        <defs>
          <linearGradient id="request-line" x1="0" x2="1"><stop stopColor="#8b87ef" /><stop offset="1" stopColor="#3d39c1" /></linearGradient>
          <linearGradient id="response-line" x1="1" x2="0"><stop stopColor="#9b9aee" /><stop offset="1" stopColor="#43439a" /></linearGradient>
          <marker id="arrow-left" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0 9 4.5 0 9Z" fill="#807fe8" /></marker>
          <marker id="arrow-right" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0 9 4.5 0 9Z" fill="#807fe8" /></marker>
        </defs>
        <path className="connector-track" d="M228 42H14" />
        <path className="connector-request" d="M228 42H14" markerEnd="url(#arrow-left)" />
        <path className="connector-track" d="M14 103H228" />
        <path className="connector-response" d="M14 103H228" markerEnd="url(#arrow-right)" />
        <circle className="connector-packet packet-request" r="3.2" fill="#9fa1f7"><animateMotion dur="2.8s" repeatCount="indefinite" path="M228 42H14" /></circle>
        <circle className="connector-packet packet-response" r="3.2" fill="#9fa1f7"><animateMotion dur="3.2s" repeatCount="indefinite" path="M14 103H228" /></circle>
      </svg>
      <svg className="connector-mobile" viewBox="0 0 100 116" aria-hidden="true">
        <defs>
          <marker id="arrow-down" markerWidth="9" markerHeight="9" refX="4.5" refY="8" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0 4.5 9 9 0Z" fill="#807fe8" /></marker>
          <marker id="arrow-up" markerWidth="9" markerHeight="9" refX="4.5" refY="8" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0 4.5 9 9 0Z" fill="#807fe8" /></marker>
        </defs>
        <path className="connector-track" d="M34 7V109" />
        <path className="connector-response" d="M34 7V109" markerEnd="url(#arrow-down)" />
        <path className="connector-track" d="M66 109V7" />
        <path className="connector-request" d="M66 109V7" markerEnd="url(#arrow-up)" />
        <circle className="connector-packet packet-response" r="3" fill="#9fa1f7"><animateMotion dur="2.8s" repeatCount="indefinite" path="M34 7V109" /></circle>
        <circle className="connector-packet packet-request" r="3" fill="#9fa1f7"><animateMotion dur="3.1s" repeatCount="indefinite" path="M66 109V7" /></circle>
      </svg>
      <div className="connector-label connector-request-label"><span>01</span><strong>TOOL REQUEST</strong><small>LLM → Sentinel</small></div>
      <div className="connector-label connector-response-label"><span>02</span><strong>INSPECTED RESPONSE</strong><small>Sentinel → LLM</small></div>
    </div>
  )
}

function ModelNode() {
  return (
    <section className="architecture-node model-node" aria-labelledby="model-title">
      <span className="model-orbit orbit-a" />
      <span className="model-orbit orbit-b" />
      <span className="model-icon"><BrainCircuit size={26} strokeWidth={1.5} /></span>
      <span className="architecture-overline">AI APPLICATION</span>
      <h3 id="model-title">LLM</h3>
      <p>Plans tasks and requests tools through the MCP client.</p>
      <span className="model-status"><i /> CONNECTED</span>
    </section>
  )
}

export function WorkflowGraph() {
  const [selected, setSelected] = useState(guards[0].id)
  const [showDetailed, setShowDetailed] = useState(false)
  const activeGuard = guards.find((guard) => guard.id === selected) ?? guards[0]
  return (
    <div className="workflow-view">
      <div className="workflow-view-toolbar">
        <div><span className="workflow-view-state"><i /> {showDetailed ? 'DETAILED ARCHITECTURE' : 'SIMPLIFIED ARCHITECTURE'}</span><span className="workflow-view-caption">{showDetailed ? 'Explore every check, decision, execution path, and feedback loop.' : 'Select a Sentinel control to inspect how it protects an MCP tool call.'}</span></div>
        <button className="view-more-button" type="button" aria-expanded={showDetailed} onClick={() => setShowDetailed((current) => !current)}>
          {showDetailed ? 'Back to overview' : 'View detailed flow'} <ChevronDown size={14} className={showDetailed ? 'is-rotated' : ''} />
        </button>
      </div>
      {showDetailed ? (
        <DetailedFlowchart />
      ) : (
        <div className="architecture-experience">
          <div className="architecture-diagram">
            <SecurityGateway selected={selected} onSelect={setSelected} />
            <CommunicationArrows />
            <ModelNode />
          </div>
          <div className="architecture-detail" aria-live="polite" key={activeGuard.id}>
            <span className="detail-signal" />
            <span className="detail-index">{activeGuard.index} / CONTROL DETAIL</span>
            <p><strong>{activeGuard.title}.</strong> {activeGuard.detail}</p>
            <span className="detail-direction">SELECT A CONTROL TO INSPECT</span>
          </div>
          <div className="architecture-legend"><span><i className="legend-request" /> Request & context</span><span><i className="legend-response" /> Policy & inspected result</span><span className="architecture-legend-note">Illustrative architecture · enforcement depends on gateway configuration</span></div>
        </div>
      )}
    </div>
  )
}
