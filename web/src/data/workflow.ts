import { MarkerType, type Edge, type Node } from '@xyflow/react'

export type NodeGroup = 'flow' | 'check' | 'decision' | 'execution' | 'feedback'

export type WorkflowNodeData = {
  title: string
  subtitle: string
  icon: string
  group: NodeGroup
  description: string
  checks: string
  produces: string
  next: string
  state?: 'idle' | 'active' | 'passed' | 'blocked' | 'warning'
  stateLabel?: string
  selected?: boolean
}

export type WorkflowStep = {
  nodeId: string
  message: string
  stateLabel: string
  state?: 'passed' | 'warning' | 'blocked'
  decision?: string
}

export type Scenario = {
  id: string
  eyebrow: string
  title: string
  tools: string
  description: string
  outcome: string
  outcomeTone: 'green' | 'red' | 'amber'
  steps: WorkflowStep[]
}

type NodeDef = Node<WorkflowNodeData>

export const nodeDefinitions: NodeDef[] = [
  { id: 'user_request', type: 'workflow', position: { x: 30, y: 35 }, data: { title: 'User request', subtitle: 'Intent & task', icon: 'user', group: 'flow', description: 'A person asks the AI application to complete a task that may involve MCP tools.', checks: 'The task intent and the authenticated session context.', produces: 'A request for the AI host to interpret.', next: 'The AI host decides whether a tool interaction is needed.' } },
  { id: 'ai_host', type: 'workflow', position: { x: 245, y: 35 }, data: { title: 'AI host / LLM', subtitle: 'Proposed action', icon: 'brain', group: 'flow', description: 'The host interprets the task and proposes a tool action.', checks: 'Conversation context and the tool request produced by the host.', produces: 'A proposed MCP call.', next: 'The MCP client carries it toward the protected gateway.' } },
  { id: 'mcp_client', type: 'workflow', position: { x: 460, y: 35 }, data: { title: 'MCP client', subtitle: 'Protocol request', icon: 'plug', group: 'flow', description: 'The client issues an MCP request. For enforcement to work, protected calls must be configured to pass through MCP-Sentinel.', checks: 'The method, tool name, arguments, and configured destination.', produces: 'A request routed to the gateway.', next: 'MCP-Sentinel becomes the enforcement boundary.' } },
  { id: 'gateway', type: 'workflow', position: { x: 675, y: 35 }, data: { title: 'MCP-Sentinel', subtitle: 'Security gateway', icon: 'shield', group: 'flow', description: 'The gateway coordinates pre-execution checks, policy decisions, forwarding, response inspection, and audit evidence.', checks: 'Identity, tool trust, capabilities, request context, and available behavior signals.', produces: 'An enforceable decision before a protected request is forwarded.', next: 'Pre-flight validation begins.' } },
  { id: 'identity', type: 'workflow', position: { x: 675, y: 180 }, data: { title: 'Identity verification', subtitle: 'Who is asking?', icon: 'fingerprint', group: 'check', description: 'Verifies who is requesting the tool action.', checks: 'Identity, roles, and scopes.', produces: 'Verified identity context.', next: 'The tool baseline is checked.' } },
  { id: 'integrity', type: 'workflow', position: { x: 460, y: 180 }, data: { title: 'Tool integrity', subtitle: 'Approved baseline', icon: 'scan', group: 'check', description: 'Checks whether the registered tool still matches its approved baseline.', checks: 'Version, schema, and declared capabilities.', produces: 'Tool trust evidence.', next: 'The request context is checked.' } },
  { id: 'context', type: 'workflow', position: { x: 245, y: 180 }, data: { title: 'Workflow context & policy', subtitle: 'Does it fit?', icon: 'git', group: 'check', description: 'Checks the request against the workflow, permissions, data sensitivity, and destination.', checks: 'Call sequence and policy rules.', produces: 'Policy and context evidence.', next: 'Selected tools are tested in isolation.' } },
  { id: 'sandbox', type: 'workflow', position: { x: 30, y: 180 }, data: { title: 'Sandbox isolation', subtitle: 'Test selected tools', icon: 'flask', group: 'check', description: 'Tests selected tools with synthetic data and controlled resources before execution.', checks: 'Dummy credentials, isolated filesystem and network, and limits.', produces: 'Behavior evidence for the decision.', next: 'The evidence is assessed for risk.' } },
  { id: 'risk', type: 'workflow', position: { x: 30, y: 325 }, data: { title: 'Risk assessment', subtitle: 'Evidence → response', icon: 'gauge', group: 'check', description: 'Combines the available evidence into a clear security state.', checks: 'Identity, integrity, policy, and sandbox evidence.', produces: 'A recommended decision.', next: 'The request is allowed or blocked.' } },
  { id: 'decision', type: 'workflow', position: { x: 245, y: 325 }, data: { title: 'Allow or block', subtitle: 'Policy decision', icon: 'shieldCheck', group: 'decision', description: 'Applies policy before the request reaches the tool.', checks: 'The current request and security evidence.', produces: 'Allow or deny.', next: 'Allowed requests continue to protected execution.' } },
  { id: 'execution', type: 'workflow', position: { x: 460, y: 325 }, data: { title: 'Protected tool execution', subtitle: 'MCP server + tool', icon: 'server', group: 'execution', description: 'The approved request reaches the MCP server and selected tool.', checks: 'Server-side authorization and tool controls.', produces: 'A tool result.', next: 'The result returns through the gateway.' } },
  { id: 'result', type: 'workflow', position: { x: 675, y: 325 }, data: { title: 'Tool result', subtitle: 'Return to the AI app', icon: 'fileOutput', group: 'feedback', description: 'The tool result returns through the protected path to the AI application.', checks: 'Result content and configured response rules.', produces: 'A response for the AI host.', next: 'The client returns the result to the host.' } },
]

const edge = (id: string, source: string, target: string, tone = 'request', label?: string): Edge => {
  const sourceNode = nodeDefinitions.find((item) => item.id === source)
  const targetNode = nodeDefinitions.find((item) => item.id === target)
  const dx = (targetNode?.position.x ?? 0) - (sourceNode?.position.x ?? 0)
  const dy = (targetNode?.position.y ?? 0) - (sourceNode?.position.y ?? 0)
  const fromSide = Math.abs(dx) >= Math.abs(dy)
    ? (dx >= 0 ? 'right' : 'left')
    : (dy >= 0 ? 'bottom' : 'top')
  const toSide = fromSide === 'right' ? 'left'
    : fromSide === 'left' ? 'right'
      : fromSide === 'bottom' ? 'top' : 'bottom'
  return {
    id,
    source,
    target,
    sourceHandle: 'out-' + fromSide,
    targetHandle: 'in-' + toSide,
    type: 'signal',
    label,
    data: { tone },
    markerEnd: { type: MarkerType.ArrowClosed },
  }
}

export const edgeDefinitions: Edge[] = [
  edge('e-request-host', 'user_request', 'ai_host'),
  edge('e-host-client', 'ai_host', 'mcp_client'),
  edge('e-client-gateway', 'mcp_client', 'gateway'),
  edge('e-gateway-identity', 'gateway', 'identity'),
  edge('e-identity-integrity', 'identity', 'integrity'),
  edge('e-integrity-context', 'integrity', 'context'),
  edge('e-context-sandbox', 'context', 'sandbox'),
  edge('e-sandbox-risk', 'sandbox', 'risk', 'review'),
  edge('e-risk-decision', 'risk', 'decision'),
  edge('e-decision-execution', 'decision', 'execution'),
  edge('e-execution-result', 'execution', 'result', 'response'),
]

const step = (nodeId: string, message: string, stateLabel: string, state?: WorkflowStep['state'], decision?: string): WorkflowStep =>
  ({ nodeId, message, stateLabel, state, decision })

export const scenarios: Scenario[] = [
  {
    id: 'normal',
    eyebrow: 'Scenario A',
    title: 'Normal investigation',
    tools: 'search_logs()  →  lookup_ip()  →  create_incident()',
    description: 'A security analyst investigates a suspicious login through a permitted sequence.',
    outcome: 'ALLOWED',
    outcomeTone: 'green',
    steps: [
      step('user_request', 'An analyst asks the assistant to investigate a suspicious login.', 'REQUEST RECEIVED'),
      step('ai_host', 'The host proposes a log search, IP lookup, and incident creation.', 'ACTION PROPOSED'),
      step('mcp_client', 'The MCP client routes the proposed call through the configured gateway.', 'ROUTED TO GATEWAY'),
      step('gateway', 'MCP-Sentinel begins the pre-execution checks.', 'PRE-FLIGHT'),
      step('identity', 'The analyst identity and required scopes are valid for this task.', 'IDENTITY VERIFIED', 'passed'),
      step('integrity', 'The registered server and tool match the approved baseline in this illustration.', 'BASELINE MATCH', 'passed'),
      step('semantic', 'No unexpected capability expansion is shown in this scenario.', 'NO CHANGE FLAG', 'passed'),
      step('input_lease', 'Arguments match the tool schema and the lease covers the log resource.', 'SCOPE VALID', 'passed'),
      step('context', 'The investigation sequence fits the configured workflow policy.', 'CONTEXT FITS', 'passed'),
      step('risk', 'Available signals support the configured allow decision.', 'LOWER RISK SIGNALS', 'passed'),
      step('allow', 'Policy permits this request; monitoring continues as configured.', 'PERMITTED', 'passed', 'ALLOWED'),
      step('server', 'The protected MCP server receives the approved request.', 'FORWARDED', 'passed'),
      step('tool', 'The selected tool executes within its server-side controls.', 'EXECUTING', 'passed'),
      step('resource', 'The tool accesses the intended security log resource.', 'SCOPED ACCESS', 'passed'),
      step('result', 'A tool result returns through the protected path.', 'RESULT RECEIVED', 'passed'),
      step('output_guard', 'The response and data-flow checks complete for the configured policy.', 'OUTPUT CHECKED', 'passed'),
      step('gateway', 'The inspected result is returned through MCP-Sentinel.', 'RESPONSE CLEARED', 'passed'),
      step('mcp_client', 'The client receives the gateway-cleared response.', 'RETURNED TO CLIENT', 'passed'),
      step('ai_host', 'The AI host receives the response for the user’s task.', 'RESULT DELIVERED', 'passed'),
      step('runtime', 'Available runtime evidence is included in monitoring.', 'MONITORING', 'passed'),
      step('audit', 'The decision and relevant evidence are recorded.', 'RECEIPT RECORDED', 'passed'),
      step('feedback', 'Relevant findings can inform the next request assessment.', 'FEEDBACK READY', 'passed'),
    ],
  },
  {
    id: 'sequence',
    eyebrow: 'Scenario B',
    title: 'Suspicious call sequence',
    tools: 'search_logs()  →  get_credentials()  →  send_data()',
    description: 'A sequence that attempts to retrieve credentials and send sensitive data reaches a policy boundary.',
    outcome: 'BLOCKED',
    outcomeTone: 'red',
    steps: [
      step('user_request', 'A request begins as a routine investigation.', 'REQUEST RECEIVED'),
      step('ai_host', 'The proposed sequence shifts from log search to credential access and data transfer.', 'SEQUENCE PROPOSED', 'warning'),
      step('mcp_client', 'The client routes the request through MCP-Sentinel.', 'ROUTED TO GATEWAY'),
      step('gateway', 'The gateway evaluates the request before any protected forwarding.', 'PRE-FLIGHT'),
      step('identity', 'Identity is checked; valid identity alone does not authorise every action.', 'IDENTITY CHECKED', 'passed'),
      step('integrity', 'The registered tool identity is checked against its approved baseline.', 'BASELINE CHECKED', 'passed'),
      step('input_lease', 'The requested credential scope is not covered by the investigation lease.', 'SCOPE MISMATCH', 'warning'),
      step('context', 'The call history and proposed destination create a prohibited data-flow under this scenario’s configured rules.', 'PROHIBITED FLOW', 'blocked'),
      step('risk', 'Context and policy evidence require a denial; a risk score cannot override the rule.', 'POLICY DENIAL', 'blocked'),
      step('block', 'The pending transfer is denied and is not sent to the protected tool.', 'NOT FORWARDED', 'blocked', 'BLOCKED'),
      step('audit', 'The denial reason and relevant call sequence are recorded without logging secrets.', 'DENIAL RECORDED', 'passed'),
      step('feedback', 'The security event is available to inform a later assessment.', 'FEEDBACK READY', 'passed'),
    ],
  },
  {
    id: 'changed',
    eyebrow: 'Scenario C',
    title: 'Unexpected tool change',
    tools: 'Fingerprint change  →  sample behavior alert  →  reassessment',
    description: 'A previously approved tool changes and illustrative sample signals prompt a restricted response.',
    outcome: 'RESTRICTED / QUARANTINED',
    outcomeTone: 'amber',
    steps: [
      step('user_request', 'A request arrives for a tool that was previously approved.', 'REQUEST RECEIVED'),
      step('ai_host', 'The host proposes using the registered tool for the task.', 'ACTION PROPOSED'),
      step('mcp_client', 'The MCP client routes it through the gateway.', 'ROUTED TO GATEWAY'),
      step('gateway', 'The gateway checks the current trust evidence before forwarding.', 'PRE-FLIGHT'),
      step('identity', 'The requester is verified for this workflow.', 'IDENTITY VERIFIED', 'passed'),
      step('integrity', 'The current fingerprint differs from the recorded baseline.', 'CHANGE DETECTED', 'warning'),
      step('runtime', 'Illustrative sample evidence shows environment access and an undeclared network destination; no live host telemetry is being read.', 'SAMPLE ALERT', 'warning'),
      step('risk', 'Changed identity plus sample behavior signals trigger a risk reassessment.', 'REASSESSMENT', 'warning'),
      step('restrict', 'The configured response revokes or narrows the active capability lease.', 'LEASE REVOKED', 'warning'),
      step('quarantine', 'The sample policy isolates the tool from protected execution pending review.', 'QUARANTINED', 'blocked', 'RESTRICTED / QUARANTINED'),
      step('audit', 'The change, response, and evidence summary are recorded.', 'RECEIPT RECORDED', 'passed'),
      step('feedback', 'The new trust evidence informs subsequent assessments.', 'FEEDBACK READY', 'passed'),
    ],
  },
]

export const stepEdge = (from: string, to: string) =>
  edgeDefinitions.find((item) => item.source === from && item.target === to)?.id
