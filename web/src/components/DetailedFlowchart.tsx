import { useMemo, useState } from 'react'
import {
  Activity,
  Ban,
  BrainCircuit,
  CircleCheck,
  Database,
  Diff,
  Fingerprint,
  FlaskConical,
  KeyRound,
  Network,
  PlugZap,
  ReceiptText,
  ScanSearch,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  UserRound,
  UserRoundCheck,
  Wrench,
  FileOutput,
  RotateCcw,
  type LucideIcon,
} from 'lucide-react'
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import { edgeDefinitions, nodeDefinitions, type WorkflowNodeData } from '../data/workflow'

const icons: Record<string, LucideIcon> = {
  activity: Activity,
  ban: Ban,
  brain: BrainCircuit,
  circleCheck: CircleCheck,
  database: Database,
  diff: Diff,
  fileOutput: FileOutput,
  fingerprint: Fingerprint,
  flask: FlaskConical,
  key: KeyRound,
  git: Network,
  plug: PlugZap,
  receipt: ReceiptText,
  rotate: RotateCcw,
  scan: ScanSearch,
  server: Server,
  shield: Shield,
  shieldAlert: ShieldAlert,
  shieldCheck: ShieldCheck,
  shieldX: ShieldX,
  user: UserRound,
  userCheck: UserRoundCheck,
  wrench: Wrench,
}

type DetailNode = Node<WorkflowNodeData>

function DetailNodeCard({ data }: NodeProps<DetailNode>) {
  const Icon = icons[data.icon] ?? ShieldCheck
  const groupLabel: Record<WorkflowNodeData['group'], string> = {
    flow: 'REQUEST PATH',
    check: 'SECURITY CHECK',
    decision: 'POLICY DECISION',
    execution: 'PROTECTED EXECUTION',
    feedback: 'MONITOR & LEARN',
  }
  return (
    <>
      <Handle type="target" position={Position.Left} id="in-left" />
      <Handle type="target" position={Position.Right} id="in-right" />
      <Handle type="target" position={Position.Top} id="in-top" />
      <Handle type="target" position={Position.Bottom} id="in-bottom" />
      <div className={'flow-node-card flow-node-' + data.group + (data.selected ? ' is-selected' : '')} aria-label={data.title + ': ' + data.subtitle}>
        <span className="flow-node-icon"><Icon size={15} strokeWidth={1.8} /></span>
        <span className="flow-node-copy">
          <span className="flow-node-title">{data.title}</span>
          <span className="flow-node-subtitle">{data.subtitle}</span>
        </span>
        <span className="flow-node-status">{groupLabel[data.group]}</span>
      </div>
      <Handle type="source" position={Position.Left} id="out-left" />
      <Handle type="source" position={Position.Right} id="out-right" />
      <Handle type="source" position={Position.Top} id="out-top" />
      <Handle type="source" position={Position.Bottom} id="out-bottom" />
    </>
  )
}

const nodeTypes = { detail: DetailNodeCard }
const edgeColors: Record<string, string> = {
  request: '#5d4fe1',
  response: '#8c84df',
  approval: '#d8ad63',
  deny: '#d67d78',
  review: '#9b9bb8',
  feedback: '#7978a8',
}

export function DetailedFlowchart() {
  const [selectedId, setSelectedId] = useState('gateway')
  const nodes = useMemo<DetailNode[]>(() => nodeDefinitions.map((node) => ({
    ...node,
    type: 'detail',
    data: { ...node.data, selected: node.id === selectedId },
  })), [selectedId])
  const edges = useMemo<Edge[]>(() => edgeDefinitions.map((edge) => {
    const tone = String(edge.data?.tone ?? 'request')
    const color = edgeColors[tone] ?? edgeColors.request
    return {
      ...edge,
      type: 'smoothstep',
      markerEnd: { type: MarkerType.ArrowClosed, color },
      style: { stroke: color, strokeWidth: 1.25, opacity: tone === 'feedback' ? .48 : .72, strokeDasharray: tone === 'review' ? '4 5' : undefined },
      labelStyle: { fill: tone === 'deny' ? '#df9892' : tone === 'approval' ? '#dfc582' : '#a7a9c6', fontFamily: 'DM Mono, monospace', fontSize: 8 },
      labelBgStyle: { fill: '#070810', fillOpacity: .94 },
      labelBgPadding: [4, 3] as [number, number],
      labelBgBorderRadius: 4,
    }
  }), [])
  const selected = nodeDefinitions.find((node) => node.id === selectedId) ?? nodeDefinitions[0]

  return (
    <div className="detail-flow-experience">
      <div className="flow-canvas-shell detail-flow-canvas-shell">
        <div className="flow-canvas-topline">
          <span><span className="live-dot" /> COMPLETE REQUEST · POLICY · RESPONSE PATH</span>
          <span className="canvas-hint">Pan to explore · Use controls to zoom · Select a node for details</span>
        </div>
        <div className="detail-flow-scroll">
          <div className="flow-desktop-canvas detail-flow-canvas" aria-label="Detailed MCP-Sentinel security flowchart">
            <ReactFlow
            key="complete-flow"
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            defaultViewport={{ x: 0, y: 0, zoom: .7 }}
            minZoom={.35}
            maxZoom={1.2}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable
            fitView
            fitViewOptions={{ padding: .08, minZoom: .5, maxZoom: 1 }}
            onInit={(instance) => {
              window.requestAnimationFrame(() => {
                instance.fitView({ padding: .08, minZoom: .5, maxZoom: 1 })
              })
            }}
            panOnDrag
            zoomOnScroll={false}
            zoomOnPinch
            zoomOnDoubleClick={false}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_event, node) => setSelectedId(node.id)}
          >
            <Background color="rgba(137, 139, 178,0.12)" gap={26} size={1} variant={BackgroundVariant.Dots} />
            <MiniMap
              pannable
              zoomable
              nodeColor={(node) => {
                const definition = nodeDefinitions.find((item) => item.id === node.id)
                const group = definition?.data.group
                if (group === 'decision') return '#bd9560'
                if (group === 'check') return '#3e3996'
                if (group === 'execution') return '#594d9c'
                if (group === 'feedback') return '#66668b'
                return '#555476'
              }}
              maskColor="rgba(3, 2, 7,.76)"
              className="flow-minimap"
            />
            <Controls position="bottom-right" showInteractive={false} />
            </ReactFlow>
          </div>
        </div>
      </div>
      <div className="detail-flow-inspector" aria-live="polite">
        <span className="detail-signal" />
        <div className="detail-flow-inspector-title"><small>{selected.data.group.toUpperCase()} · NODE DETAILS</small><strong>{selected.data.title}</strong></div>
        <p>{selected.data.description}</p>
        <div className="detail-flow-next"><small>NEXT</small><span>{selected.data.next}</span></div>
      </div>
      <div className="detail-flow-legend"><span><i className="legend-request" /> Request path</span><span><i className="legend-response" /> Result path</span><span><i className="legend-deny" /> Policy decision</span></div>
    </div>
  )
}
