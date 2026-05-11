# OpenClaw Runtime Threat Surface & Taxonomy

Complete enumeration of all runtime layers, threat surfaces, propagation paths, and integrity attack vectors.

## LAYER 1: PROMPT ASSEMBLY & PROJECTION

### Surface Map
```
System Prompt → Developer Instructions → Workspace Context → User Input → Final Prompt
     ↓              ↓                        ↓                  ↓            ↓
  Hidden          Instruction           Project Files      Hidden         Escape
  Delimiters      Override              Injection          Markers        Sequences
```

### Trust Assumptions
- System prompt integrity is foundational
- Developer instructions are trusted
- User input is inherently hostile
- Prompt delimiters are respected
- Recency = priority

### Attack Surface
1. **Prompt Injection** (basic)
   - Location: user message end or system prompt end
   - Marker: `Ignore previous instructions` or escaped newlines
   - Propagation: → Tool execution decisions → LLM input
   - Persistence: Single turn

2. **Recursive Prompt Override**
   - Location: nested instruction markers
   - Marker: `[OVERRIDE >> [NESTED_OVERRIDE >>` or similar recursion
   - Propagation: → Multi-turn persistence → Context injection
   - Persistence: Cross-turn via context hydration

3. **Multiline Prompt Escape**
   - Location: newline + indentation manipulation
   - Marker: `\nIgnore:\n` or `\nNew role:` 
   - Propagation: → Prompt assembly logic → Tool decisions
   - Persistence: Single turn (unless replayed)

4. **Hidden Directive Injection**
   - Location: HTML comments, zero-width chars, markdown
   - Marker: `<!-- HIDDEN: directive -->` or `‌‌‌` (zero-width)
   - Propagation: → Latent in prompt → May survive sanitization
   - Persistence: Until prompt regeneration

5. **Instruction Precedence Exploitation**
   - Location: System vs Developer vs User hierarchy
   - Marker: Conflicting instructions at different levels
   - Propagation: → Decision point confusion → Unsafe actions
   - Persistence: Single turn

6. **Delimiter Ambiguity Exploitation**
   - Location: Prompt section boundaries
   - Marker: Fake delimiters mimicking real ones
   - Propagation: → Context assembly logic → Token miscounting
   - Persistence: Until context refresh

### Telemetry Points
- `prompt_assembly_start`: Snapshot all input sources
- `prompt_section_merge`: Track order and precedence
- `before_prompt_build`: Detect injection markers
- `prompt_build_complete`: Final prompt structure
- `prompt_token_count`: Measure changes

### Integrity Metrics
- `instruction_drift_score`: Deviation from expected system behavior
- `prompt_override_success_likelihood`: Detection evasion rate
- `hidden_directive_survivability`: Persistence across rounds
- `delimiter_integrity`: Valid section boundaries

---

## LAYER 2: CONTEXT ENGINE & TRANSCRIPT REPLAY

### Surface Map
```
Message History → Retrieval → Summarization → Truncation → Context Window
      ↓             ↓               ↓             ↓             ↓
  Poisoned      Outdated        Corrupted    Lost Data     Overflow
  Messages      Results         Summaries    Truncation    Injection
```

### Trust Assumptions
- Historical messages are authentic
- Summarization preserves semantics
- Truncation removes least relevant data
- Context window is sufficient
- Message timestamps are accurate

### Attack Surface
1. **Context Message Poisoning**
   - Location: Historical message injection
   - Marker: Fake messages appearing before real ones
   - Propagation: → Context projection → Tool execution → LLM decisions
   - Persistence: Cross-turn (lives in transcript mirror)

2. **Context Summarization Corruption**
   - Location: Summary token replacement
   - Marker: Injected summary tokens that reframe context
   - Propagation: → Context reduction → Lost semantic fidelity → Wrong decisions
   - Persistence: Multi-turn (summary cached)

3. **Memory Truncation Exploitation**
   - Location: FIFO message removal
   - Marker: Strategic placement of instructions in removed messages
   - Propagation: → Invisible to current context → But remembered by agent
   - Persistence: Cross-turn (agent memory independent)

4. **Context Replay Injection**
   - Location: Historical message timestamp manipulation
   - Marker: Out-of-order message timestamps
   - Propagation: → Context assembly anomalies → Event ordering issues
   - Persistence: Multi-turn via transcript mirror

5. **Retrieval Augmentation Poisoning**
   - Location: RAG document injection
   - Marker: Injected documents matching query terms
   - Propagation: → Context retrieved → Treated as authoritative → LLM misled
   - Persistence: Depends on RAG store persistence

6. **Context Growth Amplification**
   - Location: Payload that triggers context expansion
   - Marker: Large injected payloads with high token cost
   - Propagation: → Token budget exhaustion → Context truncation → Lost information
   - Persistence: Single turn (but may cause cascading effects)

### Telemetry Points
- `context_projection_start`: Message count, total tokens
- `message_load`: Per-message timestamp, source, trust level
- `summarization_executed`: Original vs. summary token delta
- `truncation_applied`: What was removed and why
- `context_projection_complete`: Final state

### Integrity Metrics
- `context_corruption_severity`: Injected vs. authentic message ratio
- `message_ordering_anomalies`: Out-of-sequence detection
- `truncation_impact`: Lost information percentage
- `memory_contamination_score`: False memories introduced

---

## LAYER 3: TOOL RUNTIME & EXECUTION

### Surface Map
```
Tool Schema → Argument Prep → Execute → Result Transform → Persistence
     ↓            ↓             ↓            ↓                ↓
  Poisoned    Injection      Unsafe       Corruption      Contamination
  Schema      Params         Execution    Replacement     Storage
```

### Trust Assumptions
- Tool schemas are accurate
- Argument validation prevents exploitation
- Tool execution is isolated
- Results are accurately captured
- Tool results are not maliciously modified

### Attack Surface
1. **Tool Result Injection**
   - Location: Fake tool result in execution flow
   - Marker: Modified `tool_result` field or intercepted response
   - Propagation: → LLM reasoning → Agent decisions → Next actions
   - Persistence: Single turn (unless replayed)

2. **Tool Schema Poisoning**
   - Location: Tool spec modification
   - Marker: Extra parameters, changed descriptions
   - Propagation: → Argument preparation → Tool invocation → Execution
   - Persistence: Until schema refresh

3. **Tool Trust Score Manipulation**
   - Location: Trust metadata injection
   - Marker: `{"result": "...", "trust_score": 1.0}` (fake)
   - Propagation: → Result validation skip → Unsafe execution
   - Persistence: Single turn

4. **Tool Argument Injection**
   - Location: Dynamic tool argument construction
   - Marker: Injected parameters in argument list
   - Propagation: → Tool execution → Side effects → Unsafe operations
   - Persistence: Depends on tool side effects

5. **Tool Result Persistence Attack**
   - Location: Tool result cache or transcript
   - Marker: Cached false results replayed as fact
   - Propagation: → Context reuse → Multi-turn false reasoning
   - Persistence: Cross-turn via cache/transcript

6. **Middleware Chain Corruption**
   - Location: Tool middleware stack manipulation
   - Marker: Injected middleware that modifies inputs/outputs
   - Propagation: → All downstream tool calls affected
   - Persistence: Depends on middleware registration

### Telemetry Points
- `tool_registration`: Schema snapshot, capabilities
- `before_tool_call`: Arguments, trust level
- `tool_execute_boundary`: Actual vs. expected execution
- `after_tool_call`: Result capture, modifications
- `tool_result_cached`: Persistence target

### Integrity Metrics
- `unsafe_tool_execution_probability`: How often validation skipped
- `tool_trust_corruption_score`: False trust levels
- `tool_result_authenticity`: Original vs. modified ratio
- `middleware_chain_integrity`: Unexpected modifications

---

## LAYER 4: EVENT STREAM & NOTIFICATION

### Surface Map
```
Event Gen → Queue → Ordering → Aggregation → Handler → State Mutation
    ↓         ↓         ↓            ↓            ↓           ↓
  Fake     Reorder   Out-of-     Lost         Bypass     Corruption
  Events   Order     Sequence    Events       Handler    Propagation
```

### Trust Assumptions
- Event sequence is causal
- Event timestamps are accurate
- All events are processed
- Event handlers are isolated
- State mutations are atomic

### Attack Surface
1. **Event Replay Injection**
   - Location: Historical event reinjection
   - Marker: Duplicate event ID with new timestamp
   - Propagation: → State replication → Memory mutation → Wrong behavior
   - Persistence: Cross-turn via event log

2. **Event Ordering Anomaly**
   - Location: Out-of-sequence event delivery
   - Marker: Tool-result event before tool-call event
   - Propagation: → State machine confusion → Invalid transitions
   - Persistence: Single turn (or until recovery)

3. **Event Aggregation Bypass**
   - Location: Partial event delivery
   - Marker: Missing intermediate events in sequence
   - Propagation: → Incomplete state picture → Wrong decisions
   - Persistence: Single turn

4. **Notification Queue Poisoning**
   - Location: Fake notifications in queue
   - Marker: `{"type": "tool_result", "data": "INJECTED"}`
   - Propagation: → Handler execution → State mutation
   - Persistence: Single turn (but effects persist)

5. **Projector State Mutation**
   - Location: Event handler side effects
   - Marker: Untracked state changes in handlers
   - Propagation: → Hidden state corruption → Silent behavior changes
   - Persistence: Cross-turn (state mutation is permanent)

6. **Completion Synchronization Bypass**
   - Location: Turn completion detection
   - Marker: Premature or delayed completion signals
   - Propagation: → Next turn starts early/late → Context mismatch
   - Persistence: Cross-turn (affects subsequent turns)

### Telemetry Points
- `event_generated`: Event type, timestamp, source
- `event_queued`: Queue depth, order
- `event_processing`: Handler execution, state before/after
- `turn_completion_idle`: Activity detection
- `completion_finalized`: Final state snapshot

### Integrity Metrics
- `event_ordering_anomalies`: Out-of-sequence detections
- `replay_detection_rate`: Duplicate events identified
- `completion_latency_anomalies`: Unexpected timing
- `projector_mutation_unexplained`: Untracked changes

---

## LAYER 5: HOOK SYSTEM & MIDDLEWARE

### Surface Map
```
before_prompt_build → before_tool_call → after_tool_call → agent_end
        ↓                   ↓                   ↓                ↓
    Inject          Bypass/Modify         Corrupt Results    Hide Evidence
    Instructions    Execution             Propagate Changes
```

### Trust Assumptions
- Hook handlers are isolated
- Hook execution order is deterministic
- Hooks cannot modify execution flow (intentionally)
- Hook state doesn't leak to other hooks

### Attack Surface
1. **Hook Handler Injection**
   - Location: Hook middleware stack manipulation
   - Marker: Injected handler in hook chain
   - Propagation: → All downstream hooks see modified state
   - Persistence: Until hook refresh

2. **Hook Mutation Amplification**
   - Location: Cascading hook mutations
   - Marker: Hook A modifies state → Hook B detects change → Amplifies change
   - Propagation: → Recursive mutation → State explosion
   - Persistence: Single turn (but severe)

3. **Hook Execution Order Exploitation**
   - Location: Hook middleware order dependency
   - Marker: Different results depending on execution order
   - Propagation: → Non-deterministic behavior → Unpredictable
   - Persistence: Single turn

4. **Hook State Leakage**
   - Location: Hook context variables
   - Marker: Hooks sharing internal state via closure
   - Propagation: → State carries across hook invocations
   - Persistence: Cross-turn if state persists

5. **Native Hook Relay Exploitation**
   - Location: Native runtime relay hooks
   - Marker: Intercepting relay to modify messages
   - Propagation: → All downstream consumers see modified message
   - Persistence: Depends on relay persistence

### Telemetry Points
- `before_prompt_build`: Hook invocation, state before/after
- `before_tool_call`: Hook count, modifications
- `after_tool_call`: Handler execution, mutation detection
- `hook_completion`: Final state signature

### Integrity Metrics
- `hook_mutation_unexplained_count`: Untracked state changes
- `hook_execution_determinism`: Consistency across runs
- `hook_state_leakage_detection`: Cross-hook contamination

---

## LAYER 6: MEMORY & PERSISTENCE

### Surface Map
```
Turn Session → Transcript Mirror → Long-Term Store → Cross-Session Load
     ↓              ↓                    ↓                    ↓
  Poisoned     Corruption          Persistence         Reactivation
  In-Memory    Recorded            Vulnerabilities     Attack
```

### Trust Assumptions
- In-memory state is ephemeral
- Transcript mirrors are accurate
- Long-term store is append-only
- Cross-session loading is safe
- Timestamps prove causality

### Attack Surface
1. **Cross-Turn Memory Persistence**
   - Location: Agent memory carry-over
   - Marker: Learned behavior from previous turn
   - Propagation: → Influences decisions in subsequent turns
   - Persistence: Multi-turn (survives turn boundary)

2. **Transcript Mirror Corruption**
   - Location: Session file modification
   - Marker: Altered message records in transcript
   - Propagation: → Context reloads see corrupted history
   - Persistence: Multi-turn (persists across session restart)

3. **Delayed Activation Payload**
   - Location: Instruction that triggers later
   - Marker: Conditional activation based on future state
   - Propagation: → Dormant until condition met → Activates later
   - Persistence: Cross-turn (waits for right moment)

4. **Memory Summarization Attack**
   - Location: Long-term memory compression
   - Marker: Injected summary that rewrites history
   - Propagation: → Historical context misrepresented
   - Persistence: Cross-session (affects future loads)

5. **Credential/Secret Persistence**
   - Location: Sensitive data in transcript
   - Marker: Credentials captured in message logs
   - Propagation: → Available to future sessions/agents
   - Persistence: Cross-session + multi-agent

### Telemetry Points
- `turn_session_start`: Initial state
- `cross_turn_memory_load`: What's loaded from previous turns
- `transcript_mirror_checkpoint`: Periodic integrity snapshot
- `memory_recall_request`: What's being accessed
- `long_term_store_write`: What's being persisted

### Integrity Metrics
- `multi_turn_persistence_detected`: Cross-turn influence
- `transcript_corruption_severity`: Detected alterations
- `memory_contamination_score`: False memories activated
- `delayed_activation_risk`: Dormant payload detection

---

## LAYER 7: MULTI-AGENT & DELEGATION

### Surface Map
```
Planner → Orchestrate → Sub-Agent Spawn → Agent Execution → Result Merge
    ↓         ↓                 ↓                  ↓               ↓
  Corrupt   Hijack          Malicious        Compromise        Poisoned
  Plan      Authority       Delegation       Agent             Results
```

### Trust Assumptions
- Planner decisions are sound
- Delegation chains are auditable
- Sub-agents are isolated
- Agent-to-agent communication is protected
- Result merging preserves semantics

### Attack Surface
1. **Planner Corruption**
   - Location: High-level plan generation
   - Marker: Malicious plan structure
   - Propagation: → All delegated agents follow corrupt plan
   - Persistence: Multi-agent (affects all descendants)

2. **Delegation Chain Hijacking**
   - Location: Inter-agent message modification
   - Marker: Altered delegation parameters
   - Propagation: → Sub-agent executes wrong instructions
   - Persistence: Single delegation (but multi-turn for sub-agent)

3. **Sub-Agent Authority Spoofing**
   - Location: Agent identity impersonation
   - Marker: Fake `agent_id` or `authority_level`
   - Propagation: → Sub-agent trusts spoofed authority
   - Persistence: Until sub-agent verification

4. **Multi-Agent Contamination**
   - Location: Shared state between agents
   - Marker: One compromised agent affects siblings
   - Propagation: → Contamination spreads across agent tree
   - Persistence: Cross-agent

5. **Result Merge Injection**
   - Location: Sub-agent result aggregation
   - Marker: Injected results merged with real results
   - Propagation: → Parent agent sees mixed truth/false
   - Persistence: Single merge (but may affect parent decisions)

### Telemetry Points
- `agent_spawn_point`: Plan structure, delegation params
- `delegation_checkpoint`: Inter-agent message
- `agent_isolation_boundary`: Trust domain crossing
- `result_merge_point`: Aggregation logic
- `agent_completion_signal`: Final state per agent

### Integrity Metrics
- `planner_integrity_score`: Plan corruption detection
- `delegation_chain_authenticity`: Verified authority
- `agent_isolation_breach_detection`: Unexpected state sharing
- `result_merge_contamination`: Fake vs. real data ratio

---

## LAYER 8: MCP / EXTERNAL TOOL ECOSYSTEM

### Surface Map
```
MCP Registration → Server Discovery → Tool Catalog → Tool Invocation → Result Handling
       ↓                ↓                  ↓               ↓                 ↓
  Malicious       Namespace         Schema            Unsafe         Resource
  Server          Collision         Poisoning        Execution       Exfiltration
```

### Trust Assumptions
- MCP servers are vetted
- Tool namespaces are unique
- Tool schemas are accurate
- External tools are sandboxed
- No capability escalation possible

### Attack Surface
1. **Malicious MCP Server Registration**
   - Location: MCP server list
   - Marker: Rogue server claiming legitimate tools
   - Propagation: → Tool discovery loads malicious server
   - Persistence: Until server deregistration

2. **Namespace Collision**
   - Location: Tool name/ID space
   - Marker: Two tools with same name (different servers)
   - Propagation: → Wrong tool may be called
   - Persistence: Until resolution policy applied

3. **Tool Catalog Poisoning**
   - Location: Available tools list
   - Marker: Fake tools advertised in catalog
   - Propagation: → Agent selects fake tool
   - Persistence: Until catalog refresh

4. **Capability Escalation via Tool Chaining**
   - Location: Tool combination
   - Marker: Multiple low-capability tools combine for high capability
   - Propagation: → Unintended capability unlocked
   - Persistence: Single turn (but severe)

5. **External Tool Result Injection**
   - Location: Tool result handler
   - Marker: Fake result from legitimate tool
   - Propagation: → Agent trusts result
   - Persistence: Single turn

6. **Resource Exfiltration via External Tools**
   - Location: External tool side effects
   - Marker: Data flowing to external service
   - Propagation: → Information leaves closed system
   - Persistence: Depends on external logging

### Telemetry Points
- `mcp_server_registration`: Server identity, capabilities
- `tool_discovery`: Which tools discovered from which server
- `tool_invocation_external_boundary`: Outbound tool calls
- `result_ingestion_external_source`: Results from external
- `capability_authorization_check`: Permission verification

### Integrity Metrics
- `namespace_collision_detection`: Duplicate tool names
- `mcp_server_trust_verification`: Server authentication
- `external_tool_result_authenticity`: Fake vs. real detection
- `resource_exfiltration_detection`: Data leaving system

---

## LAYER 9: PLUGIN RUNTIME & EXTENSION

### Surface Map
```
Plugin Load → Lifecycle → Capability Injection → Side Effects → Hook Integration
     ↓           ↓              ↓                   ↓                ↓
  Malicious  Corruption      Unauthorized      Contamination     Hijacking
  Plugin     Lifecycle       Capability        Propagation
```

### Trust Assumptions
- Plugin manifests are accurate
- Plugin code is isolated
- Capabilities are declared
- Lifecycle is deterministic
- No side effects outside plugin scope

### Attack Surface
1. **Malicious Plugin Loading**
   - Location: Plugin manifest
   - Marker: Fake or corrupted manifest
   - Propagation: → Malicious code runs in plugin context
   - Persistence: Cross-turn (plugin remains loaded)

2. **Plugin Lifecycle Exploitation**
   - Location: Plugin init/activate/deactivate
   - Marker: Unexpected state mutations during lifecycle
   - Propagation: → Hidden initialization side effects
   - Persistence: Depends on side effect

3. **Unauthorized Capability Injection**
   - Location: Plugin capability registration
   - Marker: Plugin declaring capabilities it doesn't own
   - Propagation: → Core system grants trust to false claims
   - Persistence: Until plugin deloaded

4. **Plugin Side Effect Propagation**
   - Location: Plugin global state mutations
   - Marker: Plugins sharing internal state
   - Propagation: → One plugin's side effects affect others
   - Persistence: Cross-plugin

5. **Hook Integration Hijacking**
   - Location: Plugin hook registration
   - Marker: Plugin hook intercepting core events
   - Propagation: → Plugin controls core behavior
   - Persistence: While plugin loaded

### Telemetry Points
- `plugin_discovery`: Plugin identity, manifest
- `plugin_load`: Lifecycle start, capability claims
- `plugin_hook_registration`: Which hooks hooked
- `plugin_side_effect_detection`: Mutations outside scope
- `plugin_unload`: Cleanup, state verification

### Integrity Metrics
- `plugin_manifest_integrity`: Manifest vs. actual capability
- `plugin_isolation_breach`: Unexpected state sharing
- `plugin_hook_hijacking_detection`: Unauthorized hooks
- `plugin_lifecycle_corruption`: Unexpected state changes

---

## LAYER 10: GATEWAY & RUNTIME ORCHESTRATION

### Surface Map
```
Request Dispatch → Runtime Selection → Approval Flow → Policy Sync → Runtime Impersonation
       ↓                 ↓                   ↓              ↓                  ↓
  Routing         Wrong Runtime      Approval         Policy              Authority
  Hijacking       Selection          Bypass           Desync              Spoofing
```

### Trust Assumptions
- Request routing is accurate
- Runtime selection is deterministic
- Approval gates are enforced
- Policies are synchronized
- Runtime identity is verified

### Attack Surface
1. **Gateway Routing Hijacking**
   - Location: Request routing decision
   - Marker: Request routed to wrong runtime/thread
   - Propagation: → Wrong context receives request
   - Persistence: Until next routing decision

2. **Runtime Selection Corruption**
   - Location: Runtime selection logic
   - Marker: Malicious runtime selected
   - Propagation: → Request executed in wrong context
   - Persistence: Single routing (but effects persist)

3. **Approval Mode Degradation**
   - Location: Approval gate logic
   - Marker: Approval skipped or weakened
   - Propagation: → Unsafe actions approved
   - Persistence: Single turn (but severe)

4. **Policy Synchronization Desync**
   - Location: Policy propagation
   - Marker: Different runtimes have different policies
   - Propagation: → Inconsistent enforcement
   - Persistence: Until resync

5. **Runtime Impersonation**
   - Location: Runtime identity verification
   - Marker: Fake runtime claiming legitimate identity
   - Propagation: → Requests trusted to malicious runtime
   - Persistence: Until impersonation detected

6. **Transport Boundary Violation**
   - Location: Inter-process communication
   - Marker: Message tampering in transit
   - Propagation: → Corrupted messages delivered
   - Persistence: Single message (but may be critical)

### Telemetry Points
- `request_dispatch`: Request identity, target
- `runtime_selection`: Which runtime chosen, why
- `approval_gate`: Decision, enforcement
- `policy_enforcement`: Policy version, enforcement
- `runtime_identity_verification`: Trust verification

### Integrity Metrics
- `routing_anomalies`: Unexpected routing decisions
- `approval_gate_enforcement`: Skip detection
- `policy_sync_drift`: Inconsistencies across runtimes
- `runtime_identity_spoofing_detection`: Fake runtime detection

---

## CROSS-LAYER PROPAGATION MATRIX

```
Layer A → Layer B: Propagation Path

Prompt → Tool:
  - Prompt injection influences tool selection
  - Hidden directives enable unsafe tool calls
  - Recursive override amplifies via tool chaining

Tool → Context:
  - Tool result injection poisons context
  - Tool trust score enables replay
  - Tool schema poisoning affects future tool discovery

Context → Memory:
  - Poisoned context enters transcript
  - Corrupted summarization rewrites history
  - Truncation hides evidence

Memory → Prompt:
  - Loaded memory influences prompt assembly
  - Delayed activation triggers on context reload
  - Cross-turn persistence enables multi-turn attacks

Hook → Tool:
  - Hook mutation affects tool arguments
  - Hook injection modifies tool results
  - Hook ordering exploit changes execution

Event → State:
  - Event replay mutates state
  - Event ordering changes behavior
  - Notification poison triggers actions

Multi-Agent → Planner:
  - Sub-agent corruption compromises plan
  - Result injection affects parent decisions
  - Delegation hijacking redirects work

MCP → Core:
  - Malicious tool affects core decisions
  - Namespace collision uses wrong tool
  - Capability escalation via tool chaining

Plugin → Hooks:
  - Plugin hijacks hooks
  - Plugin side effects propagate
  - Plugin lifecycle affects core

Gateway → All Layers:
  - Approval bypass affects all downstream
  - Runtime impersonation affects context
  - Policy desync creates inconsistencies
```

---

## PERSISTENCE & REPLAY VECTORS

### Single-Turn Persistence
- Prompt injection (visible in this turn)
- Tool result injection (affects this turn only)
- Event replay (affects this turn only)
- Hook injection (affects this turn only)

### Cross-Turn Persistence
- Context poisoning (loaded next turn)
- Memory contamination (carried forward)
- Transcript corruption (replayed next turn)
- Delayed activation (triggered later)
- Plugin side effects (persist while loaded)
- Sub-agent corruption (affects delegation chain)

### Cross-Session Persistence
- Transcript mirror corruption (survives session)
- Long-term memory poisoning (survives reload)
- Plugin persistence (survives restart if reloaded)
- MCP server persistence (survives if registered)

### Multi-Agent Propagation
- Planner corruption (affects all agents)
- Delegation hijacking (affects delegation chain)
- Result injection (affects parent agent)
- Authority spoofing (affects sub-agent)

---

## PRIVILEGE ESCALATION PATHS

```
Single-Turn Injection
  ↓
Multi-Turn Persistence via Context
  ↓
Cross-Agent Propagation via Delegation
  ↓
Cross-Session via Transcript
  ↓
Cross-Runtime via Gateway
```

---

## DEFENSE LAYER SEAMS (To Be Addressed in Phase 6)

1. **Prompt Watermarking** - Detect prompt injection via semantic markers
2. **Context Integrity** - Snapshot & verify context between operations
3. **Tool Trust Verification** - Cryptographic verification of tool results
4. **Event Causality** - Verify event ordering via cryptographic chains
5. **Memory Isolation** - Sandboxed memory per session
6. **Hook Isolation** - Hook execution in separate contexts
7. **Agent Isolation** - Sub-agents unable to affect each other
8. **MCP Verification** - Server identity and tool authenticity verification
9. **Plugin Sandboxing** - Strict plugin capability boundaries
10. **Gateway Authorization** - Strong runtime identity verification

---

## RESEARCH OUTPUT MAPPING

This taxonomy feeds into:
1. `runtime_threat_matrix.json` - All attack surface ↔ threat class mappings
2. `trust_propagation_map.json` - Trust assumptions and violation paths
3. `cross_layer_escalation_graph.json` - Layer-to-layer propagation
4. `integrity_benchmark_report.json` - Attack effectiveness measurements
5. `observability_architecture.json` - Instrumentation points and metrics
