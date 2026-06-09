"""
DCR Graph Generator Module v1.0
Automatically generates DCR/OC-DCR graphs from detected patterns
Includes Interactive D3.js HTML Dashboard Generation (Pure Light Theme Edition)

Author: PhD Candidate Giatzis Antonios
Date: February 8, 2026
"""

import json
from typing import Dict, List, Set, Tuple
from enum import Enum

class DCRRelation(Enum):
    CONDITION = "dcr:condition"      # Orange arrow
    RESPONSE = "dcr:response"        # Blue arrow
    EXCLUSION = "dcr:exclusion"      # Red arrow
    INCLUSION = "dcr:inclusion"      # Green arrow

class DCREvent:
    def __init__(self, event_id: str, label: str, maps_to_function: str = None):
        self.event_id = event_id
        self.label = label
        self.maps_to_function = maps_to_function
        self.is_executable = True
        self.is_pending = False
        self.is_included = True

    def to_dict(self):
        return {
            "id": self.event_id,
            "label": self.label,
            "mapsToFunction": self.maps_to_function,
            "executable": self.is_executable,
            "pending": self.is_pending,
            "included": self.is_included
        }

class DCRProcess:
    def __init__(self, process_id: str, pattern_type: str, struct_name: str = None):
        self.process_id = process_id
        self.pattern_type = pattern_type
        self.struct_name = struct_name
        self.events: Dict[str, DCREvent] = {}
        self.relations: List[Tuple[str, DCRRelation, str]] = []

    def add_event(self, event: DCREvent):
        self.events[event.event_id] = event

    def add_relation(self, source: str, relation: DCRRelation, target: str):
        self.relations.append((source, relation, target))

    def to_dict(self):
        return {
            "processId": self.process_id,
            "patternType": self.pattern_type,
            "definesLifecycleOf": self.struct_name,
            "events": [e.to_dict() for e in self.events.values()],
            "relations": [
                {"source": src, "type": rel.value, "target": tgt} 
                for src, rel, tgt in self.relations
            ]
        }

class DCRGraphGenerator:
    def __init__(self):
        self.processes: Dict[str, DCRProcess] = {}

    def generate_access_control_graph(self, module_name: str, capability_struct: str, functions: Dict[str, str]) -> DCRProcess:
        process = DCRProcess(f"AC_{module_name}", "AccessControlPattern", capability_struct)
        process.add_event(DCREvent("ACGrantRole", "Grant Role", functions.get("grant")))
        process.add_event(DCREvent("ACProtectedCall", "Protected Call", functions.get("protected")))
        process.add_event(DCREvent("ACRevokeRole", "Revoke Role", functions.get("revoke")))
        process.add_relation("ACGrantRole", DCRRelation.CONDITION, "ACProtectedCall")
        process.add_relation("ACRevokeRole", DCRRelation.EXCLUSION, "ACProtectedCall")
        process.add_relation("ACGrantRole", DCRRelation.INCLUSION, "ACProtectedCall")
        self.processes[process.process_id] = process
        return process

    def generate_circuit_breaker_graph(self, module_name: str, deny_cap_struct: str, functions: Dict[str, str]) -> DCRProcess:
        process = DCRProcess(f"CB_{module_name}", "CircuitBreakerPattern", deny_cap_struct)
        process.add_event(DCREvent("CBPause", "Pause Operations", functions.get("pause")))
        process.add_event(DCREvent("CBUnpause", "Unpause Operations", functions.get("unpause")))
        process.add_event(DCREvent("CBOperationalCall", "Operational Call", functions.get("operation")))
        process.add_relation("CBPause", DCRRelation.EXCLUSION, "CBOperationalCall")
        process.add_relation("CBPause", DCRRelation.INCLUSION, "CBUnpause")
        process.add_relation("CBUnpause", DCRRelation.INCLUSION, "CBOperationalCall")
        self.processes[process.process_id] = process
        return process

    def generate_time_incentivization_graph(self, module_name: str, wallet_struct: str, functions: Dict[str, str]) -> DCRProcess:
        process = DCRProcess(f"TI_{module_name}", "TimeIncentivizationPattern", wallet_struct)
        process.add_event(DCREvent("TIStart", "Start Vesting", functions.get("start")))
        process.add_event(DCREvent("TIProceed", "Claim Vested", functions.get("proceed")))
        process.add_event(DCREvent("TITimeout", "Timeout/Complete", functions.get("timeout")))
        process.add_relation("TIStart", DCRRelation.CONDITION, "TIProceed")
        process.add_relation("TIStart", DCRRelation.RESPONSE, "TIProceed")
        process.add_relation("TIStart", DCRRelation.CONDITION, "TITimeout")
        self.processes[process.process_id] = process
        return process

    def generate_escapability_graph(self, module_name: str, upgrade_cap_struct: str, functions: Dict[str, str]) -> DCRProcess:
        process = DCRProcess(f"ES_{module_name}", "EscapabilityPattern", upgrade_cap_struct)
        process.add_event(DCREvent("ESAuthorize", "Authorize Upgrade", functions.get("authorize")))
        process.add_event(DCREvent("ESEscape", "Execute Upgrade", functions.get("escape")))
        process.add_event(DCREvent("ESMakeImmutable", "Make Immutable", functions.get("immutable")))
        process.add_relation("ESAuthorize", DCRRelation.CONDITION, "ESEscape")
        process.add_relation("ESAuthorize", DCRRelation.INCLUSION, "ESEscape")
        process.add_relation("ESMakeImmutable", DCRRelation.EXCLUSION, "ESAuthorize")
        process.add_relation("ESMakeImmutable", DCRRelation.EXCLUSION, "ESEscape")
        self.processes[process.process_id] = process
        return process

    def generate_interactive_html(self) -> str:
        """Generates pure light-theme D3.js interactive HTML."""
        graphs_data = {pid: p.to_dict() for pid, p in self.processes.items()}
        if not graphs_data:
            graphs_data = {"empty": {"patternType": "No Patterns Detected", "events": [], "relations": []}}
            
        json_string = json.dumps(graphs_data)
        
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analyzer DCR Process Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #ffffff; margin: 0; height: 100vh; }
        .node circle { stroke: #cbd5e1; stroke-width: 3px; cursor: grab; fill: #ffffff; }
        .node circle:active { stroke: #94a3b8; cursor: grabbing; }
        .link { fill: none; stroke-width: 3px; opacity: 0.85; }
        
        /* Relation Colors */
        .link.condition { stroke: #d97706; } /* Dark Orange */
        .link.response { stroke: #2563eb; }  /* Dark Blue */
        .link.exclusion { stroke: #dc2626; } /* Dark Red */
        .link.inclusion { stroke: #059669; } /* Dark Green */
        
        svg { background-color: #ffffff; border-radius: 0.75rem; border: 1px solid #e2e8f0; }
        
        /* Tab Styles */
        .tab-btn { transition: all 0.2s ease; border: 1px solid transparent; }
        .tab-active { background-color: #0f766e; color: white; border-color: #0d9488; box-shadow: 0 2px 4px rgba(15, 118, 110, 0.15); }
        .tab-inactive { background-color: #f1f5f9; color: #334155; border-color: #e2e8f0; }
        .tab-inactive:hover { background-color: #e2e8f0; color: #0f172a; border-color: #cbd5e1; }
        
        /* Typography overrides to force black text */
        h1, h2, span, p { color: #0f172a; }
        .text-gray { color: #475569; }
    </style>
</head>
<body class="flex flex-col p-4 md:p-6 gap-6">

    <!-- TOP HEADER RECTANGLE -->
    <header class="flex flex-col gap-4 bg-white p-4 rounded-xl shadow-sm border border-slate-200">
        <div>
            <h1 class="text-2xl font-bold text-slate-900">
                Detected Business Logic Patterns
            </h1>
            <p class="text-gray text-sm mt-1">Formal Dynamic Condition Response (DCR) Graphs</p>
        </div>
        <div id="tabsContainer" class="flex flex-wrap gap-2"></div>
    </header>

    <main class="flex-1 flex flex-col lg:flex-row gap-6 min-h-0">
        
        <!-- SIDEBAR LEGEND RECTANGLE -->
        <aside class="w-full lg:w-1/4 flex flex-col gap-4">
            <div class="bg-white p-4 rounded-xl shadow-sm border border-slate-200">
                <h2 class="text-lg font-bold text-slate-900 mb-3">DCR Relations Legend</h2>
                <div class="flex flex-col gap-3 text-sm" style="color: #1e293b; font-weight: 500;">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-1 bg-amber-600 rounded relative"><div class="absolute right-0 -mt-1 w-0 h-0 border-t-4 border-b-4 border-l-4 border-transparent border-l-amber-600"></div></div>
                        <span><strong style="color: #d97706;">Condition:</strong> A must happen before B</span>
                    </div>
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-1 bg-blue-600 rounded relative"><div class="absolute right-0 -mt-1 w-0 h-0 border-t-4 border-b-4 border-l-4 border-transparent border-l-blue-600"></div></div>
                        <span><strong style="color: #2563eb;">Response:</strong> A forces B to eventually happen</span>
                    </div>
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-1 bg-red-600 rounded relative"><div class="absolute right-0 -mt-1 w-0 h-0 border-t-4 border-b-4 border-l-4 border-transparent border-l-red-600"></div></div>
                        <span><strong style="color: #dc2626;">Exclusion:</strong> A prevents B from happening</span>
                    </div>
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-1 bg-emerald-600 rounded relative"><div class="absolute right-0 -mt-1 w-0 h-0 border-t-4 border-b-4 border-l-4 border-transparent border-l-emerald-600"></div></div>
                        <span><strong style="color: #059669;">Inclusion:</strong> A allows B to happen again</span>
                    </div>
                </div>
            </div>
        </aside>

        <!-- MAIN GRAPH RECTANGLE -->
        <section class="flex-1 bg-white rounded-xl shadow-sm border border-slate-200 relative overflow-hidden flex flex-col">
            <div class="absolute top-4 left-4 z-10 pointer-events-none">
                <h2 id="graphTitle" class="text-xl font-bold text-slate-900">Process Graph</h2>
                <p id="graphSubtitle" class="text-gray text-sm">Defines Lifecycle of: <span id="graphStruct" class="font-mono font-bold" style="color:#0f766e;">None</span></p>
            </div>
            <div id="graphContainer" class="flex-1 w-full h-full bg-white"></div>
        </section>
    </main>

    <script>
        const graphData = __JSON_DATA_HERE__;
        const tabsContainer = document.getElementById('tabsContainer');
        let currentActiveBtn = null;

        const keys = Object.keys(graphData);
        if (keys.length === 1 && keys[0] === "empty") {
            document.getElementById('graphTitle').textContent = "No Patterns Detected";
            document.getElementById('graphSubtitle').style.display = "none";
        } else {
            keys.forEach((key, index) => {
                const data = graphData[key];
                const btn = document.createElement('button');
                btn.className = `tab-btn px-4 py-2 text-sm font-medium rounded-lg ${index === 0 ? 'tab-active' : 'tab-inactive'}`;
                btn.textContent = data.patternType;
                btn.onclick = () => {
                    if (currentActiveBtn) currentActiveBtn.classList.replace('tab-active', 'tab-inactive');
                    btn.classList.replace('tab-inactive', 'tab-active');
                    currentActiveBtn = btn;
                    renderGraph(data);
                };
                tabsContainer.appendChild(btn);
                if (index === 0) currentActiveBtn = btn;
            });
            if(keys.length > 0) renderGraph(graphData[keys[0]]);
        }

        function renderGraph(data) {
            document.getElementById('graphTitle').textContent = data.patternType || 'Process Graph';
            document.getElementById('graphStruct').textContent = data.definesLifecycleOf || 'N/A';
            drawD3Graph(data);
        }

        function drawD3Graph(data) {
            d3.select("#graphContainer").selectAll("*").remove();
            if (!data.events || data.events.length === 0) return;

            const container = document.getElementById('graphContainer');
            const width = container.clientWidth;
            const height = container.clientHeight;

            const svg = d3.select("#graphContainer").append("svg")
                .attr("width", "100%").attr("height", "100%")
                .call(d3.zoom().on("zoom", (event) => { g.attr("transform", event.transform); })).append("g");

            const g = svg.append("g");

            const typeColors = {"dcr:condition": "#d97706", "dcr:response": "#2563eb", "dcr:exclusion": "#dc2626", "dcr:inclusion": "#059669"};
            const typeClasses = {"dcr:condition": "condition", "dcr:response": "response", "dcr:exclusion": "exclusion", "dcr:inclusion": "inclusion"};

            svg.append("defs").selectAll("marker").data(Object.keys(typeColors)).enter().append("marker")
                .attr("id", d => `arrow-${d.replace('dcr:', '')}`)
                .attr("viewBox", "0 -5 10 10").attr("refX", 32).attr("refY", 0)
                .attr("markerWidth", 6).attr("markerHeight", 6).attr("orient", "auto")
                .append("path").attr("fill", d => typeColors[d]).attr("d", "M0,-5L10,0L0,5");

            const nodes = data.events.map(d => Object.create(d));
            const links = data.relations.map(d => {
                return { source: nodes.find(n => n.id === d.source), target: nodes.find(n => n.id === d.target), type: d.type };
            }).filter(l => l.source && l.target);

            links.forEach(link => {
                const sameDirection = links.filter(l => l.source === link.source && l.target === link.target);
                link.linknum = sameDirection.indexOf(link) + 1;
                link.totalLinks = sameDirection.length;
            });

            const simulation = d3.forceSimulation(nodes)
                .force("link", d3.forceLink(links).distance(200))
                .force("charge", d3.forceManyBody().strength(-2000))
                .force("center", d3.forceCenter(width / 2, height / 2))
                .force("collide", d3.forceCollide().radius(60));

            const path = g.append("g").selectAll("path").data(links).enter().append("path")
                .attr("class", d => `link ${typeClasses[d.type]}`)
                .attr("marker-end", d => `url(#arrow-${d.type.replace('dcr:', '')})`);

            const node = g.append("g").selectAll("g").data(nodes).enter().append("g")
                .call(d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended));

            node.append("circle").attr("r", 25);

            // NODE MAIN LABEL - PURE BLACK
            node.append("text").attr("dy", 45).attr("text-anchor", "middle")
                .style("fill", "#000000").style("font-weight", "700")
                .text(d => d.label);

            // NODE FUNCTION LABEL - TEAL
            node.append("text").attr("dy", 62).attr("text-anchor", "middle")
                .style("font-size", "11px").style("fill", "#0f766e").style("font-family", "monospace").style("font-weight", "600")
                .text(d => d.mapsToFunction ? `fn: ${d.mapsToFunction}()` : "");

            // EMOJI ICONS
            node.append("text").attr("dy", 6).attr("text-anchor", "middle")
                .text(d => {
                    if(d.label.includes('Pause') || d.label.includes('Revoke')) return '⏹';
                    if(d.label.includes('Grant') || d.label.includes('Start')) return '▶';
                    if(d.label.includes('Authorize')) return '🔑';
                    return '⚙️';
                });

            simulation.on("tick", () => {
                path.attr("d", d => {
                    const dx = d.target.x - d.source.x, dy = d.target.y - d.source.y;
                    const dr = Math.sqrt(dx * dx + dy * dy);
                    if (d.totalLinks === 1) return `M${d.source.x},${d.source.y}L${d.target.x},${d.target.y}`;
                    const sweep = d.linknum % 2 === 0 ? 1 : 0;
                    return `M${d.source.x},${d.source.y}A${dr*(1+(d.linknum*0.2))},${dr*(1+(d.linknum*0.2))} 0 0,${sweep} ${d.target.x},${d.target.y}`;
                });
                node.attr("transform", d => `translate(${d.x},${d.y})`);
            });

            function dragstarted(event, d) { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
            function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
            function dragended(event, d) { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }
        }
        
        window.addEventListener('resize', () => {
            if(currentActiveBtn) {
                const activeKey = Object.keys(graphData).find(k => graphData[k].patternType === currentActiveBtn.textContent);
                if(activeKey) renderGraph(graphData[activeKey]);
            }
        });
    </script>
</body>
</html>"""
        return html_template.replace("__JSON_DATA_HERE__", json_string)
        
    def export_interactive_html(self, output_path: str = "dcr_report.html"):
        html_content = self.generate_interactive_html()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_path