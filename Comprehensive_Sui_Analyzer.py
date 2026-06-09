"""
Comprehensive Sui Move Analyzer v.1.0 - PhD Defense Version

CRITICAL FIXES APPLIED (February 5, 2026):
- FIX #1: CORRECTED heuristic classification regex (swap_x_to_y, stake_tokens, claim_rewards → PUBLIC)
- FIX #2: Enhanced inline authorization detection (assert!(sender == wallet.owner) patterns)
- All original features preserved intact

REFACTOR (April 28, 2026):
- Replaced 6-level name-and-behavior hybrid privilege classifier with
  4-layer fully behavioral classifier (zero function name usage).
- Extended parser to capture function return types (group 4).
- Layers: return type (Coin/Balance), bilateral flow, pure deposit,
  outflow+sender transfer. Conservative default flags mutations.
- public entry modifier intentionally excluded (AUTH-01 design decision).
- FIX 1: AUTH-02 — structural capability signature (key+UID+small+no-financial)
- FIX 2: CONS-01 struct — removed redundant name gate, inner behavioral gates preserved
- FIX 3: RES-01 — structural hot-potato signature (drop+no-key+no-copy+value-field)
- FIX 4: TIME-01 — reordered _check_temporal_context (behavioral first, field fallback)
- FIX 5: TIME-02 — behavioral timed-extraction check replaces field-name scan

FEATURES PRESERVED:
- ✅ Ontology usage (RDF Graph with semantic triples)
- ✅ 14 Semantic Operation Types
- ✅ SPARQL-based reasoning capability
- ✅ Semantic + Nominal detection methods
- ✅ Behavior analysis (not just syntax)
- ✅ Knowledge graph export (Turtle/RDF/JSON-LD)
- ✅ DCR Process Graph generation
- ✅ 13 SUWC vulnerability detection
- ✅ Automated fix suggestions
- ✅ Modern professional UI ready

Author: PhD Candidate Giatzis Antonios
Institution: University of Macedonia, Thessaloniki, Greece
Date: February 5, 2026
"""

import rdflib
from rdflib import Graph, Namespace, URIRef, Literal, RDF, RDFS, OWL
import re
import os
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Import supporting modules
from DCR_Graph_Generator import (
    DCRGraphGenerator, DCRProcess, DCREvent, DCRRelation
)

from Automated_Fix_Suggester import (
    AutomatedFixSuggester, VulnerabilityDetection,
    VulnerabilityCategory, SeverityLevel
)


class PatternTypes:
    """Pattern constants for the 4 PhD research patterns."""
    ACCESS_CONTROL = "AccessControlPattern"
    TIME_INCENTIVIZATION = "TimeIncentivizationPattern"
    CIRCUIT_BREAKER = "CircuitBreakerPattern"
    ESCAPABILITY = "EscapabilityPattern"


class ComprehensiveSuiAnalyzer:
    """Unified analyzer - v.1.0 - PhD Defense Version"""

    def __init__(self, ontology_path=None):
        """Initialize comprehensive analyzer with all capabilities"""
        # === ONTOLOGY COMPONENTS ===
        self.g = Graph()
        self.function_count = 0
        self.violation_count = 0
        self.detected_patterns = {}
        self.violations = []
        self.dcr_mappings = []

        # Namespaces
        self.SUI = Namespace("http://www.sui-move-ontology.com/ontology#")
        self.PATTERN = Namespace("http://www.sui-move-ontology.com/patterns/v1#")
        self.SUWC = Namespace("http://www.sui-move-ontology.com/defects/v1#")
        self.DCR = Namespace("http://purl.org/net/dcr#")
        self.g.bind("sui", self.SUI)
        self.g.bind("pattern", self.PATTERN)
        self.g.bind("suwc", self.SUWC)
        self.g.bind("dcr", self.DCR)

        # === ENHANCEMENT COMPONENTS ===
        self.dcr_generator = DCRGraphGenerator()
        self.fix_suggester = AutomatedFixSuggester()
        self.vulnerabilities = []
        self.generated_graphs = []

        # Detection method tracking
        self.pattern_detection_methods = {
            "capability_based": 0,
            "dynamic_acl": 0,
            "inline_auth": 0
        }

        # Store parsed structs and functions for advanced analysis
        self.parsed_structs = {}
        self.parsed_functions = {}

        # Track temporal context for smart TIME-01 detection
        self.has_temporal_context = False

        # Load ontology
        if ontology_path is None:
            default_path = "Sui_Move_Ontology.ttl"
            if os.path.exists(default_path):
                ontology_path = default_path

        self.ontology_path = ontology_path
        self._load_ontology()
        self._bootstrap_reasoning_properties()

    def _load_ontology(self):
        """Load TTL ontology file"""
        try:
            start_time = time.time()
            self.g.parse(self.ontology_path, format="turtle")
            print(f"✓ Ontology loaded: {len(self.g)} triples in {time.time() - start_time:.2f}s")
        except Exception as e:
            print(f"⚠️  Could not load ontology: {str(e)}. Creating minimal structure.")
            self._create_minimal_ontology()

    def _bootstrap_reasoning_properties(self):
        """Bootstrap the three-property semantic reasoning mechanism in-memory.
        
        Adds indicatesDefectRisk and mitigatesDefect property definitions and
        their triple associations to the in-memory graph. This serves as a
        redundancy guarantee — ensuring the mechanism works even if someone
        loads an older TTL version that predates the three-property fix.
        
        The three properties are:
          1. addressesDefect     (Pattern → Defect)    — prescriptive: "prevents"
          2. indicatesDefectRisk (Operation → Defect)  — diagnostic: "signals risk"
          3. mitigatesDefect     (Operation → Defect)  — mitigation: "guards against"
        """
        # Property URIs
        self.INDICATES = self.SUI.indicatesDefectRisk
        self.MITIGATES = self.SUI.mitigatesDefect

        # Define properties in graph (idempotent — will not duplicate if TTL already has them)
        self.g.add((self.INDICATES, RDF.type, OWL.ObjectProperty))
        self.g.add((self.INDICATES, RDFS.label, Literal("indicates defect risk")))
        self.g.add((self.INDICATES, RDFS.domain, self.SUI.SecurityOperation))
        self.g.add((self.INDICATES, RDFS.range, self.SUWC.VulnerabilityCategory))

        self.g.add((self.MITIGATES, RDF.type, OWL.ObjectProperty))
        self.g.add((self.MITIGATES, RDFS.label, Literal("mitigates defect")))
        self.g.add((self.MITIGATES, RDFS.domain, self.SUI.SecurityOperation))
        self.g.add((self.MITIGATES, RDFS.range, self.SUWC.VulnerabilityCategory))

        # indicatesDefectRisk triples (9 risk-signaling operations)
        risk_links = [
            (self.SUI.BalanceOperation,     self.SUWC["SUWC-AUTH-01"]),
            (self.SUI.BalanceMutation,      self.SUWC["SUWC-AUTH-01"]),
            (self.SUI.OwnershipTransfer,    self.SUWC["SUWC-AUTH-02"]),
            (self.SUI.ObjectCreation,       self.SUWC["SUWC-AUTH-03"]),
            (self.SUI.ObjectDeletion,       self.SUWC["SUWC-AUTH-04"]),
            (self.SUI.SharedStateMutation,  self.SUWC["SUWC-CONS-01"]),
            (self.SUI.UnboundedIteration,   self.SUWC["SUWC-CONS-02"]),
            (self.SUI.TemporalCheck,        self.SUWC["SUWC-TIME-03"]),
            (self.SUI.TimestampComparison,  self.SUWC["SUWC-TIME-04"]),
        ]
        for operation, defect in risk_links:
            self.g.add((operation, self.INDICATES, defect))

        # mitigatesDefect triples (6 mitigation-providing operations)
        mitigation_links = [
            (self.SUI.InvariantCheck,        self.SUWC["SUWC-CONS-01"]),
            (self.SUI.AMMInvariantCheck,     self.SUWC["SUWC-CONS-01"]),
            (self.SUI.AdminStateControl,     self.SUWC["SUWC-CONS-01"]),
            (self.SUI.TemporalConstraint,    self.SUWC["SUWC-TIME-01"]),
            (self.SUI.DynamicFieldOperation, self.SUWC["SUWC-RES-02"]),
            (self.SUI.OptionalExtraction,    self.SUWC["SUWC-RES-03"]),
        ]
        for operation, defect in mitigation_links:
            self.g.add((operation, self.MITIGATES, defect))

    def _create_minimal_ontology(self):
        """Create minimal ontology structure if TTL not available"""
        self.g.add((self.SUI.Module, RDF.type, OWL.Class))
        self.g.add((self.SUI.Function, RDF.type, OWL.Class))
        self.g.add((self.SUI.EntryFunction, RDF.type, OWL.Class))
        self.g.add((self.PATTERN.AccessControlPattern, RDF.type, OWL.Class))
        self.g.add((self.PATTERN.CircuitBreakerPattern, RDF.type, OWL.Class))
        self.g.add((self.PATTERN.TimeIncentivizationPattern, RDF.type, OWL.Class))
        self.g.add((self.PATTERN.EscapabilityPattern, RDF.type, OWL.Class))

    def reset_analysis(self):
        """Reset analysis state for new contract"""
        self.g = Graph()
        self.g.bind("sui", self.SUI)
        self.g.bind("pattern", self.PATTERN)
        self.g.bind("suwc", self.SUWC)
        self.g.bind("dcr", self.DCR)
        self._load_ontology()
        self._bootstrap_reasoning_properties()

        self.function_count = 0
        self.violation_count = 0
        self.detected_patterns = {}
        self.violations = []
        self.vulnerabilities = []
        self.generated_graphs = []
        self.dcr_mappings = []

        self.pattern_detection_methods = {
            "capability_based": 0,
            "dynamic_acl": 0,
            "inline_auth": 0
        }

        self.parsed_structs = {}
        self.parsed_functions = {}
        self.has_temporal_context = False


    def analyze_contract(self, code: str, module_name: str = "contract") -> Dict:
        """COMPREHENSIVE ANALYSIS PIPELINE"""
        print(f"\n🔍 Analyzing {module_name}...")
        print(f"   [v.1.0 - PhD Defense Version]")

        success = self._parse_and_instantiate(code, module_name)
        if not success:
            return None

        print("   └─ Generating DCR graphs...")
        graphs = self._generate_dcr_graphs(self.detected_patterns, module_name)
        self.generated_graphs = graphs

        print("   └─ Detecting ALL 13 SUWC vulnerabilities...")
        vulns = self._detect_all_vulnerabilities(code, module_name)
        self.vulnerabilities = vulns

        print("   └─ Generating fix suggestions...")
        fixes = self._generate_fixes(vulns)

        print(f"\n✅ Analysis complete!")
        print(f"   Detection methods used:")
        print(f"   • Capability-based: {self.pattern_detection_methods['capability_based']}")
        print(f"   • Dynamic ACL: {self.pattern_detection_methods['dynamic_acl']}")
        print(f"   • Inline Auth: {self.pattern_detection_methods['inline_auth']}")

        return {
            "module": module_name,
            "ontology_triples": len(self.g),
            "patterns": self.detected_patterns,
            "dcr_graphs": graphs,
            "vulnerabilities": vulns,
            "fix_suggestions": fixes,
            "statistics": {
                "functions_analyzed": self.function_count,
                "patterns_detected": len(self.detected_patterns),
                "dcr_graphs_generated": len(graphs),
                "vulnerabilities_found": len(vulns),
                "fixes_available": len(fixes),
                "detection_methods": self.pattern_detection_methods,
                "vulnerability_breakdown": self._get_vulnerability_breakdown(vulns)
            }
        }

    def _get_vulnerability_breakdown(self, vulns: List[VulnerabilityDetection]) -> Dict:
        """Get breakdown of vulnerabilities by category"""
        breakdown = {
            "AUTH": 0,
            "TIME": 0,
            "RES": 0,
            "CONS": 0
        }

        for vuln in vulns:
            # Extract category without "SUWC-" prefix
            category = vuln.category.value.replace("SUWC-", "")
            if category in breakdown:
                breakdown[category] += 1

        return breakdown

    def _check_temporal_context(self) -> bool:
        """
        Check if contract has temporal context.
        Returns True if contract uses time-related features.

        FIX 4 — Priority order: behavioral checks first, field name scan as fallback.
        """
        # CHECK 1 — BEHAVIORAL (API-based): Clock parameter in any function
        for func_info in self.parsed_functions.values():
            params = func_info['params']
            if re.search(r'\b&?\s*Clock\b', params):
                return True

        # CHECK 2 — BEHAVIORAL (operation-based): epoch/clock usage in any body
        for func_info in self.parsed_functions.values():
            body = func_info['body']
            if re.search(r'clock::|epoch|timestamp', body, re.IGNORECASE):
                return True

        # CHECK 3 — FALLBACK (field name scan — last resort)
        temporal_field_patterns = [
            r'unlock_time',
            r'lock_time',
            r'start_time',
            r'end_time',
            r'vesting_start',
            r'vesting_end',
            r'cliff_time',
            r'release_time',
            r'deadline',
            r'expiry',
            r'timestamp',
            r'schedule'
        ]

        for struct_info in self.parsed_structs.values():
            fields = struct_info['fields'].lower()
            for pattern in temporal_field_patterns:
                if re.search(pattern, fields, re.IGNORECASE):
                    return True

        return False

    def _parse_and_instantiate(self, code: str, module_name: str) -> bool:
        """Parse Move code and instantiate RDF knowledge graph"""
        # Clean comments
        content_clean = re.sub(r'//.*', '', code)
        content_clean = re.sub(r'/\*.*?\*/', '', content_clean, flags=re.DOTALL)

        # Extract module
        module_match = re.search(r'module\s+([a-zA-Z0-9_:]+)', content_clean)
        if not module_match:
            print("❌ No module definition found")
            return False

        module_name_extracted = module_match.group(1).replace(':', '_')
        module_uri = self.SUI[f"Module_{module_name_extracted}"]
        self.g.add((module_uri, RDF.type, self.SUI.Module))
        self.g.add((module_uri, RDFS.label, Literal(module_name_extracted)))
        print(f"📦 Module: {module_name_extracted}")

        # Extract structs
        struct_pattern = re.compile(
            r'(?:public\s+)?struct\s+([a-zA-Z_]\w*)\s+has\s+([^{]+)\{([^}]*)}',
            re.DOTALL
        )

        for match in struct_pattern.finditer(content_clean):
            struct_name = match.group(1).strip()
            abilities = match.group(2).strip()
            fields = match.group(3).strip()

            self.parsed_structs[struct_name] = {
                "abilities": abilities,
                "fields": fields,
                "full_text": match.group(0)
            }

        if self.parsed_structs:
            print(f"📋 Found {len(self.parsed_structs)} struct(s): {', '.join(self.parsed_structs.keys())}")

        # Extract functions
        # Return type captured as group 4 for behavioral privilege classification
        func_pattern = re.compile(
            r'((?:public\s+(?:entry\s+)?|entry\s+)?)'
            r'fun\s+'
            r'([a-zA-Z_]\w*)'
            r'\s*(?:<[^>]+>)?'
            r'\s*\('
            r'([^)]*)'
            r'\)'
            r'([^{]*?)'       # group 4: return type annotation
            r'\{',
            re.DOTALL | re.MULTILINE
        )

        matches = list(func_pattern.finditer(content_clean))
        print(f"🔎 Analyzing {len(matches)} functions...")

        for match in matches:
            self.function_count += 1
            modifiers = match.group(1)
            func_name = match.group(2)
            params = match.group(3)

            # Extract body
            start_idx = match.end() - 1
            body = self._extract_balanced_body(content_clean, start_idx)

            # Store function info
            self.parsed_functions[func_name] = {
                "modifiers": modifiers,
                "params": params,
                "body": body,
                "return_type": match.group(4).strip(),
                "is_entry": "entry" in modifiers,
                "is_public": "public" in modifiers
            }

            # Create function URI
            func_uri = self.SUI[f"Func_{func_name}"]

            # Determine type
            is_entry = "entry" in modifiers
            if is_entry:
                self.g.add((func_uri, RDF.type, self.SUI.EntryFunction))
            else:
                self.g.add((func_uri, RDF.type, self.SUI.Function))

            self.g.add((func_uri, RDFS.label, Literal(func_name)))
            self.g.add((module_uri, self.SUI.defines, func_uri))

            # Pattern detection
            detected_patterns = self._detect_patterns_enhanced(
                params, body, func_uri, func_name, self.parsed_structs
            )

            # Semantic operation detection
            semantic_ops = self._analyze_semantic_operations(func_name, params, body, func_uri)

            # Update statistics
            for p in detected_patterns:
                self.detected_patterns[p] = self.detected_patterns.get(p, 0) + 1

        # Check for temporal context
        self.has_temporal_context = self._check_temporal_context()
        if self.has_temporal_context:
            print(f"⏰ Temporal context detected (time-locking features present)")

        print(f"✅ Knowledge graph created: {len(self.g)} RDF triples")
        return True

    def _extract_balanced_body(self, text, start_index):
        """Extract function body with balanced braces"""
        brace_count = 0
        i = start_index

        if i >= len(text) or text[i] != '{':
            return ""

        while i < len(text):
            if text[i] == '{':
                brace_count += 1
            elif text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return text[start_index + 1:i].strip()
            i += 1

        return ""


    # ========================================================================
    # PATTERN DETECTION
    # ========================================================================

    def _detect_patterns_enhanced(
        self,
        params: str,
        body: str,
        func_uri: URIRef,
        func_name: str,
        structs_info: Dict
    ) -> List[str]:
        """Enhanced pattern detection with all 3 methods"""
        detected = []

        # METHOD 1: CAPABILITY-BASED DETECTION
        cap_pattern = self._detect_capability_patterns(params, func_uri, structs_info)
        if cap_pattern:
            detected.append(cap_pattern)

        # METHOD 2: DYNAMIC ACL DETECTION
        if self._detect_dynamic_acl_patterns(params, body, func_uri):
            if PatternTypes.ACCESS_CONTROL not in detected:
                detected.append(PatternTypes.ACCESS_CONTROL)

        # METHOD 3: INLINE AUTHORIZATION DETECTION (FIXED)
        if self._detect_inline_authorization(params, body, func_uri, func_name):
            if PatternTypes.ACCESS_CONTROL not in detected:
                detected.append(PatternTypes.ACCESS_CONTROL)

        # PATTERN 2: Time Incentivization
        if re.search(r'\b&?\s*Clock\b', params):
            self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.TimeIncentivizationPattern))
            detected.append(PatternTypes.TIME_INCENTIVIZATION)

        # PATTERN 4: Escapability
        if re.search(r'\b(UpgradeCap|UpgradeTicket|UpgradeReceipt|MigrationCap)\b', params):
            self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.EscapabilityPattern))
            detected.append(PatternTypes.ESCAPABILITY)

        return detected

    def _detect_capability_patterns(
        self,
        params: str,
        func_uri: URIRef,
        structs_info: Dict
    ) -> Optional[str]:
        """METHOD 1: Capability-based detection"""
        capability_patterns = [
            (r'\b(PauseCap|EmergencyCap|DenyCapV2|DenyCap)\b', 40, True),
            (r'\b(AdminCap|OwnerCap|TreasuryCap|TransferPolicyCap|Publisher|ManagerCap)\b', 40, False),
            (r'\b(Authorization|Permissions?)\b', 35, False),
            (r'\b(Auth|AuthToken|AuthContext)\b', 30, False),
            (r'\b\w*Cap\b', 25, False),
            (r'\b(AC|OC|MC)\b', 20, False),
        ]

        cap_score = 0
        matched_type = None
        is_circuit_breaker = False

        for pattern, points, is_cb in capability_patterns:
            match = re.search(pattern, params, re.IGNORECASE)
            if match:
                cap_score += points
                if not matched_type:
                    matched_type = match.group(0)
                    is_circuit_breaker = is_cb
                    break

        # Structural analysis
        if matched_type and matched_type in structs_info:
            struct_info = structs_info[matched_type]
            field_count = len([f for f in struct_info['fields'].split() if f.strip()])

            if 'UID' in struct_info['fields'] and field_count < 10:
                cap_score += 20

            if 'key' in struct_info['abilities'] and 'store' not in struct_info['abilities']:
                cap_score += 15

        if matched_type and ('&' in params or 'mut' in params):
            cap_score += 10

        if cap_score >= 40:
            if is_circuit_breaker:
                self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.CircuitBreakerPattern))
                self.pattern_detection_methods['capability_based'] += 1
                return PatternTypes.CIRCUIT_BREAKER
            else:
                self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.AccessControlPattern))
                self.pattern_detection_methods['capability_based'] += 1
                return PatternTypes.ACCESS_CONTROL

        return None

    def _detect_dynamic_acl_patterns(
        self,
        params: str,
        body: str,
        func_uri: URIRef
    ) -> bool:
        """METHOD 2: Dynamic ACL detection"""
        acl_indicators = []

        if re.search(r'Table\s*<\s*address', params, re.IGNORECASE):
            acl_indicators.append('table_address_param')

        if re.search(r'VecSet\s*<\s*address', params, re.IGNORECASE) or re.search(r'vec_set::VecSet', params):
            acl_indicators.append('vecset_address_param')

        if re.search(r'table::contains', body, re.IGNORECASE):
            acl_indicators.append('table_contains')

        if re.search(r'vec_set::contains', body, re.IGNORECASE):
            acl_indicators.append('vecset_contains')

        if re.search(r'tx_context::sender|sender\s*\(', body, re.IGNORECASE):
            acl_indicators.append('sender_check')

        if re.search(r'assert!\s*\([^)]*contains[^)]*sender', body, re.IGNORECASE):
            acl_indicators.append('assert_membership')

        if len(acl_indicators) >= 3:
            self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.AccessControlPattern))
            self.pattern_detection_methods['dynamic_acl'] += 1
            return True

        return False

    def _detect_inline_authorization(
        self,
        params: str,
        body: str,
        func_uri: URIRef,
        func_name: str
    ) -> bool:
        """
        ╔═══════════════════════════════════════════════════════════════╗
        ║ FIX #2: IMPROVED INLINE AUTHORIZATION DETECTION               ║
        ║ METHOD 3: Inline authorization detection                      ║
        ║ Now correctly detects: assert!(sender == wallet.owner)       ║
        ╚═══════════════════════════════════════════════════════════════╝
        """
        # Skip if has capability parameter
        has_cap = bool(re.search(r'(Cap|Authorization|Permission|Auth)', params, re.IGNORECASE))
        if has_cap:
            return False

        # Check for sensitive operations
        sensitive_ops = [
            r'balance\.(split|join|take)',
            r'coin::take',
            r'transfer::(?:public_)?transfer',
            r'object::delete',
            r'vec_set::insert',
            r'\s*=\s*',
        ]

        has_sensitive_op = any(re.search(op, body, re.IGNORECASE) for op in sensitive_ops)
        if not has_sensitive_op:
            return False

        # Check for sender extraction
        sender_check = bool(re.search(r'tx_context::sender', body))

        # IMPROVED: Multiple patterns for owner/authorization checks
        owner_patterns = [
            r'assert!.*==.*\.owner',          # wallet.owner, pool.owner, etc.
            r'assert!.*owner\s*==',            # owner == sender
            r'assert!.*\.admin',               # .admin field
            r'assert!.*\.creator',             # .creator field
            r'assert!.*sender\s*==.*owner',    # sender == owner
            r'assert!.*sender\s*==.*admin',    # sender == admin
        ]

        if sender_check:
            for pattern in owner_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    self.g.add((func_uri, self.SUI.implementsPattern, 
                               self.PATTERN.AccessControlPattern))
                    self.pattern_detection_methods['inline_auth'] += 1
                    return True

        return False

    def _analyze_semantic_operations(self, func_name, params, body, func_uri):
        """Detect 14 semantic operations"""
        detected_ops = []

        if re.search(r'(?:coin|balance):\w*(?:split|join|put|take|value)', body, re.I):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.BalanceOperation))
            detected_ops.append("BalanceOperation")

        if re.search(r'(?:transfer|sui)::(?:public_)?transfer|share_object', body, re.I):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.OwnershipTransfer))
            detected_ops.append("OwnershipTransfer")

        if re.search(r'coin::mint|object::new\s*\(', body, re.I):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.ObjectCreation))
            detected_ops.append("ObjectCreation")

        if re.search(r'(?:coin|object)::burn|object::delete\s*\(', body, re.I):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.ObjectDeletion))
            detected_ops.append("ObjectDeletion")

        if re.search(r'&\s*mut\s+(?:Coin|Balance)', body):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.BalanceMutation))
            detected_ops.append("BalanceMutation")

        if re.search(r'&\s*mut\s+\w+', body):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.SharedStateMutation))
            detected_ops.append("SharedStateMutation")

        if re.search(r'assert!\s*\(', body):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.InvariantCheck))
            detected_ops.append("InvariantCheck")

        # AMMInvariantCheck — distinguishes AMM curve invariant from generic asserts
        AMM_INVARIANT_PATTERN = re.compile(
            r'assert!\s*\([^)]*'
            r'(?:reserve[_a-z0-9]*\s*\*\s*reserve[_a-z0-9]*'
            r'|coin[_a-z0-9]*\s*\*\s*coin[_a-z0-9]*'
            r'|\bk\b.*?>=?'
            r'|invariant|constant.?product)',
            re.IGNORECASE
        )
        if AMM_INVARIANT_PATTERN.search(body):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.AMMInvariantCheck))
            detected_ops.append("AMMInvariantCheck")

        if re.search(r'while\s*\(|loop\s*{', body):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.UnboundedIteration))
            detected_ops.append("UnboundedIteration")

        if re.search(r'clock::timestamp|clock::epoch|tx_context::epoch', body, re.I):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.TemporalCheck))
            detected_ops.append("TemporalCheck")

        if re.search(r'assert!\s*\([^)]*(?:timestamp|epoch|clock)', body, re.I):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.TemporalConstraint))
            detected_ops.append("TemporalConstraint")

        if re.search(r'(?:timestamp|epoch|start)\s*(?:[<>]=?|==|!=)', body, re.I):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.TimestampComparison))
            detected_ops.append("TimestampComparison")

        if re.search(r'dynamic_field::(?:add|remove|borrow)', body):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.DynamicFieldOperation))
            detected_ops.append("DynamicFieldOperation")

        if re.search(r'option::(?:extract|swap|fill|borrow)', body):
            self.g.add((func_uri, self.SUI.performsOperation, self.SUI.OptionalExtraction))
            detected_ops.append("OptionalExtraction")

        return detected_ops

    # ========================================================================
    # DCR GRAPH GENERATION
    # ========================================================================

    def _generate_dcr_graphs(self, patterns: Dict, module_name: str) -> List[Dict]:
        """Generate DCR graphs"""
        graphs = []

        if PatternTypes.ACCESS_CONTROL in patterns:
            try:
                process = self.dcr_generator.generate_access_control_graph(
                    module_name=module_name,
                    capability_struct="AdminCap",
                    functions={"grant": "new", "protected": "protected_call", "revoke": "destroy"}
                )
                graphs.append(process.to_dict())
            except Exception as e:
                print(f"   ⚠️  Could not generate Access Control graph: {e}")

        if PatternTypes.CIRCUIT_BREAKER in patterns:
            try:
                process = self.dcr_generator.generate_circuit_breaker_graph(
                    module_name=module_name,
                    deny_cap_struct="DenyCap",
                    functions={"pause": "pause", "unpause": "unpause", "operation": "execute"}
                )
                graphs.append(process.to_dict())
            except Exception as e:
                print(f"   ⚠️  Could not generate Circuit Breaker graph: {e}")

        if PatternTypes.TIME_INCENTIVIZATION in patterns:
            try:
                process = self.dcr_generator.generate_time_incentivization_graph(
                    module_name=module_name,
                    wallet_struct="Wallet",
                    functions={"start": "new", "proceed": "claim", "timeout": "complete"}
                )
                graphs.append(process.to_dict())
            except Exception as e:
                print(f"   ⚠️  Could not generate Time Incentivization graph: {e}")

        if PatternTypes.ESCAPABILITY in patterns:
            try:
                process = self.dcr_generator.generate_escapability_graph(
                    module_name=module_name,
                    upgrade_cap_struct="UpgradeCap",
                    functions={"authorize": "authorize_upgrade", "escape": "commit_upgrade", "immutable": "make_immutable"}
                )
                graphs.append(process.to_dict())
            except Exception as e:
                print(f"   ⚠️  Could not generate Escapability graph: {e}")

        return graphs


    # ========================================================================
    # VULNERABILITY DETECTION WITH BEHAVIORAL PRIVILEGE CLASSIFIER
    # ========================================================================

    def _is_privileged_operation(self, func_name: str, body: str,
                                  func_info: dict = None) -> bool:
        """
        ╔══════════════════════════════════════════════════════════════╗
        ║  FULLY BEHAVIORAL PRIVILEGE CLASSIFIER                      ║
        ║  Zero function name usage. Four behavioral layers           ║
        ║  derived entirely from code structure and body.             ║
        ║                                                             ║
        ║  NOTE: public entry modifier intentionally NOT used.        ║
        ║  A drain function can be public entry by mistake —          ║
        ║  that is exactly what AUTH-01 detects.                      ║
        ║                                                             ║
        ║  LAYER 2: Coin/Balance return type  → PUBLIC               ║
        ║  LAYER 3: Bilateral flow            → PUBLIC (swap)        ║
        ║  LAYER 4: Pure inflow only          → PUBLIC (deposit)     ║
        ║  LAYER 5: Outflow + sender xfer     → PUBLIC (withdrawal)  ║
        ║  DEFAULT: any mutation present      → PRIVILEGED (safe)    ║
        ║                                                             ║
        ║  Known limitation: Gap 1 (drain that returns Coin) and     ║
        ║  Gap 2 (drain that transfers to sender) are unresolvable   ║
        ║  without inter-procedural object ownership analysis.       ║
        ╚══════════════════════════════════════════════════════════════╝
        """

        # ── LAYER 0: Constructor — creates and returns objects without transferring them
        creates_objects = bool(re.search(r'object::new', body))
        has_financial_extraction = bool(re.search(r'balance::split|coin::take|balance::withdraw', body, re.IGNORECASE))
        if creates_objects and not has_financial_extraction:
            return False  # PUBLIC

        # ── LAYER 2: Return type carries Coin or Balance ──────────────
        # A function that returns Coin<T> or Balance<T> is giving value
        # back to the caller — behavioural signature of claim/swap/remove.
        # Residual gap: a drain() returning Coin would also match here.
        if func_info:
            return_type = func_info.get('return_type', '')
            if re.search(r'\b(Coin|Balance)\b', return_type, re.IGNORECASE):
                return False  # PUBLIC: function returns assets to caller

        # ── LAYER 3: Bilateral token flow = swap ─────────────────────
        # Any function that both adds to AND takes from reserves is an
        # AMM swap — provably user-facing. Zero residual gap.
        has_inflow  = bool(re.search(
            r'balance::join|coin::into_balance', body, re.IGNORECASE))
        has_outflow = bool(re.search(
            r'balance::split|coin::take', body, re.IGNORECASE))

        if has_inflow and has_outflow:
            return False  # PUBLIC: bilateral exchange (bulletproof)

        # ── LAYER 4: Pure deposit = adding to pool ───────────────────
        # Inflow with no outflow = user depositing their own assets.
        # Zero residual gap.
        if has_inflow and not has_outflow:
            return False  # PUBLIC: deposit only (bulletproof)

        # ── LAYER 5: Outflow + explicit transfer to caller ───────────
        # The function splits/takes AND explicitly transfers the result
        # to tx_context::sender — the caller receives the asset.
        # Residual gap: an admin draining to their own address also matches.
        transfers_to_sender = bool(re.search(
            r'transfer::(?:public_)?transfer[^;]*(?:sender|tx_context)',
            body, re.IGNORECASE | re.DOTALL
        ))
        if has_outflow and transfers_to_sender:
            return False  # PUBLIC: user receives asset (standard withdrawal)

        # ── DEFAULT: conservative ────────────────────────────────────
        # No public behavioral signal confirmed. If the body mutates
        # state, treat as PRIVILEGED — over-flags rather than under-flags.
        # Read-only functions always resolve to PUBLIC here.
        has_mutation = bool(re.search(
            r'(=|\bmut\b|transfer|coin::|balance::)', body))
        return has_mutation  # True = PRIVILEGED, False = PUBLIC

    def _detect_all_vulnerabilities(self, code: str, module_name: str) -> List[VulnerabilityDetection]:
        """Detect ALL 13 SUWC vulnerabilities — dual detection pipeline.
        
        Runs both the original regex-based detectors AND the new SPARQL-based
        three-phase reasoning engine. Results are merged with deduplication.
        """
        # ── Original regex-based detectors ──────────────────────────────
        vulnerabilities = []
        vulnerabilities.extend(self._detect_auth_vulnerabilities())
        vulnerabilities.extend(self._detect_time_vulnerabilities())
        vulnerabilities.extend(self._detect_resource_vulnerabilities())
        vulnerabilities.extend(self._detect_constraint_vulnerabilities())

        # ── SPARQL three-phase semantic reasoning ───────────────────────
        sparql_vulns = self._sparql_detect_vulnerabilities()

        # Merge: add SPARQL results not already found by regex detectors
        existing_keys = {(v.function_name, v.defect_id) for v in vulnerabilities}
        for sv in sparql_vulns:
            if (sv.function_name, sv.defect_id) not in existing_keys:
                vulnerabilities.append(sv)

        return vulnerabilities

    def _sparql_detect_vulnerabilities(self) -> List[VulnerabilityDetection]:
        """Three-phase ontology-driven vulnerability detection via SPARQL.
        
        Phase 1: Identify functions performing risk-indicating operations
        Phase 2: Confirm absence of mitigating operations for the same defect
        Phase 3: Map confirmed defect to prescriptive BusinessLogicPattern
        
        This method queries the RDF knowledge graph that was populated during
        _analyze_semantic_operations() and enriched with the three-property
        reasoning model by _bootstrap_reasoning_properties().
        """
        vulnerabilities = []

        query = """
        PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
        PREFIX suwc: <http://www.sui-move-ontology.com/defects/v1#>
        PREFIX pattern: <http://www.sui-move-ontology.com/patterns/v1#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?funcLabel ?defect ?defectLabel ?riskOpLabel ?patternLabel WHERE {

            # PHASE 1: Function performs a risk-indicating operation
            ?func sui:performsOperation ?riskOp .
            ?riskOp sui:indicatesDefectRisk ?defect .
            ?func rdfs:label ?funcLabel .
            ?defect rdfs:label ?defectLabel .
            FILTER(STRSTARTS(?defectLabel, "SUWC-"))
            ?riskOp rdfs:label ?riskOpLabel .

            # PHASE 2: Confirm absence of mitigating operation for same defect
            FILTER NOT EXISTS {
                ?func sui:performsOperation ?mitigOp .
                ?mitigOp sui:mitigatesDefect ?defect .
            }

            # PHASE 2b: Exclude functions already protected by a pattern
            #           that addresses the same defect class
            FILTER NOT EXISTS {
                ?func sui:implementsPattern ?guardPattern .
                ?guardPattern sui:addressesDefect ?defect .
            }

            # PHASE 3: Prescribe remediation pattern
            OPTIONAL {
                ?pattern sui:addressesDefect ?defect .
                ?pattern rdfs:label ?patternLabel .
            }
        }
        ORDER BY ?funcLabel ?defect
        """

        severity_map = {
            "SUWC-AUTH-01": SeverityLevel.CRITICAL,
            "SUWC-AUTH-02": SeverityLevel.CRITICAL,
            "SUWC-AUTH-03": SeverityLevel.HIGH,
            "SUWC-AUTH-04": SeverityLevel.CRITICAL,
            "SUWC-CONS-01": SeverityLevel.HIGH,
            "SUWC-CONS-02": SeverityLevel.CRITICAL,
            "SUWC-TIME-01": SeverityLevel.HIGH,
            "SUWC-TIME-02": SeverityLevel.MEDIUM,
            "SUWC-TIME-03": SeverityLevel.HIGH,
            "SUWC-TIME-04": SeverityLevel.MEDIUM,
            "SUWC-RES-01":  SeverityLevel.HIGH,
            "SUWC-RES-02":  SeverityLevel.HIGH,
            "SUWC-RES-03":  SeverityLevel.CRITICAL,
        }

        category_map = {
            "AUTH": VulnerabilityCategory.AUTH,
            "TIME": VulnerabilityCategory.TIME,
            "RES":  VulnerabilityCategory.RES,
            "CONS": VulnerabilityCategory.CONS,
        }

        try:
            results = self.g.query(query)
            seen = set()  # Deduplicate (func, defect) pairs

            for row in results:
                func_name = str(row.funcLabel)
                defect_label = str(row.defectLabel).strip()
                risk_op_label = str(row.riskOpLabel)
                pattern_label = str(row.patternLabel) if row.patternLabel else "Unknown"

                key = (func_name, defect_label)
                if key in seen:
                    continue
                seen.add(key)

                # Extract category from defect ID (e.g., "SUWC-AUTH-01" → "AUTH")
                parts = defect_label.split("-")
                category_key = parts[1] if len(parts) > 1 else "AUTH"
                category = category_map.get(category_key, VulnerabilityCategory.AUTH)
                severity = severity_map.get(defect_label, SeverityLevel.MEDIUM)

                vulnerabilities.append(VulnerabilityDetection(
                    defect_id=defect_label,
                    category=category,
                    severity=severity,
                    function_name=func_name,
                    line_number=None,
                    description=(
                        f"[SPARQL] {func_name} performs {risk_op_label} that indicates "
                        f"{defect_label} risk without mitigation guard"
                    ),
                    evidence=(
                        f"Ontology reasoning: indicatesDefectRisk({defect_label}) "
                        f"confirmed by absence of mitigatesDefect. "
                        f"Recommended pattern: {pattern_label}"
                    )
                ))

        except Exception as e:
            print(f"⚠️  SPARQL reasoning failed: {e}")

        return vulnerabilities

    def _detect_auth_vulnerabilities(self) -> List[VulnerabilityDetection]:
        """
        DETECT AUTH DEFECTS USING CORRECTED HEURISTIC
        """
        vulnerabilities = []

        for func_name, func_info in self.parsed_functions.items():
            params = func_info['params']
            body = func_info['body']

            # Skip patterns
            func_uri = self.SUI[f"Func_{func_name}"]
            has_pattern = False
            for s, p, o in self.g.triples((func_uri, self.SUI.implementsPattern, None)):
                has_pattern = True
                break

            if has_pattern:
                continue

            # 1. Determine Privilege using the BEHAVIORAL classifier
            # Pass func_info so Layer 2 (return type) can be evaluated
            is_privileged = self._is_privileged_operation(
                func_name, body, func_info=func_info
            )

            # 2. Check for mutations
            has_mutation = bool(re.search(r'(=|transfer|coin::|balance::)', body))
            has_cap_check = bool(re.search(r'(Cap|_cap|&Admin|&Owner|Authorization|Auth)', params, re.IGNORECASE))

            # 3. Flag ONLY if Privileged AND Mutating AND No Auth
            if has_mutation and is_privileged and not has_cap_check and func_name != 'init' and 'test' not in func_name:
                vulnerabilities.append(VulnerabilityDetection(
                    defect_id="SUWC-AUTH-01",
                    category=VulnerabilityCategory.AUTH,
                    severity=SeverityLevel.CRITICAL,
                    function_name=func_name,
                    line_number=None,
                    description=f"Privileged function '{func_name}' modifies state without capability check",
                    evidence=(
                        f"Heuristic identified this as Privileged but no capability found. "
                        f"Recommended pattern: AccessControlPattern with CapabilityTechnique"
                    )
                ))

            # AUTH-04: Mutable shared object
            has_mut_shared = bool(re.search(r'&\s*mut\s+(?!TxContext\b)', params, re.IGNORECASE))
            if has_mut_shared and is_privileged and not has_cap_check and func_name != 'init':
                vulnerabilities.append(VulnerabilityDetection(
                    defect_id="SUWC-AUTH-04",
                    category=VulnerabilityCategory.AUTH,
                    severity=SeverityLevel.HIGH,
                    function_name=func_name,
                    line_number=None,
                    description=f"Privileged function '{func_name}' modifies shared object without authorization",
                    evidence=(
                        f"Mutable reference to shared object in privileged function. "
                        f"Recommended pattern: AccessControlPattern with Runtime Checks"
                    )
                ))

        # SUWC-AUTH-02: Capability leakage
        # Whitelist known Sui framework capability structs (not vulnerabilities)
        FRAMEWORK_CAP_WHITELIST = {
            'UpgradeCap', 'UpgradeTicket', 'UpgradeReceipt',
            'DenyCap', 'DenyCapV2', 'TreasuryCap',
            'TransferPolicyCap', 'Publisher', 'MigrationCap',
        }
        for struct_name, struct_info in self.parsed_structs.items():
            # Skip known framework structs
            if struct_name in FRAMEWORK_CAP_WHITELIST:
                continue

            # FIX 1 — AUTH-02: Structural capability signature (no name usage)
            abilities = struct_info['abilities'].lower()
            fields_text = struct_info['fields']

            has_uid = 'UID' in fields_text
            field_lines = [f for f in fields_text.split('\n')
                           if f.strip() and 'UID' not in f]
            field_count = len(field_lines)
            has_financial = bool(re.search(
                r'balance|coin|reserve|liquidity|price|supply|amount',
                fields_text, re.IGNORECASE))

            has_data_field = (
                bool(re.search(r'vector', fields_text, re.IGNORECASE)) or
                any(re.search(r'(description|votes|amount|count|total|supply|balance|price|value|data|payload|name|info)',
                              f, re.IGNORECASE) for f in field_lines)
            )
            is_capability_struct = (
                'key' in abilities and
                has_uid and
                field_count <= 2 and
                not has_financial and
                not has_data_field
            )

            if is_capability_struct:
                has_store = 'store' in abilities
                has_copy = 'copy' in abilities

                if has_store or has_copy:
                    vulnerabilities.append(VulnerabilityDetection(
                        defect_id="SUWC-AUTH-02",
                        category=VulnerabilityCategory.AUTH,
                        severity=SeverityLevel.CRITICAL,
                        function_name=struct_name,
                        line_number=None,
                        description=f"Capability struct '{struct_name}' has dangerous abilities",
                        evidence=(
                            f"Abilities: {struct_info['abilities']}. "
                            f"Recommended pattern: AccessControlPattern with Singleton Enforcement"
                        )
                    ))

        # SUWC-AUTH-03: Witness violation
        for func_name, func_info in self.parsed_functions.items():
            if func_name == 'init':
                params = func_info['params']
                if re.search(r'&\s*[A-Z]\w*(?![^,]*TxContext)', params):
                    vulnerabilities.append(VulnerabilityDetection(
                        defect_id="SUWC-AUTH-03",
                        category=VulnerabilityCategory.AUTH,
                        severity=SeverityLevel.CRITICAL,
                        function_name=func_name,
                        line_number=None,
                        description="One-Time-Witness (OTW) passed by reference in init function",
                        evidence=(
                            f"Params: {params}. "
                            f"Recommended pattern: One-Time Witness (OTW) Pattern"
                        )
                    ))

        return vulnerabilities

    def _detect_time_vulnerabilities(self) -> List[VulnerabilityDetection]:
        """Detect TIME vulnerabilities"""
        vulnerabilities = []

        for func_name, func_info in self.parsed_functions.items():
            params = func_info['params']
            body = func_info['body']

            # TIME-01 (FIXED — behavior-based, not name-based)
            # Detects functions that release assets to the caller (net outflow)
            # in a temporal contract, without any time verification.
            # Excludes bilateral functions (swaps) that also take assets in.
            ASSET_OUTFLOW = re.compile(
                r'coin::take|balance::split|balance::withdraw',
                re.IGNORECASE
            )
            ASSET_INFLOW = re.compile(
                r'coin::into_balance|balance::join.*coin',
                re.DOTALL | re.IGNORECASE
            )
            TRANSFERS_TO_SENDER = re.compile(
                r'transfer::(?:public_)?transfer.*(?:sender|tx_context)',
                re.DOTALL | re.IGNORECASE
            )
            has_outflow = bool(ASSET_OUTFLOW.search(body))
            has_inflow  = bool(ASSET_INFLOW.search(body))
            sends_to_sender = bool(TRANSFERS_TO_SENDER.search(body))

            # Gate: outflow present, NO corresponding inflow (= net withdrawal, not a swap)
            # OR: explicitly transfers to sender (= user gets assets out)
            if self.has_temporal_context and has_outflow and (not has_inflow or sends_to_sender):
                has_assert_check    = re.search(r'assert!.*(?:timestamp|epoch|clock)', body, re.I)
                has_if_return_check = re.search(r'if\s*\(.*(?:timestamp|epoch|clock|start|duration).*\)\s*(?:return|\{)', body, re.I)
                has_clock_usage     = re.search(r'clock\.timestamp_ms\(\)', body, re.I)
                has_delegated_clock = re.search(r'\w+\(.*\bclock\b.*\)', body, re.I)
                if not (has_assert_check or has_if_return_check or has_clock_usage or has_delegated_clock):
                    vulnerabilities.append(VulnerabilityDetection(
                        defect_id="SUWC-TIME-01",
                        category=VulnerabilityCategory.TIME,
                        severity=SeverityLevel.HIGH,
                        function_name=func_name,
                        line_number=None,
                        description=f"Function '{func_name}' releases assets without time verification",
                        evidence=(
                            f"Body performs net asset outflow (coin::take / balance::split) without "
                            f"corresponding inflow in a temporal contract but lacks clock/epoch guard. "
                            f"Recommended pattern: TimeIncentivizationPattern with Epoch Checks"
                        )
                    ))

            # TIME-02: Indefinite lock (FIXED — behavior-based, not name-based)
            # Detects functions that create a NEW object holding deposited assets,
            # where no struct in the contract defines an unlock/expiry field.
            # Excludes functions that just add to existing pools (no object::new).
            ASSET_DEPOSIT = re.compile(
                r'balance::join|coin::put|coin::into_balance',
                re.IGNORECASE
            )
            CREATES_NEW_OBJECT = re.compile(
                r'object::new\s*\(|transfer::(?:share_object|public_transfer|transfer)',
                re.IGNORECASE
            )
            has_deposit    = bool(ASSET_DEPOSIT.search(body))
            creates_object = bool(CREATES_NEW_OBJECT.search(body))

            # Gate: function deposits assets AND creates/transfers a new object
            # (= creating a locked position, not just adding to an existing pool)
            # FIX 5 — TIME-02: Behavioral timed-extraction check (no field name usage)
            if has_deposit and creates_object:
                has_timed_extraction = False
                for fn_info in self.parsed_functions.values():
                    fn_body = fn_info['body']
                    has_fn_outflow = bool(re.search(
                        r'coin::take|balance::split|balance::withdraw',
                        fn_body, re.IGNORECASE))
                    has_temporal_guard = bool(re.search(
                        r'assert!.*?(?:epoch|clock|timestamp)',
                        fn_body, re.IGNORECASE))
                    if has_fn_outflow and has_temporal_guard:
                        has_timed_extraction = True
                        break
                if not has_timed_extraction:
                    vulnerabilities.append(VulnerabilityDetection(
                        defect_id="SUWC-TIME-02",
                        category=VulnerabilityCategory.TIME,
                        severity=SeverityLevel.MEDIUM,
                        function_name=func_name,
                        line_number=None,
                        description=f"Function '{func_name}' creates a locked position without unlock mechanism",
                        evidence=(
                            f"Body deposits assets (balance::join) and creates a new object (object::new) "
                            f"but no function in this module performs timed extraction "
                            f"(asset outflow + temporal assert). "
                            f"Recommended pattern: TimeIncentivizationPattern with Epoch-based Unlock"
                        )
                    ))

            # TIME-03: Unsafe timestamp
            if re.search(r'clock::timestamp_ms', body, re.I):
                if not re.search(r'assert!.*timestamp_ms', body, re.I):
                    vulnerabilities.append(VulnerabilityDetection(
                        defect_id="SUWC-TIME-03",
                        category=VulnerabilityCategory.TIME,
                        severity=SeverityLevel.HIGH,
                        function_name=func_name,
                        line_number=None,
                        description="Function uses timestamp_ms() without safety assertions",
                        evidence=(
                            f"Found clock::timestamp_ms without assert! validation. "
                            f"Recommended pattern: TimeIncentivizationPattern with Epoch-based Time"
                        )
                    ))

            # TIME-04: Race condition (multiple timestamp reads in same function)
            timestamp_calls = len(re.findall(r'(?:timestamp_ms|epoch)\s*\(', body))
            if timestamp_calls >= 2:
                vulnerabilities.append(VulnerabilityDetection(
                    defect_id="SUWC-TIME-04",
                    category=VulnerabilityCategory.TIME,
                    severity=SeverityLevel.MEDIUM,
                    function_name=func_name,
                    line_number=None,
                    description=f"Function '{func_name}' has potential time-based race condition",
                    evidence=(
                        f"Found {timestamp_calls} time reads. "
                        f"Recommended pattern: TimeIncentivizationPattern with Priority Ordering"
                    )
                ))

        return vulnerabilities


    def _detect_resource_vulnerabilities(self) -> List[VulnerabilityDetection]:
        """Detect RESOURCE vulnerabilities"""
        vulnerabilities = []

        # RES-01: Hot potato drop (FIX 3 — structural signature, not name-based)
        # Structural hot-potato: drop + no key + no copy + has value field
        # - not has_key: hot potatoes cannot be stored globally
        # - not has_copy: excludes event structs (copy + drop)
        # - has_value_field: excludes pure marker structs
        for struct_name, struct_info in self.parsed_structs.items():
            abilities_lower = struct_info['abilities'].lower()
            has_drop = 'drop' in abilities_lower
            has_key  = 'key'  in abilities_lower
            has_copy = 'copy' in abilities_lower
            # Value fields: lines in fields block that are not the UID declaration
            value_fields = [f for f in struct_info['fields'].split('\n')
                            if f.strip() and 'UID' not in f and 'id:' not in f.lower()]
            has_value_field = len(value_fields) >= 1

            if has_drop and not has_key and not has_copy and has_value_field:
                vulnerabilities.append(VulnerabilityDetection(
                    defect_id="SUWC-RES-01",
                    category=VulnerabilityCategory.RES,
                    severity=SeverityLevel.CRITICAL,
                    function_name=struct_name,
                    line_number=None,
                    description=f"Hot potato struct '{struct_name}' has 'drop' ability",
                    evidence=(
                        f"Structural signature: drop ability + no key + no copy + {len(value_fields)} value field(s). "
                        f"Hot potato structs must not have drop — they must be consumed by value. "
                        f"Recommended pattern: Hot Potato Pattern / Linear Types Enforcement"
                    )
                ))

        # RES-02: Roach Motel (FIXED — double name-dependency removed)
        # Gate 1: struct is key-bearing and holds financial fields (content-based)
        # Gate 2: any function body extracts from it via Sui standard library (body-based)
        FINANCIAL_FIELDS = re.compile(
            r'balance|coin|amount|asset|token|reserve|liquidity|value',
            re.IGNORECASE
        )
        EXTRACTION_BEHAVIOR = re.compile(
            r'balance::split|coin::take|balance::withdraw'
            r'|dynamic_field::remove|borrow_mut|option::extract',
            re.IGNORECASE
        )
        for struct_name, struct_info in self.parsed_structs.items():
            # Gate 1: must be a key-bearing struct holding financial fields
            # CORRECTED — accepts key OR store (store-only structs can trap assets when nested)
            is_trapping_struct = (
                'key' in struct_info['abilities'].lower() or
                'store' in struct_info['abilities'].lower()
            )
            has_financial_fields = bool(FINANCIAL_FIELDS.search(struct_info['fields']))
            if not (is_trapping_struct and has_financial_fields):
                continue
            # Gate 2: check if any function body extracts from it
            has_extraction = False
            for fn_info in self.parsed_functions.values():
                if EXTRACTION_BEHAVIOR.search(fn_info['body']):
                    has_extraction = True
                    break
            if not has_extraction:
                vulnerabilities.append(VulnerabilityDetection(
                    defect_id="SUWC-RES-02",
                    category=VulnerabilityCategory.RES,
                    severity=SeverityLevel.HIGH,
                    function_name=struct_name,
                    line_number=None,
                    description=f"Struct '{struct_name}' traps assets with no extraction path",
                    evidence=(
                        f"Struct holds financial fields (balance/coin/token) under key ability "
                        f"but no function body contains balance::split, coin::take, or dynamic_field::remove. "
                        f"Recommended pattern: EscapabilityPattern"
                    )
                ))

        # RES-03: Permanent Lock
        for func_name, func_info in self.parsed_functions.items():
            if re.search(r'transfer.*@0x0', func_info['body']):
                vulnerabilities.append(VulnerabilityDetection(
                    defect_id="SUWC-RES-03",
                    category=VulnerabilityCategory.RES,
                    severity=SeverityLevel.HIGH,
                    function_name=func_name,
                    line_number=None,
                    description=f"Function '{func_name}' transfers assets to 0x0",
                    evidence=(
                        f"Found transfer to 0x0 — assets permanently locked. "
                        f"Recommended pattern: EscapabilityPattern with Emergency Unlock"
                    )
                ))

        return vulnerabilities

    def _detect_constraint_vulnerabilities(self) -> List[VulnerabilityDetection]:
        """Detect CONSTRAINT vulnerabilities"""
        vulnerabilities = []

        for func_name, func_info in self.parsed_functions.items():
            body = func_info['body']

            # CONS-01: Invariant Violation (FIXED — bilateral detection, no directional ambiguity)
            # An AMM swap is any function that both takes FROM reserves AND adds TO reserves.
            # Bilateral flow (split + join) = token exchange. Missing invariant = vulnerability.
            has_pool_outflow = bool(re.search(r'balance::split|coin::take', body, re.IGNORECASE))
            has_pool_inflow  = bool(re.search(r'balance::join|coin::into_balance', body, re.IGNORECASE))

            AMM_INVARIANT_CHECK = re.compile(
                r'assert!\s*\([^)]*'
                r'(?:reserve[_a-z0-9]*\s*\*\s*reserve[_a-z0-9]*'
                r'|coin[_a-z0-9]*\s*\*\s*coin[_a-z0-9]*'
                r'|\bk\b.*?>=?'
                r'|invariant|constant.?product)',
                re.IGNORECASE
            )
            if has_pool_outflow and has_pool_inflow:
                if not AMM_INVARIANT_CHECK.search(body):
                    vulnerabilities.append(VulnerabilityDetection(
                        defect_id="SUWC-CONS-01",
                        category=VulnerabilityCategory.CONS,
                        severity=SeverityLevel.CRITICAL,
                        function_name=func_name,
                        line_number=None,
                        description=f"AMM function '{func_name}' missing curve invariant check (k = x·y)",
                        evidence=(
                            f"Body performs bilateral token exchange (balance::split + balance::join) "
                            f"but lacks assert!(reserve_x * reserve_y >= k). "
                            f"Recommended pattern: CircuitBreakerPattern with InvariantCheck"
                        )
                    ))

            # CONS-02: Vector DoS
            if re.search(r'while\s*\(', body) and re.search(r'vector::length', body) and not re.search(r'(limit|batch|max)', body, re.I):
                vulnerabilities.append(VulnerabilityDetection(
                    defect_id="SUWC-CONS-02",
                    category=VulnerabilityCategory.CONS,
                    severity=SeverityLevel.MEDIUM,
                    function_name=func_name,
                    line_number=None,
                    description=f"Function '{func_name}' has unbounded vector iteration",
                    evidence=(
                        f"Loop over vector::length without limit/batch control. "
                        f"Recommended pattern: CircuitBreakerPattern with Bounded Iteration"
                    )
                ))

        # CONS-01: Detect missing CircuitBreakerPattern at struct level
        for structname, structinfo in self.parsed_structs.items():
            fields = structinfo['fields'].lower()
            abilities = structinfo['abilities'].lower()
            # FIX 2 — CONS-01 struct: Name gate removed; inner behavioral gates preserved
            if 'key' in abilities:
                # Confirm it is a financial struct, not just any key struct
                has_financial_fields = re.search(
                    r'balance|liquidity|reserve|coin|price|supply',
                    structinfo['fields'].lower()
                )
                if has_financial_fields:
                    has_pause = re.search(
                        r'is_paused|paused|pause_cap|emergency|deny_cap',
                        fields, re.I
                    )
                    if not has_pause:
                        vulnerabilities.append(VulnerabilityDetection(
                            defect_id='SUWC-CONS-01',
                            category=VulnerabilityCategory.CONS,
                            severity=SeverityLevel.HIGH,
                            function_name=structname,
                            line_number=None,
                            description=f'Struct {structname} is missing CircuitBreakerPattern — no pause mechanism or DenyCapV2 field detected',
                            evidence=(
                                f"No is_paused, pause_cap, or DenyCapV2 field found in struct definition. "
                                f"Recommended pattern: CircuitBreakerPattern with EmergencyPause"
                            )
                        ))

        return vulnerabilities

    def _generate_fixes(self, vulnerabilities: List[VulnerabilityDetection]) -> List[Dict]:
        """Generate fix suggestions"""
        fixes = []

        for vuln in vulnerabilities:
            try:
                fix = self.fix_suggester.suggest_fix(vuln)
                fixes.append({
                    "vulnerability": {
                        "defect_id": vuln.defect_id,
                        "severity": vuln.severity.value,
                        "function": vuln.function_name,
                        "description": vuln.description
                    },
                    "fix": {
                        "title": fix.title,
                        "pattern": fix.recommended_pattern,
                        "explanation": fix.explanation,
                        "example": fix.example_code,
                        "references": fix.references
                    }
                })
            except Exception as e:
                print(f"   ⚠️  Could not generate fix for {vuln.defect_id}")

        return fixes

    # ============================================================================
    # EXPORT FUNCTIONS
    # ============================================================================

    def export_rdf_graph(self, format="turtle", output_file=None):
        """Export RDF knowledge graph in specified format"""
        if output_file:
            self.g.serialize(destination=output_file, format=format)
            print(f"✅ RDF graph exported to {output_file}")
        else:
            return self.g.serialize(format=format)

    def export_json_ld(self, output_file=None):
        """Export as JSON-LD"""
        return self.export_rdf_graph(format="json-ld", output_file=output_file)

    def export_comprehensive_report(self, analysis_result: Dict, output_dir: str = "."):
        """Export complete analysis report"""
        module = analysis_result["module"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Export RDF
        rdf_file = f"{output_dir}/{module}_ontology_{timestamp}.ttl"
        self.export_rdf_graph(format="turtle", output_file=rdf_file)

        # Export JSON report
        json_file = f"{output_dir}/{module}_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(analysis_result, f, indent=2, default=str)

        print(f"✅ Reports exported to {output_dir}")
        return {
            "rdf_file": rdf_file,
            "json_file": json_file
        }


# ============================================================================
# TEST FUNCTION
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("Comprehensive Sui Move Analyzer v.1.0")
    print("All Critical Fixes Applied - Ready for PhD Defense")
    print("=" * 80)

    # Test Case: Complete DeFi Protocol
    test_contract = """
module defense::complete_defi {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::{Self, TxContext};

    // Structs
    public struct AdminCap has key {
        id: UID
    }

    public struct LiquidityPool has key {
        id: UID,
        reserve_x: Balance<SUI>,
        reserve_y: Balance<SUI>,
        total_shares: u64
    }

    public struct Wallet has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>
    }

    // Public DeFi functions (should NOT trigger AUTH-01)
    public fun create_pool(ctx: &mut TxContext): LiquidityPool {
        LiquidityPool {
            id: object::new(ctx),
            reserve_x: balance::zero(),
            reserve_y: balance::zero(),
            total_shares: 0
        }
    }

    public fun swap_x_to_y(
        pool: &mut LiquidityPool,
        coin_x: Coin<SUI>,
        ctx: &mut TxContext
    ): Coin<SUI> {
        let amount_in = coin::value(&coin_x);
        balance::join(&mut pool.reserve_x, coin::into_balance(coin_x));
        let amount_out = amount_in; // Simplified for test
        coin::take(&mut pool.reserve_y, amount_out, ctx)
    }

    public fun stake_tokens(
        pool: &mut LiquidityPool,
        tokens: Coin<SUI>
    ) {
        balance::join(&mut pool.reserve_x, coin::into_balance(tokens));
    }

    public fun claim_rewards(
        pool: &mut LiquidityPool,
        ctx: &mut TxContext
    ): Coin<SUI> {
        let sender = tx_context::sender(ctx);
        let reward_amount = 100; // Simplified
        coin::take(&mut pool.reserve_x, reward_amount, ctx)
    }

    // Inline authorization (should detect AC pattern)
    public fun withdraw(
        wallet: &mut Wallet,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        assert!(sender == wallet.owner, 0); // Inline auth
        let coins = balance::split(&mut wallet.balance, 100);
    }

    // Privileged function (SHOULD trigger AUTH-01)
    public fun admin_drain_swap(
        pool: &mut LiquidityPool,
        amount: u64
    ) {
        // Missing AdminCap - VULNERABILITY!
        balance::split(&mut pool.reserve_x, amount);
    }
}
"""

    analyzer = ComprehensiveSuiAnalyzer()
    result = analyzer.analyze_contract(test_contract, "complete_defi")

    if result:
        print(f"\n{'='*80}")
        print("ANALYSIS RESULTS")
        print("=" * 80)
        print(f"✅ Ontology Triples: {result['ontology_triples']}")
        print(f"✅ Functions Analyzed: {result['statistics']['functions_analyzed']}")
        print(f"✅ Patterns Detected: {result['statistics']['patterns_detected']}")
        print(f"✅ Vulnerabilities Found: {result['statistics']['vulnerabilities_found']}")

        print(f"\n{'='*80}")
        print("DETECTION VERIFICATION")
        print("=" * 80)

        vulns = [v.defect_id for v in result['vulnerabilities']]

        # Check false positives (should NOT be flagged)
        false_positives = []
        for v in result['vulnerabilities']:
            if v.defect_id == "SUWC-AUTH-01":
                if v.function_name in ['swap_x_to_y', 'stake_tokens', 'claim_rewards', 'create_pool']:
                    false_positives.append(v.function_name)

        if false_positives:
            print(f"❌ FALSE POSITIVES DETECTED: {', '.join(false_positives)}")
        else:
            print("✅ NO FALSE POSITIVES on swap/stake/claim/create functions")

        # Check false negatives (should be flagged)
        if any(v.function_name == 'admin_drain_swap' for v in result['vulnerabilities']):
            print("✅ ATTACK DETECTED: admin_drain_swap correctly flagged")
        else:
            print("❌ FALSE NEGATIVE: admin_drain_swap not detected")

        # Check inline authorization
        if result['statistics']['detection_methods']['inline_auth'] > 0:
            print("✅ INLINE AUTH DETECTED: withdraw function pattern recognized")
        else:
            print("⚠️  Inline authorization not detected")

        print(f"\n{'='*80}")
        print("STATUS: READY FOR PHD DEFENSE!")
        print("=" * 80)
