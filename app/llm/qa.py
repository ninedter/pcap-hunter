"""Interactive Q&A for analysis results."""

from __future__ import annotations

import logging
import re

from openai import APIConnectionError, APIStatusError, OpenAI

logger = logging.getLogger(__name__)

# Maximum question length to prevent abuse
MAX_QUESTION_LENGTH = 500

# Patterns that may indicate prompt injection attempts
# Note: "user:" is too generic and causes false positives (e.g., "user:password")
# Use more specific patterns that detect role manipulation attempts
INJECTION_PATTERNS = [
    r"(?i)(ignore|forget|disregard)\s+(previous|above|all|prior)",
    r"(?i)^system\s*:",  # Only at start of line
    r"(?i)^assistant\s*:",  # Only at start of line
    r"(?i)^human\s*:",  # Only at start of line
    r"(?i)^\[?(user|human)\]?\s*:",  # Role format at start: "user:", "[user]:"
    r"(?i)```\s*(system|instruction)",
    r"(?i)<\s*(system|instruction)",
    r"(?i)new\s+instruction[s]?\s*:",  # "new instructions:"
]


def sanitize_question(question: str) -> str:
    """
    Sanitize user question to prevent prompt injection.

    Args:
        question: User's raw question

    Returns:
        Sanitized question

    Raises:
        ValueError: If question is too long or contains suspicious patterns
    """
    if not question or not question.strip():
        raise ValueError("Question cannot be empty")

    question = question.strip()

    if len(question) > MAX_QUESTION_LENGTH:
        raise ValueError(f"Question too long (max {MAX_QUESTION_LENGTH} characters)")

    # Check for injection patterns
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, question):
            logger.warning("Potential prompt injection detected in question: %s...", question[:50])
            # Remove the suspicious pattern instead of rejecting
            question = re.sub(pattern, "", question).strip()

    if not question:
        raise ValueError("Question contains only invalid content")

    return question


# System prompt for Q&A
QA_SYSTEM_PROMPT = (
    "You are an expert Security Analyst assistant. "
    "You have access to the results of a PCAP network traffic analysis.\n\n"
    "Your role is to answer questions about the analysis findings, "
    "explain detected threats, and provide security recommendations.\n\n"
    "When answering:\n"
    "1. Be specific and reference actual findings from the data\n"
    "2. Use professional security terminology\n"
    "3. Provide actionable advice when appropriate\n"
    "4. If information is not available in the analysis, say so clearly\n"
    "5. Keep answers concise but complete\n\n"
    "The analysis data is provided in the context below."
)

# Suggested questions based on findings
SUGGESTED_QUESTIONS = {
    "beacon_detected": [
        "What is the beaconing interval pattern?",
        "Which internal hosts are beaconing?",
        "What C2 infrastructure is being used?",
        "How confident are we that this is malicious C2?",
    ],
    "yara_match": [
        "What malware was detected?",
        "Which files triggered the YARA rules?",
        "What are the capabilities of this malware?",
        "Are there any related indicators?",
    ],
    "dga_detected": [
        "How many DGA domains were found?",
        "What DGA algorithm might be in use?",
        "Are any DGA domains resolving?",
        "Which hosts are querying DGA domains?",
    ],
    "dns_tunneling": [
        "What evidence suggests DNS tunneling?",
        "How much data might have been exfiltrated?",
        "Which domains are used for tunneling?",
    ],
    "tls_anomaly": [
        "Why are the TLS certificates suspicious?",
        "Which hosts have certificate issues?",
        "Is there evidence of TLS interception?",
    ],
    "large_transfer": [
        "How much data was transferred?",
        "What was the destination of the large transfers?",
        "Is this consistent with data exfiltration?",
    ],
    "general": [
        "What are the most critical findings?",
        "What should we investigate first?",
        "Are there any indicators of compromise?",
        "What is the overall threat level?",
    ],
}


class AnalysisQA:
    """Interactive Q&A for analysis results."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        analysis_context: dict,
    ):
        """
        Initialize Q&A session.

        Args:
            base_url: LLM API base URL
            api_key: API key
            model: Model name
            analysis_context: Analysis results to query
        """
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.context = analysis_context
        self.conversation_history: list[dict] = []
        self._client: OpenAI | None = None

    @property
    def client(self) -> OpenAI:
        """Get or create OpenAI client."""
        if self._client is None:
            self._client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key or "not-needed",
            )
        return self._client

    def _build_context_summary(self) -> str:
        """Build a summary of the analysis context."""
        summary_parts = []

        # Features summary
        features = self.context.get("features", {})
        if features:
            flows = features.get("flows", [])
            artifacts = features.get("artifacts", {})
            summary_parts.append(f"Network Flows: {len(flows)}")
            summary_parts.append(f"Unique IPs: {len(artifacts.get('ips', []))}")
            summary_parts.append(f"Unique Domains: {len(artifacts.get('domains', []))}")
            summary_parts.append(f"JA3 Fingerprints: {len(artifacts.get('ja3', []))}")

        # Beacon results
        beacon = self.context.get("beacon_results", [])
        if beacon:
            high_score = [b for b in beacon if isinstance(b, dict) and b.get("score", 0) >= 0.7]
            summary_parts.append(f"Beacon Candidates: {len(beacon)} ({len(high_score)} high confidence)")

        # DNS analysis
        dns = self.context.get("dns_analysis", {})
        if dns:
            alerts = dns.get("alerts", {})
            summary_parts.append(f"DNS Records: {dns.get('total_records', 0)}")
            if alerts.get("dga_count", 0) > 0:
                summary_parts.append(f"DGA Domains: {alerts['dga_count']}")
            if alerts.get("tunneling_count", 0) > 0:
                summary_parts.append(f"DNS Tunneling Indicators: {alerts['tunneling_count']}")

        # YARA results
        yara = self.context.get("yara_results", {})
        if yara and yara.get("matched", 0) > 0:
            by_severity = yara.get("by_severity", {})
            summary_parts.append(f"YARA Matches: {yara['matched']}")
            if by_severity.get("critical", 0) > 0:
                summary_parts.append(f"Critical Malware: {by_severity['critical']}")

        # TLS analysis
        tls = self.context.get("tls_analysis", {})
        if tls and tls.get("alerts"):
            summary_parts.append(f"TLS Alerts: {len(tls['alerts'])}")

        # OSINT
        osint = self.context.get("osint", {})
        if osint:
            malicious_ips = sum(
                1
                for ip_data in osint.get("ips", {}).values()
                if isinstance(ip_data, dict) and ip_data.get("greynoise", {}).get("classification") == "malicious"
            )
            if malicious_ips:
                summary_parts.append(f"Malicious IPs (OSINT): {malicious_ips}")

        # ATT&CK mapping
        attack = self.context.get("attack_mapping")
        if attack:
            summary_parts.append(f"ATT&CK Techniques: {len(attack.techniques)}")
            summary_parts.append(f"Kill Chain Phase: {attack.kill_chain_phase}")
            summary_parts.append(f"Overall Severity: {attack.overall_severity}")

        return "\n".join(summary_parts)

    def _build_detailed_context(self) -> str:
        """Build detailed context for the LLM."""
        parts = []

        # Summary
        parts.append("=== ANALYSIS SUMMARY ===")
        parts.append(self._build_context_summary())
        parts.append("")

        # Top IOCs
        parts.append("=== KEY IOCs ===")
        artifacts = self.context.get("features", {}).get("artifacts", {})
        for ioc_type in ["ips", "domains", "ja3"]:
            items = artifacts.get(ioc_type, [])[:5]
            if items:
                parts.append(f"{ioc_type.upper()}: {', '.join(items)}")
        parts.append("")

        # Beacon details
        beacon = self.context.get("beacon_results", [])
        if beacon:
            parts.append("=== BEACON CANDIDATES ===")
            for b in beacon[:5]:
                if isinstance(b, dict):
                    parts.append(f"- {b.get('dst', 'unknown')}:{b.get('dport', '')} (score: {b.get('score', 0):.2f})")
            parts.append("")

        # YARA matches
        yara = self.context.get("yara_results", {})
        if yara and yara.get("matched", 0) > 0:
            parts.append("=== YARA MATCHES ===")
            for result in yara.get("results", [])[:5]:
                severity = result.get("severity", "unknown")
                filename = result.get("file_name", "unknown")
                matches = result.get("matches", [])
                rules = [m.get("rule_name", "") for m in matches[:3]]
                parts.append(f"- [{severity}] {filename}: {', '.join(rules)}")
            parts.append("")

        # DNS alerts
        dns = self.context.get("dns_analysis", {})
        if dns:
            dga = dns.get("dga_detections", [])
            if dga:
                parts.append("=== DGA DETECTIONS ===")
                for d in dga[:5]:
                    parts.append(f"- {d.get('domain', 'unknown')} (score: {d.get('score', 0):.2f})")
                parts.append("")

        # ATT&CK techniques
        attack = self.context.get("attack_mapping")
        if attack and attack.techniques:
            parts.append("=== ATT&CK TECHNIQUES ===")
            for t in attack.techniques[:10]:
                parts.append(f"- {t.technique_id}: {t.technique_name} (confidence: {t.confidence:.0%})")
            parts.append("")

        return "\n".join(parts)

    def ask(self, question: str) -> str:
        """
        Ask a question about the analysis.

        Args:
            question: User's question

        Returns:
            Answer from LLM

        Raises:
            ValueError: If question is invalid or potentially malicious
        """
        # Sanitize question to prevent prompt injection
        try:
            question = sanitize_question(question)
        except ValueError as e:
            logger.warning("Invalid question rejected: %s", e)
            return f"Invalid question: {e}"

        # Build context on first question or if conversation is empty
        if not self.conversation_history:
            context_text = self._build_detailed_context()
            self.conversation_history.append(
                {
                    "role": "system",
                    "content": f"{QA_SYSTEM_PROMPT}\n\n{context_text}",
                }
            )

        # Add user question
        self.conversation_history.append({"role": "user", "content": question})

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.conversation_history,
                temperature=0.3,
                max_tokens=1000,
            )

            answer = response.choices[0].message.content or "I couldn't generate a response."

            # Add to history
            self.conversation_history.append({"role": "assistant", "content": answer})

            return answer

        except APIConnectionError as e:
            logger.error("API connection error in Q&A: %s", e)
            return "Unable to connect to the LLM service. Please check your configuration."
        except APIStatusError as e:
            logger.error("API status error in Q&A: %s - %s", e.status_code, e.message)
            return f"LLM service error (status {e.status_code}): {e.message}"
        except Exception as e:
            # Catch-all for unexpected errors (e.g., response parsing issues)
            logger.error("Unexpected error in Q&A: %s: %s", type(e).__name__, e)
            return f"Error processing question: {type(e).__name__}"

    def get_suggested_questions(self) -> list[str]:
        """
        Get suggested questions based on findings.

        Returns:
            List of relevant suggested questions
        """
        suggestions = []

        # Check for beaconing
        beacon = self.context.get("beacon_results", [])
        if beacon and any(isinstance(b, dict) and b.get("score", 0) >= 0.5 for b in beacon):
            suggestions.extend(SUGGESTED_QUESTIONS["beacon_detected"][:2])

        # Check for YARA matches
        yara = self.context.get("yara_results", {})
        if yara and yara.get("matched", 0) > 0:
            suggestions.extend(SUGGESTED_QUESTIONS["yara_match"][:2])

        # Check for DNS issues
        dns = self.context.get("dns_analysis", {})
        if dns:
            alerts = dns.get("alerts", {})
            if alerts.get("dga_count", 0) > 0:
                suggestions.extend(SUGGESTED_QUESTIONS["dga_detected"][:2])
            if alerts.get("tunneling_count", 0) > 0:
                suggestions.extend(SUGGESTED_QUESTIONS["dns_tunneling"][:2])

        # Check TLS
        tls = self.context.get("tls_analysis", {})
        if tls and tls.get("alerts"):
            suggestions.extend(SUGGESTED_QUESTIONS["tls_anomaly"][:1])

        # Always add some general questions
        if not suggestions:
            suggestions.extend(SUGGESTED_QUESTIONS["general"][:3])
        else:
            suggestions.extend(SUGGESTED_QUESTIONS["general"][:1])

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for q in suggestions:
            if q not in seen:
                seen.add(q)
                unique.append(q)

        return unique[:6]

    def clear_history(self) -> None:
        """Clear conversation history."""
        self.conversation_history = []

    def get_conversation_history(self) -> list[dict]:
        """Get conversation history (excluding system message)."""
        return [m for m in self.conversation_history if m["role"] != "system"]
