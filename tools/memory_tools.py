"""
CyberAgent Working & Cognitive Memory Toolset
============================================
Provides capabilities for:
- Committing security findings & intelligence into permanent storage
- Recalling past audit findings using Hybrid BM25 + Dense Vector Cosine Similarity
- Inspecting target attack surface dossiers and score progression
"""

from typing import Dict, Any, Optional


class MemoryToolsMixin:
    """Mixin implementing working session and cognitive memory tool operations."""

    def _get_memory_engine(self):
        try:
            try:
                from ..modules.memory import get_memory_engine
            except Exception:
                from cyber_agent.modules.memory import get_memory_engine
        except ImportError:
            from memory_engine import get_memory_engine
        return get_memory_engine()

    def remember_memory(self, content: str, target: Optional[str] = None, category: str = "finding", metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Explicitly stores a security finding, vulnerability, credential, or technical intelligence
        into long-term Cognitive Memory.
        Indexed using NLTK morphological stemming (e.g. vulnerabilities -> vulner) and dense vector embeddings.
        """
        try:
            mem = self._get_memory_engine()
            doc_id = mem.store_finding(content=content, target=target, category=category, metadata=metadata)
            return {
                "success": True,
                "document_id": doc_id,
                "target": target,
                "category": category,
                "message": "Finding successfully committed to persistent cognitive memory."
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to store memory: {str(e)}"}

    def recall_memory(self, query: str = "", target: Optional[str] = None, category: Optional[str] = None, top_k: int = 5) -> Dict[str, Any]:
        """
        Recalls security findings, audit progression, and target intelligence from Cognitive Memory.
        Powered by Hybrid Reciprocal Rank Fusion (Stemmed BM25 + Dense Vector Cosine Similarity).
        """
        try:
            mem = self._get_memory_engine()
            response: Dict[str, Any] = {"success": True}

            # If target provided, fetch target dossier
            if target:
                dossier = mem.get_target_dossier(target)
                if dossier:
                    response["target_dossier"] = dossier
                else:
                    response["target_message"] = f"No dossier found for '{target}'."

            # If search query provided, run hybrid stemmed search
            if query:
                matched_findings = mem.recall(query=query, target=target, category=category, top_k=top_k)
                response["query"] = query
                response["matches_count"] = len(matched_findings)
                response["matched_findings"] = matched_findings

            # If neither target nor query provided, return overview summary
            if not query and not target:
                response["overview"] = mem.get_overview_summary()

            return response
        except Exception as e:
            return {"success": False, "error": f"Failed to recall memory: {str(e)}"}

    def get_target_dossier(self, target: str) -> Dict[str, Any]:
        """
        Retrieves complete intelligence dossier on a target: historical scores, grades,
        open ports, verified vulnerabilities, sensitive endpoints, and MITRE ATT&CK mappings.
        """
        try:
            mem = self._get_memory_engine()
            dossier = mem.get_target_dossier(target)
            if dossier:
                return {"success": True, "target": target, "dossier": dossier}
            return {"success": False, "target": target, "message": f"No dossier found for '{target}'."}
        except Exception as e:
            return {"success": False, "error": str(e)}
