"""
CyberAgent Cognitive Memory Engine (Backward Compatibility Wrapper)
Real implementation resides in: cyber_agent.modules.memory
"""

try:
    from .modules.memory import (
        ShortTermMemory,
        get_short_term_memory,
        CyberMemoryEngine,
        get_memory_engine,
        StemmedTokenizer,
        DenseVectorEmbedder
    )
except ImportError:
    try:
        from modules.memory import (
            ShortTermMemory,
            get_short_term_memory,
            CyberMemoryEngine,
            get_memory_engine,
            StemmedTokenizer,
            DenseVectorEmbedder
        )
    except ImportError:
        from cyber_agent.modules.memory import (
            ShortTermMemory,
            get_short_term_memory,
            CyberMemoryEngine,
            get_memory_engine,
            StemmedTokenizer,
            DenseVectorEmbedder
        )

__all__ = [
    "ShortTermMemory",
    "get_short_term_memory",
    "CyberMemoryEngine",
    "get_memory_engine",
    "StemmedTokenizer",
    "DenseVectorEmbedder"
]
