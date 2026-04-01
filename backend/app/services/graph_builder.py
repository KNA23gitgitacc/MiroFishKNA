"""
Graph Builder Service
Interface 2: Build graphs using local Neo4j via GraphStorage abstraction.

Replaces the original Zep Cloud-based graph_builder.py.
Supports switching between local (Neo4j) and cloud (Zep) backends
via the STORAGE_BACKEND environment variable.
"""

import os
import uuid
import time
import threading
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass

from ..config import Config
from ..models.task import TaskManager, TaskStatus
from ..storage import Neo4jStorage, GraphStorage
from .text_processor import TextProcessor


# --- Singleton storage instance ---
_storage_instance: Optional[GraphStorage] = None
_storage_lock = threading.Lock()


def get_storage() -> GraphStorage:
    """Get or create the shared GraphStorage singleton."""
    global _storage_instance
    if _storage_instance is None:
        with _storage_lock:
            if _storage_instance is None:
                _storage_instance = Neo4jStorage()
    return _storage_instance


@dataclass
class GraphInfo:
    """Graph information"""
    graph_id: str
    node_count: int
    edge_count: int
    entity_types: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "entity_types": self.entity_types,
        }


class GraphBuilderService:
    """
    Graph Builder Service
    Uses GraphStorage (Neo4j) to build knowledge graphs locally.
    """

    def __init__(self, storage: Optional[GraphStorage] = None, api_key: Optional[str] = None):
        # api_key kept for backward compatibility but not used with Neo4j
        self.storage = storage or get_storage()
        self.task_manager = TaskManager()

    def build_graph_async(
        self,
        text: str,
        ontology: Dict[str, Any],
        graph_name: str = "MiroFish Graph",
        chunk_size: int = 500,
        chunk_overlap: int = 50,
        batch_size: int = 3
    ) -> str:
        """
        Async graph building.

        Args:
            text: Input text
            ontology: Ontology definition (from interface 1)
            graph_name: Graph name
            chunk_size: Text chunk size
            chunk_overlap: Chunk overlap size
            batch_size: Chunks per batch

        Returns:
            Task ID
        """
        task_id = self.task_manager.create_task(
            task_type="graph_build",
            metadata={
                "graph_name": graph_name,
                "chunk_size": chunk_size,
                "text_length": len(text),
            }
        )

        thread = threading.Thread(
            target=self._build_graph_worker,
            args=(task_id, text, ontology, graph_name, chunk_size, chunk_overlap, batch_size)
        )
        thread.daemon = True
        thread.start()

        return task_id

    def _build_graph_worker(
        self,
        task_id: str,
        text: str,
        ontology: Dict[str, Any],
        graph_name: str,
        chunk_size: int,
        chunk_overlap: int,
        batch_size: int
    ):
        """Graph building worker thread"""
        try:
            self.task_manager.update_task(
                task_id,
                status=TaskStatus.PROCESSING,
                progress=5,
                message="Starting graph construction..."
            )

            # 1. Create graph
            graph_id = self.create_graph(graph_name)
            self.task_manager.update_task(
                task_id,
                progress=10,
                message=f"Graph created: {graph_id}"
            )

            # 2. Set ontology
            self.set_ontology(graph_id, ontology)
            self.task_manager.update_task(
                task_id,
                progress=15,
                message="Ontology configured"
            )

            # 3. Split text into chunks
            chunks = TextProcessor.split_text(text, chunk_size, chunk_overlap)
            total_chunks = len(chunks)
            self.task_manager.update_task(
                task_id,
                progress=20,
                message=f"Text split into {total_chunks} chunks"
            )

            # 4. Add text in batches (NER + embedding happens inside storage)
            def progress_cb(progress):
                pct = 20 + int(progress * 70)  # 20-90%
                self.task_manager.update_task(
                    task_id,
                    progress=pct,
                    message=f"Processing chunks... {int(progress * 100)}%"
                )

            episode_ids = self.storage.add_text_batch(
                graph_id, chunks, batch_size, progress_callback=progress_cb
            )

            # 5. Wait for processing (no-op for Neo4j, kept for API compat)
            self.storage.wait_for_processing(episode_ids)

            # 6. Get graph info
            self.task_manager.update_task(
                task_id,
                progress=90,
                message="Retrieving graph info..."
            )

            graph_info = self._get_graph_info(graph_id)

            self.task_manager.complete_task(task_id, {
                "graph_id": graph_id,
                "graph_info": graph_info.to_dict(),
                "chunks_processed": total_chunks,
            })

        except Exception as e:
            import traceback
            error_msg = f"{str(e)}\n{traceback.format_exc()}"
            self.task_manager.fail_task(task_id, error_msg)

    def create_graph(self, name: str) -> str:
        """Create a graph"""
        return self.storage.create_graph(name, description="MiroFish Social Simulation Graph")

    def set_ontology(self, graph_id: str, ontology: Dict[str, Any]):
        """Set graph ontology"""
        self.storage.set_ontology(graph_id, ontology)

    def add_text_batches(
        self,
        graph_id: str,
        chunks: List[str],
        batch_size: int = 3,
        progress_callback: Optional[Callable] = None
    ) -> List[str]:
        """Add text chunks to graph in batches, return episode IDs."""
        def adapted_callback(progress):
            if progress_callback:
                batch_num = int(progress * len(chunks)) // batch_size + 1
                total_batches = (len(chunks) + batch_size - 1) // batch_size
                progress_callback(
                    f"Sending batch {batch_num}/{total_batches}...",
                    progress
                )

        return self.storage.add_text_batch(
            graph_id, chunks, batch_size, progress_callback=adapted_callback
        )

    def _get_graph_info(self, graph_id: str) -> GraphInfo:
        """Get graph info"""
        info = self.storage.get_graph_info(graph_id)
        return GraphInfo(
            graph_id=graph_id,
            node_count=info.get("node_count", 0),
            edge_count=info.get("edge_count", 0),
            entity_types=info.get("entity_types", [])
        )

    def get_graph_data(self, graph_id: str) -> Dict[str, Any]:
        """Get full graph data (nodes + edges with enriched info)."""
        return self.storage.get_graph_data(graph_id)

    def delete_graph(self, graph_id: str):
        """Delete a graph"""
        self.storage.delete_graph(graph_id)
