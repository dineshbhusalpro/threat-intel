"""
Multilingual Embedding Module for Threat Intelligence Pipeline
Generates embeddings for text chunks using sentence-transformers
"""

import logging
import numpy as np
from typing import List, Dict, Optional, Union, Tuple
from dataclasses import dataclass
import torch
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import normalize
import hashlib
import pickle
import os
from pathlib import Path
from tqdm import tqdm
import json

logger = logging.getLogger(__name__)


@dataclass
class EmbeddingResult:
    """Result of embedding generation"""
    text: str
    embedding: np.ndarray
    model_name: str
    dimension: int
    metadata: Dict
    

class MultilingualEmbedder:
    """Multilingual embedding generator with caching and batching"""
    
    # Model recommendations for different use cases
    MODELS = {
        'multilingual': 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2',
        'english': 'sentence-transformers/all-MiniLM-L6-v2',
        'large_multilingual': 'sentence-transformers/LaBSE',
        'security': 'sentence-transformers/all-mpnet-base-v2',
        'fast': 'sentence-transformers/all-MiniLM-L12-v2'
    }
    
    def __init__(self, 
                 model_name: str = None,
                 device: str = None,
                 cache_dir: str = "cache/embeddings",
                 batch_size: int = 32,
                 normalize_embeddings: bool = True):
        """
        Initialize embedder
        
        Args:
            model_name: Name of the sentence-transformer model
            device: Device to use (cuda/cpu/mps)
            cache_dir: Directory for caching embeddings
            batch_size: Batch size for encoding
            normalize_embeddings: Whether to normalize embeddings
        """
        # Select model
        if model_name is None:
            model_name = self.MODELS['multilingual']
        elif model_name in self.MODELS:
            model_name = self.MODELS[model_name]
        
        self.model_name = model_name
        
        # Set device
        if device is None:
            if torch.cuda.is_available():
                device = 'cuda'
            elif torch.backends.mps.is_available():
                device = 'mps'
            else:
                device = 'cpu'
        
        self.device = device
        
        # Load model
        logger.info(f"Loading embedding model: {model_name} on {device}")
        self.model = SentenceTransformer(model_name, device=device)
        self.dimension = self.model.get_sentence_embedding_dimension()
        
        # Settings
        self.batch_size = batch_size
        self.normalize_embeddings = normalize_embeddings
        
        # Setup cache
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / f"{hashlib.md5(model_name.encode()).hexdigest()}.pkl"
        self.cache = self._load_cache()
        
    def _load_cache(self) -> Dict[str, np.ndarray]:
        """Load embedding cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'rb') as f:
                    cache = pickle.load(f)
                logger.info(f"Loaded {len(cache)} cached embeddings")
                return cache
            except Exception as e:
                logger.warning(f"Could not load cache: {e}")
        return {}
    
    def _save_cache(self):
        """Save embedding cache to disk"""
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.cache, f)
        except Exception as e:
            logger.warning(f"Could not save cache: {e}")
    
    def embed_text(self, text: Union[str, List[str]], use_cache: bool = True) -> Union[np.ndarray, List[np.ndarray]]:
        """
        Generate embeddings for text
        
        Args:
            text: Single text or list of texts
            use_cache: Whether to use cached embeddings
            
        Returns:
            Embedding vector(s)
        """
        is_single = isinstance(text, str)
        texts = [text] if is_single else text
        
        embeddings = []
        texts_to_encode = []
        text_indices = []
        
        # Check cache
        for i, t in enumerate(texts):
            cache_key = hashlib.md5(t.encode()).hexdigest()
            
            if use_cache and cache_key in self.cache:
                embeddings.append((i, self.cache[cache_key]))
            else:
                texts_to_encode.append(t)
                text_indices.append(i)
        
        # Encode uncached texts
        if texts_to_encode:
            new_embeddings = self._encode_batch(texts_to_encode)
            
            # Add to cache and results
            for idx, text, embedding in zip(text_indices, texts_to_encode, new_embeddings):
                cache_key = hashlib.md5(text.encode()).hexdigest()
                self.cache[cache_key] = embedding
                embeddings.append((idx, embedding))
        
        # Sort by original index
        embeddings.sort(key=lambda x: x[0])
        result = [emb for _, emb in embeddings]
        
        # Save cache periodically
        if len(self.cache) % 100 == 0:
            self._save_cache()
        
        return result[0] if is_single else result
    
    def _encode_batch(self, texts: List[str]) -> List[np.ndarray]:
        """Encode a batch of texts"""
        all_embeddings = []
        
        # Process in batches
        for i in range(0, len(texts), self.batch_size):
            batch = texts[i:i + self.batch_size]
            
            # Encode batch
            batch_embeddings = self.model.encode(
                batch,
                convert_to_numpy=True,
                show_progress_bar=False,
                normalize_embeddings=self.normalize_embeddings
            )
            
            all_embeddings.extend(batch_embeddings)
        
        return all_embeddings
    
    def embed_chunks(self, 
                     chunks: List,
                     text_field: str = 'content',
                     show_progress: bool = True) -> List[np.ndarray]:
        """
        Embed a list of text chunks
        
        Args:
            chunks: List of chunk objects
            text_field: Field name containing text
            show_progress: Show progress bar
            
        Returns:
            List of embeddings
        """
        texts = []
        for chunk in chunks:
            if hasattr(chunk, text_field):
                texts.append(getattr(chunk, text_field))
            elif isinstance(chunk, dict):
                texts.append(chunk[text_field])
            else:
                texts.append(str(chunk))
        
        # Batch encode with progress bar
        if show_progress:
            embeddings = []
            with tqdm(total=len(texts), desc="Generating embeddings") as pbar:
                for i in range(0, len(texts), self.batch_size):
                    batch = texts[i:i + self.batch_size]
                    batch_embeddings = self.embed_text(batch)
                    embeddings.extend(batch_embeddings)
                    pbar.update(len(batch))
        else:
            embeddings = self.embed_text(texts)
        
        return embeddings
    
    def embed_with_metadata(self, 
                            texts: List[str], 
                            metadata: List[Dict] = None) -> List[EmbeddingResult]:
        """
        Generate embeddings with metadata
        
        Args:
            texts: List of texts to embed
            metadata: Optional metadata for each text
            
        Returns:
            List of EmbeddingResult objects
        """
        embeddings = self.embed_text(texts)
        
        if metadata is None:
            metadata = [{}] * len(texts)
        
        results = []
        for text, embedding, meta in zip(texts, embeddings, metadata):
            result = EmbeddingResult(
                text=text,
                embedding=embedding,
                model_name=self.model_name,
                dimension=self.dimension,
                metadata=meta
            )
            results.append(result)
        
        return results
    
    def compute_similarity(self, 
                          embedding1: np.ndarray, 
                          embedding2: np.ndarray) -> float:
        """Compute cosine similarity between two embeddings"""
        # Ensure embeddings are normalized
        if not self.normalize_embeddings:
            embedding1 = normalize(embedding1.reshape(1, -1))[0]
            embedding2 = normalize(embedding2.reshape(1, -1))[0]
        
        return np.dot(embedding1, embedding2)
    
    def find_similar(self, 
                    query_embedding: np.ndarray,
                    corpus_embeddings: np.ndarray,
                    top_k: int = 10,
                    threshold: float = 0.0) -> List[Tuple[int, float]]:
        """
        Find most similar embeddings in corpus
        
        Args:
            query_embedding: Query embedding vector
            corpus_embeddings: Matrix of corpus embeddings
            top_k: Number of top results to return
            threshold: Minimum similarity threshold
            
        Returns:
            List of (index, similarity) tuples
        """
        # Normalize if needed
        if not self.normalize_embeddings:
            query_embedding = normalize(query_embedding.reshape(1, -1))[0]
            corpus_embeddings = normalize(corpus_embeddings)
        
        # Compute similarities
        similarities = np.dot(corpus_embeddings, query_embedding)
        
        # Filter by threshold
        valid_indices = np.where(similarities >= threshold)[0]
        valid_similarities = similarities[valid_indices]
        
        # Sort and get top-k
        top_indices = np.argsort(valid_similarities)[::-1][:top_k]
        
        results = [
            (valid_indices[idx], valid_similarities[idx]) 
            for idx in top_indices
        ]
        
        return results
    
    def create_index(self, embeddings: np.ndarray) -> 'FaissIndex':
        """
        Create a FAISS index for fast similarity search
        
        Args:
            embeddings: Matrix of embeddings
            
        Returns:
            FaissIndex object
        """
        try:
            import faiss
            
            # Normalize embeddings if needed
            if not self.normalize_embeddings:
                embeddings = normalize(embeddings)
            
            # Create index
            dimension = embeddings.shape[1]
            index = faiss.IndexFlatIP(dimension)  # Inner product for cosine similarity
            
            # Add embeddings
            index.add(embeddings.astype('float32'))
            
            return FaissIndex(index, dimension)
            
        except ImportError:
            logger.warning("FAISS not installed. Using numpy for similarity search.")
            return None
    
    def save_embeddings(self, 
                       embeddings: List[np.ndarray],
                       output_path: str,
                       metadata: List[Dict] = None):
        """Save embeddings to file"""
        
        data = {
            'model_name': self.model_name,
            'dimension': self.dimension,
            'embeddings': [emb.tolist() for emb in embeddings],
            'metadata': metadata or [{}] * len(embeddings)
        }
        
        # Save as JSON for portability
        with open(output_path, 'w') as f:
            json.dump(data, f)
        
        logger.info(f"Saved {len(embeddings)} embeddings to {output_path}")
    
    def load_embeddings(self, input_path: str) -> Tuple[List[np.ndarray], List[Dict]]:
        """Load embeddings from file"""
        
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        embeddings = [np.array(emb) for emb in data['embeddings']]
        metadata = data.get('metadata', [{}] * len(embeddings))
        
        logger.info(f"Loaded {len(embeddings)} embeddings from {input_path}")
        
        return embeddings, metadata
    
    def get_model_info(self) -> Dict:
        """Get information about the current model"""
        return {
            'model_name': self.model_name,
            'dimension': self.dimension,
            'device': self.device,
            'max_sequence_length': self.model.max_seq_length,
            'normalize_embeddings': self.normalize_embeddings,
            'cache_size': len(self.cache)
        }
    
    def clear_cache(self):
        """Clear the embedding cache"""
        self.cache.clear()
        if self.cache_file.exists():
            self.cache_file.unlink()
        logger.info("Cleared embedding cache")
    
    def __del__(self):
        """Save cache on deletion"""
        if hasattr(self, 'cache') and self.cache:
            self._save_cache()


class FaissIndex:
    """Wrapper for FAISS index"""
    
    def __init__(self, index, dimension: int):
        self.index = index
        self.dimension = dimension
    
    def search(self, query: np.ndarray, k: int = 10) -> Tuple[np.ndarray, np.ndarray]:
        """
        Search for similar vectors
        
        Args:
            query: Query vector
            k: Number of results
            
        Returns:
            Distances and indices
        """
        query = query.reshape(1, -1).astype('float32')
        distances, indices = self.index.search(query, k)
        return distances[0], indices[0]
    
    def add(self, embeddings: np.ndarray):
        """Add embeddings to index"""
        self.index.add(embeddings.astype('float32'))
    
    def save(self, path: str):
        """Save index to file"""
        import faiss
        faiss.write_index(self.index, path)
    
    @classmethod
    def load(cls, path: str):
        """Load index from file"""
        import faiss
        index = faiss.read_index(path)
        return cls(index, index.d)