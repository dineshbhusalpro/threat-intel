"""
Intelligent Text Chunking Module for Threat Intelligence Pipeline
Implements semantic chunking with sliding window and overlap strategies
"""

import re
import logging
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import spacy
import hashlib
from collections import Counter

logger = logging.getLogger(__name__)


@dataclass
class TextChunk:
    """Represents a text chunk with metadata"""
    chunk_id: str
    content: str
    start_position: int
    end_position: int
    chunk_index: int
    document_id: str
    page_numbers: List[int]
    metadata: Dict = field(default_factory=dict)
    embedding: Optional[np.ndarray] = None
    indicators_count: int = 0
    language: str = "en"
    
    def __hash__(self):
        return hash(self.chunk_id)


class SemanticChunker:
    """Advanced semantic chunking with multiple strategies"""
    
    def __init__(self,
                 chunk_size: int = 512,
                 chunk_overlap: int = 128,
                 min_chunk_size: int = 100,
                 max_chunk_size: int = 1000,
                 use_semantic_splitting: bool = True,
                 preserve_indicators: bool = True):
        """
        Initialize semantic chunker
        
        Args:
            chunk_size: Target size for chunks (in tokens)
            chunk_overlap: Overlap between chunks (in tokens)
            min_chunk_size: Minimum allowed chunk size
            max_chunk_size: Maximum allowed chunk size
            use_semantic_splitting: Use semantic boundaries for splitting
            preserve_indicators: Ensure indicators aren't split across chunks
        """
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.min_chunk_size = min_chunk_size
        self.max_chunk_size = max_chunk_size
        self.use_semantic_splitting = use_semantic_splitting
        self.preserve_indicators = preserve_indicators
        
        # Load spaCy models for different languages
        self.nlp_models = {}
        self._load_language_models()
        
        # Semantic similarity model for advanced chunking
        if use_semantic_splitting:
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Regex patterns for indicators (simplified)
        self.indicator_patterns = [
            r'https?://[^\s]+',  # URLs
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Emails
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IPs
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b',  # SHA256
        ]
        
    def _load_language_models(self):
        """Load spaCy models for supported languages"""
        models = {
            'en': 'en_core_web_sm',
            'fr': 'fr_core_news_sm',
            'de': 'de_core_news_sm'
        }
        
        for lang, model_name in models.items():
            try:
                self.nlp_models[lang] = spacy.load(model_name)
                logger.info(f"Loaded spaCy model for {lang}")
            except Exception as e:
                logger.warning(f"Could not load spaCy model {model_name}: {e}")
                # Fallback to English model
                if lang != 'en' and 'en' in self.nlp_models:
                    self.nlp_models[lang] = self.nlp_models['en']
    
    def chunk_document(self, 
                       text: str, 
                       document_id: str,
                       metadata: Dict = None) -> List[TextChunk]:
        """
        Chunk a document using the configured strategy
        
        Args:
            text: Document text to chunk
            document_id: Unique document identifier
            metadata: Additional metadata for chunks
            
        Returns:
            List of TextChunk objects
        """
        if not text:
            return []

        # Clean text - remove NULL bytes
        text = text.replace('\x00', '')
        
        # Detect language
        language = self._detect_language(text)
        
        # Choose chunking strategy
        if self.use_semantic_splitting:
            chunks = self._semantic_chunk(text, document_id, language, metadata)
        else:
            chunks = self._sliding_window_chunk(text, document_id, language, metadata)
        
        # Post-process chunks
        chunks = self._post_process_chunks(chunks)
        
        return chunks
    
    def chunk_pages(self,
                   pages: List[Tuple[int, str]],
                   document_id: str,
                   metadata: Dict = None) -> List[TextChunk]:
        """
        Chunk multiple pages while preserving page boundaries
        
        Args:
            pages: List of (page_number, text) tuples
            document_id: Document identifier
            metadata: Additional metadata
            
        Returns:
            List of TextChunk objects
        """
        all_chunks = []
        current_position = 0
        
        for page_num, page_text in pages:
            if not page_text:
                continue
            
            # Chunk individual page
            page_chunks = self.chunk_document(
                page_text, 
                document_id,
                {**(metadata or {}), 'page_number': page_num}
            )
            
            # Update positions and page numbers
            for chunk in page_chunks:
                chunk.start_position += current_position
                chunk.end_position += current_position
                chunk.page_numbers = [page_num]
                chunk.chunk_index = len(all_chunks)
                all_chunks.append(chunk)
            
            current_position += len(page_text)
        
        # Merge chunks across page boundaries if beneficial
        if self.chunk_overlap > 0:
            all_chunks = self._merge_cross_page_chunks(all_chunks)
        
        return all_chunks
    
    def _semantic_chunk(self, 
                       text: str, 
                       document_id: str,
                       language: str,
                       metadata: Dict = None) -> List[TextChunk]:
        """Perform semantic chunking based on content similarity"""
        
        # Get NLP model for language
        nlp = self.nlp_models.get(language, self.nlp_models['en'])
        
        # Process text with spaCy
        doc = nlp(text)
        
        # Extract sentences
        sentences = [sent.text for sent in doc.sents]
        if not sentences:
            return self._sliding_window_chunk(text, document_id, language, metadata)
        
        # Calculate sentence embeddings
        embeddings = self.embedding_model.encode(sentences)
        
        # Find semantic boundaries
        boundaries = self._find_semantic_boundaries(sentences, embeddings)
        
        # Create chunks based on boundaries
        chunks = []
        current_chunk = []
        current_length = 0
        start_position = 0
        
        for i, sentence in enumerate(sentences):
            sentence_length = len(nlp(sentence))
            
            # Check if adding sentence exceeds max size
            if current_length + sentence_length > self.max_chunk_size and current_chunk:
                # Create chunk
                chunk_text = ' '.join(current_chunk)
                chunk = self._create_chunk(
                    chunk_text,
                    start_position,
                    start_position + len(chunk_text),
                    len(chunks),
                    document_id,
                    language,
                    metadata
                )
                chunks.append(chunk)
                
                # Reset for next chunk (with overlap)
                if self.chunk_overlap > 0:
                    overlap_sentences = self._get_overlap_sentences(
                        current_chunk, 
                        self.chunk_overlap,
                        nlp
                    )
                    current_chunk = overlap_sentences
                    current_length = sum(len(nlp(s)) for s in overlap_sentences)
                    start_position += len(chunk_text) - len(' '.join(overlap_sentences))
                else:
                    current_chunk = []
                    current_length = 0
                    start_position += len(chunk_text) + 1
            
            current_chunk.append(sentence)
            current_length += sentence_length
            
            # Check if at semantic boundary
            if i in boundaries and current_length >= self.min_chunk_size:
                # Create chunk
                chunk_text = ' '.join(current_chunk)
                chunk = self._create_chunk(
                    chunk_text,
                    start_position,
                    start_position + len(chunk_text),
                    len(chunks),
                    document_id,
                    language,
                    metadata
                )
                chunks.append(chunk)
                
                # Reset for next chunk
                current_chunk = []
                current_length = 0
                start_position += len(chunk_text) + 1
        
        # Handle remaining text
        if current_chunk:
            chunk_text = ' '.join(current_chunk)
            chunk = self._create_chunk(
                chunk_text,
                start_position,
                start_position + len(chunk_text),
                len(chunks),
                document_id,
                language,
                metadata
            )
            chunks.append(chunk)
        
        return chunks
    
    def _sliding_window_chunk(self,
                             text: str,
                             document_id: str,
                             language: str,
                             metadata: Dict = None) -> List[TextChunk]:
        """Simple sliding window chunking with overlap"""
        
        # Get NLP model for tokenization
        nlp = self.nlp_models.get(language, self.nlp_models['en'])
        
        # Tokenize text
        doc = nlp(text)
        tokens = [token.text for token in doc]
        
        if not tokens:
            return []
        
        chunks = []
        start_idx = 0
        
        while start_idx < len(tokens):
            # Calculate end index
            end_idx = min(start_idx + self.chunk_size, len(tokens))
            
            # Extract chunk tokens
            chunk_tokens = tokens[start_idx:end_idx]
            chunk_text = ' '.join(chunk_tokens)
            
            # Find actual positions in original text
            start_position = text.find(chunk_tokens[0], start_idx)
            end_position = start_position + len(chunk_text)
            
            # Create chunk
            chunk = self._create_chunk(
                chunk_text,
                start_position,
                end_position,
                len(chunks),
                document_id,
                language,
                metadata
            )
            chunks.append(chunk)
            
            # Move window with overlap
            if end_idx >= len(tokens):
                break
            start_idx += self.chunk_size - self.chunk_overlap
        
        return chunks
    
    def _find_semantic_boundaries(self, 
                                  sentences: List[str], 
                                  embeddings: np.ndarray) -> List[int]:
        """Find semantic boundaries between sentences"""
        
        if len(sentences) <= 1:
            return []
        
        # Calculate similarity between consecutive sentences
        similarities = []
        for i in range(len(embeddings) - 1):
            sim = cosine_similarity(
                embeddings[i].reshape(1, -1),
                embeddings[i + 1].reshape(1, -1)
            )[0][0]
            similarities.append(sim)
        
        # Find boundaries (low similarity points)
        boundaries = []
        if similarities:
            threshold = np.mean(similarities) - np.std(similarities)
            for i, sim in enumerate(similarities):
                if sim < threshold:
                    boundaries.append(i + 1)
        
        return boundaries
    
    def _get_overlap_sentences(self, 
                               sentences: List[str], 
                               overlap_tokens: int,
                               nlp) -> List[str]:
        """Get sentences for overlap region"""
        overlap_sentences = []
        token_count = 0
        
        for sentence in reversed(sentences):
            sent_tokens = len(nlp(sentence))
            if token_count + sent_tokens <= overlap_tokens:
                overlap_sentences.insert(0, sentence)
                token_count += sent_tokens
            else:
                break
        
        return overlap_sentences
    
    def _create_chunk(self,
                     text: str,
                     start_pos: int,
                     end_pos: int,
                     index: int,
                     document_id: str,
                     language: str,
                     metadata: Dict = None) -> TextChunk:
        """Create a TextChunk object"""
        
        # Generate unique chunk ID
        chunk_id = hashlib.md5(
            f"{document_id}_{index}_{text[:50]}".encode()
        ).hexdigest()
        
        # Count indicators in chunk
        indicator_count = self._count_indicators(text)
        
        chunk = TextChunk(
            chunk_id=chunk_id,
            content=text,
            start_position=start_pos,
            end_position=end_pos,
            chunk_index=index,
            document_id=document_id,
            page_numbers=[],
            metadata=metadata or {},
            indicators_count=indicator_count,
            language=language
        )
        
        return chunk
    
    def _count_indicators(self, text: str) -> int:
        """Count potential indicators in text"""
        count = 0
        for pattern in self.indicator_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            count += len(matches)
        return count
    
    def _post_process_chunks(self, chunks: List[TextChunk]) -> List[TextChunk]:
        """Post-process chunks to ensure quality"""
        processed_chunks = []
        
        for chunk in chunks:
            # Skip chunks that are too small
            if len(chunk.content.strip()) < self.min_chunk_size:
                continue
            
            # Ensure indicators aren't split
            if self.preserve_indicators:
                chunk = self._preserve_indicators_in_chunk(chunk)
            
            # Clean up whitespace
            chunk.content = ' '.join(chunk.content.split())
            
            processed_chunks.append(chunk)
        
        return processed_chunks
    
    def _preserve_indicators_in_chunk(self, chunk: TextChunk) -> TextChunk:
        """Ensure indicators aren't split at chunk boundaries"""
        
        # Check if chunk starts or ends with partial indicator
        for pattern in self.indicator_patterns:
            # Check start of chunk
            if re.match(r'^\S+[:./@]', chunk.content):
                # Might be partial indicator at start
                # Would need access to previous chunk to fix
                pass
            
            # Check end of chunk
            if re.search(r'[:./@]\S+', chunk.content):
                # Might be partial indicator at end
                # Would need access to next chunk to fix
                pass
        
        return chunk
    
    def _merge_cross_page_chunks(self, chunks: List[TextChunk]) -> List[TextChunk]:
        """Merge chunks across page boundaries if beneficial"""
        if len(chunks) <= 1:
            return chunks
        
        merged_chunks = []
        i = 0
        
        while i < len(chunks):
            current_chunk = chunks[i]
            
            # Check if can merge with next chunk
            if i < len(chunks) - 1:
                next_chunk = chunks[i + 1]
                
                # Check if chunks are from consecutive pages
                if (current_chunk.page_numbers and next_chunk.page_numbers and
                    max(current_chunk.page_numbers) == min(next_chunk.page_numbers) - 1):
                    
                    # Check combined size
                    combined_length = len(current_chunk.content) + len(next_chunk.content)
                    
                    if combined_length <= self.max_chunk_size:
                        # Merge chunks
                        merged_content = current_chunk.content + " " + next_chunk.content
                        merged_chunk = TextChunk(
                            chunk_id=current_chunk.chunk_id,
                            content=merged_content,
                            start_position=current_chunk.start_position,
                            end_position=next_chunk.end_position,
                            chunk_index=len(merged_chunks),
                            document_id=current_chunk.document_id,
                            page_numbers=current_chunk.page_numbers + next_chunk.page_numbers,
                            metadata={**current_chunk.metadata, **next_chunk.metadata},
                            indicators_count=current_chunk.indicators_count + next_chunk.indicators_count,
                            language=current_chunk.language
                        )
                        merged_chunks.append(merged_chunk)
                        i += 2
                        continue
            
            merged_chunks.append(current_chunk)
            i += 1
        
        return merged_chunks
    
    def _detect_language(self, text: str) -> str:
        """Detect language of text"""
        try:
            from langdetect import detect
            lang = detect(text[:500])
            
            # Map to supported languages
            lang_map = {
                'en': 'en',
                'fr': 'fr',
                'de': 'de'
            }
            return lang_map.get(lang, 'en')
        except:
            return 'en'
    
    def calculate_chunk_statistics(self, chunks: List[TextChunk]) -> Dict:
        """Calculate statistics about chunks"""
        if not chunks:
            return {}
        
        sizes = [len(chunk.content) for chunk in chunks]
        indicator_counts = [chunk.indicators_count for chunk in chunks]
        
        return {
            'total_chunks': len(chunks),
            'avg_chunk_size': np.mean(sizes),
            'min_chunk_size': min(sizes),
            'max_chunk_size': max(sizes),
            'std_chunk_size': np.std(sizes),
            'total_indicators': sum(indicator_counts),
            'avg_indicators_per_chunk': np.mean(indicator_counts),
            'language_distribution': Counter(chunk.language for chunk in chunks)
        }
