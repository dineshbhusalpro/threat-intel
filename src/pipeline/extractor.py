"""
PDF Extraction Module for Threat Intelligence Pipeline
Handles multi-column layouts, tables, images, and multilingual content
"""

import os
import logging
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
import pdfplumber
import PyPDF2
from PIL import Image
import pytesseract
import cv2
import numpy as np
from pathlib import Path
import hashlib
import json
from datetime import datetime
import re
import magic

logger = logging.getLogger(__name__)


@dataclass
class PDFPage:
    """Represents a single PDF page with extracted content"""
    page_number: int
    text: str
    tables: List[List[List[str]]] = field(default_factory=list)
    images: List[Dict] = field(default_factory=list)
    layout_type: str = "single_column"  # single_column, multi_column, mixed
    language: str = "en"
    metadata: Dict = field(default_factory=dict)
    

@dataclass
class PDFDocument:
    """Represents a complete PDF document"""
    file_path: str
    file_hash: str
    title: str
    pages: List[PDFPage]
    metadata: Dict
    extraction_timestamp: str
    total_pages: int
    languages_detected: List[str]
    

class PDFExtractor:
    """Advanced PDF extraction with layout preservation and OCR support"""
    
    def __init__(self, 
                 enable_ocr: bool = True,
                 ocr_languages: List[str] = None,
                 preserve_layout: bool = True,
                 extract_images: bool = True,
                 extract_tables: bool = True):
        """
        Initialize PDF extractor
        
        Args:
            enable_ocr: Enable OCR for scanned PDFs
            ocr_languages: Languages for OCR (default: ['eng', 'fra', 'deu'])
            preserve_layout: Attempt to preserve document layout
            extract_images: Extract images from PDFs
            extract_tables: Extract tables from PDFs
        """
        self.enable_ocr = enable_ocr
        self.ocr_languages = ocr_languages or ['eng', 'fra', 'deu']
        self.preserve_layout = preserve_layout
        self.extract_images = extract_images
        self.extract_tables = extract_tables
        self.temp_dir = Path("temp/pdf_extraction")
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
    def extract_document(self, pdf_path: str) -> PDFDocument:
        """
        Extract complete content from a PDF document
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            PDFDocument object with all extracted content
        """
        logger.info(f"Starting extraction for: {pdf_path}")
        
        # Validate file
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
        
        if not self._validate_pdf(pdf_path):
            raise ValueError(f"Invalid PDF file: {pdf_path}")
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(pdf_path)
        
        # Extract metadata
        metadata = self._extract_metadata(pdf_path)
        
        # Extract pages
        pages = []
        languages_detected = set()
        
        try:
            with pdfplumber.open(pdf_path) as pdf:
                total_pages = len(pdf.pages)
                
                for page_num, page in enumerate(pdf.pages, 1):
                    logger.debug(f"Processing page {page_num}/{total_pages}")
                    
                    # Extract page content
                    page_obj = self._extract_page(page, page_num, pdf_path)
                    pages.append(page_obj)
                    languages_detected.add(page_obj.language)
                    
        except Exception as e:
            logger.error(f"Error extracting PDF: {e}")
            # Try alternative extraction method
            pages = self._extract_with_pypdf2(pdf_path)
            
        return PDFDocument(
            file_path=pdf_path,
            file_hash=file_hash,
            title=metadata.get('title', os.path.basename(pdf_path)),
            pages=pages,
            metadata=metadata,
            extraction_timestamp=datetime.utcnow().isoformat(),
            total_pages=len(pages),
            languages_detected=list(languages_detected)
        )
    
    def _validate_pdf(self, pdf_path: str) -> bool:
        """Validate if file is a valid PDF"""
        try:
            mime = magic.from_file(pdf_path, mime=True)
            return mime == 'application/pdf'
        except:
            # Fallback to checking file header
            with open(pdf_path, 'rb') as f:
                header = f.read(5)
                return header == b'%PDF-'
    
    def _calculate_file_hash(self, pdf_path: str) -> str:
        """Calculate SHA256 hash of PDF file"""
        sha256_hash = hashlib.sha256()
        with open(pdf_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _extract_metadata(self, pdf_path: str) -> Dict:
        """Extract PDF metadata"""
        metadata = {}
        
        try:
            with open(pdf_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                info = reader.metadata
                
                if info:
                    metadata = {
                        'title': info.get('/Title', ''),
                        'author': info.get('/Author', ''),
                        'subject': info.get('/Subject', ''),
                        'creator': info.get('/Creator', ''),
                        'producer': info.get('/Producer', ''),
                        'creation_date': str(info.get('/CreationDate', '')),
                        'modification_date': str(info.get('/ModDate', '')),
                        'pages': len(reader.pages)
                    }
        except Exception as e:
            logger.warning(f"Error extracting metadata: {e}")
            
        return metadata
    
    def _extract_page(self, page, page_num: int, pdf_path: str) -> PDFPage:
        """Extract content from a single PDF page"""
        page_obj = PDFPage(page_number=page_num, text="")
        
        # Extract text
        text = self._extract_text_with_layout(page)
        
        # If text extraction failed or page is mostly empty, try OCR
        if not text or len(text.strip()) < 50:
            if self.enable_ocr:
                logger.debug(f"Page {page_num} appears to be scanned, attempting OCR")
                text = self._ocr_page(page, pdf_path, page_num)
        
        page_obj.text = text
        
        # Detect layout type
        page_obj.layout_type = self._detect_layout_type(page)
        
        # Extract tables
        if self.extract_tables:
            tables = self._extract_tables(page)
            page_obj.tables = tables
        
        # Extract images
        if self.extract_images:
            images = self._extract_images(page, page_num)
            page_obj.images = images
        
        # Detect language
        page_obj.language = self._detect_language(text)
        
        # Add page metadata
        page_obj.metadata = {
            'width': page.width,
            'height': page.height,
            'rotation': page.rotation or 0,
            'has_text': bool(text),
            'has_tables': bool(page_obj.tables),
            'has_images': bool(page_obj.images)
        }
        
        return page_obj
    
    def _extract_text_with_layout(self, page) -> str:
        """Extract text while preserving layout"""
        if not self.preserve_layout:
            return page.extract_text() or ""
        
        # Extract text with position information
        chars = page.chars
        if not chars:
            return ""
        
        # Group characters into lines based on y-position
        lines = {}
        for char in chars:
            y_pos = round(char['top'])
            if y_pos not in lines:
                lines[y_pos] = []
            lines[y_pos].append(char)
        
        # Sort lines by y-position
        sorted_lines = sorted(lines.items())
        
        # Build text with proper spacing
        text_lines = []
        for y_pos, line_chars in sorted_lines:
            # Sort characters in line by x-position
            line_chars.sort(key=lambda c: c['x0'])
            
            # Build line text with spacing
            line_text = ""
            prev_x1 = None
            
            for char in line_chars:
                if prev_x1 is not None:
                    # Add space if there's a gap
                    gap = char['x0'] - prev_x1
                    if gap > char['width'] * 0.3:
                        line_text += " "
                
                line_text += char['text']
                prev_x1 = char['x1']
            
            text_lines.append(line_text)
        
        return '\n'.join(text_lines)
    
    def _detect_layout_type(self, page) -> str:
        """Detect if page has single or multi-column layout"""
        chars = page.chars
        if not chars:
            return "single_column"
        
        # Analyze x-positions to detect columns
        x_positions = [char['x0'] for char in chars]
        if not x_positions:
            return "single_column"
        
        # Calculate page width zones
        page_width = page.width
        left_third = page_width / 3
        right_third = 2 * page_width / 3
        
        # Count characters in each zone
        left_count = sum(1 for x in x_positions if x < left_third)
        middle_count = sum(1 for x in x_positions if left_third <= x < right_third)
        right_count = sum(1 for x in x_positions if x >= right_third)
        
        total = len(x_positions)
        
        # Determine layout type
        if left_count > total * 0.3 and right_count > total * 0.3:
            return "multi_column"
        elif middle_count > total * 0.6:
            return "single_column"
        else:
            return "mixed"
    
    def _extract_tables(self, page) -> List[List[List[str]]]:
        """Extract tables from page"""
        tables = []
        
        try:
            page_tables = page.extract_tables()
            for table in page_tables:
                if table:  # Filter out empty tables
                    # Clean table data
                    cleaned_table = []
                    for row in table:
                        cleaned_row = [str(cell).strip() if cell else "" for cell in row]
                        if any(cleaned_row):  # Skip completely empty rows
                            cleaned_table.append(cleaned_row)
                    
                    if cleaned_table:
                        tables.append(cleaned_table)
        except Exception as e:
            logger.warning(f"Error extracting tables: {e}")
        
        return tables
    
    def _extract_images(self, page, page_num: int) -> List[Dict]:
        """Extract images from page"""
        images = []
        
        try:
            # Extract images using pdfplumber
            for img_obj in page.images:
                image_info = {
                    'page': page_num,
                    'x0': img_obj.get('x0', 0),
                    'y0': img_obj.get('y0', 0),
                    'width': img_obj.get('width', 0),
                    'height': img_obj.get('height', 0),
                    'object_type': 'image'
                }
                
                # Try to extract actual image data if needed
                # This would require additional processing
                
                images.append(image_info)
        except Exception as e:
            logger.warning(f"Error extracting images: {e}")
        
        return images
    
    def _ocr_page(self, page, pdf_path: str, page_num: int) -> str:
        """Perform OCR on a PDF page"""
        try:
            # Convert page to image
            import fitz  # PyMuPDF
            
            pdf_document = fitz.open(pdf_path)
            pdf_page = pdf_document[page_num - 1]
            
            # Render page to image
            mat = fitz.Matrix(2, 2)  # 2x zoom for better OCR
            pix = pdf_page.get_pixmap(matrix=mat)
            
            # Convert to PIL Image
            img_data = pix.tobytes("png")
            img = Image.open(io.BytesIO(img_data))
            
            # Convert to numpy array for OpenCV processing
            img_array = np.array(img)
            
            # Preprocess image for better OCR
            processed_img = self._preprocess_image_for_ocr(img_array)
            
            # Perform OCR
            ocr_config = f"-l {'+'.join(self.ocr_languages)}"
            text = pytesseract.image_to_string(processed_img, config=ocr_config)
            
            pdf_document.close()
            
            return text
            
        except Exception as e:
            logger.error(f"OCR failed for page {page_num}: {e}")
            return ""
    
    def _preprocess_image_for_ocr(self, image: np.ndarray) -> np.ndarray:
        """Preprocess image for better OCR results"""
        # Convert to grayscale if needed
        if len(image.shape) == 3:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        else:
            gray = image
        
        # Apply thresholding to get binary image
        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        
        # Denoise
        denoised = cv2.medianBlur(binary, 3)
        
        # Deskew if needed
        angle = self._get_skew_angle(denoised)
        if abs(angle) > 0.5:
            denoised = self._rotate_image(denoised, angle)
        
        return denoised
    
    def _get_skew_angle(self, image: np.ndarray) -> float:
        """Detect skew angle in image"""
        edges = cv2.Canny(image, 50, 150, apertureSize=3)
        lines = cv2.HoughLines(edges, 1, np.pi/180, 200)
        
        if lines is not None:
            angles = []
            for rho, theta in lines[0]:
                angle = (theta * 180 / np.pi) - 90
                if abs(angle) < 45:
                    angles.append(angle)
            
            if angles:
                return np.median(angles)
        
        return 0.0
    
    def _rotate_image(self, image: np.ndarray, angle: float) -> np.ndarray:
        """Rotate image by given angle"""
        (h, w) = image.shape[:2]
        center = (w // 2, h // 2)
        M = cv2.getRotationMatrix2D(center, angle, 1.0)
        rotated = cv2.warpAffine(image, M, (w, h), 
                                flags=cv2.INTER_CUBIC, 
                                borderMode=cv2.BORDER_REPLICATE)
        return rotated
    
    def _detect_language(self, text: str) -> str:
        """Detect language of text"""
        if not text or len(text) < 50:
            return "en"
        
        try:
            from langdetect import detect
            lang = detect(text[:500])  # Use first 500 chars for detection
            return lang
        except:
            return "en"
    
    def _extract_with_pypdf2(self, pdf_path: str) -> List[PDFPage]:
        """Fallback extraction method using PyPDF2"""
        pages = []
        
        try:
            with open(pdf_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                
                for page_num, page in enumerate(reader.pages, 1):
                    text = page.extract_text()
                    
                    page_obj = PDFPage(
                        page_number=page_num,
                        text=text,
                        layout_type="unknown",
                        language=self._detect_language(text)
                    )
                    pages.append(page_obj)
                    
        except Exception as e:
            logger.error(f"PyPDF2 extraction failed: {e}")
            
        return pages
    
    def extract_text_only(self, pdf_path: str) -> str:
        """Quick extraction of text only (for simple use cases)"""
        try:
            document = self.extract_document(pdf_path)
            
            # Combine all page texts
            full_text = "\n\n".join(page.text for page in document.pages)
            
            # Include table content
            for page in document.pages:
                for table in page.tables:
                    table_text = "\n".join(["\t".join(row) for row in table])
                    full_text += f"\n\n[Table]\n{table_text}\n"
            
            return full_text
            
        except Exception as e:
            logger.error(f"Text extraction failed: {e}")
            return ""
    
    def save_extraction_results(self, document: PDFDocument, output_path: str):
        """Save extraction results to JSON file"""
        
        # Convert to serializable format
        doc_dict = {
            'file_path': document.file_path,
            'file_hash': document.file_hash,
            'title': document.title,
            'metadata': document.metadata,
            'extraction_timestamp': document.extraction_timestamp,
            'total_pages': document.total_pages,
            'languages_detected': document.languages_detected,
            'pages': []
        }
        
        for page in document.pages:
            page_dict = {
                'page_number': page.page_number,
                'text': page.text,
                'tables': page.tables,
                'images': page.images,
                'layout_type': page.layout_type,
                'language': page.language,
                'metadata': page.metadata
            }
            doc_dict['pages'].append(page_dict)
        
        # Save to JSON
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(doc_dict, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Extraction results saved to: {output_path}")