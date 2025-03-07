import os
import magic
import re
from typing import List, Dict, Any

class CodeAnalyzer:
    """Analyzes code and extracts metadata."""
    
    SUPPORTED_EXTENSIONS = {
        '.py': 'Python',
        '.js': 'JavaScript',
        '.ts': 'TypeScript',
        '.java': 'Java',
        '.cpp': 'C++',
        '.h': 'C/C++ Header',
        '.c': 'C',
        '.go': 'Go',
        '.rb': 'Ruby',
        '.php': 'PHP',
        '.html': 'HTML',
        '.css': 'CSS',
        '.jsx': 'React JSX',
        '.tsx': 'React TSX',
        '.scala': 'Scala',
        '.rs': 'Rust',
        '.swift': 'Swift',
        '.kt': 'Kotlin',
        '.sh': 'Shell',
    }
    
    def __init__(self):
        pass
        
    def find_files(self, directory: str) -> List[str]:
        """Find all files in a directory tree."""
        file_list = []
        
        # Common directories to exclude
        exclude_dirs = {
            '.git', '.github', 'node_modules', 'venv', '.venv',
            '__pycache__', '.idea', '.vscode', 'build', 'dist',
        }
        
        for root, dirs, files in os.walk(directory):
            # Modify dirs in-place to exclude certain directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                file_list.append(file_path)
                
        return file_list
    
    def is_supported_file(self, file_path: str) -> bool:
        """Determine if file type is supported for analysis."""
        _, ext = os.path.splitext(file_path)
        return ext.lower() in self.SUPPORTED_EXTENSIONS
    
    def get_file_language(self, file_path: str) -> str:
        """Determine the programming language of the file."""
        _, ext = os.path.splitext(file_path)
        return self.SUPPORTED_EXTENSIONS.get(ext.lower(), 'Unknown')
    
    def extract_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from file."""
        _, ext = os.path.splitext(file_path)
        language = self.get_file_language(file_path)
        
        try:
            # Use libmagic to detect file type
            mime_type = magic.from_file(file_path, mime=True)
            
            # Get file stats
            stat_info = os.stat(file_path)
            
            # Count lines of code
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.count('\n') + 1
                code_lines = self._count_code_lines(content, language)
                comment_lines = self._count_comment_lines(content, language)
                
            return {
                'file_path': file_path,
                'filename': os.path.basename(file_path),
                'extension': ext,
                'language': language,
                'mime_type': mime_type,
                'size_bytes': stat_info.st_size,
                'last_modified': stat_info.st_mtime,
                'total_lines': lines,
                'code_lines': code_lines,
                'comment_lines': comment_lines,
                'complexity_estimate': self._estimate_complexity(content, language)
            }
        except Exception as e:
            return {
                'file_path': file_path,
                'error': str(e)
            }
    
    def _count_code_lines(self, content: str, language: str) -> int:
        """Count non-empty, non-comment lines of code."""
        if language == 'Python':
            # Remove multi-line strings
            content = re.sub(r'""".*?"""', '', content, flags=re.DOTALL)
            content = re.sub(r"'''.*?'''", '', content, flags=re.DOTALL)
            
            # Remove single line comments
            lines = [line for line in content.split('\n') 
                    if line.strip() and not line.strip().startswith('#')]
            
            return len(lines)
            
        # Add other language cases here
        # Default implementation
        lines = [line for line in content.split('\n') if line.strip()]
        return len(lines)
    
    def _count_comment_lines(self, content: str, language: str) -> int:
        """Count comment lines."""
        if language == 'Python':
            # Count single line comments
            single_comments = len([line for line in content.split('\n') 
                                if line.strip().startswith('#')])
            
            # Count multi-line comments
            multi_comments = 0
            multi_regions = re.findall(r'""".*?"""', content, flags=re.DOTALL)
            multi_regions.extend(re.findall(r"'''.*?'''", content, flags=re.DOTALL))
            
            for region in multi_regions:
                multi_comments += region.count('\n') + 1
                
            return single_comments + multi_comments
            
        # Add other language cases here
        # Default implementation
        return 0
    
    def _estimate_complexity(self, content: str, language: str) -> int:
        """Estimate code complexity based on language-specific indicators."""
        complexity = 1
        
        if language == 'Python':
            # Count decision points
            complexity += content.count('if ') 
            complexity += content.count('elif ') 
            complexity += content.count('else:') 
            complexity += content.count('for ') 
            complexity += content.count('while ') 
            complexity += content.count('try:') 
            complexity += content.count('except ') 
            complexity += content.count('with ') 
            # Count classes and functions
            complexity += len(re.findall(r'def\s+\w+\s*\(', content))
            complexity += len(re.findall(r'class\s+\w+\s*', content))
            
        # Add other language cases here
        return complexity