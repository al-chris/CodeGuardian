import re
from typing import Dict, Any, Optional

class FixGenerator:
    """Generates intelligent code fixes for detected vulnerabilities."""
    
    def __init__(self):
        # Templates for common fixes
        self.fix_templates = {
            'sql_injection': {
                'pattern': r'cursor\.execute\s*\(\s*[\'"].*?\s*\+\s*(.+?)\s*[\'"]\s*\)',
                'replacement': "cursor.execute('{}', [{}])",
                'explanation': "Use parameterized queries to prevent SQL injection."
            },
            'command_injection': {
                'pattern': r'(os\.system|subprocess\.call|subprocess\.Popen)\s*\(\s*[\'"].*?\s*\+\s*(.+?)\s*[\'"]\s*\)',
                'replacement': "# SECURITY: Avoid shell commands with user input\n# Consider using secure alternatives like:\n# shlex.quote() or dedicated APIs",
                'explanation': "Avoid shell commands with concatenated user input."
            },
            'hardcoded_secrets': {
                'pattern': r'(\w+)\s*=\s*[\'"]((?!.*\$\{)(?!.*\{\{).+?)[\'"]\s*',
                'replacement': "{} = os.environ.get('{}', '')",
                'explanation': "Store secrets in environment variables or a secure vault service."
            },
            'insecure_deserialization': {
                'pattern': r'pickle\.loads\s*\(\s*(.+?)\s*\)',
                'replacement': "# SECURITY: Avoid pickle with untrusted data\n# Consider JSON or other safer serialization formats",
                'explanation': "Pickle is vulnerable to code execution attacks with untrusted data."
            }
        }
    
    def generate_fix(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate a fix for a vulnerability."""
        vuln_type = vulnerability.get('type', '').lower()
        code_snippet = vulnerability.get('code_snippet', '')
        
        # First try exact template match
        for template_type, template in self.fix_templates.items():
            if template_type in vuln_type:
                fix = self._apply_template(template, code_snippet)
                if fix:
                    return fix
        
        # If no exact match, try type-based fixes
        return self._generate_type_based_fix(vulnerability)
    
    def _apply_template(self, template: Dict[str, str], code_snippet: str) -> Optional[Dict[str, Any]]:
        """Apply a fix template to a code snippet."""
        try:
            pattern = template['pattern']
            replacement_template = template['replacement']
            explanation = template['explanation']
            
            match = re.search(pattern, code_snippet)
            if not match:
                return None
                
            # Handle specific cases
            if 'sql_injection' in template:
                query_parts = code_snippet.split('+')
                static_part = query_parts[0].strip().strip('\'').strip('"')
                param_part = match.group(1).strip()
                fixed_code = replacement_template.format(static_part, param_part)
                
            elif 'command_injection' in template:
                fixed_code = replacement_template
                
            elif 'hardcoded_secrets' in template:
                var_name = match.group(1)
                secret_value = match.group(2)
                env_var_name = var_name.upper()
                fixed_code = replacement_template.format(var_name, env_var_name)
                
            else:
                # Generic replacement
                fixed_code = template['replacement']
            
            return {
                'fixed_code': fixed_code,
                'explanation': explanation,
                'confidence': 'medium'
            }
            
        except Exception as e:
            print(f"Fix template application error: {str(e)}")
            return None
    
    def _generate_type_based_fix(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a fix based on vulnerability type."""
        vuln_type = vulnerability.get('type', '').lower()
        code_snippet = vulnerability.get('code_snippet', '')
        
        # SQL Injection
        if 'sql' in vuln_type:
            return {
                'fixed_code': "# Use parameterized queries\ncursor.execute('SELECT * FROM table WHERE field = %s', [user_input])",
                'explanation': "Use parameterized queries to prevent SQL injection.",
                'confidence': 'low'
            }
        
        # Command Injection
        elif any(x in vuln_type for x in ['command', 'os.system', 'subprocess']):
            return {
                'fixed_code': "# Avoid shell=True and command concatenation\nimport shlex\nsafe_args = [safe_command, shlex.quote(user_input)]\nsubprocess.run(safe_args, shell=False, check=True)",
                'explanation': "Use subprocess with properly quoted arguments and avoid shell=True.",
                'confidence': 'low'
            }
        
        # XSS
        elif 'xss' in vuln_type:
            return {
                'fixed_code': "# Use proper escaping/encoding\nfrom html import escape\nsafe_output = escape(user_input)\nresponse.write(f'<div>{safe_output}</div>')",
                'explanation': "Always encode/escape user input before rendering in HTML context.",
                'confidence': 'low'
            }
        
        # Path Traversal
        elif 'path' in vuln_type or 'file' in vuln_type:
            return {
                'fixed_code': "# Validate file paths\nimport os.path\nsafe_path = os.path.normpath(os.path.join(safe_base_dir, user_filename))\nif not safe_path.startswith(safe_base_dir):\n    raise ValueError('Invalid path')",
                'explanation': "Validate and sanitize file paths to prevent directory traversal.",
                'confidence': 'low'
            }
        
        # Default
        return {
            'fixed_code': "# Review and fix this vulnerability\n# " + code_snippet,
            'explanation': "This requires manual review.",
            'confidence': 'low'
        }