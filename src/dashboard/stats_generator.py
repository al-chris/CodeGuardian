from typing import List, Dict, Any
from datetime import datetime
import collections
import statistics

class StatsGenerator:
    """Generates statistics and visualizations for dashboard."""
    
    def __init__(self):
        pass
    
    def generate(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics from vulnerabilities."""
        if not vulnerabilities:
            return self._empty_stats()
        
        # Count vulnerabilities by risk level
        risk_levels = [v.get('risk_level', 'unknown').lower() for v in vulnerabilities]
        risk_counts = dict(collections.Counter(risk_levels))
        
        # Count vulnerabilities by type
        vuln_types = [v.get('type', 'unknown').lower() for v in vulnerabilities]
        type_counts = dict(collections.Counter(vuln_types))
        
        # Top 5 most common vulnerability types
        top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Calculate average confidence
        confidences = [float(v.get('confidence', 0)) if isinstance(v.get('confidence', 0), (int, float)) else 0 
                       for v in vulnerabilities]
        avg_confidence = statistics.mean(confidences) if confidences else 0
        
        # Files with most vulnerabilities
        file_counts = collections.Counter([v.get('file_path', 'unknown') for v in vulnerabilities])
        top_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'risk_distribution': risk_counts,
            'type_distribution': type_counts,
            'top_vulnerability_types': dict(top_types),
            'average_confidence': avg_confidence,
            'top_vulnerable_files': dict(top_files),
            'generated_at': datetime.now().isoformat()
        }
    
    def _empty_stats(self) -> Dict[str, Any]:
        """Return empty statistics."""
        return {
            'total_vulnerabilities': 0,
            'risk_distribution': {},
            'type_distribution': {},
            'top_vulnerability_types': {},
            'average_confidence': 0,
            'top_vulnerable_files': {},
            'generated_at': datetime.now().isoformat()
        }
    
    def calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score (0-100)."""
        if not vulnerabilities:
            return 0
        
        # Weights for different risk levels
        risk_weights = {
            'critical': 10,
            'high': 5,
            'medium': 3,
            'low': 1,
            'info': 0.5,
            'unknown': 1
        }
        
        # Calculate weighted sum of vulnerabilities
        total_weight = 0
        for vuln in vulnerabilities:
            risk_level = vuln.get('risk_level', 'unknown').lower()
            weight = risk_weights.get(risk_level, 1)
            total_weight += weight
        
        # Normalize to 0-100 scale (logarithmic scale to prevent extremely high scores)
        import math
        max_reasonable_weight = 50  # Equivalent to 5 critical issues or 10 high issues
        if total_weight == 0:
            return 0
        
        # Log-based scaling that approaches 100 as weight increases
        normalized_score = min(100, 100 * math.log(1 + total_weight / max_reasonable_weight) / math.log(2))
        return round(normalized_score, 1)
    
    def generate_trend_data(self, scan_ids: List[str], scan_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Generate trend data for multiple scans."""
        trend_data = {
            'dates': [],
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'risk_scores': []
        }
        
        for scan_id in scan_ids:
            if scan_id not in scan_results:
                continue
                
            result = scan_results[scan_id]
            timestamp = result.get('timestamp', '')
            vulns = result.get('vulnerabilities', [])
            
            # Count vulnerabilities by risk level
            risk_levels = [v.get('risk_level', 'unknown').lower() for v in vulns]
            risk_counts = collections.Counter(risk_levels)
            
            # Add data points
            trend_data['dates'].append(timestamp)
            trend_data['critical'].append(risk_counts.get('critical', 0))
            trend_data['high'].append(risk_counts.get('high', 0))
            trend_data['medium'].append(risk_counts.get('medium', 0))
            trend_data['low'].append(risk_counts.get('low', 0))
            
            # Add risk score
            risk_score = result.get('risk_score', 0)
            trend_data['risk_scores'].append(risk_score)
        
        return trend_data