"""
Flask Integration Helper for Audit Risk Detector
This module helps integrate the AI risk detector into your Flask application
"""

from audit_risk_detector import AuditRiskDetector
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json

class AuditRiskAnalyzer:
    """
    Wrapper class for integrating the audit risk detector into Flask
    Provides helper methods to prepare data from your audit logs
    """
    
    def __init__(self, model_path='models/'):
        self.detector = AuditRiskDetector()
        try:
            self.detector.load_models(model_path)
            print(f"✅ Audit risk detector loaded from {model_path}")
        except FileNotFoundError:
            print(f"⚠️  No trained model found at {model_path}")
            print("   Run train_audit_risk_detector.py first to train the model")
    
    def analyze_user_audit_logs(self, user_id: int, db_connection) -> dict:
        """
        Analyze audit logs for a specific user and return risk assessment
        
        Args:
            user_id: The user ID to analyze
            db_connection: Database connection object
            
        Returns:
            dict with risk_score, is_suspicious, reasons, risk_level, and details
        """
        # Fetch recent audit logs for user
        cursor = db_connection.cursor()
        
        # Get logs from last 24 hours (MySQL syntax)
        cursor.execute("""
            SELECT action, entity_type, entity_id, result, timestamp, 
                   ip_address, device_info, risk_score
            FROM audit_logs 
            WHERE user_id = %s AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            ORDER BY timestamp DESC
        """, (user_id,))
        
        recent_logs = cursor.fetchall()
        
        if not recent_logs:
            return {
                'risk_score': 0.0,
                'is_suspicious': False,
                'reasons': ['No recent activity'],
                'risk_level': 'Low',
                'activity_count': 0
            }
        
        # Get logs from last hour (MySQL syntax)
        cursor.execute("""
            SELECT action, entity_type, result
            FROM audit_logs 
            WHERE user_id = %s AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        """, (user_id,))
        
        last_hour_logs = cursor.fetchall()
        
        # Prepare audit data for risk detector
        audit_data = self.prepare_audit_data_from_logs(recent_logs, last_hour_logs)
        
        # Run risk detection
        risk_score, is_suspicious, reasons, risk_level = self.detector.predict_risk(audit_data)
        
        return {
            'risk_score': risk_score,
            'is_suspicious': is_suspicious,
            'reasons': reasons,
            'risk_level': risk_level,
            'activity_count': len(recent_logs),
            'last_hour_count': len(last_hour_logs),
            'audit_data': audit_data  # Include for debugging
        }
    
    def prepare_audit_data_from_logs(self, recent_logs: list, last_hour_logs: list) -> dict:
        """
        Convert raw audit logs into features for the risk detector
        
        Args:
            recent_logs: List of audit log tuples from last 24 hours
            last_hour_logs: List of audit log tuples from last hour
            
        Returns:
            dict with all required features for risk detection
        """
        # Extract data from logs
        actions_24h = [log[0] for log in recent_logs]
        entity_types_24h = [log[1] for log in recent_logs]
        results_24h = [log[3] for log in recent_logs]
        
        actions_1h = [log[0] for log in last_hour_logs]
        entity_types_1h = [log[1] for log in last_hour_logs]
        results_1h = [log[2] for log in last_hour_logs]
        
        # Calculate metrics
        actions_last_hour = len(last_hour_logs)
        actions_last_day = len(recent_logs)
        
        # Count failures
        failed_actions = sum(1 for r in results_24h if r != 'Success')
        failed_1h = sum(1 for r in results_1h if r != 'Success')
        
        # Calculate consecutive failures
        consecutive_failures = 0
        current_streak = 0
        for result in results_24h:
            if result != 'Success':
                current_streak += 1
                consecutive_failures = max(consecutive_failures, current_streak)
            else:
                current_streak = 0
        
        # Calculate average interval between actions
        if len(recent_logs) > 1:
            try:
                timestamps = []
                for log in recent_logs:
                    if log[4]:
                        # Handle both datetime objects and strings
                        if isinstance(log[4], str):
                            # Try different datetime formats
                            try:
                                ts = datetime.fromisoformat(log[4].replace('Z', '+00:00'))
                            except:
                                ts = datetime.strptime(log[4], '%Y-%m-%d %H:%M:%S')
                        else:
                            ts = log[4]  # Already a datetime object
                        timestamps.append(ts)
                
                if timestamps and len(timestamps) > 1:
                    intervals = [(timestamps[i] - timestamps[i+1]).total_seconds() / 60 
                               for i in range(len(timestamps)-1)]
                    avg_interval = sum(intervals) / len(intervals) if intervals else 0
                else:
                    avg_interval = 0
            except Exception as e:
                avg_interval = 0
        else:
            avg_interval = 0
        
        # Categorize actions
        sensitive_keywords = ['DELETE', 'GRANT', 'REVOKE', 'PERMISSION', 'ROLE', 
                             'EXPORT', 'MODIFY', 'DISABLE', 'ALTER', 'CREDENTIAL']
        sensitive_actions = sum(1 for action in actions_24h 
                               if any(kw in action.upper() for kw in sensitive_keywords))
        
        # Count operation types
        delete_ops = sum(1 for action in actions_24h if 'DELETE' in action.upper())
        update_ops = sum(1 for action in actions_24h if 'UPDATE' in action.upper() or 'MODIFY' in action.upper())
        create_ops = sum(1 for action in actions_24h if 'CREATE' in action.upper() or 'ADD' in action.upper())
        view_ops = sum(1 for action in actions_24h if 'VIEW' in action.upper() or 'READ' in action.upper() or 'GET' in action.upper())
        
        # Entity diversity
        unique_entity_types = len(set(entity_types_24h))
        
        # Detect privilege changes
        privilege_keywords = ['ROLE', 'PERMISSION', 'ACCESS', 'GRANT', 'REVOKE']
        privilege_changes = sum(1 for action in actions_24h 
                               if any(kw in action.upper() for kw in privilege_keywords))
        
        # Estimate data access volume (rough approximation)
        data_access = len(recent_logs) * 5  # Assume each action accesses ~5 records on average
        
        # Get IP and device diversity
        ip_addresses = [log[5] for log in recent_logs if log[5]]
        unique_ips = len(set(ip_addresses))
        ip_diversity_score = unique_ips * (unique_ips / max(1, len(ip_addresses)))
        
        devices = [log[6] for log in recent_logs if log[6]]
        device_changes = len(set(devices)) - 1 if devices else 0
        
        # Time-based features
        now = datetime.now()
        hour_of_day = now.hour
        is_weekend = 1 if now.weekday() >= 5 else 0
        
        return {
            'actions_last_hour': actions_last_hour,
            'actions_last_day': actions_last_day,
            'failed_actions_count': failed_actions,
            'avg_action_interval_minutes': avg_interval,
            'sensitive_actions_count': sensitive_actions,
            'delete_operations_count': delete_ops,
            'update_operations_count': update_ops,
            'create_operations_count': create_ops,
            'view_operations_count': view_ops,
            'unique_entity_types': unique_entity_types,
            'consecutive_failures': consecutive_failures,
            'privilege_level_changes': privilege_changes,
            'data_access_volume': data_access,
            'ip_diversity_score': ip_diversity_score,
            'device_changes': device_changes,
            'hour_of_day': hour_of_day,
            'is_weekend': is_weekend,
            'recent_actions': actions_1h[:10],  # Last 10 actions
            'entity_types_accessed': list(set(entity_types_1h))
        }
    
    def get_risk_summary(self, db_connection, hours: int = 24) -> dict:
        """
        Get overall risk summary for all users in the specified time period
        
        Args:
            db_connection: Database connection
            hours: Number of hours to analyze (default 24)
            
        Returns:
            dict with statistics about risky activities
        """
        cursor = db_connection.cursor()
        
        # Get all users with activity in the time period (MySQL syntax)
        cursor.execute("""
            SELECT DISTINCT user_id 
            FROM audit_logs 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        """, (hours,))
        
        user_ids = [row[0] for row in cursor.fetchall()]
        
        risk_summary = {
            'total_users_analyzed': len(user_ids),
            'high_risk_users': [],
            'critical_risk_users': [],
            'medium_risk_users': [],
            'total_suspicious_activities': 0,
            'risk_distribution': {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        }
        
        for user_id in user_ids:
            result = self.analyze_user_audit_logs(user_id, db_connection)
            
            risk_level = result['risk_level']
            risk_summary['risk_distribution'][risk_level] += 1
            
            if result['is_suspicious']:
                risk_summary['total_suspicious_activities'] += 1
                
                user_info = {
                    'user_id': user_id,
                    'risk_score': result['risk_score'],
                    'risk_level': risk_level,
                    'reasons': result['reasons'],
                    'activity_count': result['activity_count']
                }
                
                if risk_level == 'Critical':
                    risk_summary['critical_risk_users'].append(user_info)
                elif risk_level == 'High':
                    risk_summary['high_risk_users'].append(user_info)
                elif risk_level == 'Medium':
                    risk_summary['medium_risk_users'].append(user_info)
        
        return risk_summary


# Example Flask route integration
def example_flask_integration():
    """
    Example of how to integrate into your Flask app
    """
    from flask import Flask, jsonify, request
    from database import get_db_connection
    
    app = Flask(__name__)
    analyzer = AuditRiskAnalyzer()
    
    @app.route('/api/audit-risk/<int:user_id>')
    def check_user_risk(user_id):
        """Check risk for a specific user"""
        with get_db_connection() as conn:
            result = analyzer.analyze_user_audit_logs(user_id, conn)
            return jsonify(result)
    
    @app.route('/api/audit-risk/summary')
    def risk_summary():
        """Get overall risk summary"""
        hours = request.args.get('hours', 24, type=int)
        with get_db_connection() as conn:
            summary = analyzer.get_risk_summary(conn, hours)
            return jsonify(summary)
    
    @app.route('/api/audit-risk/real-time', methods=['POST'])
    def real_time_check():
        """
        Real-time risk check when a new audit log is created
        Call this after adding an audit log entry
        """
        data = request.json
        user_id = data.get('user_id')
        
        with get_db_connection() as conn:
            result = analyzer.analyze_user_audit_logs(user_id, conn)
            
            # If high risk, trigger alert
            if result['risk_level'] in ['High', 'Critical']:
                # Send alert notification
                print(f"🚨 SECURITY ALERT: User {user_id} - {result['risk_level']} risk detected!")
                print(f"   Reasons: {', '.join(result['reasons'])}")
                
                # You could integrate with:
                # - Email alerts
                # - Slack notifications
                # - SMS alerts
                # - Security dashboard
            
            return jsonify(result)


if __name__ == '__main__':
    # Example usage
    from database import get_db_connection
    
    analyzer = AuditRiskAnalyzer()
    
    print("=" * 70)
    print("AUDIT RISK ANALYZER - INTEGRATION EXAMPLE")
    print("=" * 70)
    
    # Example: Check risk for user ID 1
    print("\nAnalyzing user ID 1...")
    with get_db_connection() as conn:
        result = analyzer.analyze_user_audit_logs(1, conn)
        print(f"\nRisk Score: {result['risk_score']:.3f}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Suspicious: {'🚨 YES' if result['is_suspicious'] else '✅ NO'}")
        print(f"Activity: {result['activity_count']} actions in 24h, {result['last_hour_count']} in last hour")
        if result['reasons']:
            print("Reasons:")
            for reason in result['reasons']:
                print(f"  - {reason}")
