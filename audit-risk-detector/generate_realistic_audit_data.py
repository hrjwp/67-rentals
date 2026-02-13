import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

class RealisticAuditDataGenerator:
    """
    Generate realistic audit log data for training the AI risk detector
    Creates both legitimate admin activity and various attack patterns
    """
    
    def __init__(self):
        self.action_types = {
            'normal': [
                'VIEW_DASHBOARD', 'UPDATE_VEHICLE', 'UPDATE_BOOKING', 'VIEW_USER',
                'CREATE_VEHICLE', 'UPDATE_USER', 'VIEW_BOOKING', 'CREATE_BOOKING',
                'APPROVE_REFUND', 'VIEW_ANALYTICS', 'GENERATE_REPORT', 'UPDATE_LISTING'
            ],
            'sensitive': [
                'DELETE_USER', 'DELETE_BOOKING', 'UPDATE_PERMISSIONS', 'GRANT_ACCESS',
                'REVOKE_ACCESS', 'CHANGE_PASSWORD', 'UPDATE_ROLE', 'EXPORT_DATA',
                'BULK_DELETE', 'MODIFY_SECURITY', 'SYSTEM_CONFIG', 'CREDENTIAL_CHANGE'
            ],
            'exfiltration': [
                'EXPORT_USERS', 'EXPORT_BOOKINGS', 'BULK_READ', 'DOWNLOAD_LOGS',
                'EXPORT_VEHICLES', 'VIEW_ALL_USERS', 'BACKUP_DATA', 'COPY_DATA'
            ]
        }
        
        self.entity_types = [
            'USER', 'BOOKING', 'VEHICLE', 'PAYMENT', 'DOCUMENT', 
            'LOG', 'PERMISSION', 'ROLE', 'REFUND', 'INCIDENT'
        ]
    
    def generate_normal_activity(self, num_samples: int = 800) -> pd.DataFrame:
        """Generate legitimate admin activity patterns"""
        data = []
        
        for _ in range(num_samples):
            # Normal activity during business hours
            hour = random.choice(range(8, 18))  # 8 AM - 6 PM
            is_weekend = random.random() < 0.1  # 10% weekend work
            
            # Moderate activity levels
            actions_last_hour = np.random.poisson(4)  # Average 4 actions/hour
            actions_last_day = np.random.poisson(25)  # Average 25 actions/day
            
            # Low failure rates
            failed_actions = np.random.binomial(actions_last_hour, 0.05)  # 5% failure rate
            consecutive_failures = min(failed_actions, 2)
            
            # Reasonable intervals
            avg_interval = np.random.normal(15, 5)  # 15 min avg, 5 min std
            avg_interval = max(5, avg_interval)  # At least 5 minutes
            
            # Few sensitive actions
            sensitive_actions = np.random.binomial(actions_last_hour, 0.2)  # 20% sensitive
            
            # Balanced operation types
            total_ops = actions_last_hour
            delete_ops = np.random.binomial(total_ops, 0.05)  # 5% deletes
            update_ops = np.random.binomial(total_ops, 0.3)  # 30% updates
            create_ops = np.random.binomial(total_ops, 0.15)  # 15% creates
            view_ops = total_ops - delete_ops - update_ops - create_ops
            view_ops = max(0, view_ops)
            
            # Low diversity (focused work)
            unique_entities = random.randint(1, 3)
            
            # Minimal privilege changes
            privilege_changes = np.random.binomial(1, 0.05)  # 5% chance of 1 change
            
            # Moderate data access
            data_access = np.random.poisson(20)  # Average 20 records
            
            # Stable IP/device
            ip_diversity = np.random.uniform(0, 1)
            device_changes = np.random.binomial(1, 0.1)  # 10% chance of device change
            
            # Generate action list
            num_actions = min(actions_last_hour, 10)
            recent_actions = random.choices(self.action_types['normal'], k=num_actions)
            
            # Entity types accessed
            entity_types = random.choices(self.entity_types, k=unique_entities)
            
            data.append({
                'actions_last_hour': actions_last_hour,
                'actions_last_day': actions_last_day,
                'failed_actions_count': failed_actions,
                'avg_action_interval_minutes': avg_interval,
                'sensitive_actions_count': sensitive_actions,
                'delete_operations_count': delete_ops,
                'update_operations_count': update_ops,
                'create_operations_count': create_ops,
                'view_operations_count': view_ops,
                'unique_entity_types': unique_entities,
                'consecutive_failures': consecutive_failures,
                'privilege_level_changes': privilege_changes,
                'data_access_volume': data_access,
                'ip_diversity_score': ip_diversity,
                'device_changes': device_changes,
                'hour_of_day': hour,
                'is_weekend': int(is_weekend),
                'recent_actions': '|'.join(recent_actions),
                'entity_types_accessed': '|'.join(entity_types),
                'is_suspicious': 0
            })
        
        return pd.DataFrame(data)
    
    def generate_data_exfiltration(self, num_samples: int = 50) -> pd.DataFrame:
        """Generate data exfiltration attack patterns"""
        data = []
        
        for _ in range(num_samples):
            # Off-hours activity
            hour = random.choice(list(range(0, 6)) + list(range(22, 24)))
            is_weekend = random.random() < 0.6  # 60% during weekends
            
            # HIGH activity
            actions_last_hour = np.random.randint(20, 60)
            actions_last_day = np.random.randint(100, 300)
            
            # Some failures (trying different methods)
            failed_actions = np.random.randint(3, 12)
            consecutive_failures = np.random.randint(1, 5)
            
            # RAPID actions
            avg_interval = np.random.uniform(0.5, 3)  # 30 sec - 3 min
            
            # Many sensitive/export actions
            sensitive_actions = np.random.randint(5, 15)
            
            # Mostly view/export operations
            delete_ops = 0
            update_ops = np.random.randint(0, 3)
            create_ops = 0
            view_ops = actions_last_hour - update_ops
            
            # HIGH diversity (accessing many different things)
            unique_entities = np.random.randint(4, 8)
            
            # No privilege changes (already have access)
            privilege_changes = 0
            
            # VERY HIGH data access
            data_access = np.random.randint(100, 500)
            
            # Variable IP (using VPN/proxy)
            ip_diversity = np.random.uniform(2, 6)
            device_changes = np.random.randint(1, 4)
            
            # Generate exfiltration actions
            num_exfil = random.randint(3, 8)
            num_normal = max(0, min(actions_last_hour, 10) - num_exfil)
            recent_actions = (
                random.choices(self.action_types['exfiltration'], k=num_exfil) +
                random.choices(self.action_types['normal'], k=num_normal)
            )
            random.shuffle(recent_actions)
            
            # Many entity types
            entity_types = random.sample(self.entity_types, k=unique_entities)
            
            data.append({
                'actions_last_hour': actions_last_hour,
                'actions_last_day': actions_last_day,
                'failed_actions_count': failed_actions,
                'avg_action_interval_minutes': avg_interval,
                'sensitive_actions_count': sensitive_actions,
                'delete_operations_count': delete_ops,
                'update_operations_count': update_ops,
                'create_operations_count': create_ops,
                'view_operations_count': view_ops,
                'unique_entity_types': unique_entities,
                'consecutive_failures': consecutive_failures,
                'privilege_level_changes': privilege_changes,
                'data_access_volume': data_access,
                'ip_diversity_score': ip_diversity,
                'device_changes': device_changes,
                'hour_of_day': hour,
                'is_weekend': int(is_weekend),
                'recent_actions': '|'.join(recent_actions[:10]),
                'entity_types_accessed': '|'.join(entity_types),
                'is_suspicious': 1
            })
        
        return pd.DataFrame(data)
    
    def generate_privilege_escalation(self, num_samples: int = 40) -> pd.DataFrame:
        """Generate privilege escalation attack patterns"""
        data = []
        
        for _ in range(num_samples):
            # Often during off-hours
            hour = random.choice(list(range(0, 7)) + list(range(20, 24)) + list(range(10, 16)))
            is_weekend = random.random() < 0.4
            
            # Moderate to high activity
            actions_last_hour = np.random.randint(8, 25)
            actions_last_day = np.random.randint(30, 80)
            
            # HIGH failures (testing access levels)
            failed_actions = np.random.randint(5, 15)
            consecutive_failures = np.random.randint(4, 10)
            
            # Fast actions
            avg_interval = np.random.uniform(2, 8)
            
            # MANY sensitive actions
            sensitive_actions = np.random.randint(6, 15)
            
            # Mix of operations
            delete_ops = np.random.randint(1, 4)
            update_ops = np.random.randint(3, 8)
            create_ops = np.random.randint(1, 5)
            view_ops = max(0, actions_last_hour - delete_ops - update_ops - create_ops)
            
            # Moderate diversity
            unique_entities = np.random.randint(2, 5)
            
            # MANY privilege changes
            privilege_changes = np.random.randint(3, 7)
            
            # Moderate data access
            data_access = np.random.randint(30, 100)
            
            # Variable IP
            ip_diversity = np.random.uniform(2, 5)
            device_changes = np.random.randint(1, 4)
            
            # Generate privilege-related actions
            num_sensitive = random.randint(4, 8)
            num_normal = max(0, min(actions_last_hour, 10) - num_sensitive)
            recent_actions = (
                random.choices(self.action_types['sensitive'], k=num_sensitive) +
                random.choices(self.action_types['normal'], k=num_normal)
            )
            random.shuffle(recent_actions)
            
            # Focus on permission-related entities
            entity_types = random.sample(['USER', 'PERMISSION', 'ROLE'] + 
                                       random.choices(self.entity_types, k=2), 
                                       k=unique_entities)
            
            data.append({
                'actions_last_hour': actions_last_hour,
                'actions_last_day': actions_last_day,
                'failed_actions_count': failed_actions,
                'avg_action_interval_minutes': avg_interval,
                'sensitive_actions_count': sensitive_actions,
                'delete_operations_count': delete_ops,
                'update_operations_count': update_ops,
                'create_operations_count': create_ops,
                'view_operations_count': view_ops,
                'unique_entity_types': unique_entities,
                'consecutive_failures': consecutive_failures,
                'privilege_level_changes': privilege_changes,
                'data_access_volume': data_access,
                'ip_diversity_score': ip_diversity,
                'device_changes': device_changes,
                'hour_of_day': hour,
                'is_weekend': int(is_weekend),
                'recent_actions': '|'.join(recent_actions[:10]),
                'entity_types_accessed': '|'.join(entity_types),
                'is_suspicious': 1
            })
        
        return pd.DataFrame(data)
    
    def generate_bulk_deletion(self, num_samples: int = 35) -> pd.DataFrame:
        """Generate bulk deletion/sabotage attack patterns"""
        data = []
        
        for _ in range(num_samples):
            # Random hours (disgruntled insiders can act anytime)
            hour = random.randint(0, 23)
            is_weekend = random.random() < 0.5
            
            # Moderate activity focused on deletion
            actions_last_hour = np.random.randint(10, 30)
            actions_last_day = np.random.randint(25, 70)
            
            # Some failures (deletion not allowed)
            failed_actions = np.random.randint(2, 8)
            consecutive_failures = np.random.randint(2, 6)
            
            # Fast deletions
            avg_interval = np.random.uniform(1, 5)
            
            # Many sensitive operations
            sensitive_actions = np.random.randint(7, 15)
            
            # HIGH delete operations
            delete_ops = np.random.randint(5, 12)
            update_ops = np.random.randint(1, 4)
            create_ops = 0
            view_ops = max(0, actions_last_hour - delete_ops - update_ops)
            
            # Moderate diversity
            unique_entities = np.random.randint(3, 6)
            
            # Some privilege changes (trying to get delete access)
            privilege_changes = np.random.randint(0, 3)
            
            # Moderate data access
            data_access = np.random.randint(40, 120)
            
            # Stable or variable IP
            ip_diversity = np.random.uniform(0, 3)
            device_changes = np.random.randint(0, 2)
            
            # Generate delete-heavy actions
            delete_actions = ['DELETE_USER', 'DELETE_BOOKING', 'BULK_DELETE', 'DELETE_VEHICLE', 'DELETE_LOG']
            num_deletes = random.randint(4, 7)
            num_other = max(0, min(actions_last_hour, 10) - num_deletes)
            recent_actions = (
                random.choices(delete_actions, k=num_deletes) +
                random.choices(self.action_types['normal'] + self.action_types['sensitive'], k=num_other)
            )
            random.shuffle(recent_actions)
            
            # Various entity types
            entity_types = random.sample(self.entity_types, k=unique_entities)
            
            data.append({
                'actions_last_hour': actions_last_hour,
                'actions_last_day': actions_last_day,
                'failed_actions_count': failed_actions,
                'avg_action_interval_minutes': avg_interval,
                'sensitive_actions_count': sensitive_actions,
                'delete_operations_count': delete_ops,
                'update_operations_count': update_ops,
                'create_operations_count': create_ops,
                'view_operations_count': view_ops,
                'unique_entity_types': unique_entities,
                'consecutive_failures': consecutive_failures,
                'privilege_level_changes': privilege_changes,
                'data_access_volume': data_access,
                'ip_diversity_score': ip_diversity,
                'device_changes': device_changes,
                'hour_of_day': hour,
                'is_weekend': int(is_weekend),
                'recent_actions': '|'.join(recent_actions[:10]),
                'entity_types_accessed': '|'.join(entity_types),
                'is_suspicious': 1
            })
        
        return pd.DataFrame(data)
    
    def generate_automated_attack(self, num_samples: int = 35) -> pd.DataFrame:
        """Generate automated bot/script attack patterns"""
        data = []
        
        for _ in range(num_samples):
            # Random hours
            hour = random.randint(0, 23)
            is_weekend = random.random() < 0.5
            
            # EXTREMELY HIGH activity
            actions_last_hour = np.random.randint(30, 100)
            actions_last_day = np.random.randint(150, 500)
            
            # Many failures (probing)
            failed_actions = np.random.randint(10, 30)
            consecutive_failures = np.random.randint(5, 15)
            
            # VERY RAPID (bot speed)
            avg_interval = np.random.uniform(0.1, 1.5)  # 6 sec - 90 sec
            
            # Variable sensitive actions
            sensitive_actions = np.random.randint(3, 20)
            
            # Mix of operations
            total_ops = min(actions_last_hour, 50)
            delete_ops = np.random.randint(0, 8)
            update_ops = np.random.randint(2, 15)
            create_ops = np.random.randint(0, 10)
            view_ops = max(0, total_ops - delete_ops - update_ops - create_ops)
            
            # HIGH diversity (scanning everything)
            unique_entities = np.random.randint(5, 9)
            
            # Variable privilege changes
            privilege_changes = np.random.randint(0, 5)
            
            # Variable data access
            data_access = np.random.randint(50, 300)
            
            # High IP diversity (bot networks)
            ip_diversity = np.random.uniform(3, 8)
            device_changes = np.random.randint(2, 6)
            
            # Generate mixed actions
            all_actions = (self.action_types['normal'] + 
                          self.action_types['sensitive'] + 
                          self.action_types['exfiltration'])
            recent_actions = random.choices(all_actions, k=10)
            
            # Many entity types
            entity_types = random.sample(self.entity_types, k=unique_entities)
            
            data.append({
                'actions_last_hour': actions_last_hour,
                'actions_last_day': actions_last_day,
                'failed_actions_count': failed_actions,
                'avg_action_interval_minutes': avg_interval,
                'sensitive_actions_count': sensitive_actions,
                'delete_operations_count': delete_ops,
                'update_operations_count': update_ops,
                'create_operations_count': create_ops,
                'view_operations_count': view_ops,
                'unique_entity_types': unique_entities,
                'consecutive_failures': consecutive_failures,
                'privilege_level_changes': privilege_changes,
                'data_access_volume': data_access,
                'ip_diversity_score': ip_diversity,
                'device_changes': device_changes,
                'hour_of_day': hour,
                'is_weekend': int(is_weekend),
                'recent_actions': '|'.join(recent_actions),
                'entity_types_accessed': '|'.join(entity_types),
                'is_suspicious': 1
            })
        
        return pd.DataFrame(data)
    
    def generate_reconnaissance(self, num_samples: int = 40) -> pd.DataFrame:
        """Generate reconnaissance/information gathering patterns"""
        data = []
        
        for _ in range(num_samples):
            # Various hours
            hour = random.randint(0, 23)
            is_weekend = random.random() < 0.3
            
            # High view activity
            actions_last_hour = np.random.randint(15, 40)
            actions_last_day = np.random.randint(50, 150)
            
            # Moderate failures (access denied to some resources)
            failed_actions = np.random.randint(3, 10)
            consecutive_failures = np.random.randint(1, 5)
            
            # Fast viewing
            avg_interval = np.random.uniform(1, 4)
            
            # Some sensitive actions
            sensitive_actions = np.random.randint(2, 8)
            
            # Mostly view operations
            delete_ops = 0
            update_ops = np.random.randint(0, 2)
            create_ops = 0
            view_ops = actions_last_hour - update_ops
            
            # VERY HIGH diversity (looking at everything)
            unique_entities = np.random.randint(5, 9)
            
            # Few privilege changes
            privilege_changes = np.random.randint(0, 2)
            
            # High data access (viewing lots of records)
            data_access = np.random.randint(80, 250)
            
            # Variable IP
            ip_diversity = np.random.uniform(1, 4)
            device_changes = np.random.randint(0, 3)
            
            # Generate view-heavy actions
            view_actions = ['VIEW_USER', 'VIEW_BOOKING', 'VIEW_DASHBOARD', 'VIEW_ALL_USERS', 'VIEW_ANALYTICS']
            recent_actions = random.choices(view_actions + self.action_types['normal'], k=10)
            
            # Many different entity types
            entity_types = random.sample(self.entity_types, k=unique_entities)
            
            data.append({
                'actions_last_hour': actions_last_hour,
                'actions_last_day': actions_last_day,
                'failed_actions_count': failed_actions,
                'avg_action_interval_minutes': avg_interval,
                'sensitive_actions_count': sensitive_actions,
                'delete_operations_count': delete_ops,
                'update_operations_count': update_ops,
                'create_operations_count': create_ops,
                'view_operations_count': view_ops,
                'unique_entity_types': unique_entities,
                'consecutive_failures': consecutive_failures,
                'privilege_level_changes': privilege_changes,
                'data_access_volume': data_access,
                'ip_diversity_score': ip_diversity,
                'device_changes': device_changes,
                'hour_of_day': hour,
                'is_weekend': int(is_weekend),
                'recent_actions': '|'.join(recent_actions),
                'entity_types_accessed': '|'.join(entity_types),
                'is_suspicious': 1
            })
        
        return pd.DataFrame(data)
    
    def generate_complete_dataset(self, 
                                  num_normal: int = 800,
                                  num_exfiltration: int = 50,
                                  num_privilege_esc: int = 40,
                                  num_bulk_delete: int = 35,
                                  num_automated: int = 35,
                                  num_recon: int = 40) -> pd.DataFrame:
        """Generate complete dataset with all attack types"""
        
        print("Generating normal admin activity...")
        normal_df = self.generate_normal_activity(num_normal)
        
        print("Generating data exfiltration patterns...")
        exfil_df = self.generate_data_exfiltration(num_exfiltration)
        
        print("Generating privilege escalation patterns...")
        priv_df = self.generate_privilege_escalation(num_privilege_esc)
        
        print("Generating bulk deletion patterns...")
        delete_df = self.generate_bulk_deletion(num_bulk_delete)
        
        print("Generating automated attack patterns...")
        auto_df = self.generate_automated_attack(num_automated)
        
        print("Generating reconnaissance patterns...")
        recon_df = self.generate_reconnaissance(num_recon)
        
        # Combine all datasets
        complete_df = pd.concat([
            normal_df, exfil_df, priv_df, delete_df, auto_df, recon_df
        ], ignore_index=True)
        
        # Shuffle the dataset
        complete_df = complete_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Add derived features
        complete_df['entity_diversity_score'] = complete_df.apply(
            lambda row: len(set(row['entity_types_accessed'].split('|'))) * 
                       (len(row['entity_types_accessed'].split('|')) / max(1, row['unique_entity_types'])),
            axis=1
        )
        
        complete_df['unusual_time_score'] = complete_df.apply(
            lambda row: (
                (3 if row['hour_of_day'] < 6 or row['hour_of_day'] > 22 else 0) +
                (2 if row['is_weekend'] else 0) +
                (4 if row['avg_action_interval_minutes'] < 1 else 0)
            ),
            axis=1
        )
        
        complete_df['action_velocity'] = complete_df['actions_last_hour'] / 60.0
        complete_df['risk_score_trend'] = (complete_df['failed_actions_count'] * 0.1 + 
                                          complete_df['sensitive_actions_count'] * 0.15)
        complete_df['anomaly_score'] = (complete_df['unusual_time_score'] * 0.2 + 
                                       complete_df['ip_diversity_score'] * 0.3)
        
        print(f"\nDataset generated successfully!")
        print(f"Total samples: {len(complete_df)}")
        print(f"Suspicious: {complete_df['is_suspicious'].sum()} ({complete_df['is_suspicious'].mean()*100:.1f}%)")
        print(f"Normal: {(~complete_df['is_suspicious'].astype(bool)).sum()} ({(1-complete_df['is_suspicious'].mean())*100:.1f}%)")
        
        return complete_df


# Example usage
if __name__ == '__main__':
    generator = RealisticAuditDataGenerator()
    dataset = generator.generate_complete_dataset()
    
    # Save to CSV
    dataset.to_csv('realistic_audit_data.csv', index=False)
    print("\nDataset saved to 'realistic_audit_data.csv'")
    
    # Show sample statistics
    print("\n" + "=" * 70)
    print("DATASET STATISTICS")
    print("=" * 70)
    print(dataset.describe())
    
    print("\n" + "=" * 70)
    print("ATTACK TYPE DISTRIBUTION")
    print("=" * 70)
    print(f"Suspicious samples: {dataset['is_suspicious'].sum()}")
    print(f"Normal samples: {(~dataset['is_suspicious'].astype(bool)).sum()}")
