import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random


class RealisticDataGenerator:
    """
    Generates realistic user behavior data with actual fraud patterns
    that ML can learn from
    """

    def __init__(self):
        self.user_ids = [f'user_{i:04d}' for i in range(1, 201)]
        self.vehicle_ids = [f'VEH_{i:03d}' for i in range(100, 300)]

    def generate_legitimate_users(self, num_users=150):
        """Generate realistic legitimate user behavior"""
        legitimate_data = []

        for i in range(num_users):
            # Normal users have consistent, reasonable patterns
            base_behavior = {
                'user_id': random.choice(self.user_ids[:150]),  # First 150 users are legitimate
                'timestamp': datetime.now() - timedelta(hours=random.randint(0, 168)),

                # Login patterns - occasional failed login
                'failed_logins': np.random.choice([0, 1, 2], p=[0.7, 0.25, 0.05]),
                'logins_last_hour': np.random.choice([1, 2, 3], p=[0.6, 0.3, 0.1]),

                # Booking patterns - normal frequency
                'bookings_last_hour': np.random.choice([0, 1, 2], p=[0.5, 0.4, 0.1]),
                'bookings_last_day': np.random.randint(1, 5),
                'avg_booking_interval_minutes': np.random.randint(120, 720),  # 2-12 hours

                # Payment patterns - mostly successful
                'card_declines': np.random.choice([0, 1], p=[0.9, 0.1]),
                'unique_cards_count': np.random.choice([1, 2], p=[0.8, 0.2]),

                # Vehicle usage - realistic speeds and distances
                'reported_mileage': np.random.randint(20, 150),
                'gps_mileage': 0,  # Will calculate
                'travel_speed_kmh': np.random.randint(40, 110),  # Normal driving
                'gps_jump_km': np.random.randint(0, 30),  # Small, reasonable jumps

                # Location patterns - stable
                'location_changes_last_hour': np.random.choice([0, 1, 2], p=[0.6, 0.3, 0.1]),
                'ip_changes_last_day': np.random.choice([0, 1, 2], p=[0.7, 0.25, 0.05]),
                'ip_country_match': 1,  # IP matches user country
                'vpn_detected': 0,  # No VPN

                # Time patterns - normal hours
                'hour_of_day': np.random.choice(range(7, 23)),  # Active during day
                'is_weekend': random.choice([0, 0, 0, 0, 1]),  # Mostly weekdays
            }

            # GPS mileage close to reported (small discrepancy is normal)
            base_behavior['gps_mileage'] = base_behavior['reported_mileage'] + np.random.randint(-5, 5)
            base_behavior['mileage_discrepancy'] = abs(
                base_behavior['reported_mileage'] - base_behavior['gps_mileage']
            )

            # Label
            base_behavior['is_fraud'] = 0

            legitimate_data.append(base_behavior)

        return pd.DataFrame(legitimate_data)

    def generate_fraud_users(self, num_fraudsters=50):
        """Generate realistic fraudulent behavior patterns"""
        fraud_data = []

        for i in range(num_fraudsters):
            # Choose fraud type
            fraud_type = random.choice([
                'account_takeover',
                'rapid_booking_fraud',
                'payment_fraud',
                'mileage_fraud',
                'gps_spoofing'
            ])

            fraud_behavior = {
                'user_id': random.choice(self.user_ids[150:]),  # Last 50 users are fraudsters
                'timestamp': datetime.now() - timedelta(hours=random.randint(0, 168)),
                'fraud_type': fraud_type,
            }

            if fraud_type == 'account_takeover':
                # Multiple failed logins, then success, IP changes
                fraud_behavior.update({
                    'failed_logins': np.random.randint(5, 20),
                    'logins_last_hour': np.random.randint(3, 10),
                    'bookings_last_hour': np.random.randint(0, 3),
                    'bookings_last_day': np.random.randint(1, 8),
                    'avg_booking_interval_minutes': np.random.randint(5, 60),
                    'card_declines': np.random.randint(0, 3),
                    'unique_cards_count': np.random.randint(1, 3),
                    'reported_mileage': np.random.randint(30, 100),
                    'travel_speed_kmh': np.random.randint(40, 120),
                    'gps_jump_km': np.random.randint(0, 50),
                    'location_changes_last_hour': np.random.randint(3, 10),
                    'ip_changes_last_day': np.random.randint(3, 15),
                    'ip_country_match': 0,  # Different country
                    'vpn_detected': np.random.choice([0, 1], p=[0.3, 0.7]),
                    'hour_of_day': np.random.choice(range(0, 24)),
                    'is_weekend': random.choice([0, 1]),
                })

            elif fraud_type == 'rapid_booking_fraud':
                # Multiple bookings in short time
                fraud_behavior.update({
                    'failed_logins': np.random.randint(0, 3),
                    'logins_last_hour': np.random.randint(1, 5),
                    'bookings_last_hour': np.random.randint(5, 20),  # RED FLAG
                    'bookings_last_day': np.random.randint(10, 40),  # RED FLAG
                    'avg_booking_interval_minutes': np.random.randint(1, 15),  # RED FLAG
                    'card_declines': np.random.randint(0, 5),
                    'unique_cards_count': np.random.randint(2, 8),  # Multiple cards
                    'reported_mileage': np.random.randint(20, 100),
                    'travel_speed_kmh': np.random.randint(50, 150),
                    'gps_jump_km': np.random.randint(10, 100),
                    'location_changes_last_hour': np.random.randint(2, 8),
                    'ip_changes_last_day': np.random.randint(0, 5),
                    'ip_country_match': np.random.choice([0, 1], p=[0.3, 0.7]),
                    'vpn_detected': np.random.choice([0, 1], p=[0.5, 0.5]),
                    'hour_of_day': np.random.choice(range(0, 24)),
                    'is_weekend': random.choice([0, 1]),
                })

            elif fraud_type == 'payment_fraud':
                # Multiple card declines, trying different cards
                fraud_behavior.update({
                    'failed_logins': np.random.randint(0, 5),
                    'logins_last_hour': np.random.randint(1, 4),
                    'bookings_last_hour': np.random.randint(2, 8),
                    'bookings_last_day': np.random.randint(3, 15),
                    'avg_booking_interval_minutes': np.random.randint(10, 120),
                    'card_declines': np.random.randint(4, 15),  # RED FLAG
                    'unique_cards_count': np.random.randint(3, 10),  # RED FLAG
                    'reported_mileage': np.random.randint(20, 100),
                    'travel_speed_kmh': np.random.randint(40, 120),
                    'gps_jump_km': np.random.randint(5, 60),
                    'location_changes_last_hour': np.random.randint(0, 5),
                    'ip_changes_last_day': np.random.randint(0, 5),
                    'ip_country_match': np.random.choice([0, 1], p=[0.4, 0.6]),
                    'vpn_detected': np.random.choice([0, 1], p=[0.6, 0.4]),
                    'hour_of_day': np.random.choice(range(0, 24)),
                    'is_weekend': random.choice([0, 1]),
                })

            elif fraud_type == 'mileage_fraud':
                # Fake mileage reports
                reported = np.random.randint(150, 300)
                actual = np.random.randint(50, 120)
                fraud_behavior.update({
                    'failed_logins': np.random.randint(0, 2),
                    'logins_last_hour': np.random.randint(1, 3),
                    'bookings_last_hour': np.random.randint(0, 3),
                    'bookings_last_day': np.random.randint(1, 6),
                    'avg_booking_interval_minutes': np.random.randint(60, 300),
                    'card_declines': np.random.randint(0, 2),
                    'unique_cards_count': np.random.randint(1, 2),
                    'reported_mileage': reported,
                    'gps_mileage': actual,
                    'mileage_discrepancy': abs(reported - actual),  # RED FLAG
                    'travel_speed_kmh': np.random.randint(40, 110),
                    'gps_jump_km': np.random.randint(0, 40),
                    'location_changes_last_hour': np.random.randint(0, 3),
                    'ip_changes_last_day': np.random.randint(0, 2),
                    'ip_country_match': 1,
                    'vpn_detected': 0,
                    'hour_of_day': np.random.choice(range(7, 23)),
                    'is_weekend': random.choice([0, 1]),
                })

            elif fraud_type == 'gps_spoofing':
                # Impossible travel speed, GPS jumps
                fraud_behavior.update({
                    'failed_logins': np.random.randint(0, 3),
                    'logins_last_hour': np.random.randint(1, 4),
                    'bookings_last_hour': np.random.randint(1, 5),
                    'bookings_last_day': np.random.randint(2, 10),
                    'avg_booking_interval_minutes': np.random.randint(30, 180),
                    'card_declines': np.random.randint(0, 3),
                    'unique_cards_count': np.random.randint(1, 3),
                    'reported_mileage': np.random.randint(50, 200),
                    'travel_speed_kmh': np.random.randint(200, 400),  # RED FLAG
                    'gps_jump_km': np.random.randint(200, 800),  # RED FLAG
                    'location_changes_last_hour': np.random.randint(5, 15),
                    'ip_changes_last_day': np.random.randint(1, 8),
                    'ip_country_match': np.random.choice([0, 1], p=[0.5, 0.5]),
                    'vpn_detected': np.random.choice([0, 1], p=[0.4, 0.6]),
                    'hour_of_day': np.random.choice(range(0, 24)),
                    'is_weekend': random.choice([0, 1]),
                })

            # Calculate mileage discrepancy if not already set
            if 'mileage_discrepancy' not in fraud_behavior:
                fraud_behavior['gps_mileage'] = fraud_behavior['reported_mileage'] + np.random.randint(-10, 10)
                fraud_behavior['mileage_discrepancy'] = abs(
                    fraud_behavior['reported_mileage'] - fraud_behavior['gps_mileage']
                )

            # Label as fraud
            fraud_behavior['is_fraud'] = 1

            fraud_data.append(fraud_behavior)

        return pd.DataFrame(fraud_data)

    def generate_complete_dataset(self, num_legitimate=500, num_fraud=100):
        """Generate complete training dataset"""
        print(f"Generating {num_legitimate} legitimate users...")
        legitimate = self.generate_legitimate_users(num_legitimate)

        print(f"Generating {num_fraud} fraudulent users...")
        fraud = self.generate_fraud_users(num_fraud)

        # Combine
        complete_data = pd.concat([legitimate, fraud], ignore_index=True)

        # Shuffle
        complete_data = complete_data.sample(frac=1).reset_index(drop=True)

        print(f"\n Generated {len(complete_data)} total records")
        print(f"   - Legitimate: {len(legitimate)} ({len(legitimate) / len(complete_data) * 100:.1f}%)")
        print(f"   - Fraud: {len(fraud)} ({len(fraud) / len(complete_data) * 100:.1f}%)")

        return complete_data


# ============= USAGE EXAMPLE =============
if __name__ == '__main__':
    generator = RealisticDataGenerator()

    # Generate dataset
    dataset = generator.generate_complete_dataset(
        num_legitimate=500,
        num_fraud=100
    )

    # Save to CSV
    dataset.to_csv('realistic_fraud_data.csv', index=False)
    print("\nSaved to: realistic_fraud_data.csv")

    # Show sample
    print("\nSample legitimate user:")
    print(dataset[dataset['is_fraud'] == 0].iloc[0])

    print("\nSample fraud user:")
    print(dataset[dataset['is_fraud'] == 1].iloc[0])

    # Show statistics
    print("\nDataset Statistics:")
    print(dataset.describe())