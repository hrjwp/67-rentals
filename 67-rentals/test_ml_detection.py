"""
Test Script to Verify ML Fraud Detection is Working
Run this script to test all ML detection features
"""
from fraud_detection import FraudDetector
from utils.ml_behavior_collector import collect_user_behavior_data
import os
import sys

# Fix Unicode encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

def test_model_loaded():
    """Test 1: Verify ML model is loaded"""
    print("\n" + "="*60)
    print("TEST 1: Checking if ML Model is Loaded")
    print("="*60)
    
    detector = FraudDetector()
    model_path = 'models/fraud_detector.pkl'
    
    if os.path.exists(model_path):
        try:
            detector.load_models('models/')
            if detector.anomaly_model is not None:
                print("[PASS] ML Anomaly Detection Model is loaded")
                return True
            else:
                print("[WARNING] Model file exists but anomaly_model is None")
                return False
        except Exception as e:
            print(f"[FAIL] Could not load model: {e}")
            return False
    else:
        print("[WARNING] Model file not found at models/fraud_detector.pkl")
        print("   Run: python train_with_realistic_data.py")
        return False


def test_booking_frequency_detection():
    """Test 2: Verify booking frequency anomaly detection"""
    print("\n" + "="*60)
    print("TEST 2: Booking Frequency Anomaly Detection")
    print("="*60)
    
    detector = FraudDetector()
    if os.path.exists('models/fraud_detector.pkl'):
        try:
            detector.load_models('models/')
        except:
            pass
    
    # Normal user (1 booking per hour)
    normal_user = {
        'failed_logins': 0,
        'logins_last_hour': 1,
        'bookings_last_hour': 1,
        'bookings_last_day': 3,
        'avg_booking_interval_minutes': 240,
        'card_declines': 0,
        'unique_cards_count': 1,
        'reported_mileage': 85,
        'gps_mileage': 82,
        'mileage_discrepancy': 3,
        'travel_speed_kmh': 65,
        'gps_jump_km': 15,
        'location_changes_last_hour': 1,
        'ip_changes_last_day': 0,
        'ip_country_match': 1,
        'vpn_detected': 0,
        'hour_of_day': 14,
        'is_weekend': 0
    }
    
    # Fraud user (12 bookings per hour - abnormal frequency)
    fraud_user = {
        'failed_logins': 2,
        'logins_last_hour': 3,
        'bookings_last_hour': 12,  # RED FLAG - Abnormal frequency
        'bookings_last_day': 25,   # RED FLAG
        'avg_booking_interval_minutes': 5,  # RED FLAG
        'card_declines': 3,
        'unique_cards_count': 5,
        'reported_mileage': 50,
        'gps_mileage': 48,
        'mileage_discrepancy': 2,
        'travel_speed_kmh': 75,
        'gps_jump_km': 40,
        'location_changes_last_hour': 6,
        'ip_changes_last_day': 2,
        'ip_country_match': 0,
        'vpn_detected': 1,
        'hour_of_day': 3,
        'is_weekend': 0
    }
    
    # Test normal user
    score_normal, is_fraud_normal, reasons_normal = detector.predict_fraud(normal_user)
    print(f"\nNormal User Test:")
    print(f"  Score: {score_normal:.3f}")
    print(f"  Is Fraud: {is_fraud_normal}")
    print(f"  Reasons: {reasons_normal if reasons_normal else 'None (Normal)'}")
    
    # Test fraud user
    score_fraud, is_fraud_fraud, reasons_fraud = detector.predict_fraud(fraud_user)
    print(f"\nFraud User Test (12 bookings/hour):")
    print(f"  Score: {score_fraud:.3f}")
    print(f"  Is Fraud: {is_fraud_fraud}")
    print(f"  Reasons: {reasons_fraud}")
    
    # Verify detection
    if is_fraud_fraud or score_fraud > 0.5:
        print("\n[PASS] Booking frequency anomaly detected correctly")
        return True
    else:
        print("\n[WARNING] Booking frequency anomaly not detected (may need model training)")
        return False


def test_mileage_detection():
    """Test 3: Verify mileage discrepancy detection"""
    print("\n" + "="*60)
    print("TEST 3: Mileage Discrepancy Detection")
    print("="*60)
    
    detector = FraudDetector()
    if os.path.exists('models/fraud_detector.pkl'):
        try:
            detector.load_models('models/')
        except:
            pass
    
    # User with fake mileage (large discrepancy)
    fake_mileage_user = {
        'failed_logins': 1,
        'logins_last_hour': 2,
        'bookings_last_hour': 2,
        'bookings_last_day': 5,
        'avg_booking_interval_minutes': 90,
        'card_declines': 1,
        'unique_cards_count': 2,
        'reported_mileage': 200,  # User reports 200 km
        'gps_mileage': 50,        # GPS shows only 50 km (150 km discrepancy!)
        'mileage_discrepancy': 150,  # 75% discrepancy - RED FLAG
        'travel_speed_kmh': 70,
        'gps_jump_km': 20,
        'location_changes_last_hour': 2,
        'ip_changes_last_day': 1,
        'ip_country_match': 1,
        'vpn_detected': 0,
        'hour_of_day': 14,
        'is_weekend': 0
    }
    
    score, is_fraud, reasons = detector.predict_fraud(fake_mileage_user)
    print(f"\nFake Mileage Test (200km reported, 50km GPS):")
    print(f"  Score: {score:.3f}")
    print(f"  Is Fraud: {is_fraud}")
    print(f"  Reasons: {reasons}")
    
    # Check if mileage discrepancy is detected
    mileage_detected = any('mileage' in str(r).lower() for r in reasons) or is_fraud
    
    if mileage_detected or score > 0.5:
        print("\n[PASS] Mileage discrepancy detected")
        return True
    else:
        print("\n[WARNING] Mileage discrepancy not detected (rule-based should catch >20% discrepancy)")
        return False


def test_travel_speed_detection():
    """Test 4: Verify impossible travel speed detection"""
    print("\n" + "="*60)
    print("TEST 4: Impossible Travel Speed Detection")
    print("="*60)
    
    detector = FraudDetector()
    if os.path.exists('models/fraud_detector.pkl'):
        try:
            detector.load_models('models/')
        except:
            pass
    
    # User with impossible travel speed (GPS spoofing)
    impossible_speed_user = {
        'failed_logins': 1,
        'logins_last_hour': 2,
        'bookings_last_hour': 2,
        'bookings_last_day': 5,
        'avg_booking_interval_minutes': 90,
        'card_declines': 1,
        'unique_cards_count': 2,
        'reported_mileage': 120,
        'gps_mileage': 115,
        'mileage_discrepancy': 5,
        'travel_speed_kmh': 280,  # RED FLAG - Impossible speed (>200 km/h)
        'gps_jump_km': 450,       # RED FLAG - Teleportation (>500 km)
        'location_changes_last_hour': 8,
        'ip_changes_last_day': 3,
        'ip_country_match': 0,
        'vpn_detected': 1,
        'hour_of_day': 2,
        'is_weekend': 1
    }
    
    score, is_fraud, reasons = detector.predict_fraud(impossible_speed_user)
    print(f"\nImpossible Speed Test (280 km/h, 450 km GPS jump):")
    print(f"  Score: {score:.3f}")
    print(f"  Is Fraud: {is_fraud}")
    print(f"  Reasons: {reasons}")
    
    # Check if speed anomaly is detected
    speed_detected = any('speed' in str(r).lower() or 'travel' in str(r).lower() or 'gps' in str(r).lower() 
                        for r in reasons) or is_fraud
    
    if speed_detected:
        print("\n[PASS] Impossible travel speed detected")
        return True
    else:
        print("\n[FAIL] Impossible travel speed NOT detected (should be caught by rule-based checks)")
        return False


def test_behavior_collector():
    """Test 5: Verify behavior data collection"""
    print("\n" + "="*60)
    print("TEST 5: Behavior Data Collection")
    print("="*60)
    
    try:
        # Test with a sample user_id (use 1 if exists, otherwise will show what data is available)
        test_user_id = 1
        
        behavior_data = collect_user_behavior_data(
            user_id=test_user_id,
            vehicle_id=1,
            current_location=None,
            prev_location=None,
            time_diff_minutes=1,
            current_ip='127.0.0.1',
            current_country='SG'
        )
        
        print(f"\nCollected Behavior Data for User {test_user_id}:")
        print(f"  Bookings Last Hour: {behavior_data.get('bookings_last_hour', 0)}")
        print(f"  Bookings Last Day: {behavior_data.get('bookings_last_day', 0)}")
        print(f"  Avg Booking Interval: {behavior_data.get('avg_booking_interval_minutes', 0):.1f} minutes")
        print(f"  Failed Logins: {behavior_data.get('failed_logins', 0)}")
        print(f"  Reported Mileage: {behavior_data.get('reported_mileage', 0)}")
        print(f"  GPS Mileage: {behavior_data.get('gps_mileage', 0)}")
        print(f"  Travel Speed: {behavior_data.get('travel_speed_kmh', 0)} km/h")
        print(f"  IP Changes: {behavior_data.get('ip_changes_last_day', 0)}")
        
        # Check if key features are collected
        required_features = ['bookings_last_hour', 'bookings_last_day', 
                            'reported_mileage', 'travel_speed_kmh']
        all_present = all(key in behavior_data for key in required_features)
        
        if all_present:
            print("\n[PASS] Behavior data collection working")
            return True
        else:
            print("\n[WARNING] Some behavior features missing")
            return False
            
    except Exception as e:
        print(f"\n[FAIL] Error collecting behavior data: {e}")
        print("   This might be normal if database is empty or user doesn't exist")
        return False


def test_integration():
    """Test 6: Verify integration in app.py"""
    print("\n" + "="*60)
    print("TEST 6: App Integration Check")
    print("="*60)
    
    try:
        # Check if app.py imports the ML components
        with open('app.py', 'r', encoding='utf-8') as f:
            app_content = f.read()
        
        checks = {
            'FraudDetector imported': 'from fraud_detection import FraudDetector' in app_content,
            'Behavior collector imported': 'from utils.ml_behavior_collector import' in app_content,
            'ML detection in booking flow': 'collect_user_behavior_data' in app_content,
            'Fraud detection called': 'fraud_detector.predict_fraud' in app_content,
            'Auto-retraining scheduled': 'schedule_periodic_retraining' in app_content
        }
        
        print("\nIntegration Checks:")
        all_passed = True
        for check, passed in checks.items():
            status = "[OK]" if passed else "[MISSING]"
            print(f"  {status} {check}")
            if not passed:
                all_passed = False
        
        if all_passed:
            print("\n[PASS] ML system integrated in app.py")
        else:
            print("\n[WARNING] Some integration components missing")
        
        return all_passed
        
    except Exception as e:
        print(f"\n[FAIL] Error checking integration: {e}")
        return False


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("ML FRAUD DETECTION VERIFICATION TESTS")
    print("="*60)
    
    results = []
    
    # Run all tests
    results.append(("Model Loaded", test_model_loaded()))
    results.append(("Booking Frequency Detection", test_booking_frequency_detection()))
    results.append(("Mileage Detection", test_mileage_detection()))
    results.append(("Travel Speed Detection", test_travel_speed_detection()))
    results.append(("Behavior Data Collection", test_behavior_collector()))
    results.append(("App Integration", test_integration()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[SUCCESS] ALL TESTS PASSED! ML system is working correctly.")
    elif passed >= total * 0.7:
        print("\n[WARNING] Most tests passed. ML system is mostly working.")
        print("   Some features may need model training or database data.")
    else:
        print("\n[ERROR] Many tests failed. Check model training and integration.")
    
    print("\n" + "="*60)
    print("HOW TO VERIFY IN PRODUCTION:")
    print("="*60)
    print("1. Make a test booking through the web interface")
    print("2. Check console logs for 'ML Fraud Detection' messages")
    print("3. Visit /booking-fraud-logs to see detected anomalies")
    print("4. Check database: SELECT * FROM booking_fraud_logs ORDER BY timestamp DESC LIMIT 10")
    print("5. Look for entries with 'ML Anomaly Detection' or 'Suspicious Activity'")
    print("="*60)


if __name__ == '__main__':
    main()
