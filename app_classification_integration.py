"""
Data Classification Integration for app.py
===========================================

Add these imports and routes to your existing app.py file.
These modifications add data classification protection to sensitive routes.
"""

# ============================================================================
# STEP 1: Add these imports at the top of app.py (after existing imports)
# ============================================================================

from data_classification import (
    check_access,
    enforce_classification,
    redact_dict,
    redact_list,
    require_classification,
    can_access_table,
    get_classification_stats,
    AccessDeniedException
)
from data_classification_config import (
    UserRole,
    ClassificationLevel,
    DATA_CLASSIFICATION,
    TABLE_CLASSIFICATIONS,
    CLASSIFICATION_METADATA
)


# ============================================================================
# STEP 2: Add this new route for Data Classification Dashboard
# ============================================================================

@app.route('/data-classification-dashboard')
@login_required
def data_classification_dashboard():
    """Data Classification Dashboard - Admin only"""
    # Check if user is admin
    if session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Get classification statistics
    stats = get_classification_stats()
    
    return render_template(
        'data_classification_dashboard.html',
        stats=stats,
        all_classifications=DATA_CLASSIFICATION,
        table_classifications=TABLE_CLASSIFICATIONS,
        classification_metadata=CLASSIFICATION_METADATA
    )


# ============================================================================
# STEP 3: Update existing routes with classification protection
# ============================================================================

# Example 1: Protect admin document viewing (EXISTING ROUTE - MODIFY)
@app.route('/admin/document/<int:doc_id>')
@require_classification('user_documents.file_data')  # Add this decorator
def admin_document(doc_id):
    """Admin document view - now protected by classification"""
    # Original code stays the same...
    # existing implementation
    pass


# Example 2: Protect admin panel with user data redaction (EXISTING ROUTE - MODIFY)
@app.route('/admin/panel')
def admin_panel():
    """Admin panel with data classification applied"""
    if 'user' not in session or session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Get current user role and ID
    user_role = session.get('user_type', 'guest')
    user_id = session.get('user_id')
    
    # Original document processing function
    def adapt(ticket):
        user = get_user_by_id(ticket.get('user_id'))
        if not user:
            return None
        
        # Apply data classification to user data
        safe_user = redact_dict(user, 'users', user_role, user_id, user.get('user_id'))
        
        docs = get_user_documents(user['user_id'])
        # ... rest of original code
        
        return {
            'ticket_id': ticket.get('id'),
            'user_id': user['user_id'],
            'email': safe_user.get('email'),  # Now redacted if needed
            'first_name': safe_user.get('first_name'),
            'last_name': safe_user.get('last_name'),
            'phone': safe_user.get('phone_number'),
            'nric': safe_user.get('nric'),  # Redacted for non-admins
            'license': safe_user.get('license_number'),
            'user_type': ticket.get('user_type'),
            'submitted_at': ticket.get('submitted_at'),
            'status': ticket.get('status'),
            # ... rest of fields
        }
    
    # Rest of original admin_panel code...
    pending_tickets = get_signup_tickets(status='pending')
    # ... etc


# Example 3: Protect user profile viewing (NEW ROUTE or MODIFY EXISTING)
@app.route('/api/user/<int:user_id>/profile')
def get_user_profile(user_id):
    """Get user profile with classification protection"""
    user_role = session.get('user_type', 'guest')
    current_user_id = session.get('user_id')
    
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Apply data classification
    safe_user = redact_dict(
        user,
        'users',
        user_role,
        user_id=current_user_id,
        data_owner_id=user['user_id']
    )
    
    return jsonify(safe_user)


# Example 4: Protect booking details (EXISTING ROUTE - MODIFY)
@app.route('/api/booking/<booking_id>')
def get_booking_details(booking_id):
    """Get booking with classification applied"""
    user_role = session.get('user_type', 'guest')
    current_user_id = session.get('user_id')
    
    # Get booking from database
    booking = get_booking_by_id(booking_id)
    if not booking:
        return jsonify({'error': 'Booking not found'}), 404
    
    # Apply data classification
    safe_booking = redact_dict(
        booking,
        'bookings',
        user_role,
        user_id=current_user_id,
        data_owner_id=booking.get('user_id')
    )
    
    return jsonify(safe_booking)


# Example 5: Protect sensitive audit log access
@app.route('/api/audit-logs')
@require_classification('audit_logs.ip_address')  # Only admins can access
def api_audit_logs():
    """Get audit logs - admin only due to RESTRICTED ip_address field"""
    # If decorator doesn't raise exception, user is admin
    logs = get_audit_logs(limit=100)
    return jsonify(logs)


# Example 6: Protect security logs with classification
@app.route('/security-logs')
def security_logs():
    """Security logs page with access control"""
    user_role = session.get('user_type', 'guest')
    
    # Check table-level access
    if not can_access_table('security_logs', user_role):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('index'))
    
    # User has access, render page
    return render_template('security_logs.html')


# Example 7: Protect incident reports
@app.route('/api/incident-reports')
def api_incident_reports():
    """Get incident reports with classification"""
    user_role = session.get('user_type', 'guest')
    current_user_id = session.get('user_id')
    
    # Get all reports
    reports = get_incident_reports()
    
    # Apply classification to entire list
    safe_reports = redact_list(reports, 'incident_reports', user_role, current_user_id)
    
    return jsonify(safe_reports)


# Example 8: Check access before operation
@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    """Delete user - check RESTRICTED access first"""
    user_role = session.get('user_type', 'guest')
    
    try:
        # Enforce that user can access RESTRICTED data (admin only)
        enforce_classification('users.password_hash', user_role)
        
        # If we get here, user is admin - proceed with deletion
        delete_user(user_id)
        
        # Log the action
        add_audit_log(
            user_id=session.get('user_id'),
            action='Delete User',
            entity_type='USER',
            entity_id=user_id,
            result='Success',
            severity='High'
        )
        
        flash('User deleted successfully', 'success')
        return redirect(url_for('admin_panel'))
        
    except AccessDeniedException as e:
        flash(str(e), 'error')
        return redirect(url_for('index'))


# ============================================================================
# STEP 4: Update security dashboard to include classification link
# ============================================================================

# Modify your existing security_dashboard route to add the classification link:
@app.route('/security-dashboard')
def security_dashboard():
    """Security dashboard with data classification link"""
    if session.get('user_type') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Your existing security dashboard code...
    # Just make sure the template includes a link to data_classification_dashboard
    
    return render_template('security_dashboard.html')


# ============================================================================
# STEP 5: Helper function to check access in templates
# ============================================================================

@app.context_processor
def utility_processor():
    """Make classification functions available in templates"""
    def can_user_access(column_name):
        """Check if current user can access a column"""
        user_role = session.get('user_type', 'guest')
        return check_access(column_name, user_role)
    
    def get_user_role():
        """Get current user's role"""
        return session.get('user_type', 'guest')
    
    return dict(
        can_user_access=can_user_access,
        get_user_role=get_user_role
    )


# ============================================================================
# STEP 6: Error handler for AccessDeniedException
# ============================================================================

@app.errorhandler(AccessDeniedException)
def handle_access_denied(e):
    """Handle access denied exceptions"""
    flash(str(e), 'error')
    
    # Log the denied access
    add_audit_log(
        user_id=session.get('user_id', 0),
        action='Access Denied',
        entity_type='SECURITY',
        entity_id=e.column,
        reason=str(e),
        result='Failure',
        severity='Medium'
    )
    
    return redirect(url_for('index'))


# ============================================================================
# INTEGRATION SUMMARY
# ============================================================================
"""
To integrate data classification into your app:

1. Copy data_classification.py and data_classification_config.py to your project root

2. Add the imports from STEP 1 to the top of your app.py

3. Add the data_classification_dashboard route from STEP 2

4. For each sensitive route, add classification checks using one of these patterns:
   - @require_classification() decorator for strict enforcement
   - check_access() for conditional access
   - redact_dict() to show partial data
   - enforce_classification() to raise exceptions

5. Update your security_dashboard.html template to include a link:
   <a href="{{ url_for('data_classification_dashboard') }}">
       <i class="fas fa-tags"></i> Data Classification
   </a>

6. Copy data_classification_dashboard.html to your templates folder

7. Test with different user roles (guest, user, seller, admin)

That's it! Your app now has comprehensive data classification.
"""