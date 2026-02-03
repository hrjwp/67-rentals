@app.route("/cases")
def cases():
    """Submitted cases page - shows reports for current user."""
    cart_count = get_cart_count(session)
    reports = []

    # DEBUG: Check session data
    print("\n" + "=" * 70)
    print("DEBUG: /cases route accessed")
    print(f"  session.get('user'): {session.get('user')}")
    print(f"  session.get('user_id'): {session.get('user_id')}")
    print(f"  session.get('incident_report_email'): {session.get('incident_report_email')}")
    print("=" * 70 + "\n")

    try:
        user_email = session.get('user') or session.get('incident_report_email')
        user_id = session.get('user_id')

        print(f"🔍 Querying with email={user_email}, user_id={user_id}")

        if user_email or user_id:
            # Get ALL reports first (we'll filter after decryption if needed)
            # This is necessary because email is encrypted in the database
            all_reports = get_incident_reports()

            print(f"📊 Total reports in database: {len(all_reports)}")

            # If admin, show all reports
            if session.get('user_type') == 'admin':
                print("👤 Admin user - showing ALL reports")
                reports = all_reports
            # If regular user, filter by email (after decryption) or user_id
            else:
                print(f"👤 Regular user - filtering for email={user_email}, user_id={user_id}")
                reports = []
                for report in all_reports:
                    # Match by user_id if available (more reliable)
                    if user_id and report.get('user_id') == user_id:
                        reports.append(report)
                        print(f"  ✅ Matched by user_id: report {report.get('id')}")
                        continue

                    # Match by email (already decrypted by get_incident_reports)
                    if user_email and report.get('email'):
                        if report['email'].lower() == user_email.lower():
                            reports.append(report)
                            print(f"  ✅ Matched by email: report {report.get('id')}")

            print(f"\n✅ Retrieved {len(reports)} reports for display")

            # Process reports for display
            for idx, report in enumerate(reports):
                print(f"\n  Report {idx + 1}:")
                print(f"    ID: {report.get('id')}")
                print(f"    User ID: {report.get('user_id')}")
                print(f"    Email: {report.get('email')}")
                print(f"    Full Name: {report.get('full_name')}")
                print(f"    Status: {report.get('status')}")
                print(f"    Created: {report.get('created_at')}")
                print(f"    Files: {report.get('files')} (type: {type(report.get('files'))})")
                print(f"    Files count: {len(report.get('files', []))}")

                # Convert datetime objects to strings if needed
                if 'created_at' in report and report['created_at']:
                    if hasattr(report['created_at'], 'strftime'):
                        report['created_at'] = report['created_at'].strftime('%Y-%m-%d %H:%M:%S')

                # Ensure status field exists
                if not report.get('status'):
                    report['status'] = 'Pending Review'

                # Ensure files field exists (should be hydrated by get_incident_reports)
                if 'files' not in report:
                    print(f"  ⚠️  Report {report.get('id')} missing 'files' field!")
                    report['files'] = []
        else:
            print("⚠️ No user_email or user_id found in session - cannot fetch reports")

    except Exception as e:
        print(f"❌ ERROR loading incident reports: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading your incident reports. Please try again.", "error")
        reports = []

    print(f"\n📊 Rendering template with {len(reports)} reports\n")

    return render_template("submitted_cases.html",
                           cart_count=cart_count,
                           reports=reports)
