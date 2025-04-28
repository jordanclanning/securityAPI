import streamlit as st
import requests


st.title("API Dashboard")

domain = st.text_input("Enter a domain to lookup:")

if st.button("Search"):
    st.write(f"Looking up information for: {domain}")

    # Basic Whois lookup using a public API
    whois_url = f"https://api.api-ninjas.com/v1/whois?domain={domain}" ## uses API Ninja 
    headers = {'X-Api-Key': 'xxxxxxxxxxx'}  # Key - 
    response = requests.get(whois_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        st.json(data)  # Display the JSON nicely
    else:
        st.error("Could not fetch data. Check your API key or domain.")
     
        # Wayback Machine lookup
    wayback_url = f"http://archive.org/wayback/available?url={domain}" ## usein Archive.org
    wayback_response = requests.get(wayback_url)

    if wayback_response.status_code == 200:
        wayback_data = wayback_response.json()
        if wayback_data['archived_snapshots']:
            snapshot_url = wayback_data['archived_snapshots']['closest']['url']
            st.success(f"Wayback Machine Snapshot Found!")
            st.markdown(f"[View Snapshot]({snapshot_url})", unsafe_allow_html=True)
        else:
            st.warning("No Wayback Machine snapshots found for this domain.")
    else:
        st.error("Could not check Wayback Machine.")

        #IP Address lookup
    try:
        ip_address = requests.get(f"https://dns.google/resolve?name={domain}").json()['Answer'][0]['data']
        st.success(f"Domain resolves to IP: {ip_address}")
        
        # IP Reputation Check (using ipinfo.io free API)
        ipinfo_url = f"https://ipinfo.io/{ip_address}/json"
        ipinfo_response = requests.get(ipinfo_url)


        if ipinfo_response.status_code == 200:
            ipinfo_data = ipinfo_response.json()
            st.json(ipinfo_data)
        else:
            st.warning("Could not fetch IP reputation info.")
    except:
        st.warning("Could not resolve domain to IP address.")

    # Domain Risk Scoring
    risk_score = 0

    # Risk 1: Domain Age Check
    if 'creation_date' in data:
        from datetime import datetime
        try:
            creation_epoch = data['creation_date'][0]  # Epoch time from API
            from datetime import timezone
            creation_date = datetime.fromtimestamp(creation_epoch, tz=timezone.utc)
            from datetime import timezone
            now = datetime.now(datetime.timezone.utc)
            age_years = (now - creation_date).days / 365
            if age_years < 1:
                risk_score += 3
                st.warning(f"Domain is less than 1 year old ({round(age_years,2)} years)")
            else:
                st.success(f"Domain age: {round(age_years,2)} years")
        except:
            st.warning("Could not calculate domain age.")

    # Risk 2: Wayback Snapshot Check
    if not wayback_data['archived_snapshots']:
        risk_score += 2
        st.warning("No Wayback Machine snapshots found (possible sign of new/fake domain)")
    else:
        st.success("Wayback snapshot history found.")

    # Risk 3: IP Owner Check
    if 'ipinfo_data' in locals():
        if 'org' in ipinfo_data:
            org = ipinfo_data['org'].lower()
            if 'amazon' in org or 'google' in org or 'digitalocean' in org or 'microsoft' in org:
                risk_score += 1
                st.warning(f"IP is hosted on cloud provider: {org}")
            else:
                st.success(f"IP organization: {org}")
    else:
        st.warning("Skipped IP risk check: No IP info available.")

   # --- VirusTotal lookup (MUST BE INSIDE THIS BLOCK) ---
    virustotal_api_key = 'xxxx'
    vt_headers = { "x-apikey": virustotal_api_key }
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    vt_response = requests.get(vt_url, headers=vt_headers)

    if vt_response.status_code == 200:
        vt_data = vt_response.json()
        malicious_count = vt_data['data']['attributes']['last_analysis_stats']['malicious']
        st.subheader("VirusTotal Scan Result")
        if malicious_count > 0:
            risk_score += 5
            st.error(f"⚠️ VirusTotal flagged {malicious_count} engines reporting malicious activity!")
        else:
            st.success("✅ VirusTotal scan clean — no malicious reports found.")
    else:
        st.warning("⚠️ Could not fetch VirusTotal data.")

    # --- Domain Risk Score Display ---
    st.subheader(f"Domain Risk Score: {risk_score}")

    if risk_score <= 3:
        st.success("🟢 GOOD DOMAIN: Likely safe and trustworthy.")
    elif risk_score <= 6:
        st.warning("🟡 CAUTION: Domain shows some minor risks.")
    else:
        st.error("🔴 BAD DOMAIN: High risk detected! Recommend blocking or deeper analysis.")
