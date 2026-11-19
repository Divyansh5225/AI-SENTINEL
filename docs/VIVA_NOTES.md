 hbh# Viva Notes & Model Answers — AI-Sentinel

## Phase: Interactive SOC Dashboard & Forensics CSV Export

### 1. Dashboard me CSV Export feature kyun add kiya gaya aur iska cybersecurity me kya role hai?
**Model Answer:** 
Incident Response aur Digital Forensics ke liye. Real-world Security Operations Center (SOC) me analysts ko attack trends report karne, management ko audit data dene, aur offline SIEM tools (jaise Splunk, ELK stack) me ingest karne ke liye standardized CSV export ki zaroorat hoti hai.

### 2. CSV export endpoint (`/sentinel/export/csv`) par kaunsi security controls lagaye gaye hain?
**Model Answer:**
- **Access Control:** `_local_only()` guard verify karta hai ki request sirf `127.0.0.1` ya `::1` (localhost) se aayi ho; remote IPs ko seedha `403 Forbidden` milta hai.
- **Credential Protection:** Passwords database me save hote waqt hi `db.mask_secrets()` se mask (`***`) ho jaate hain, isliye CSV export me kabhi plaintext credentials leak nahi hote.

### 3. Dashboard filtering client-side (JavaScript) kyun rakhi gayi, server-side database query kyun nahi?
**Model Answer:**
Zero latency aur server efficiency ke liye. Latest 50 events pehle se dashboard table me render ho chuke hote hain. Client-side vanilla JS use karne se bina database par extra load daale instant (0 millisecond) instant-search aur category filtering mil jaati hai.

### 4. Auto-refresh me Pause/Resume toggle aur auto-pause feature kyun zaroori tha?
**Model Answer:**
Usability aur investigation accuracy ke liye. Default me har 5 second me page reload hota hai. Agar koi analyst ek complex SQL injection payload padh raha ho ya search input me type kar raha ho, to reload hone se state reset ho jaati. Isliye analyst ko pause button diya gaya hai aur search box me type karte hi refresh automatically pause ho jata hai.

### 5. Ye feature implement karne ke liye koi nayi external library kyun nahi use ki?
**Model Answer:**
Rule of "Simple over clever" aur offline reproducibility. Python ki built-in standard library (`csv` aur `io.StringIO`) aur vanilla HTML/CSS/JS use kiya gaya hai. Isse project lightweight rehta hai, koi npm ya heavy dependencies nahi chahiye hoti, aur evaluation bina internet ke local computer par reliably chalta hai.
