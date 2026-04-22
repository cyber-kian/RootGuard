🛡️ RootGuard v1.0

De "Zero-Trust" Behavioral Antivirus voor Linux & Windows.

RootGuard is niet je standaard antivirus die vertrouwt op verouderde databases. RootGuard is een agressieve, gedragsgebaseerde beveiligingsengine die indringers stopt op basis van hun acties, niet hun naam.
🚀 Waarom RootGuard?

Traditionele antivirus-software (zoals Avast of Defender) is vaak te laat bij nieuwe "Zero-Day" aanvallen. RootGuard kijkt naar de architectuur van een aanval:

    Honeypot Monitoring: Gebruikt "canary files" om ransomware te vangen voordat je eigen bestanden worden aangeraakt.

    Contextuele Analyse: Detecteert "imposter" processen (zoals malware die zich verschuilt onder de naam kworker).

    Zero-Permission Execution: Blokkeert automatisch alle root-processen die proberen te draaien vanuit onveilige mappen zoals /tmp.

    Instant Lockdown: Verbreekt direct de netwerkverbinding bij een kritieke infectie om data-exfiltratie te voorkomen.

🛠️ Functies

    Real-time Privilege Scan: Scant elke 500ms op verdachte root-activiteit.

    Auto-Remediation: Killt verdachte processen en zet de malware direct in quarantaine (met chmod 000 beveiliging).

    Persistence Guard: Waarschuwt bij ongeautoriseerde wijzigingen in systeem-opstartservices (systemd).

    Safe-Path Protection: Voorkomt dat vitale systeembestanden per ongeluk worden verwijderd (Self-Preservation).

📦 Installatie

    Clone de repository:
    git clone https://github.com/cyber-kian/RootGuard.git
    cd RootGuard

    Compileer de binary:
    go build -o rootguard antivirus.go

    Installeren op het systeem:
    sudo mv rootguard /usr/local/bin/

⚡ Gebruik

    Draai RootGuard altijd met root-rechten om volledige proces-inspectie mogelijk te maken:
    sudo rootguard

⚠️ Disclaimer

    RootGuard is ontworpen als een agressief beveiligingsmiddel. Het hanteert een Zero-Trust beleid. Test nieuwe software altijd eerst door deze toe te voegen aan de whitelist in de broncode om "false positives" te voorkomen.
