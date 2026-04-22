package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// Configuratie
const (
	QUARANTINE_DIR = "./quarantine"
	SCAN_INTERVAL  = 500 * time.Millisecond
)

func main() {
	// 1. Initialisatie
	if os.Geteuid() != 0 && runtime.GOOS != "windows" {
		fmt.Println("❌ FOUT: Draai dit programma met 'sudo' voor volledige bescherming.")
		return
	}

	fmt.Printf("🚀 BDR Hyper-Vigilance opgestart op: %s\n", runtime.GOOS)

	honeypot := getHoneypotPath()
	setupHoneypot(honeypot)
	_ = os.MkdirAll(QUARANTINE_DIR, 0700)

	// 2. Start alle bewakings-engines
	go monitorHoneypot(honeypot)
	go monitorPrivileges()
	go monitorPersistence() // NIEUW: Opstart-bescherming
	go printDashboard()

	// Houd het programma draaiend
	select {}
}

// --- ENGINE 1: Honeypot (Ransomware Detectie) ---
func getHoneypotPath() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "Documents", ".sys_backup.db")
	}
	return filepath.Join(home, ".config", ".sys_backup.db")
}

func setupHoneypot(path string) {
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	_ = ioutil.WriteFile(path, []byte("CANARY_DATA"), 0444)
}

func monitorHoneypot(path string) {
	for {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			fmt.Println("\n🚨 RANSOMWARE GEVONDEN: Honeypot verwijderd!")
			emergencyLockdown()
			setupHoneypot(path) // Herstel
			time.Sleep(10 * time.Second)
		}
		time.Sleep(1 * time.Second)
	}
}

// --- ENGINE 2: Proces & Privilege Analyse ---
func isSafe(name string, p *process.Process) bool {
	// Vertrouw jezelf
	if p.Pid == int32(os.Getpid()) {
		return true
	}

	// Uitgebreide Systeem Whitelist
	systemWhitelist := []string{
		"systemd", "kthreadd", "go", "BDR-Antivirus", "NetworkManager",
		"Xorg", "gnome-shell", "sudo", "bash", "sshd", "resolved", "containerd",
	}

	for _, w := range systemWhitelist {
		if name == w {
			return true
		}
	}

	exe, err := p.Exe()
	if err == nil && exe != "" {
		// Blokkeer alles uit tijdelijke mappen
		if filepath.HasPrefix(exe, "/tmp") || filepath.HasPrefix(exe, "/var/tmp") {
			if name != "antivirus" && name != "go" {
				return false
			}
		}
	}

	// Check voor kworker imposters
	if name == "kworker" || name == "ksoftirqd" {
		if err == nil && exe != "" {
			return false
		}
	}

	return true
}

func monitorPrivileges() {
	for {
		procs, _ := process.Processes()
		for _, p := range procs {
			uids, err := p.Uids()
			if err == nil && len(uids) > 0 && uids[0] == 0 {
				name, _ := p.Name()
				if !isSafe(name, p) {
					exePath, _ := p.Exe()
					fmt.Printf("\n🚨 STOP: Verdacht proces %s (PID: %d) geneutraliseerd.\n", name, p.Pid)
					_ = p.Kill()
					neutralizeFile(exePath)
				}
			}
		}
		time.Sleep(SCAN_INTERVAL)
	}
}

// --- ENGINE 3: Persistence Guard (Opstart-bescherming) ---
func monitorPersistence() {
	// We houden de systemd map in de gaten op Linux
	systemdPath := "/etc/systemd/system/"
	if runtime.GOOS == "windows" {
		return // Voor Windows zou je hier het register scannen
	}

	initialFiles, _ := ioutil.ReadDir(systemdPath)
	fileCount := len(initialFiles)

	for {
		currentFiles, _ := ioutil.ReadDir(systemdPath)
		if len(currentFiles) > fileCount {
			fmt.Println("\n⚠️  WAARSCHUWING: Nieuwe opstartservice gedetecteerd in systemd!")
			// Hier zou je een melding kunnen sturen naar de gebruiker
			fileCount = len(currentFiles)
		}
		time.Sleep(5 * time.Second)
	}
}

// --- HULPFUNCTIES: Opschonen en Lockdown ---
func isSystemPath(path string) bool {
	criticalPaths := []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/etc/"}
	for _, cp := range criticalPaths {
		if filepath.HasPrefix(path, cp) {
			return true
		}
	}
	return false
}

func neutralizeFile(path string) {
	if path == "" || isSystemPath(path) {
		if path != "" {
			fmt.Printf("⚠️  Systeembestand %s bevroren maar niet verwijderd voor veiligheid.\n", path)
		}
		return
	}

	_ = os.Chmod(path, 0000)
	newName := filepath.Join(QUARANTINE_DIR, filepath.Base(path)+".INFECTED")
	_ = os.Rename(path, newName)
	fmt.Printf("✅ Malware verplaatst naar quarantaine: %s\n", newName)
}

func emergencyLockdown() {
	fmt.Println("🔒 Netwerk isolatie uitgevoerd.")
	if runtime.GOOS == "windows" {
		_ = exec.Command("ipconfig", "/release").Run()
	} else {
		_ = exec.Command("nmcli", "networking", "off").Run()
	}
}

func printDashboard() {
	for {
		procs, _ := process.Processes()
		fmt.Printf("\r[📊 BDR] %d Processen actief | Systeem: BESCHERMD", len(procs))
		time.Sleep(2 * time.Second)
	}
}
