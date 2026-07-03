// Package match provides threat tagging for ATT&CK techniques and threat actors.
// Pure offline matching — no network calls, no dependencies beyond stdlib.
package match

import (
	"strings"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// TagResult holds threat tags extracted from text.
type TagResult struct {
	Techniques []string // ATT&CK technique IDs (e.g., "T1190")
	Actors     []string // Threat actor names (e.g., "APT28 (Fancy Bear)")
}

// Tag scans text for known threat patterns and returns matched tags.
// Ponytail: O(n×m) scan over text — ~80 actors × ~40 techniques against
// typical 2KB description text. Upgrade path: trie or Aho-Corasick if
// description sizes grow significantly (>10KB per event).
func Tag(text string) TagResult {
	text = strings.ToLower(text)
	var r TagResult
	r.Techniques = matchTechniques(text)
	r.Actors = matchActors(text)
	return r
}

// TagEvent enriches a ThreatEvent with threat tags from its description.
// Called during pipeline processing, after normalization but before matching.
func TagEvent(event *model.ThreatEvent) {
	result := Tag(event.Description)
	for _, t := range result.Techniques {
		event.Tags = append(event.Tags, "att&ck:"+t)
	}
	for _, a := range result.Actors {
		event.Tags = append(event.Tags, "threat-actor:"+a)
	}
}

// matchTechniques scans for ATT&CK technique keywords.
func matchTechniques(text string) []string {
	var found []string
	for _, t := range attackTechniques {
		for _, kw := range t.keywords {
			if strings.Contains(text, kw) {
				found = append(found, t.id)
				break // one keyword match per technique
			}
		}
	}
	return dedup(found)
}

// matchActors scans for threat actor keywords.
func matchActors(text string) []string {
	var found []string
	for _, a := range threatActors {
		for _, alias := range a.aliases {
			if strings.Contains(text, alias) {
				found = append(found, a.id)
				break
			}
		}
	}
	return dedup(found)
}

func dedup(s []string) []string {
	seen := make(map[string]bool, len(s))
	var r []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			r = append(r, v)
		}
	}
	return r
}

// ─────────────────────────────────────────────────────────────
// ATT&CK technique keywords — offline map, zero dependencies.
// ─────────────────────────────────────────────────────────────

type technique struct {
	id       string
	keywords []string
}

var attackTechniques = []technique{
	{"T1190", []string{"public-facing app", "public facing", "exploit public-facing", "internet-facing app"}},
	{"T1059", []string{"command and scripting", "powershell", "cmd.exe", "bash", "shell script"}},
	{"T1203", []string{"exploitation for client execution", "drive-by", "malicious document", "office macro"}},
	{"T1566", []string{"phishing", "spear phishing", "malicious email", "phishing attachment"}},
	{"T1047", []string{"wmi", "windows management instrumentation"}},
	{"T1053", []string{"scheduled task", "cron", "at job", "schtasks"}},
	{"T1078", []string{"valid accounts", "credential stuffing", "default credential"}},
	{"T1068", []string{"privilege escalation", "eop", "elevation of privilege"}},
	{"T1505", []string{"server software component", "web shell", "iis module", "apache module"}},
	{"T1192", []string{"spearphishing link", "malicious link", "spearphishing attachment"}},
	{"T1133", []string{"external remote services", "rdp", "vnc", "ssh"}},
	{"T1210", []string{"remote services", "smb", "rpc", "netbios"}},
	{"T1021", []string{"remote desktop protocol", "rdp", "remote desktop"}},
	{"T1090", []string{"proxy", "connection proxy", "reverse proxy", "socks"}},
	{"T1110", []string{"brute force", "password spray", "credential guessing"}},
	{"T1557", []string{"adversary-in-the-middle", "mitm", "man in the middle", "llmnr", "netbios spoof"}},
	{"T1082", []string{"system information discovery", "host enumeration"}},
	{"T1018", []string{"remote system discovery", "network scan", "port scan"}},
	{"T1046", []string{"network service discovery", "port scan", "service scan"}},
	{"T1482", []string{"domain trust discovery", "trust relationship"}},
	{"T1083", []string{"file and directory discovery", "directory listing"}},
	{"T1003", []string{"credential dumping", "lsass", "lsass.exe", "mimikatz", "sam database"}},
	{"T1552", []string{"unsecured credentials", "credentials in files", "private key"}},
	{"T1539", []string{"steal web session cookie", "session hijack", "cookie theft"}},
	{"T1027", []string{"obfuscated files or information", "base64", "encoded", "packed"}},
	{"T1140", []string{"deobfuscate/decode files or information", "decrypt", "decode"}},
	{"T1036", []string{"masquerading", "signed binary proxy", "rundll32", "regsvr32"}},
	{"T1055", []string{"process injection", "dll injection", "code injection"}},
	{"T1574", []string{"hijack execution flow", "dll search order", "path interception"}},
	{"T1070", []string{"indicator removal", "clear logs", "delete logs", "event log"}},
	{"T1562", []string{"impair defenses", "disable security tools", "disable firewall", "disable av"}},
}

// ─────────────────────────────────────────────────────────────
// Threat actor keywords — offline map, zero dependencies.
// ─────────────────────────────────────────────────────────────

type actor struct {
	id      string
	aliases []string
}

var threatActors = []actor{
	{"APT28 (Fancy Bear)", []string{"apt28", "fancy bear", "sofacy", "strontium", "tsar team", "pawn storm"}},
	{"APT29 (Cozy Bear)", []string{"apt29", "cozy bear", "the dukes", "cozyduke", "miniduke"}},
	{"APT41 (Double Dragon)", []string{"apt41", "double dragon", "barium", "winnti", "blackfly"}},
	{"Lazarus Group", []string{"lazarus", "hidden cobra", "zinc", "appleworm", "apt38"}},
	{"FIN7", []string{"fin7", "carbanak", "anunak", "cobalt group"}},
	{"Turla", []string{"turla", "snake", "uroburos", "venomous bear", "waterbug"}},
	{"Sandworm", []string{"sandworm", "voodoo bear", "telebots", "blackenergy", "iron viking"}},
	{"APT10 (Stone Panda)", []string{"apt10", "stone panda", "menuPass", "red apollo", "potassium"}},
	{"APT33 (Elfin)", []string{"apt33", "elfin", "refined kitten", "magnallium"}},
	{"APT34 (OilRig)", []string{"apt34", "oilrig", "crambus", "iridium", "helix kitten"}},
	{"APT39 (Chafer)", []string{"apt39", "chafer", "remexi"}},
	{"TA505", []string{"ta505", "sectorj04", "hive0065", "dridex"}},
	{"REvil", []string{"revil", "sodinokibi", "sodin"}},
	{"Conti", []string{"conti", "ryuk", "wizard spider"}},
	{"DarkSide", []string{"darkside", "blackmatter", "blackcat", "alphv"}},
	{"Hafnium", []string{"hafnium", "exchange", "proxyshell", "proxylogon"}},
	{"Mustang Panda", []string{"mustang panda", "bronze president", "ta416", "plugx"}},
	{"Kimsuky", []string{"kimsuky", "velvet chollima", "black banshee", "thallium"}},
	{"APT40 (Leviathan)", []string{"apt40", "leviathan", "temp.jumper", "bronze mohawk"}},
	{"Gamaredon Group", []string{"gamaredon", "primitive bear", "shuckworm", "actinium"}},
}
