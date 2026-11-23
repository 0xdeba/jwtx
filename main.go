package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const version = "1.0.0"

var ist *time.Location
var colorEnabled bool

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

func colorize(value, color string) string {
	if !colorEnabled {
		return value
	}
	return color + value + colorReset
}

func printSection(title string) {
	fmt.Println()
	fmt.Println(colorize("[ "+title+" ]", colorBlue))
	fmt.Println(colorize("-----------------------------------------------------------------", colorGray))
}

func printStatus(label, value string) {
	color := colorCyan
	upper := strings.ToUpper(value)
	switch {
	case strings.Contains(upper, "EXPIRED"), strings.Contains(upper, "INVALID"), strings.Contains(upper, "FAILED"), strings.Contains(upper, "UNSIGNED"):
		color = colorRed
	case strings.Contains(upper, "ACTIVE"), strings.Contains(upper, "VERIFIED"), upper == "PASS":
		color = colorGreen
	case strings.Contains(upper, "MISSING"), strings.Contains(upper, "NOT YET"), strings.Contains(upper, "UNDETERMINED"), strings.Contains(upper, "INDETERMINATE"), strings.Contains(upper, "NOT VERIFIED"), strings.Contains(upper, "NOT CHECKED"), upper == "REVIEW":
		color = colorYellow
	}
	fmt.Printf("%-18s: %s\n", label, colorize(value, color))
}

const banner = `
      ██╗██╗    ██╗████████╗
      ██║██║    ██║╚══██╔══╝
      ██║██║ █╗ ██║   ██║
 ██   ██║██║███╗██║   ██║
 ╚█████╔╝╚███╔███╔╝   ██║
  ╚════╝ ╚══╝╚══╝    ╚═╝

       JWT SECURITY ANALYZER
       ---------------------
`

type SecurityCheck struct {
	Check  string `json:"check"`
	Result string `json:"result"`
	Detail string `json:"detail"`
}

type TimestampInfo struct {
	Unix float64 `json:"unix"`
	IST  string  `json:"ist"`
}

type Report struct {
	Tool                 string                   `json:"tool"`
	Version              string                   `json:"version"`
	AnalyzedAt           string                   `json:"analyzed_at"`
	StructureValid       bool                     `json:"structure_valid"`
	Header               map[string]interface{}   `json:"header"`
	Claims               map[string]interface{}   `json:"claims"`
	Timestamps           map[string]TimestampInfo `json:"timestamps"`
	TokenStatus          string                   `json:"token_status"`
	TokenLifetimeSeconds *float64                 `json:"token_lifetime_seconds,omitempty"`
	RemainingSeconds     *float64                 `json:"remaining_seconds,omitempty"`
	Signature            string                   `json:"signature_verification"`
	SecurityChecks       []SecurityCheck          `json:"security_checks"`
	Findings             []string                 `json:"findings"`
}

func duration(seconds float64) string {
	seconds = abs(seconds)
	total := int64(seconds)
	days, rem := total/86400, total%86400
	hours, rem := rem/3600, rem%3600
	minutes, secs := rem/60, rem%60
	parts := []string{}
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if secs > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", secs))
	}
	return strings.Join(parts, " ")
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func formatTimestamp(value float64) string {
	sec := int64(value)
	nsec := int64((value - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).In(ist).Format("02-01-2006 03:04:05 PM MST")
}

func numberClaim(claims map[string]interface{}, name string) (float64, bool) {
	v, ok := claims[name]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	default:
		return 0, false
	}
}

func checkColor(result string) string {
	switch strings.ToUpper(result) {
	case "PASS":
		return colorGreen
	case "REVIEW", "WARN":
		return colorYellow
	case "FAIL", "ERROR":
		return colorRed
	default:
		return colorCyan
	}
}

func addCheck(r *Report, name, result, detail string) {
	r.SecurityChecks = append(r.SecurityChecks, SecurityCheck{Check: name, Result: result, Detail: detail})
	fmt.Printf("%s %s: %s\n", colorize("["+result+"]", checkColor(result)), name, detail)
}

func parsePublicKey(path, algorithm string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, _ = pem.Decode(data); len(data) == 0 {
		return nil, errors.New("empty public key file")
	}
	switch {
	case strings.HasPrefix(algorithm, "RS"), strings.HasPrefix(algorithm, "PS"):
		return jwt.ParseRSAPublicKeyFromPEM(data)
	case strings.HasPrefix(algorithm, "ES"):
		return jwt.ParseECPublicKeyFromPEM(data)
	case algorithm == "EdDSA":
		return jwt.ParseEdPublicKeyFromPEM(data)
	default:
		return nil, fmt.Errorf("unsupported public-key algorithm: %s", algorithm)
	}
}

func verifySignature(tokenString, algorithm, secret, publicKeyPath string) (bool, string) {
	if algorithm == "none" {
		return false, "unsigned JWT (alg=none)"
	}
	if secret == "" && publicKeyPath == "" {
		return false, "not checked: no verification key supplied"
	}

	var key interface{}
	if secret != "" {
		if !strings.HasPrefix(algorithm, "HS") {
			return false, "HMAC secret supplied for a non-HMAC algorithm"
		}
		key = []byte(secret)
	} else {
		parsedKey, err := parsePublicKey(publicKeyPath, algorithm)
		if err != nil {
			return false, "public key error: " + err.Error()
		}
		key = parsedKey
	}

	allowed := []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
	parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != algorithm {
			return nil, errors.New("signing algorithm mismatch")
		}
		switch key.(type) {
		case []byte:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method for HMAC key")
			}
		case *rsa.PublicKey:
			switch token.Method.(type) {
			case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
			default:
				return nil, errors.New("unexpected signing method for RSA key")
			}
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, errors.New("unexpected signing method for EC key")
			}
		case ed25519.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, errors.New("unexpected signing method for EdDSA key")
			}
		default:
			return nil, errors.New("unsupported verification key type")
		}
		return key, nil
	}, jwt.WithValidMethods(allowed), jwt.WithoutClaimsValidation())
	if err != nil {
		return false, err.Error()
	}
	if parsed == nil || !parsed.Valid {
		return false, "signature verification failed"
	}
	return true, "signature verified successfully"
}

func analyze(tokenString, secret, publicKeyPath string) Report {
	now := time.Now()
	r := Report{
		Tool: "jwtx", Version: version, AnalyzedAt: now.In(ist).Format(time.RFC3339),
		Header: map[string]interface{}{}, Claims: map[string]interface{}{},
		Timestamps: map[string]TimestampInfo{}, SecurityChecks: []SecurityCheck{}, Findings: []string{},
		Signature: "NOT VERIFIED",
	}
	fmt.Println(colorize(banner, colorCyan))
	if strings.Count(tokenString, ".") != 2 {
		fmt.Println(colorize("[!] Invalid JWT structure: expected three segments (header.payload.signature)", colorRed))
		return r
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithJSONNumber())
	parsed, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		fmt.Printf("%s JWT parsing failed: %v\n", colorize("[!]", colorRed), err)
		return r
	}
	if parsed == nil {
		fmt.Println("[!] JWT parsing failed")
		return r
	}
	r.StructureValid = true
	r.Header = parsed.Header
	b, err := json.Marshal(claims)
	if err != nil {
		fmt.Printf("[!] Claims serialization failed: %v\n", err)
		return r
	}
	if err := json.Unmarshal(b, &r.Claims); err != nil {
		fmt.Printf("[!] Claims decoding failed: %v\n", err)
		return r
	}
	alg, _ := parsed.Header["alg"].(string)

	printSection("TOKEN INFORMATION")
	fmt.Printf("%s Structure       : Valid (syntax only)\n", colorize("[+]", colorGreen))
	fmt.Printf("%s Algorithm       : %s\n", colorize("[+]", colorCyan), alg)
	fmt.Printf("%s Token Type      : %v\n", colorize("[+]", colorCyan), valueOr(parsed.Header, "typ", "Not present"))
	fmt.Printf("%s Key ID          : %v\n", colorize("[+]", colorCyan), valueOr(parsed.Header, "kid", "Not present"))
	printSection("HEADER")
	printJSON(r.Header)
	printSection("PAYLOAD")
	printJSON(r.Claims)

	printSection("TIMESTAMP ANALYSIS")
	for _, name := range []string{"iat", "nbf", "exp"} {
		v, exists := numberClaim(r.Claims, name)
		fmt.Printf("\n%s:\n", strings.ToUpper(name))
		if !exists {
			if _, present := r.Claims[name]; present {
				fmt.Println("  Value             : Invalid timestamp")
				r.Findings = append(r.Findings, "Invalid "+name+" timestamp type")
			} else {
				fmt.Println("  Value             : Not present")
				if name == "exp" {
					fmt.Println("  Expiration        : No expiration claim")
				}
			}
			continue
		}
		r.Timestamps[name] = TimestampInfo{Unix: v, IST: formatTimestamp(v)}
		fmt.Printf("  Unix              : %v\n", v)
		fmt.Printf("  IST               : %s\n", formatTimestamp(v))
		switch name {
		case "iat":
			fmt.Printf("  Token Age         : %s\n", duration(now.Sub(time.Unix(int64(v), 0)).Seconds()))
		case "exp":
			remaining := v - float64(now.Unix())
			r.RemainingSeconds = &remaining
			if remaining > 0 {
				fmt.Printf("  Remaining         : %s\n", duration(remaining))
			} else {
				fmt.Printf("  Expired Since     : %s\n", duration(remaining))
			}
		case "nbf":
			remaining := v - float64(now.Unix())
			if remaining > 0 {
				fmt.Printf("  Activates In      : %s\n", duration(remaining))
			} else {
				fmt.Println("  Status            : Activation time reached")
			}
		}
	}

	printSection("LIFETIME ANALYSIS")
	iat, hasIAT := numberClaim(r.Claims, "iat")
	exp, hasEXP := numberClaim(r.Claims, "exp")
	if hasIAT && hasEXP {
		lifetime := exp - iat
		r.TokenLifetimeSeconds = &lifetime
		fmt.Printf("[+] Total Lifetime   : %s\n", duration(lifetime))
		if lifetime < 0 {
			r.Findings = append(r.Findings, "Expiration precedes issued-at timestamp")
		}
		if lifetime > 86400 {
			r.Findings = append(r.Findings, "Token lifetime exceeds 24 hours (review threshold)")
		}
	} else if !hasEXP {
		fmt.Println("[!] Total Lifetime   : UNDETERMINED (exp claim missing)")
	} else {
		fmt.Println("[!] Cannot calculate: valid iat claim missing")
	}

	printSection("TOKEN STATUS")
	nbf, hasNBF := numberClaim(r.Claims, "nbf")
	status := "INDETERMINATE"
	_, expPresent := r.Claims["exp"]
	switch {
	case hasNBF && float64(now.Unix()) < nbf:
		status = "NOT YET VALID"
	case hasEXP && float64(now.Unix()) >= exp:
		status = "EXPIRED"
	case hasIAT && float64(now.Unix()) < iat:
		status = "FUTURE ISSUED AT"
	case !expPresent:
		status = "NO EXPIRATION CLAIM"
	case hasEXP:
		status = "ACTIVE (TIME-BASED)"
	case expPresent:
		status = "INDETERMINATE (INVALID EXP CLAIM)"
	}
	r.TokenStatus = status
	printStatus("Status", status)

	printSection("STANDARD CLAIMS")
	for _, name := range []string{"iss", "sub", "aud", "jti"} {
		fmt.Printf("%-18s: %v\n", strings.ToUpper(name), valueOr(r.Claims, name, "Not present"))
	}

	printSection("SECURITY ANALYSIS")
	switch {
	case alg == "none":
		addCheck(&r, "Algorithm", "REVIEW", "Unsigned algorithm declared; server acceptance requires testing")
	case !contains([]string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}, alg):
		addCheck(&r, "Algorithm", "REVIEW", "Unrecognized or unsupported algorithm: "+alg)
	default:
		addCheck(&r, "Algorithm", "INFO", "Declared algorithm: "+alg)
	}
	for _, name := range []string{"exp", "iat"} {
		_, present := r.Claims[name]
		_, valid := numberClaim(r.Claims, name)
		if present && valid {
			addCheck(&r, name, "PASS", name+" claim present")
		} else if present {
			addCheck(&r, name, "REVIEW", "Invalid timestamp type")
			r.Findings = append(r.Findings, "Invalid "+name+" timestamp type")
		} else {
			addCheck(&r, name, "REVIEW", name+" claim missing")
			r.Findings = append(r.Findings, "Missing "+name+" claim")
		}
	}
	for _, name := range []string{"iss", "aud"} {
		if _, ok := r.Claims[name]; ok {
			addCheck(&r, name, "INFO", name+" claim present; expected value must be checked against application configuration")
		} else {
			addCheck(&r, name, "REVIEW", name+" claim missing; requirements are application-dependent")
		}
	}
	if hasNBF {
		addCheck(&r, "nbf", "PASS", "Not-before claim present")
	} else {
		addCheck(&r, "nbf", "INFO", "Not-before claim not present")
	}
	sensitive := regexp.MustCompile(`(?i)password|passwd|secret|api.?key|access.?key|private.?key|credit.?card|ssn`)
	sensitiveKeys := []string{}
	for key := range r.Claims {
		if sensitive.MatchString(key) {
			sensitiveKeys = append(sensitiveKeys, key)
		}
	}
	if len(sensitiveKeys) > 0 {
		addCheck(&r, "Sensitive Claims", "REVIEW", fmt.Sprintf("Potentially sensitive claim names: %v", sensitiveKeys))
		r.Findings = append(r.Findings, "Potentially sensitive information may be present in JWT payload")
	} else {
		addCheck(&r, "Sensitive Claims", "INFO", "No obvious sensitive claim names detected")
	}

	printSection("SIGNATURE VERIFICATION")
	verified, message := verifySignature(tokenString, alg, secret, publicKeyPath)
	if verified {
		r.Signature = "VERIFIED"
		fmt.Printf("%s %s\n", colorize("[+]", colorGreen), message)
	} else {
		r.Signature = message
		fmt.Printf("%s %s\n", colorize("[!]", colorYellow), message)
	}

	printSection("ANALYSIS SUMMARY")
	printStatus("Time Status", status)
	fmt.Printf("Algorithm          : %s\n", alg)
	printStatus("Signature", r.Signature)
	fmt.Printf("Observations       : %d\n", len(r.Findings))
	for _, finding := range r.Findings {
		fmt.Printf("%s %s\n", colorize("[!]", colorYellow), finding)
	}
	fmt.Println("\n" + colorize("[*] Analysis completed.", colorGreen))
	return r
}

func valueOr(m map[string]interface{}, key string, fallback interface{}) interface{} {
	if v, ok := m[key]; ok {
		return v
	}
	return fallback
}
func printJSON(v interface{}) {
	b, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		fmt.Printf("[!] JSON formatting error: %v\n", err)
		return
	}
	fmt.Println(string(b))
}
func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func writeReport(path string, r Report) error {
	ext := strings.ToLower(filepath.Ext(path))
	var data []byte
	var err error
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(r, "", "    ")
	case ".txt":
		var b strings.Builder
		b.WriteString("JWT SECURITY ANALYSIS REPORT\n")
		b.WriteString("=============================\n")
		fmt.Fprintf(&b, "Tool: %s\nVersion: %s\nAnalyzed: %s\nStructure valid: %t\nToken status: %s\nSignature: %s\n\n", r.Tool, r.Version, r.AnalyzedAt, r.StructureValid, r.TokenStatus, r.Signature)
		b.WriteString("Header:\n")
		header, _ := json.MarshalIndent(r.Header, "", "  ")
		b.Write(header)
		b.WriteString("\n\nClaims:\n")
		claims, _ := json.MarshalIndent(r.Claims, "", "  ")
		b.Write(claims)
		b.WriteString("\n\nSecurity checks:\n")
		for _, c := range r.SecurityChecks {
			fmt.Fprintf(&b, "[%s] %s: %s\n", c.Result, c.Check, c.Detail)
		}
		b.WriteString("\nFindings:\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		data = []byte(b.String())
	default:
		return fmt.Errorf("output extension must be .json or .txt")
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func main() {
	var err error
	ist, err = time.LoadLocation("Asia/Kolkata")
	if err != nil {
		ist = time.FixedZone("IST", 5*3600+30*60)
	}

	tokenFlag := flag.String("t", "", "JWT token directly")
	fileFlag := flag.String("f", "", "JWT token file")
	outputFlag := flag.String("o", "", "Export report (.json or .txt)")
	secretFlag := flag.String("secret", "", "HMAC signing secret")
	publicKeyFlag := flag.String("public-key", "", "RSA/EC/EdDSA public key PEM file")
	versionFlag := flag.Bool("version", false, "Show version")
	noColorFlag := flag.Bool("no-color", false, "Disable colored terminal output")
	flag.Usage = func() {
		fmt.Println(colorize(banner, colorCyan))
		fmt.Println("Usage:")
		fmt.Println("  jwtx -t \"JWT_TOKEN\"")
		fmt.Println("  jwtx -f token.txt")
		fmt.Println("  jwtx -f token.txt -o report.json")
		fmt.Println("  jwtx -t \"JWT_TOKEN\" --secret secret")
		fmt.Println("  jwtx -f token.txt --public-key public.pem")
		fmt.Println("  jwtx -f token.txt --no-color")
		fmt.Println()
		flag.PrintDefaults()
	}
	flag.Parse()
	stdoutInfo, stdoutErr := os.Stdout.Stat()
	isTerminal := stdoutErr == nil && (stdoutInfo.Mode()&os.ModeCharDevice) != 0
	_, noColorEnv := os.LookupEnv("NO_COLOR")
	colorEnabled = isTerminal && !*noColorFlag && !noColorEnv
	if *versionFlag {
		fmt.Printf("jwtx %s\n", version)
		return
	}
	if (*tokenFlag == "") == (*fileFlag == "") {
		flag.Usage()
		os.Exit(1)
	}
	if *secretFlag != "" && *publicKeyFlag != "" {
		fmt.Fprintln(os.Stderr, "[!] Use either --secret or --public-key")
		os.Exit(1)
	}

	tokenString := strings.TrimSpace(*tokenFlag)
	if *fileFlag != "" {
		data, readErr := os.ReadFile(*fileFlag)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Cannot read file: %v\n", readErr)
			os.Exit(1)
		}
		tokenString = strings.TrimSpace(string(data))
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			tokenString = strings.TrimSpace(tokenString[7:])
		}
	}
	if tokenString == "" {
		fmt.Fprintln(os.Stderr, "[!] Empty JWT input")
		os.Exit(1)
	}

	report := analyze(tokenString, *secretFlag, *publicKeyFlag)
	if *outputFlag != "" {
		if err := writeReport(*outputFlag, report); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Report export failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n[+] Report saved: %s\n", *outputFlag)
	}
}
