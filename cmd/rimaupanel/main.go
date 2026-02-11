package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"rimaupanel/internal/system"

	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	sessionCookieName  = "rimau_session"
	languageCookieName = "rimau_lang"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed assets/*
var assetsFS embed.FS

type contextKey string

const (
	userContextKey contextKey = "user"
	langContextKey contextKey = "lang"
)

type User struct {
	ID       int64
	Username string
}

type App struct {
	db         *sql.DB
	templates  *template.Template
	sessionTTL time.Duration
}

type LoginData struct {
	Lang           string
	Error          string
	LockoutSeconds int
}

type DashboardData struct {
	Lang       string
	CurrentURI string
	Username   string
	Info       system.Info
	Error      string
}

type ChangePasswordData struct {
	Lang       string
	CurrentURI string
	Username   string
	Notice     string
	Error      string
}

type ServicePageData struct {
	Lang                string
	CurrentURI          string
	Username            string
	ServiceName         string
	ServiceKey          string
	ServiceNotes        string
	ActiveApache        bool
	ActiveNginx         bool
	Installed           bool
	StatusMessage       string
	StatusHint          string
	CanInstall          bool
	CanControl          bool
	IsRunning           bool
	ShowTabs            bool
	ShowWAFTab          bool
	IsNginx             bool
	PackageManager      string
	PackageName         string
	ServiceUnit         string
	ConfigPath          string
	VHostPath           string
	VHostEnabledPath    string
	TestCommand         string
	ReloadCommand       string
	DefaultListenPort   int
	VHostPortSummary    string
	VHostExample        string
	OptimizeSuggestions []string
	VirtualHosts        []VirtualHostRecord
	ActiveTab           string
	WAFTitle            string
	WAFSuggestions      []string
	WAFExample          string
	WAFConfig           WAFConfig
	WAFConfigPath       string
	WAFConfigPreview    string
	WAFModSecInstalled  bool
	WAFCRSInstalled     bool
	WAFCanInstall       bool
	WAFHasVHosts        bool
	WAFSelectedVHostID  int64
	WAFSelectedVHost    string
	WAFRules            []WAFRuleItem
	Notice              string
	Error               string
}

type CorazaPageData struct {
	Lang                string
	CurrentURI          string
	Username            string
	WAFConfig           WAFConfig
	CorazaConfigPath    string
	CorazaConfigPreview string
	Notice              string
	Error               string
}

type KernelConfig struct {
	Swappiness          int
	DirtyRatio          int
	DirtyBackground     int
	Somaxconn           int
	TCPFinTimeout       int
	TCPKeepaliveTime    int
	TCPMaxSynBacklog    int
	LocalPortRangeStart int
	LocalPortRangeEnd   int
	PIDMax              int
}

type KernelPageData struct {
	Lang                string
	CurrentURI          string
	Username            string
	ActiveKernel        bool
	ActiveTab           string
	Notice              string
	Error               string
	TunedInstalled      bool
	TunedCanInstall     bool
	TunedActiveProfile  string
	TunedProfiles       []string
	KernelConfigPath    string
	KernelConfig        KernelConfig
	KernelConfigPreview string
	KernelSuggestions   []string
}

type ServiceMeta struct {
	Key              string
	Name             string
	DebianPackage    string
	RPMPackage       string
	DebianService    string
	RPMService       string
	BinaryCandidates []string
}

type ServiceRuntime struct {
	Unit       string
	State      string
	IsRunning  bool
	CanControl bool
}

type VirtualHostRecord struct {
	ID               int64
	Domain           string
	Aliases          string
	RootPath         string
	ListenPort       int
	AppRuntime       string
	ConfigFile       string
	Enabled          bool
	RuntimeInstalled bool
	CreatedAt        string
}

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
var ruleIDPattern = regexp.MustCompile(`(?i)\bid\s*:\s*['"]?([0-9]{2,})`)
var apacheVHostListenPattern = regexp.MustCompile(`(?i)^(\s*<VirtualHost\s+\*:\s*)([0-9]+)(\s*>\s*)$`)
var nginxListenPortPattern = regexp.MustCompile(`(?i)^(\s*listen\s+)([0-9]+)([^;]*;\s*)$`)
var nginxListenIPv6PortPattern = regexp.MustCompile(`(?i)^(\s*listen\s+\[::\]:)([0-9]+)([^;]*;\s*)$`)
var tunedProfilePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

type WAFConfig struct {
	ServiceKey           string
	Enabled              bool
	Mode                 string
	ParanoiaLevel        int
	InboundAnomalyScore  int
	OutboundAnomalyScore int
	RequestBodyLimitKB   int
	CRSEnabled           bool
	CustomRulesPath      string
	TrustedIPs           string
	ExcludedPaths        string
	AuditEnabled         bool
	AuditLogPath         string
	LogLevel             string
	UpdatedAt            int64
}

type WAFRuleItem struct {
	FileName string
	FilePath string
	Enabled  bool
}

func main() {
	addr := getEnv("RIMAUPANEL_ADDR", ":8000")
	dbPath := getEnv("RIMAUPANEL_DB", "./data/rimaupanel.db")
	sessionHours := getEnvInt("RIMAUPANEL_SESSION_HOURS", 24)

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		log.Fatalf("gagal membuat direktori DB: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("gagal buka sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if err := initSchema(db); err != nil {
		log.Fatalf("gagal inisialisasi schema: %v", err)
	}
	if err := seedAdminUser(db); err != nil {
		log.Fatalf("gagal seed admin: %v", err)
	}

	templates, err := template.New("").Funcs(template.FuncMap{
		"formatBytes":   formatBytes,
		"formatPercent": formatPercent,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("gagal parse template: %v", err)
	}

	app := &App{
		db:         db,
		templates:  templates,
		sessionTTL: time.Duration(sessionHours) * time.Hour,
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      app.routes(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("RimauPanel berjalan di %s", addr)
	log.Printf("DB SQLite: %s", dbPath)
	log.Fatal(server.ListenAndServe())
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	assetSubFS, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		log.Printf("gagal mount assets: %v", err)
	} else {
		mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assetSubFS))))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/logout", a.handleLogout)
	mux.Handle("/dashboard", a.requireAuth(http.HandlerFunc(a.handleDashboard)))
	mux.Handle("/language", a.requireAuth(http.HandlerFunc(a.handleSetLanguage)))
	mux.Handle("/change-password", a.requireAuth(http.HandlerFunc(a.handleChangePassword)))
	mux.Handle("/kernel", a.requireAuth(http.HandlerFunc(a.handleKernel)))
	mux.Handle("/kernel/tuned/install", a.requireAuth(http.HandlerFunc(a.handleKernelInstallTuned)))
	mux.Handle("/kernel/tuned/profile", a.requireAuth(http.HandlerFunc(a.handleKernelSetTunedProfile)))
	mux.Handle("/kernel/optimize/apply", a.requireAuth(http.HandlerFunc(a.handleKernelApplyOptimizePreset)))
	mux.Handle("/kernel/configure/save", a.requireAuth(http.HandlerFunc(a.handleKernelSaveConfig)))
	mux.Handle("/apache", a.requireAuth(http.HandlerFunc(a.handleApache)))
	mux.Handle("/nginx", a.requireAuth(http.HandlerFunc(a.handleNginx)))
	mux.Handle("/coraza", a.requireAuth(http.HandlerFunc(a.handleCoraza)))
	mux.Handle("/service/install", a.requireAuth(http.HandlerFunc(a.handleServiceInstall)))
	mux.Handle("/service/action", a.requireAuth(http.HandlerFunc(a.handleServiceAction)))
	mux.Handle("/service/setting/port", a.requireAuth(http.HandlerFunc(a.handleSaveServicePort)))
	mux.Handle("/service/vhost/create", a.requireAuth(http.HandlerFunc(a.handleCreateVirtualHost)))
	mux.Handle("/service/vhost/update", a.requireAuth(http.HandlerFunc(a.handleUpdateVirtualHost)))
	mux.Handle("/service/vhost/delete", a.requireAuth(http.HandlerFunc(a.handleDeleteVirtualHost)))
	mux.Handle("/service/runtime/install", a.requireAuth(http.HandlerFunc(a.handleInstallRuntime)))
	mux.Handle("/service/waf/save", a.requireAuth(http.HandlerFunc(a.handleSaveWAFConfig)))
	mux.Handle("/service/waf/apply", a.requireAuth(http.HandlerFunc(a.handleApplyWAFConfig)))
	mux.Handle("/service/waf/install/modsec", a.requireAuth(http.HandlerFunc(a.handleInstallServiceModSecurity)))
	mux.Handle("/service/waf/install/crs", a.requireAuth(http.HandlerFunc(a.handleInstallServiceCRS)))
	mux.Handle("/service/waf/rule/toggle", a.requireAuth(http.HandlerFunc(a.handleToggleServiceWAFRule)))
	mux.Handle("/coraza/save", a.requireAuth(http.HandlerFunc(a.handleSaveCorazaConfig)))
	mux.Handle("/coraza/apply", a.requireAuth(http.HandlerFunc(a.handleApplyCorazaConfig)))
	mux.Handle("/api/system", a.requireAuth(http.HandlerFunc(a.handleSystemAPI)))

	handler := http.Handler(mux)
	handler = a.languageMiddleware(handler)
	handler = a.builtinCorazaMiddleware(handler)
	return a.loggingMiddleware(handler)
}

func (a *App) languageMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := "ms"
		if cookie, err := r.Cookie(languageCookieName); err == nil {
			lang = normalizeLang(cookie.Value)
		}
		qlang := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("lang")))
		if qlang == "ms" || qlang == "en" {
			lang = qlang
			setLanguageCookie(w, lang)
		}

		ctx := context.WithValue(r.Context(), langContextKey, lang)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) currentLang(r *http.Request) string {
	if v, ok := r.Context().Value(langContextKey).(string); ok {
		return normalizeLang(v)
	}
	if cookie, err := r.Cookie(languageCookieName); err == nil {
		return normalizeLang(cookie.Value)
	}
	return "ms"
}

func normalizeLang(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "en":
		return "en"
	default:
		return "ms"
	}
}

func setLanguageCookie(w http.ResponseWriter, lang string) {
	http.SetCookie(w, &http.Cookie{
		Name:     languageCookieName,
		Value:    normalizeLang(lang),
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) builtinCorazaMiddleware(next http.Handler) http.Handler {
	cfg, err := a.getWAFConfig("rimaupanel")
	if err != nil {
		log.Printf("gagal baca config Coraza built-in, guna default: %v", err)
		cfg = defaultWAFConfig("rimaupanel")
	}

	if !cfg.Enabled || cfg.Mode == "off" {
		log.Printf("Coraza built-in untuk RimauPanel dimatikan (mode=%s).", cfg.Mode)
		return next
	}

	directives := buildRimauPanelCorazaConfig(cfg)
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		log.Printf("Coraza built-in gagal dimuat, WAF dimatikan: %v", err)
		return next
	}

	log.Printf("Coraza built-in aktif untuk RimauPanel (mode=%s).", cfg.Mode)
	return corazahttp.WrapHandler(waf, next)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	lang := a.currentLang(r)
	clientIP := a.clientIPFromRequest(r)

	if r.Method == http.MethodGet {
		if _, err := a.currentUser(r); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		lockoutSeconds, lockErr := a.loginLockSeconds(clientIP)
		if lockErr != nil {
			log.Printf("gagal semak lockout login [%s]: %v", clientIP, lockErr)
		}
		data := LoginData{Lang: lang, LockoutSeconds: lockoutSeconds}
		if lockoutSeconds > 0 {
			data.Error = fmt.Sprintf("Terlalu banyak percubaan login gagal. Cuba lagi dalam %d saat.", lockoutSeconds)
		}
		a.render(w, "login.html", data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lockoutSeconds, lockErr := a.loginLockSeconds(clientIP)
	if lockErr != nil {
		log.Printf("gagal semak lockout login [%s]: %v", clientIP, lockErr)
	}
	if lockoutSeconds > 0 {
		a.render(w, "login.html", LoginData{
			Lang:           lang,
			Error:          fmt.Sprintf("Terlalu banyak percubaan login gagal. Cuba lagi dalam %d saat.", lockoutSeconds),
			LockoutSeconds: lockoutSeconds,
		})
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(w, "login.html", LoginData{Lang: lang, Error: "Permintaan tidak sah."})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		a.render(w, "login.html", LoginData{Lang: lang, Error: "Username dan password wajib diisi."})
		return
	}

	user, passwordHash, err := a.findUserByUsername(username)
	if err != nil {
		remainingSeconds, throttleErr := a.recordLoginFailure(clientIP)
		if throttleErr != nil {
			log.Printf("gagal rekod login gagal [%s]: %v", clientIP, throttleErr)
		}
		data := LoginData{Lang: lang, Error: "Username atau password salah."}
		if remainingSeconds > 0 {
			data.LockoutSeconds = remainingSeconds
			data.Error = fmt.Sprintf("Terlalu banyak percubaan login gagal. Cuba lagi dalam %d saat.", remainingSeconds)
		}
		a.render(w, "login.html", data)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		remainingSeconds, throttleErr := a.recordLoginFailure(clientIP)
		if throttleErr != nil {
			log.Printf("gagal rekod login gagal [%s]: %v", clientIP, throttleErr)
		}
		data := LoginData{Lang: lang, Error: "Username atau password salah."}
		if remainingSeconds > 0 {
			data.LockoutSeconds = remainingSeconds
			data.Error = fmt.Sprintf("Terlalu banyak percubaan login gagal. Cuba lagi dalam %d saat.", remainingSeconds)
		}
		a.render(w, "login.html", data)
		return
	}

	if err := a.clearLoginThrottle(clientIP); err != nil {
		log.Printf("gagal reset lockout login [%s]: %v", clientIP, err)
	}

	token, expiresAt, err := a.createSession(user.ID)
	if err != nil {
		log.Printf("gagal buat session: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	if _, err := a.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix()); err != nil {
		log.Printf("gagal cleanup session: %v", err)
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if _, err := a.db.Exec(`DELETE FROM sessions WHERE token = ?`, cookie.Value); err != nil {
			log.Printf("gagal hapus session: %v", err)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *App) handleSetLanguage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	lang := normalizeLang(r.FormValue("lang"))
	setLanguageCookie(w, lang)

	nextPath := strings.TrimSpace(r.FormValue("next"))
	if nextPath == "" || !strings.HasPrefix(nextPath, "/") || strings.HasPrefix(nextPath, "//") {
		nextPath = "/dashboard"
	}
	http.Redirect(w, r, nextPath, http.StatusFound)
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	info, err := system.Collect()
	data := DashboardData{
		Lang:       a.currentLang(r),
		CurrentURI: r.URL.RequestURI(),
		Username:   user.Username,
		Info:       info,
	}
	if err != nil {
		data.Error = "Gagal membaca status sistem: " + err.Error()
	}
	a.render(w, "dashboard.html", data)
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Notice:     strings.TrimSpace(r.URL.Query().Get("notice")),
			Error:      strings.TrimSpace(r.URL.Query().Get("error")),
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Permintaan tidak sah.",
		})
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if strings.TrimSpace(currentPassword) == "" || strings.TrimSpace(newPassword) == "" || strings.TrimSpace(confirmPassword) == "" {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Semua medan password wajib diisi.",
		})
		return
	}
	if len(newPassword) < 8 {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Password baru mesti sekurang-kurangnya 8 aksara.",
		})
		return
	}
	if len(newPassword) > 128 {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Password baru terlalu panjang.",
		})
		return
	}
	if newPassword != confirmPassword {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Pengesahan password baru tidak sepadan.",
		})
		return
	}
	if currentPassword == newPassword {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Password baru mesti berbeza daripada password lama.",
		})
		return
	}

	var existingHash string
	if err := a.db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, user.ID).Scan(&existingHash); err != nil {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Gagal membaca maklumat pengguna.",
		})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(existingHash), []byte(currentPassword)); err != nil {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Password semasa tidak tepat.",
		})
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Gagal hasilkan hash password baharu.",
		})
		return
	}

	if _, err := a.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(newHash), user.ID); err != nil {
		a.render(w, "change_password.html", ChangePasswordData{
			Lang:       a.currentLang(r),
			CurrentURI: r.URL.RequestURI(),
			Username:   user.Username,
			Error:      "Gagal kemas kini password.",
		})
		return
	}

	redirectToChangePasswordPage(w, r, "Password berjaya dikemas kini.", "")
}

func (a *App) handleKernel(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	activeTab := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tab")))
	if activeTab != "configure" && activeTab != "optimize" {
		activeTab = "optimize"
	}

	tunedInstalled, tunedActiveProfile, tunedProfiles := kernelTunedStatus()
	cfg := readKernelRuntimeConfig()
	manager := detectPackageManager()
	pageData := KernelPageData{
		Lang:                a.currentLang(r),
		CurrentURI:          r.URL.RequestURI(),
		Username:            user.Username,
		ActiveKernel:        true,
		ActiveTab:           activeTab,
		Notice:              strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:               strings.TrimSpace(r.URL.Query().Get("error")),
		TunedInstalled:      tunedInstalled,
		TunedCanInstall:     manager != "",
		TunedActiveProfile:  tunedActiveProfile,
		TunedProfiles:       tunedProfiles,
		KernelConfigPath:    kernelSysctlConfigPath(),
		KernelConfig:        cfg,
		KernelConfigPreview: buildKernelConfigContent(cfg),
		KernelSuggestions:   kernelOptimizeSuggestions(),
	}
	a.render(w, "kernel.html", pageData)
}

func (a *App) handleKernelInstallTuned(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manager := detectPackageManager()
	if manager == "" {
		redirectToKernelPage(w, r, "optimize", "", "Distro tidak disokong untuk auto install tuned.")
		return
	}
	if kernelTunedInstalled(manager) {
		redirectToKernelPage(w, r, "optimize", "tuned sudah dipasang.", "")
		return
	}
	if err := installPackages(manager, []string{"tuned"}); err != nil {
		redirectToKernelPage(w, r, "optimize", "", "Gagal pasang tuned: "+truncateString(err.Error(), 240))
		return
	}
	if commandExists("systemctl") {
		if err := runAsRoot(nil, "systemctl", "enable", "--now", "tuned"); err != nil {
			redirectToKernelPage(w, r, "optimize", "", "tuned dipasang tetapi gagal aktifkan service: "+truncateString(err.Error(), 220))
			return
		}
	}
	redirectToKernelPage(w, r, "optimize", "tuned berjaya dipasang.", "")
}

func (a *App) handleKernelSetTunedProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}
	profile := strings.TrimSpace(r.FormValue("profile"))
	if profile == "" || !tunedProfilePattern.MatchString(profile) {
		redirectToKernelPage(w, r, "optimize", "", "Profil tuned tidak sah.")
		return
	}
	manager := detectPackageManager()
	if !kernelTunedInstalled(manager) {
		redirectToKernelPage(w, r, "optimize", "", "tuned belum dipasang.")
		return
	}
	if err := runAsRoot(nil, "tuned-adm", "profile", profile); err != nil {
		redirectToKernelPage(w, r, "optimize", "", "Gagal ubah profil tuned: "+truncateString(err.Error(), 240))
		return
	}
	redirectToKernelPage(w, r, "optimize", "Profil tuned ditukar ke "+profile+".", "")
}

func (a *App) handleKernelApplyOptimizePreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}
	preset := strings.TrimSpace(r.FormValue("preset"))
	cfg, presetName, err := kernelPresetConfig(preset)
	if err != nil {
		redirectToKernelPage(w, r, "optimize", "", err.Error())
		return
	}
	if err := applyKernelConfig(cfg); err != nil {
		redirectToKernelPage(w, r, "optimize", "", "Gagal apply preset kernel: "+truncateString(err.Error(), 260))
		return
	}
	redirectToKernelPage(w, r, "optimize", "Preset kernel "+presetName+" berjaya di-apply.", "")
}

func (a *App) handleKernelSaveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}
	cfg := KernelConfig{
		Swappiness:          parseIntWithDefault(r.FormValue("swappiness"), 10),
		DirtyRatio:          parseIntWithDefault(r.FormValue("dirty_ratio"), 15),
		DirtyBackground:     parseIntWithDefault(r.FormValue("dirty_background_ratio"), 5),
		Somaxconn:           parseIntWithDefault(r.FormValue("somaxconn"), 4096),
		TCPFinTimeout:       parseIntWithDefault(r.FormValue("tcp_fin_timeout"), 15),
		TCPKeepaliveTime:    parseIntWithDefault(r.FormValue("tcp_keepalive_time"), 600),
		TCPMaxSynBacklog:    parseIntWithDefault(r.FormValue("tcp_max_syn_backlog"), 8192),
		LocalPortRangeStart: parseIntWithDefault(r.FormValue("local_port_start"), 10240),
		LocalPortRangeEnd:   parseIntWithDefault(r.FormValue("local_port_end"), 65535),
		PIDMax:              parseIntWithDefault(r.FormValue("pid_max"), 4194304),
	}
	validated, err := validateKernelConfig(cfg)
	if err != nil {
		redirectToKernelPage(w, r, "configure", "", err.Error())
		return
	}
	if err := applyKernelConfig(validated); err != nil {
		redirectToKernelPage(w, r, "configure", "", "Gagal apply konfigurasi kernel: "+truncateString(err.Error(), 280))
		return
	}
	redirectToKernelPage(w, r, "configure", "Konfigurasi kernel berjaya disimpan dan di-apply.", "")
}

func (a *App) handleApache(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	a.renderServicePage(w, r, user, "apache")
}

func (a *App) handleNginx(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	a.renderServicePage(w, r, user, "nginx")
}

func (a *App) handleCoraza(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(userContextKey).(User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	cfg, err := a.getWAFConfig("rimaupanel")
	if err != nil {
		log.Printf("gagal baca config coraza rimaupanel: %v", err)
		cfg = defaultWAFConfig("rimaupanel")
	}

	pageData := CorazaPageData{
		Lang:                a.currentLang(r),
		CurrentURI:          r.URL.RequestURI(),
		Username:            user.Username,
		WAFConfig:           cfg,
		CorazaConfigPath:    corazaConfigPath("rimaupanel"),
		CorazaConfigPreview: buildRimauPanelCorazaConfig(cfg),
		Notice:              strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:               strings.TrimSpace(r.URL.Query().Get("error")),
	}
	a.render(w, "coraza.html", pageData)
}

func (a *App) handleServiceInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(r.FormValue("service"))
	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}

	notice := ""
	errMsg := ""
	if err := installServicePackage(meta); err != nil {
		errMsg = truncateString(err.Error(), 300)
	} else {
		notice = meta.Name + " berjaya dipasang."
	}

	q := url.Values{}
	if notice != "" {
		q.Set("notice", notice)
	}
	if errMsg != "" {
		q.Set("error", errMsg)
	}
	redirectToServicePage(w, r, serviceKey, "", q.Get("notice"), q.Get("error"))
}

func (a *App) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(r.FormValue("service"))
	action := strings.TrimSpace(strings.ToLower(r.FormValue("action")))
	if action != "start" && action != "restart" && action != "reload" && action != "stop" &&
		action != "status" && action != "enable" && action != "disable" && action != "checkconfig" {
		http.Error(w, "aksi tidak disokong", http.StatusBadRequest)
		return
	}

	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}

	notice := ""
	errMsg := ""
	if action == "status" {
		statusNotice, statusErr := currentServiceStatusNotice(meta)
		if statusErr != nil {
			errMsg = truncateString(statusErr.Error(), 300)
		} else {
			notice = statusNotice
		}
	} else if action == "checkconfig" {
		testOutput, testErr := runServiceConfigTest(meta)
		if testErr != nil {
			errMsg = truncateString("Semakan config gagal: "+testErr.Error(), 300)
		} else if strings.TrimSpace(testOutput) == "" {
			notice = "Semakan config berjaya untuk " + meta.Name + "."
		} else {
			notice = truncateString("Semakan config berjaya: "+strings.TrimSpace(testOutput), 300)
		}
	} else if action == "enable" || action == "disable" {
		if err := runServiceEnableDisableAction(meta, action); err != nil {
			errMsg = truncateString(err.Error(), 300)
		} else {
			notice = fmt.Sprintf("%s berjaya untuk %s.", actionLabel(action), meta.Name)
		}
	} else {
		if err := runServiceAction(meta, action); err != nil {
			errMsg = truncateString(err.Error(), 300)
		} else {
			notice = fmt.Sprintf("%s berjaya untuk %s.", actionLabel(action), meta.Name)
		}
	}

	q := url.Values{}
	if notice != "" {
		q.Set("notice", notice)
	}
	if errMsg != "" {
		q.Set("error", errMsg)
	}

	redirectToServicePage(w, r, serviceKey, strings.TrimSpace(r.FormValue("tab")), q.Get("notice"), q.Get("error"))
}

func (a *App) handleSaveServicePort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}
	redirectWithMsg := func(notice, errMsg string) {
		redirectToServicePage(w, r, serviceKey, "setting", notice, errMsg)
	}

	port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("listen_port")))
	if err != nil || port <= 0 || port > 65535 {
		redirectWithMsg("", "Port server tidak sah.")
		return
	}

	applyToAll := r.FormValue("apply_to_all_vhosts") == "on"
	if err := a.upsertServiceSettingPort(serviceKey, port); err != nil {
		redirectWithMsg("", "Gagal simpan port default: "+truncateString(err.Error(), 220))
		return
	}

	if applyToAll {
		if err := a.applyPortToAllVirtualHosts(meta, port); err != nil {
			redirectWithMsg("", "Port default disimpan tetapi gagal apply ke virtual host: "+truncateString(err.Error(), 280))
			return
		}
	}

	notice := fmt.Sprintf("Port %d disimpan untuk %s.", port, meta.Name)
	if applyToAll {
		notice = fmt.Sprintf("Port %d disimpan dan di-apply ke semua virtual host %s.", port, meta.Name)
	}
	redirectWithMsg(notice, "")
}

func (a *App) handleCreateVirtualHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}

	redirectWithMsg := func(notice, errMsg string) {
		redirectToServicePage(w, r, serviceKey, "vhost", notice, errMsg)
	}

	manager := detectPackageManager()
	installed, _, _ := checkServiceInstalled(meta)
	if !installed {
		redirectWithMsg("", meta.Name+" belum dipasang.")
		return
	}

	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	if !isValidHost(domain) {
		redirectWithMsg("", "Domain tidak sah.")
		return
	}

	aliases := parseHostList(r.FormValue("aliases"))
	for _, alias := range aliases {
		if !isValidHost(alias) {
			redirectWithMsg("", "Alias domain tidak sah: "+alias)
			return
		}
	}

	rootPath := strings.TrimSpace(r.FormValue("root_path"))
	if rootPath == "" {
		redirectWithMsg("", "Document root wajib diisi.")
		return
	}
	rootPath = filepath.Clean(rootPath)
	if !filepath.IsAbs(rootPath) {
		redirectWithMsg("", "Document root mesti absolute path.")
		return
	}

	port := a.getServiceDefaultListenPort(serviceKey)
	portRaw := strings.TrimSpace(r.FormValue("listen_port"))
	if portRaw != "" {
		portNum, convErr := strconv.Atoi(portRaw)
		if convErr != nil || portNum <= 0 || portNum > 65535 {
			redirectWithMsg("", "Listen port tidak sah.")
			return
		}
		port = portNum
	}
	appRuntime := normalizeAppRuntime(r.FormValue("app_runtime"))
	if appRuntime == "" {
		redirectWithMsg("", "Application runtime wajib dipilih (php/java/python/dotnet).")
		return
	}

	enabled := r.FormValue("enabled") == "on"
	exists, err := a.virtualHostExists(serviceKey, domain)
	if err != nil {
		redirectWithMsg("", "Gagal semak virtual host: "+truncateString(err.Error(), 200))
		return
	}
	if exists {
		redirectWithMsg("", "Domain sudah wujud dalam senarai virtual host.")
		return
	}

	configFileName := buildConfigFileName(domain, manager, enabled)
	configDir := serviceVHostPath(meta, manager)
	if configDir == "-" {
		redirectWithMsg("", "Direktori virtual host tidak disokong untuk distro ini.")
		return
	}
	configFullPath := filepath.Join(configDir, configFileName)

	configContent, err := buildVirtualHostConfig(meta, manager, domain, aliases, rootPath, port, appRuntime)
	if err != nil {
		redirectWithMsg("", truncateString(err.Error(), 250))
		return
	}

	if err := writeConfigFileAsRoot(configFullPath, configContent); err != nil {
		redirectWithMsg("", truncateString(err.Error(), 300))
		return
	}

	enabledPath := serviceVHostEnabledPath(meta, manager)
	baseEnabledName := sanitizeFileToken(domain) + ".conf"
	if enabledPath != "" {
		linkPath := filepath.Join(enabledPath, baseEnabledName)
		linkTarget := configFullPath
		if enabled {
			if err := ensureSymlinkAsRoot(linkTarget, linkPath); err != nil {
				redirectWithMsg("", truncateString(err.Error(), 300))
				return
			}
		} else {
			if err := removePathAsRoot(linkPath); err != nil {
				redirectWithMsg("", truncateString(err.Error(), 300))
				return
			}
		}
	}

	aliasesJoined := strings.Join(aliases, " ")
	insertRes, err := a.db.Exec(
		`INSERT INTO virtual_hosts(service_key, domain, aliases, root_path, listen_port, app_runtime, config_file, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serviceKey, domain, aliasesJoined, rootPath, port, appRuntime, configFullPath, boolToInt(enabled), time.Now().Unix(),
	)
	if err != nil {
		redirectWithMsg("", "Gagal simpan data virtual host: "+truncateString(err.Error(), 300))
		return
	}
	if insertedID, idErr := insertRes.LastInsertId(); idErr == nil && insertedID > 0 {
		if vhost, vErr := a.getVirtualHostByID(serviceKey, insertedID); vErr == nil {
			if err := a.applySingleVHostWAFOverride(meta, manager, vhost); err != nil {
				log.Printf("gagal apply override waf vhost baru: %v", err)
			}
		}
	}

	redirectWithMsg("Virtual host berjaya ditambah. Sila klik Reload untuk aktifkan konfigurasi.", "")
}

func (a *App) handleUpdateVirtualHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}
	redirectWithMsg := func(notice, errMsg string) {
		redirectToServicePage(w, r, serviceKey, "vhost", notice, errMsg)
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		redirectWithMsg("", "ID virtual host tidak sah.")
		return
	}
	existing, err := a.getVirtualHostByID(serviceKey, id)
	if err != nil {
		redirectWithMsg("", "Virtual host tidak ditemui.")
		return
	}

	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	if !isValidHost(domain) {
		redirectWithMsg("", "Domain tidak sah.")
		return
	}
	aliases := parseHostList(r.FormValue("aliases"))
	for _, alias := range aliases {
		if !isValidHost(alias) {
			redirectWithMsg("", "Alias domain tidak sah: "+alias)
			return
		}
	}
	rootPath := filepath.Clean(strings.TrimSpace(r.FormValue("root_path")))
	if rootPath == "" || !filepath.IsAbs(rootPath) {
		redirectWithMsg("", "Document root mesti absolute path.")
		return
	}
	port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("listen_port")))
	if err != nil || port <= 0 || port > 65535 {
		redirectWithMsg("", "Listen port tidak sah.")
		return
	}
	appRuntime := normalizeAppRuntime(r.FormValue("app_runtime"))
	if appRuntime == "" {
		redirectWithMsg("", "Application runtime wajib dipilih (php/java/python/dotnet).")
		return
	}
	enabled := r.FormValue("enabled") == "on"

	exists, err := a.virtualHostExistsExceptID(serviceKey, domain, id)
	if err != nil {
		redirectWithMsg("", "Gagal semak domain: "+truncateString(err.Error(), 200))
		return
	}
	if exists {
		redirectWithMsg("", "Domain sudah digunakan oleh virtual host lain.")
		return
	}

	manager := detectPackageManager()
	configDir := serviceVHostPath(meta, manager)
	if configDir == "-" {
		redirectWithMsg("", "Direktori virtual host tidak disokong untuk distro ini.")
		return
	}
	configFullPath := filepath.Join(configDir, buildConfigFileName(domain, manager, enabled))
	configContent, err := buildVirtualHostConfig(meta, manager, domain, aliases, rootPath, port, appRuntime)
	if err != nil {
		redirectWithMsg("", truncateString(err.Error(), 250))
		return
	}
	if err := writeConfigFileAsRoot(configFullPath, configContent); err != nil {
		redirectWithMsg("", truncateString(err.Error(), 300))
		return
	}

	if existing.ConfigFile != configFullPath {
		if err := removePathAsRoot(existing.ConfigFile); err != nil {
			redirectWithMsg("", truncateString(err.Error(), 250))
			return
		}
	}
	oldWAFOverride := serviceVHostWAFOverridePath(meta, existing.Domain)
	newWAFOverride := serviceVHostWAFOverridePath(meta, domain)
	if oldWAFOverride != newWAFOverride {
		_ = removePathAsRoot(oldWAFOverride)
	}

	enabledPath := serviceVHostEnabledPath(meta, manager)
	if enabledPath != "" {
		oldLink := filepath.Join(enabledPath, sanitizeFileToken(existing.Domain)+".conf")
		newLink := filepath.Join(enabledPath, sanitizeFileToken(domain)+".conf")
		if oldLink != newLink {
			_ = removePathAsRoot(oldLink)
		}
		if enabled {
			if err := ensureSymlinkAsRoot(configFullPath, newLink); err != nil {
				redirectWithMsg("", truncateString(err.Error(), 250))
				return
			}
		} else {
			if err := removePathAsRoot(newLink); err != nil {
				redirectWithMsg("", truncateString(err.Error(), 250))
				return
			}
		}
	}

	aliasesJoined := strings.Join(aliases, " ")
	_, err = a.db.Exec(
		`UPDATE virtual_hosts SET domain=?, aliases=?, root_path=?, listen_port=?, app_runtime=?, config_file=?, enabled=? WHERE id=? AND service_key=?`,
		domain, aliasesJoined, rootPath, port, appRuntime, configFullPath, boolToInt(enabled), id, serviceKey,
	)
	if err != nil {
		redirectWithMsg("", "Gagal kemas kini virtual host: "+truncateString(err.Error(), 250))
		return
	}
	if updatedVHost, vErr := a.getVirtualHostByID(serviceKey, id); vErr == nil {
		if err := a.applySingleVHostWAFOverride(meta, manager, updatedVHost); err != nil {
			log.Printf("gagal apply override waf vhost update: %v", err)
		}
	}

	redirectWithMsg("Virtual host berjaya dikemas kini.", "")
}

func (a *App) handleDeleteVirtualHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	if _, err := serviceMeta(serviceKey); err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}
	redirectWithMsg := func(notice, errMsg string) {
		redirectToServicePage(w, r, serviceKey, "vhost", notice, errMsg)
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		redirectWithMsg("", "ID virtual host tidak sah.")
		return
	}

	existing, err := a.getVirtualHostByID(serviceKey, id)
	if err != nil {
		redirectWithMsg("", "Virtual host tidak ditemui.")
		return
	}

	manager := detectPackageManager()
	enabledPath := serviceVHostEnabledPath(ServiceMeta{Key: serviceKey}, manager)
	if enabledPath != "" {
		linkPath := filepath.Join(enabledPath, sanitizeFileToken(existing.Domain)+".conf")
		_ = removePathAsRoot(linkPath)
	}

	if existing.ConfigFile != "" {
		_ = removePathAsRoot(existing.ConfigFile)
	}
	_ = removePathAsRoot(serviceVHostWAFOverridePath(ServiceMeta{Key: serviceKey}, existing.Domain))

	if _, err := a.db.Exec(`DELETE FROM virtual_hosts WHERE id=? AND service_key=?`, id, serviceKey); err != nil {
		redirectWithMsg("", "Gagal padam virtual host: "+truncateString(err.Error(), 250))
		return
	}

	redirectWithMsg("Virtual host berjaya dipadam.", "")
}

func (a *App) handleInstallRuntime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	if _, err := serviceMeta(serviceKey); err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}
	redirectWithMsg := func(notice, errMsg string) {
		redirectToServicePage(w, r, serviceKey, "vhost", notice, errMsg)
	}

	runtime := normalizeAppRuntime(r.FormValue("runtime"))
	if runtime == "" {
		redirectWithMsg("", "Runtime tidak sah. Pilih php/java/python/dotnet.")
		return
	}

	if runtimeInstalled(runtime) {
		redirectWithMsg(runtimeLabel(runtime)+" sudah dipasang.", "")
		return
	}

	manager := detectPackageManager()
	candidates := runtimePackageCandidates(runtime, manager)
	if len(candidates) == 0 {
		redirectWithMsg("", "Tiada pakej runtime untuk distro ini.")
		return
	}

	if err := installPackageCandidates(manager, candidates); err != nil {
		redirectWithMsg("", truncateString(err.Error(), 300))
		return
	}

	redirectWithMsg(runtimeLabel(runtime)+" berjaya dipasang di server.", "")
}

func (a *App) handleInstallServiceModSecurity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}
	vhostID := parseInt64WithDefault(r.FormValue("vhost_id"), 0)
	redirectWithMsg := func(notice, errMsg string) {
		redirectToServiceWAFTab(w, r, serviceKey, vhostID, notice, errMsg)
	}

	manager := detectPackageManager()
	if manager == "" {
		redirectWithMsg("", "Distro tidak disokong untuk auto install ModSecurity.")
		return
	}
	if modSecurityInstalled(meta, manager) {
		redirectWithMsg("ModSecurity sudah dipasang.", "")
		return
	}

	if err := installPackageCandidates(manager, modSecurityPackageCandidates(meta, manager)); err != nil {
		redirectWithMsg("", "Gagal pasang ModSecurity: "+truncateString(err.Error(), 280))
		return
	}
	if err := ensureApacheModSecurityEnabled(meta, manager); err != nil {
		redirectWithMsg("", "ModSecurity dipasang tetapi gagal aktifkan modul Apache: "+truncateString(err.Error(), 280))
		return
	}

	if err := a.syncServiceVirtualHostConfigs(meta, manager); err != nil {
		log.Printf("gagal sync vhost config selepas install modsecurity: %v", err)
	}
	if err := a.applyVHostWAFOverrides(meta, manager); err != nil {
		log.Printf("gagal apply override vhost selepas install modsecurity: %v", err)
	}
	redirectWithMsg("ModSecurity berjaya dipasang.", "")
}

func (a *App) handleInstallServiceCRS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}
	vhostID := parseInt64WithDefault(r.FormValue("vhost_id"), 0)
	redirectWithMsg := func(notice, errMsg string) {
		redirectToServiceWAFTab(w, r, serviceKey, vhostID, notice, errMsg)
	}

	manager := detectPackageManager()
	if manager == "" {
		redirectWithMsg("", "Distro tidak disokong untuk auto install OWASP CRS.")
		return
	}

	if !modSecurityInstalled(meta, manager) {
		redirectWithMsg("", "Pasang ModSecurity dahulu sebelum pasang OWASP CRS.")
		return
	}
	if err := ensureApacheModSecurityEnabled(meta, manager); err != nil {
		redirectWithMsg("", "ModSecurity Apache belum aktif: "+truncateString(err.Error(), 280))
		return
	}
	if crsRulesInstalled() {
		redirectWithMsg("OWASP CRS sudah dipasang.", "")
		return
	}

	if err := installPackageCandidates(manager, crsPackageCandidates(manager)); err != nil {
		redirectWithMsg("", "Gagal pasang OWASP CRS: "+truncateString(err.Error(), 280))
		return
	}

	if err := a.syncServiceVirtualHostConfigs(meta, manager); err != nil {
		log.Printf("gagal sync vhost config selepas install crs: %v", err)
	}
	cfg, cfgErr := a.getWAFConfig(meta.Key)
	if cfgErr == nil {
		if err := applyServiceWAFConfig(meta, manager, cfg); err != nil {
			log.Printf("gagal apply config waf selepas install crs: %v", err)
		}
	}
	if err := a.applyVHostWAFOverrides(meta, manager); err != nil {
		log.Printf("gagal apply override vhost selepas install crs: %v", err)
	}
	redirectWithMsg("OWASP CRS berjaya dipasang.", "")
}

func (a *App) handleToggleServiceWAFRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}
	vhostID := parseInt64WithDefault(r.FormValue("vhost_id"), 0)
	if vhostID <= 0 {
		redirectToServiceWAFTab(w, r, serviceKey, 0, "", "Virtual host wajib dipilih.")
		return
	}

	vh, err := a.getVirtualHostByID(serviceKey, vhostID)
	if err != nil {
		redirectToServiceWAFTab(w, r, serviceKey, 0, "", "Virtual host tidak ditemui.")
		return
	}

	rulePath := strings.TrimSpace(r.FormValue("rule_file"))
	if rulePath == "" {
		redirectToServiceWAFTab(w, r, serviceKey, vhostID, "", "Rule file tidak sah.")
		return
	}
	enabled := r.FormValue("enabled") == "1"
	if err := a.upsertWAFVHostRule(serviceKey, vhostID, rulePath, enabled); err != nil {
		redirectToServiceWAFTab(w, r, serviceKey, vhostID, "", "Gagal simpan status rule: "+truncateString(err.Error(), 250))
		return
	}

	manager := detectPackageManager()
	if err := ensureApacheModSecurityEnabled(meta, manager); err != nil {
		log.Printf("gagal aktifkan modsecurity apache semasa toggle rule: %v", err)
	}
	if err := a.syncServiceVirtualHostConfigs(meta, manager); err != nil {
		log.Printf("gagal sync config virtual host semasa toggle rule: %v", err)
	}
	if err := a.applySingleVHostWAFOverride(meta, manager, vh); err != nil {
		log.Printf("gagal apply override rule vhost: %v", err)
	}

	msg := "Rule diaktifkan untuk " + vh.Domain + "."
	if !enabled {
		msg = "Rule dinyahaktifkan untuk " + vh.Domain + "."
	}
	redirectToServiceWAFTab(w, r, serviceKey, vhostID, msg, "")
}

func (a *App) handleSaveWAFConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	vhostID := parseInt64WithDefault(r.FormValue("vhost_id"), 0)
	if _, err := serviceMeta(serviceKey); err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}

	cfg := buildWAFConfigFromForm(r, serviceKey)
	if err := a.upsertWAFConfig(cfg); err != nil {
		redirectToServiceWAFTab(w, r, serviceKey, vhostID, "", "Gagal simpan WAF config: "+truncateString(err.Error(), 250))
		return
	}
	redirectToServiceWAFTab(w, r, serviceKey, vhostID, "Konfigurasi ModSecurity + OWASP CRS berjaya disimpan.", "")
}

func (a *App) handleApplyWAFConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	serviceKey := strings.TrimSpace(strings.ToLower(r.FormValue("service")))
	vhostID := parseInt64WithDefault(r.FormValue("vhost_id"), 0)
	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.Error(w, "service tidak disokong", http.StatusBadRequest)
		return
	}
	manager := detectPackageManager()
	if err := ensureApacheModSecurityEnabled(meta, manager); err != nil {
		redirectToServiceWAFTab(w, r, serviceKey, vhostID, "", "Gagal aktifkan modul ModSecurity Apache: "+truncateString(err.Error(), 280))
		return
	}

	cfg, err := a.getWAFConfig(meta.Key)
	if err != nil {
		redirectToServiceWAFTab(w, r, serviceKey, vhostID, "", "Gagal baca config WAF: "+truncateString(err.Error(), 250))
		return
	}
	if err := applyServiceWAFConfig(meta, manager, cfg); err != nil {
		redirectToServiceWAFTab(w, r, serviceKey, vhostID, "", "Gagal apply ModSecurity config: "+truncateString(err.Error(), 300))
		return
	}
	if err := a.syncServiceVirtualHostConfigs(meta, manager); err != nil {
		log.Printf("gagal sync config virtual host semasa apply waf: %v", err)
	}
	if err := a.applyVHostWAFOverrides(meta, manager); err != nil {
		log.Printf("gagal apply override waf vhost: %v", err)
	}
	redirectToServiceWAFTab(w, r, serviceKey, vhostID, "ModSecurity + OWASP CRS config berjaya ditulis ke server.", "")
}

func (a *App) handleSaveCorazaConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	cfg := buildWAFConfigFromForm(r, "rimaupanel")
	if err := a.upsertWAFConfig(cfg); err != nil {
		redirectToCorazaPage(w, r, "", "Gagal simpan Coraza config: "+truncateString(err.Error(), 250))
		return
	}
	redirectToCorazaPage(w, r, "Coraza config panel berjaya disimpan.", "")
}

func (a *App) handleApplyCorazaConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak sah", http.StatusBadRequest)
		return
	}

	cfg, err := a.getWAFConfig("rimaupanel")
	if err != nil {
		redirectToCorazaPage(w, r, "", "Gagal baca config Coraza: "+truncateString(err.Error(), 250))
		return
	}
	if err := applyCorazaConfig(cfg); err != nil {
		redirectToCorazaPage(w, r, "", "Gagal apply Coraza config: "+truncateString(err.Error(), 300))
		return
	}
	redirectToCorazaPage(w, r, "Coraza config panel berjaya ditulis ke server.", "")
}

func redirectToServicePage(w http.ResponseWriter, r *http.Request, serviceKey, tab, notice, errMsg string) {
	q := url.Values{}
	if strings.TrimSpace(notice) != "" {
		q.Set("notice", notice)
	}
	if strings.TrimSpace(errMsg) != "" {
		q.Set("error", errMsg)
	}
	if strings.TrimSpace(tab) != "" {
		q.Set("tab", tab)
	}
	redirectTo := "/" + serviceKey
	if encoded := q.Encode(); encoded != "" {
		redirectTo += "?" + encoded
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func redirectToCorazaPage(w http.ResponseWriter, r *http.Request, notice, errMsg string) {
	q := url.Values{}
	if strings.TrimSpace(notice) != "" {
		q.Set("notice", notice)
	}
	if strings.TrimSpace(errMsg) != "" {
		q.Set("error", errMsg)
	}
	redirectTo := "/coraza"
	if encoded := q.Encode(); encoded != "" {
		redirectTo += "?" + encoded
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func redirectToServiceWAFTab(w http.ResponseWriter, r *http.Request, serviceKey string, vhostID int64, notice, errMsg string) {
	q := url.Values{}
	q.Set("tab", "waf")
	if vhostID > 0 {
		q.Set("vhost_id", strconv.FormatInt(vhostID, 10))
	}
	if strings.TrimSpace(notice) != "" {
		q.Set("notice", notice)
	}
	if strings.TrimSpace(errMsg) != "" {
		q.Set("error", errMsg)
	}
	http.Redirect(w, r, "/"+serviceKey+"?"+q.Encode(), http.StatusFound)
}

func redirectToChangePasswordPage(w http.ResponseWriter, r *http.Request, notice, errMsg string) {
	q := url.Values{}
	if strings.TrimSpace(notice) != "" {
		q.Set("notice", notice)
	}
	if strings.TrimSpace(errMsg) != "" {
		q.Set("error", errMsg)
	}
	redirectTo := "/change-password"
	if encoded := q.Encode(); encoded != "" {
		redirectTo += "?" + encoded
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func redirectToKernelPage(w http.ResponseWriter, r *http.Request, tab, notice, errMsg string) {
	q := url.Values{}
	if strings.TrimSpace(tab) != "" {
		q.Set("tab", tab)
	}
	if strings.TrimSpace(notice) != "" {
		q.Set("notice", notice)
	}
	if strings.TrimSpace(errMsg) != "" {
		q.Set("error", errMsg)
	}
	redirectTo := "/kernel"
	if encoded := q.Encode(); encoded != "" {
		redirectTo += "?" + encoded
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (a *App) renderServicePage(w http.ResponseWriter, r *http.Request, user User, serviceKey string) {
	meta, err := serviceMeta(serviceKey)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	lang := a.currentLang(r)

	manager := detectPackageManager()
	packageName := "-"
	if pkgName, pkgErr := packageNameForManager(meta, manager); pkgErr == nil {
		packageName = pkgName
	}
	configPath := serviceConfigPath(meta, manager)
	vhostPath := serviceVHostPath(meta, manager)
	vhostEnabledPath := serviceVHostEnabledPath(meta, manager)
	testCommand := serviceTestCommand(meta)
	serviceUnit := serviceUnitForManager(meta, manager)
	reloadCommand := serviceReloadCommand(meta, manager)
	wafTitle, wafSuggestions, wafExample := serviceWAFContent(meta, manager)
	wafConfig, wafErr := a.getWAFConfig(meta.Key)
	if wafErr != nil {
		log.Printf("gagal baca WAF config: %v", wafErr)
		wafConfig = defaultWAFConfig(meta.Key)
	}
	wafConfigPath := serviceWAFConfigPath(meta, manager)
	wafConfigPreview := buildServiceWAFConfig(meta, manager, wafConfig)

	installed, canInstall, statusHint := checkServiceInstalled(meta)
	statusMessage := "Server not install"
	isRunning := false
	canControl := false
	if installed {
		runtime := detectServiceRuntime(meta, manager)
		if runtime.Unit != "" {
			serviceUnit = runtime.Unit
			reloadCommand = "systemctl reload " + runtime.Unit
		}
		isRunning = runtime.IsRunning
		canControl = runtime.CanControl
		if runtime.IsRunning {
			statusMessage = "Server running"
		} else {
			statusMessage = "Server not running"
		}
		if runtime.State != "" && runtime.State != "unknown" {
			statusHint = fmt.Sprintf("Service unit: %s (state: %s)", serviceUnit, runtime.State)
		} else {
			statusHint = fmt.Sprintf("Service unit: %s", serviceUnit)
		}
	}

	virtualHosts, vhErr := a.listVirtualHosts(meta.Key)
	if vhErr != nil {
		log.Printf("gagal baca virtual host: %v", vhErr)
	}
	defaultListenPort := a.getServiceDefaultListenPort(meta.Key)
	vhostPortSummary := "Tiada virtual host direkodkan."
	if lang == "en" {
		vhostPortSummary = "No virtual hosts recorded."
	}
	if len(virtualHosts) > 0 {
		firstPort := virtualHosts[0].ListenPort
		mixedPort := false
		for _, vh := range virtualHosts[1:] {
			if vh.ListenPort != firstPort {
				mixedPort = true
				break
			}
		}
		if mixedPort {
			vhostPortSummary = "Port virtual host bercampur. Aktifkan pilihan apply jika mahu samakan semua port."
			if lang == "en" {
				vhostPortSummary = "Virtual hosts currently use mixed ports. Enable apply option to make all ports consistent."
			}
		} else {
			vhostPortSummary = fmt.Sprintf("Semua virtual host semasa menggunakan port %d.", firstPort)
			if lang == "en" {
				vhostPortSummary = fmt.Sprintf("All current virtual hosts are using port %d.", firstPort)
			}
		}
	}
	modSecInstalled := modSecurityInstalled(meta, manager)
	crsInstalled := crsRulesInstalled()
	selectedVHostID := parseInt64WithDefault(r.URL.Query().Get("vhost_id"), 0)
	if selectedVHostID <= 0 && len(virtualHosts) > 0 {
		selectedVHostID = virtualHosts[0].ID
	}
	selectedVHostName := "-"
	if selectedVHostID > 0 {
		found := false
		for _, vh := range virtualHosts {
			if vh.ID == selectedVHostID {
				selectedVHostName = vh.Domain
				found = true
				break
			}
		}
		if !found && len(virtualHosts) > 0 {
			selectedVHostID = virtualHosts[0].ID
			selectedVHostName = virtualHosts[0].Domain
		}
	}
	wafRules := make([]WAFRuleItem, 0)
	if selectedVHostID > 0 && crsInstalled {
		rules, ruleErr := a.listWAFRulesForVHost(meta.Key, selectedVHostID)
		if ruleErr != nil {
			log.Printf("gagal baca rule waf vhost: %v", ruleErr)
		} else {
			wafRules = rules
		}
	}

	activeTab := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tab")))
	switch activeTab {
	case "vhost", "setting", "optimize", "waf":
	default:
		activeTab = "setting"
	}
	if activeTab == "waf" && len(wafSuggestions) == 0 {
		activeTab = "setting"
	}
	if activeTab == "vhost" && !installed {
		activeTab = "setting"
	}

	pageData := ServicePageData{
		Lang:                lang,
		CurrentURI:          r.URL.RequestURI(),
		Username:            user.Username,
		ServiceName:         meta.Name,
		ServiceKey:          meta.Key,
		ServiceNotes:        "Halaman pengurusan " + meta.Name + ".",
		ActiveApache:        meta.Key == "apache",
		ActiveNginx:         meta.Key == "nginx",
		Installed:           installed,
		StatusMessage:       statusMessage,
		StatusHint:          statusHint,
		CanInstall:          canInstall,
		CanControl:          canControl,
		IsRunning:           isRunning,
		ShowTabs:            installed,
		ShowWAFTab:          installed && len(wafSuggestions) > 0,
		IsNginx:             meta.Key == "nginx",
		PackageManager:      packageManagerLabel(manager),
		PackageName:         packageName,
		ServiceUnit:         serviceUnit,
		ConfigPath:          configPath,
		VHostPath:           vhostPath,
		VHostEnabledPath:    vhostEnabledPath,
		TestCommand:         testCommand,
		ReloadCommand:       reloadCommand,
		DefaultListenPort:   defaultListenPort,
		VHostPortSummary:    vhostPortSummary,
		VHostExample:        serviceVHostExample(meta, manager),
		OptimizeSuggestions: serviceOptimizeSuggestions(meta, manager, vhostPath),
		VirtualHosts:        virtualHosts,
		ActiveTab:           activeTab,
		WAFTitle:            wafTitle,
		WAFSuggestions:      wafSuggestions,
		WAFExample:          wafExample,
		WAFConfig:           wafConfig,
		WAFConfigPath:       wafConfigPath,
		WAFConfigPreview:    wafConfigPreview,
		WAFModSecInstalled:  modSecInstalled,
		WAFCRSInstalled:     crsInstalled,
		WAFCanInstall:       manager != "",
		WAFHasVHosts:        len(virtualHosts) > 0,
		WAFSelectedVHostID:  selectedVHostID,
		WAFSelectedVHost:    selectedVHostName,
		WAFRules:            wafRules,
		Notice:              strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:               strings.TrimSpace(r.URL.Query().Get("error")),
	}

	a.render(w, "service.html", pageData)
}

func (a *App) handleSystemAPI(w http.ResponseWriter, r *http.Request) {
	info, err := system.Collect()
	if err != nil {
		http.Error(w, "gagal membaca status sistem", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		log.Printf("gagal encode json: %v", err)
	}
}

func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.currentUser(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) currentUser(r *http.Request) (User, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return User{}, err
	}

	var user User
	var expiresAt int64
	err = a.db.QueryRow(`
		SELECT u.id, u.username, s.expires_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token = ?
	`, cookie.Value).Scan(&user.ID, &user.Username, &expiresAt)
	if err != nil {
		return User{}, err
	}

	if time.Now().Unix() > expiresAt {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE token = ?`, cookie.Value)
		return User{}, errors.New("session expired")
	}
	return user, nil
}

func (a *App) createSession(userID int64) (token string, expiresAt time.Time, err error) {
	token, err = randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}

	expiresAt = time.Now().Add(a.sessionTTL)
	_, err = a.db.Exec(
		`INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		token, userID, expiresAt.Unix(), time.Now().Unix(),
	)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (a *App) findUserByUsername(username string) (User, string, error) {
	var user User
	var passwordHash string
	err := a.db.QueryRow(`SELECT id, username, password_hash FROM users WHERE username = ?`, username).Scan(&user.ID, &user.Username, &passwordHash)
	if err != nil {
		return User{}, "", err
	}
	return user, passwordHash, nil
}

func (a *App) clientIPFromRequest(r *http.Request) string {
	if forward := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forward != "" {
		for _, item := range strings.Split(forward, ",") {
			candidate := strings.TrimSpace(item)
			if ip := net.ParseIP(candidate); ip != nil {
				return ip.String()
			}
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if ip := net.ParseIP(realIP); ip != nil {
			return ip.String()
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(r.RemoteAddr)); ip != nil {
		return ip.String()
	}
	return "unknown"
}

func (a *App) getLoginThrottle(ipKey string) (failedCount int, lockedUntil int64, err error) {
	err = a.db.QueryRow(`
		SELECT failed_count, locked_until
		FROM login_throttles
		WHERE ip_key = ?
	`, ipKey).Scan(&failedCount, &lockedUntil)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return failedCount, lockedUntil, nil
}

func (a *App) loginLockSeconds(ipKey string) (int, error) {
	_, lockedUntil, err := a.getLoginThrottle(ipKey)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	if lockedUntil > now {
		return int(lockedUntil - now), nil
	}
	if lockedUntil > 0 && lockedUntil <= now {
		if _, err := a.db.Exec(`
			UPDATE login_throttles
			SET failed_count = 0, locked_until = 0, updated_at = ?
			WHERE ip_key = ?
		`, now, ipKey); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func (a *App) recordLoginFailure(ipKey string) (int, error) {
	now := time.Now().Unix()
	failedCount, lockedUntil, err := a.getLoginThrottle(ipKey)
	if err != nil {
		return 0, err
	}

	if lockedUntil > now {
		return int(lockedUntil - now), nil
	}
	if lockedUntil > 0 && lockedUntil <= now {
		failedCount = 0
		lockedUntil = 0
	}

	failedCount++
	if failedCount >= 3 {
		lockedUntil = now + 60
		failedCount = 0
	}

	_, err = a.db.Exec(`
		INSERT INTO login_throttles (ip_key, failed_count, locked_until, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(ip_key) DO UPDATE SET
			failed_count = excluded.failed_count,
			locked_until = excluded.locked_until,
			updated_at = excluded.updated_at
	`, ipKey, failedCount, lockedUntil, now)
	if err != nil {
		return 0, err
	}

	if lockedUntil > now {
		return int(lockedUntil - now), nil
	}
	return 0, nil
}

func (a *App) clearLoginThrottle(ipKey string) error {
	_, err := a.db.Exec(`DELETE FROM login_throttles WHERE ip_key = ?`, ipKey)
	return err
}

func (a *App) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var out bytes.Buffer
	if err := a.templates.ExecuteTemplate(&out, name, data); err != nil {
		log.Printf("gagal render template %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	content := out.String()
	if detectRenderLang(data) == "en" {
		content = translateMalayToEnglish(content)
	}
	_, _ = w.Write([]byte(content))
}

func detectRenderLang(data any) string {
	if data == nil {
		return "ms"
	}
	rv := reflect.ValueOf(data)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return "ms"
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return "ms"
	}
	field := rv.FieldByName("Lang")
	if !field.IsValid() || field.Kind() != reflect.String {
		return "ms"
	}
	return normalizeLang(field.String())
}

func initSchema(db *sql.DB) error {
	schema := `
	PRAGMA foreign_keys = ON;
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		created_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS login_throttles (
		ip_key TEXT PRIMARY KEY,
		failed_count INTEGER NOT NULL DEFAULT 0,
		locked_until INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS virtual_hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		service_key TEXT NOT NULL,
		domain TEXT NOT NULL,
		aliases TEXT NOT NULL,
		root_path TEXT NOT NULL,
		listen_port INTEGER NOT NULL,
		app_runtime TEXT NOT NULL DEFAULT '',
		config_file TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS waf_configs (
		service_key TEXT PRIMARY KEY,
		enabled INTEGER NOT NULL DEFAULT 1,
		mode TEXT NOT NULL DEFAULT 'detection',
		paranoia_level INTEGER NOT NULL DEFAULT 1,
		inbound_anomaly_score INTEGER NOT NULL DEFAULT 5,
		outbound_anomaly_score INTEGER NOT NULL DEFAULT 4,
		request_body_limit_kb INTEGER NOT NULL DEFAULT 1024,
		crs_enabled INTEGER NOT NULL DEFAULT 1,
		custom_rules_path TEXT NOT NULL DEFAULT '',
		trusted_ips TEXT NOT NULL DEFAULT '',
		excluded_paths TEXT NOT NULL DEFAULT '',
		audit_enabled INTEGER NOT NULL DEFAULT 1,
		audit_log_path TEXT NOT NULL DEFAULT '/var/log/modsec_audit.log',
		log_level TEXT NOT NULL DEFAULT 'info',
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS waf_vhost_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		service_key TEXT NOT NULL,
		vhost_id INTEGER NOT NULL,
		rule_file TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		updated_at INTEGER NOT NULL,
		FOREIGN KEY(vhost_id) REFERENCES virtual_hosts(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS service_settings (
		service_key TEXT PRIMARY KEY,
		default_listen_port INTEGER NOT NULL DEFAULT 80,
		updated_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_login_throttles_updated_at ON login_throttles(updated_at);
	CREATE INDEX IF NOT EXISTS idx_virtual_hosts_service_created ON virtual_hosts(service_key, created_at DESC);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_virtual_hosts_unique_domain ON virtual_hosts(service_key, domain);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_waf_vhost_rule_unique ON waf_vhost_rules(service_key, vhost_id, rule_file);
	CREATE INDEX IF NOT EXISTS idx_waf_vhost_rule_service_vhost ON waf_vhost_rules(service_key, vhost_id);
	`
	_, err := db.Exec(schema)
	if err != nil {
		return err
	}
	if err := ensureVirtualHostColumns(db); err != nil {
		return err
	}
	return nil
}

func seedAdminUser(db *sql.DB) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	adminUser := getEnv("RIMAUPANEL_ADMIN_USER", "admin")
	adminPass := getEnv("RIMAUPANEL_ADMIN_PASS", "admin123")
	hashed, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Exec(`INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)`, adminUser, string(hashed), time.Now().Unix())
	if err != nil {
		return err
	}

	log.Printf("Admin default dicipta: username=%s password=%s", adminUser, adminPass)
	return nil
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func formatBytes(size uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	val := float64(size)
	idx := 0
	for val >= 1024 && idx < len(units)-1 {
		val /= 1024
		idx++
	}
	if idx == 0 {
		return fmt.Sprintf("%d %s", size, units[idx])
	}
	return fmt.Sprintf("%.2f %s", val, units[idx])
}

func formatPercent(v float64) string {
	return fmt.Sprintf("%.2f%%", v)
}

func getEnv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func getEnvInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func (a *App) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).Truncate(time.Millisecond))
	})
}

func serviceMeta(serviceKey string) (ServiceMeta, error) {
	switch serviceKey {
	case "apache":
		return ServiceMeta{
			Key:           "apache",
			Name:          "Apache",
			DebianPackage: "apache2",
			RPMPackage:    "httpd",
			DebianService: "apache2",
			RPMService:    "httpd",
			BinaryCandidates: []string{
				"apache2ctl",
				"apachectl",
				"httpd",
			},
		}, nil
	case "nginx":
		return ServiceMeta{
			Key:           "nginx",
			Name:          "Nginx",
			DebianPackage: "nginx",
			RPMPackage:    "nginx",
			DebianService: "nginx",
			RPMService:    "nginx",
			BinaryCandidates: []string{
				"nginx",
			},
		}, nil
	default:
		return ServiceMeta{}, errors.New("service tidak disokong")
	}
}

func detectPackageManager() string {
	if commandExists("apt-get") && commandExists("dpkg-query") {
		return "apt"
	}
	if commandExists("dnf") && commandExists("rpm") {
		return "dnf"
	}
	if commandExists("yum") && commandExists("rpm") {
		return "yum"
	}
	return ""
}

func packageManagerLabel(manager string) string {
	switch manager {
	case "apt":
		return "APT (Debian/Ubuntu)"
	case "dnf":
		return "DNF (RedHat/Rocky)"
	case "yum":
		return "YUM (RedHat/Rocky)"
	default:
		return "Unknown"
	}
}

func packageNameForManager(meta ServiceMeta, manager string) (string, error) {
	switch manager {
	case "apt":
		if meta.DebianPackage == "" {
			return "", errors.New("package Debian tiada")
		}
		return meta.DebianPackage, nil
	case "dnf", "yum":
		if meta.RPMPackage == "" {
			return "", errors.New("package RPM tiada")
		}
		return meta.RPMPackage, nil
	default:
		return "", errors.New("package manager tidak disokong")
	}
}

func serviceUnitForManager(meta ServiceMeta, manager string) string {
	switch manager {
	case "apt":
		if meta.DebianService != "" {
			return meta.DebianService
		}
	case "dnf", "yum":
		if meta.RPMService != "" {
			return meta.RPMService
		}
	}
	if meta.Key == "apache" {
		return "apache2"
	}
	if meta.Key == "nginx" {
		return "nginx"
	}
	return "-"
}

func serviceUnitCandidates(meta ServiceMeta, manager string) []string {
	switch meta.Key {
	case "apache":
		switch manager {
		case "apt":
			return []string{"apache2"}
		case "dnf", "yum":
			return []string{"httpd"}
		default:
			return []string{"apache2", "httpd"}
		}
	case "nginx":
		return []string{"nginx"}
	default:
		return []string{}
	}
}

func serviceConfigPath(meta ServiceMeta, manager string) string {
	switch meta.Key {
	case "apache":
		if manager == "apt" {
			return "/etc/apache2/apache2.conf"
		}
		return "/etc/httpd/conf/httpd.conf"
	case "nginx":
		return "/etc/nginx/nginx.conf"
	default:
		return "-"
	}
}

func serviceVHostPath(meta ServiceMeta, manager string) string {
	switch meta.Key {
	case "apache":
		if manager == "apt" {
			return "/etc/apache2/sites-available"
		}
		return "/etc/httpd/conf.d"
	case "nginx":
		if manager == "apt" {
			return "/etc/nginx/sites-available"
		}
		return "/etc/nginx/conf.d"
	default:
		return "-"
	}
}

func serviceVHostEnabledPath(meta ServiceMeta, manager string) string {
	switch meta.Key {
	case "apache":
		if manager == "apt" {
			return "/etc/apache2/sites-enabled"
		}
		return ""
	case "nginx":
		if manager == "apt" {
			return "/etc/nginx/sites-enabled"
		}
		return ""
	default:
		return ""
	}
}

func serviceTestCommand(meta ServiceMeta) string {
	switch meta.Key {
	case "apache":
		return "apachectl configtest"
	case "nginx":
		return "nginx -t"
	default:
		return "-"
	}
}

func serviceReloadCommand(meta ServiceMeta, manager string) string {
	serviceUnit := serviceUnitForManager(meta, manager)
	if serviceUnit == "-" {
		return "systemctl reload <service>"
	}
	return "systemctl reload " + serviceUnit
}

func serviceVHostExample(meta ServiceMeta, manager string) string {
	switch meta.Key {
	case "apache":
		return `<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example

    ErrorLog ${APACHE_LOG_DIR}/example_error.log
    CustomLog ${APACHE_LOG_DIR}/example_access.log combined
</VirtualHost>`
	case "nginx":
		return `server {
    listen 80;
    server_name example.com www.example.com;
    root /var/www/example;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
}`
	default:
		return "# Tiada contoh konfigurasi"
	}
}

func serviceOptimizeSuggestions(meta ServiceMeta, manager string, vhostPath string) []string {
	switch meta.Key {
	case "nginx":
		suggestions := []string{
			"Gunakan workflow panel: simpan fail virtual host di " + vhostPath + ", uji konfigurasi dengan `nginx -t`, kemudian reload (bukan restart).",
			"Sediakan templat SSL default: redirect HTTP ke HTTPS, aktifkan TLS 1.2/1.3, dan urus sijil Let's Encrypt terus dari panel.",
			"Paparkan tetapan prestasi penting di panel: `worker_processes auto`, `worker_connections`, `keepalive_timeout`, `client_max_body_size`.",
			"Bagi aplikasi reverse proxy, sediakan preset `proxy_read_timeout`, `proxy_send_timeout`, dan `proxy_buffering`.",
			"Aktifkan Gzip/Brotli melalui toggle panel serta whitelist MIME type supaya respon lebih ringan.",
			"Sediakan polisi keselamatan boleh pilih (preset): `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy`.",
			"Tambah monitoring asas di panel: graf status 4xx/5xx, request rate, dan amaran bila `nginx -t` gagal selepas perubahan.",
		}
		if manager == "apt" {
			suggestions = append(suggestions, "Untuk Debian/Ubuntu, gunakan model `sites-available` + symlink ke `sites-enabled` supaya rollback konfigurasi lebih mudah.")
		}
		return suggestions
	case "apache":
		return []string{
			"Selepas ubah konfigurasi, jalankan `apachectl configtest` sebelum reload servis.",
			"Pisahkan virtual host mengikut domain untuk mudahkan backup dan rollback.",
			"Guna modul yang perlu sahaja (contoh: `rewrite`, `ssl`) untuk kurangkan permukaan serangan.",
			"Pantau access/error log secara berpusat dan tambah amaran untuk lonjakan 4xx/5xx.",
		}
	default:
		return []string{"Tiada cadangan tersedia."}
	}
}

func serviceWAFContent(meta ServiceMeta, manager string) (title string, suggestions []string, example string) {
	switch meta.Key {
	case "nginx":
		title = "Cadangan penting untuk Nginx WAF panel."
		suggestions = []string{
			"Guna ModSecurity v3 + OWASP CRS sebagai default profile untuk perlindungan SQLi/XSS.",
			"Sediakan mod `DetectionOnly` dan `On` dalam panel supaya rollout boleh dibuat secara bertahap.",
			"Tambah whitelist route penting (contoh webhook/API callback) bagi kurangkan false positive.",
			"Asingkan log WAF daripada access/error log supaya analisis insiden lebih jelas.",
			"Sebelum aktif penuh, uji rule pada trafik sebenar dan pantau kenaikan latency.",
		}
		example = `modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;

# Dalam main.conf aktifkan OWASP CRS
Include /etc/nginx/modsec/crs-setup.conf
Include /etc/nginx/modsec/rules/*.conf`
		return title, suggestions, example
	case "apache":
		title = "Cadangan penting untuk Apache WAF panel."
		suggestions = []string{
			"Guna `mod_security` + OWASP CRS untuk perlindungan aplikasi web asas.",
			"Bina toggle panel untuk `SecRuleEngine DetectionOnly` dan `SecRuleEngine On`.",
			"Pisahkan rule custom mengikut aplikasi untuk mudahkan debug false positive.",
			"Paparkan statistik top blocked IP/rule dan log audit dalam panel.",
			"Uji konfigurasi dengan `apachectl configtest` sebelum reload servis.",
		}
		if manager == "apt" {
			suggestions = append(suggestions, "Debian/Ubuntu: pasang `libapache2-mod-security2` dan aktifkan modul dengan `a2enmod security2`.")
		} else if manager == "dnf" || manager == "yum" {
			suggestions = append(suggestions, "RedHat/Rocky: pasang pakej `mod_security` dan semak fail rule di `/etc/httpd/modsecurity.d/`.")
		}
		example = `<IfModule security2_module>
    SecRuleEngine On
    SecRequestBodyAccess On
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /usr/share/modsecurity-crs/*.conf
</IfModule>`
		return title, suggestions, example
	default:
		return "", nil, ""
	}
}

func (a *App) listVirtualHosts(serviceKey string) ([]VirtualHostRecord, error) {
	rows, err := a.db.Query(`
		SELECT id, domain, aliases, root_path, listen_port, app_runtime, config_file, enabled, created_at
		FROM virtual_hosts
		WHERE service_key = ?
		ORDER BY created_at DESC
	`, serviceKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]VirtualHostRecord, 0)
	for rows.Next() {
		var rec VirtualHostRecord
		var enabledInt int
		var createdAtUnix int64
		if err := rows.Scan(
			&rec.ID,
			&rec.Domain,
			&rec.Aliases,
			&rec.RootPath,
			&rec.ListenPort,
			&rec.AppRuntime,
			&rec.ConfigFile,
			&enabledInt,
			&createdAtUnix,
		); err != nil {
			return nil, err
		}
		rec.Enabled = enabledInt == 1
		rec.AppRuntime = normalizeAppRuntime(rec.AppRuntime)
		rec.RuntimeInstalled = runtimeInstalled(rec.AppRuntime)
		rec.CreatedAt = time.Unix(createdAtUnix, 0).Format("2006-01-02 15:04")
		if strings.TrimSpace(rec.Aliases) == "" {
			rec.Aliases = "-"
		}
		result = append(result, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *App) virtualHostExists(serviceKey, domain string) (bool, error) {
	var count int
	err := a.db.QueryRow(
		`SELECT COUNT(1) FROM virtual_hosts WHERE service_key = ? AND domain = ?`,
		serviceKey, domain,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (a *App) virtualHostExistsExceptID(serviceKey, domain string, excludeID int64) (bool, error) {
	var count int
	err := a.db.QueryRow(
		`SELECT COUNT(1) FROM virtual_hosts WHERE service_key = ? AND domain = ? AND id <> ?`,
		serviceKey, domain, excludeID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (a *App) getVirtualHostByID(serviceKey string, id int64) (VirtualHostRecord, error) {
	var rec VirtualHostRecord
	var enabledInt int
	var createdAtUnix int64
	err := a.db.QueryRow(
		`SELECT id, domain, aliases, root_path, listen_port, app_runtime, config_file, enabled, created_at FROM virtual_hosts WHERE service_key = ? AND id = ?`,
		serviceKey, id,
	).Scan(
		&rec.ID,
		&rec.Domain,
		&rec.Aliases,
		&rec.RootPath,
		&rec.ListenPort,
		&rec.AppRuntime,
		&rec.ConfigFile,
		&enabledInt,
		&createdAtUnix,
	)
	if err != nil {
		return VirtualHostRecord{}, err
	}
	rec.Enabled = enabledInt == 1
	rec.AppRuntime = normalizeAppRuntime(rec.AppRuntime)
	rec.RuntimeInstalled = runtimeInstalled(rec.AppRuntime)
	rec.CreatedAt = time.Unix(createdAtUnix, 0).Format("2006-01-02 15:04")
	return rec, nil
}

func modSecurityPackageCandidates(meta ServiceMeta, manager string) [][]string {
	switch manager {
	case "apt":
		if meta.Key == "apache" {
			return [][]string{{"libapache2-mod-security2"}}
		}
		if meta.Key == "nginx" {
			return [][]string{
				{"libmodsecurity3", "libnginx-mod-http-modsecurity"},
				{"libmodsecurity3"},
			}
		}
	case "dnf", "yum":
		if meta.Key == "apache" {
			return [][]string{{"mod_security"}}
		}
		if meta.Key == "nginx" {
			return [][]string{
				{"nginx-mod-modsecurity"},
				{"mod_security"},
			}
		}
	}
	return nil
}

func crsPackageCandidates(manager string) [][]string {
	switch manager {
	case "apt":
		return [][]string{{"modsecurity-crs"}}
	case "dnf", "yum":
		return [][]string{
			{"mod_security_crs"},
			{"owasp-modsecurity-crs"},
			{"modsecurity-crs"},
		}
	default:
		return nil
	}
}

func installPackageCandidates(manager string, candidates [][]string) error {
	if len(candidates) == 0 {
		return errors.New("tiada pakej tersedia untuk distro ini")
	}
	errs := make([]string, 0, len(candidates))
	for _, pkgs := range candidates {
		if len(pkgs) == 0 {
			continue
		}
		if err := installPackages(manager, pkgs); err == nil {
			return nil
		} else {
			errs = append(errs, fmt.Sprintf("%s: %s", strings.Join(pkgs, ","), truncateString(err.Error(), 120)))
		}
	}
	if len(errs) == 0 {
		return errors.New("tiada candidate pakej untuk dipasang")
	}
	return errors.New(strings.Join(errs, " | "))
}

func packageSetInstalled(manager string, packages []string) bool {
	for _, pkg := range packages {
		ok, _ := isPackageInstalled(manager, pkg)
		if !ok {
			return false
		}
	}
	return len(packages) > 0
}

func modSecurityInstalled(meta ServiceMeta, manager string) bool {
	candidates := modSecurityPackageCandidates(meta, manager)
	for _, pkgs := range candidates {
		if packageSetInstalled(manager, pkgs) {
			if meta.Key == "apache" && manager == "apt" {
				return apacheModSecurityModuleEnabled()
			}
			return true
		}
	}

	switch meta.Key {
	case "apache":
		moduleFiles := []string{
			"/usr/lib/apache2/modules/mod_security2.so",
			"/etc/httpd/modules/mod_security2.so",
			"/usr/lib64/httpd/modules/mod_security2.so",
		}
		for _, f := range moduleFiles {
			if _, err := os.Stat(f); err == nil {
				if manager == "apt" {
					return apacheModSecurityModuleEnabled()
				}
				return true
			}
		}
		return apacheModSecurityModuleEnabled()
	case "nginx":
		if nginxModSecurityModuleAvailable() {
			return true
		}
	}
	return false
}

func nginxModSecurityModuleAvailable() bool {
	moduleFiles := []string{
		"/usr/lib/nginx/modules/ngx_http_modsecurity_module.so",
		"/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so",
	}
	for _, f := range moduleFiles {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	matches, _ := filepath.Glob("/etc/nginx/modules-enabled/*modsecurity*.conf")
	return len(matches) > 0
}

func apacheModSecurityModuleEnabled() bool {
	if _, err := os.Stat("/etc/apache2/mods-enabled/security2.load"); err == nil {
		return true
	}
	if commandExists("apachectl") {
		out, _ := exec.Command("apachectl", "-M").CombinedOutput()
		return strings.Contains(strings.ToLower(string(out)), "security2_module")
	}
	return false
}

func ensureApacheModSecurityEnabled(meta ServiceMeta, manager string) error {
	if meta.Key != "apache" || manager != "apt" {
		return nil
	}
	if apacheModSecurityModuleEnabled() {
		return nil
	}
	if !commandExists("a2enmod") {
		return errors.New("a2enmod tidak ditemui untuk aktifkan security2")
	}
	if err := runAsRoot(nil, "a2enmod", "security2"); err != nil {
		if apacheModSecurityModuleEnabled() {
			return nil
		}
		return err
	}
	return nil
}

func crsRuleDirs() []string {
	return []string{
		"/etc/modsecurity/crs/rules",
		"/usr/share/modsecurity-crs/rules",
		"/usr/share/owasp-modsecurity-crs/rules",
	}
}

func firstAvailableCRSIncludeLines(meta ServiceMeta, manager string) []string {
	if meta.Key == "apache" && manager == "apt" {
		if _, err := os.Stat("/usr/share/modsecurity-crs/owasp-crs.load"); err == nil {
			return []string{
				"# Debian/Ubuntu Apache memuat CRS melalui /usr/share/modsecurity-crs/*.load (security2.conf).",
				"# Elak include berganda dari panel untuk menghindari duplicate rule id.",
			}
		}
	}

	loaderCandidates := []string{
		"/usr/share/modsecurity-crs/owasp-crs.load",
		"/usr/share/owasp-modsecurity-crs/owasp-crs.load",
	}
	for _, loadPath := range loaderCandidates {
		if _, err := os.Stat(loadPath); err == nil {
			return []string{"IncludeOptional " + loadPath}
		}
	}

	type crsPathPair struct {
		setupPath string
		rulesPath string
	}
	candidates := []crsPathPair{
		{setupPath: "/etc/modsecurity/crs/crs-setup.conf", rulesPath: "/usr/share/modsecurity-crs/rules/*.conf"},
		{setupPath: "/etc/modsecurity/crs/crs-setup.conf", rulesPath: "/etc/modsecurity/crs/rules/*.conf"},
		{setupPath: "/usr/share/modsecurity-crs/crs-setup.conf", rulesPath: "/usr/share/modsecurity-crs/rules/*.conf"},
		{setupPath: "/usr/share/owasp-modsecurity-crs/crs-setup.conf", rulesPath: "/usr/share/owasp-modsecurity-crs/rules/*.conf"},
	}
	for _, c := range candidates {
		if _, err := os.Stat(c.setupPath); err != nil {
			continue
		}
		matches, _ := filepath.Glob(c.rulesPath)
		if len(matches) == 0 {
			continue
		}
		return []string{
			"IncludeOptional " + c.setupPath,
			"IncludeOptional " + c.rulesPath,
		}
	}
	return nil
}

func listCRSRuleFiles() ([]WAFRuleItem, error) {
	seen := map[string]WAFRuleItem{}
	for _, dir := range crsRuleDirs() {
		matches, err := filepath.Glob(filepath.Join(dir, "*.conf"))
		if err != nil {
			continue
		}
		for _, fullPath := range matches {
			info, statErr := os.Stat(fullPath)
			if statErr != nil || info.IsDir() {
				continue
			}
			base := filepath.Base(fullPath)
			if _, ok := seen[base]; ok {
				continue
			}
			seen[base] = WAFRuleItem{
				FileName: base,
				FilePath: fullPath,
				Enabled:  true,
			}
		}
	}

	items := make([]WAFRuleItem, 0, len(seen))
	for _, item := range seen {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].FileName < items[j].FileName
	})
	return items, nil
}

func crsRulesInstalled() bool {
	items, err := listCRSRuleFiles()
	if err != nil {
		return false
	}
	return len(items) > 0
}

func (a *App) listWAFVHostRuleStates(serviceKey string, vhostID int64) (map[string]bool, error) {
	rows, err := a.db.Query(`SELECT rule_file, enabled FROM waf_vhost_rules WHERE service_key = ? AND vhost_id = ?`, serviceKey, vhostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[string]bool{}
	for rows.Next() {
		var ruleFile string
		var enabled int
		if err := rows.Scan(&ruleFile, &enabled); err != nil {
			return nil, err
		}
		result[ruleFile] = enabled == 1
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *App) upsertWAFVHostRule(serviceKey string, vhostID int64, ruleFile string, enabled bool) error {
	_, err := a.db.Exec(`
		INSERT INTO waf_vhost_rules(service_key, vhost_id, rule_file, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(service_key, vhost_id, rule_file) DO UPDATE SET
			enabled=excluded.enabled,
			updated_at=excluded.updated_at
	`, serviceKey, vhostID, ruleFile, boolToInt(enabled), time.Now().Unix())
	return err
}

func (a *App) listWAFRulesForVHost(serviceKey string, vhostID int64) ([]WAFRuleItem, error) {
	files, err := listCRSRuleFiles()
	if err != nil {
		return nil, err
	}
	states, err := a.listWAFVHostRuleStates(serviceKey, vhostID)
	if err != nil {
		return nil, err
	}
	for i := range files {
		if enabled, ok := states[files[i].FilePath]; ok {
			files[i].Enabled = enabled
		} else {
			files[i].Enabled = true
		}
	}
	return files, nil
}

func serviceVHostWAFOverridePath(meta ServiceMeta, domain string) string {
	return filepath.Join("/opt/rimaupanel/waf/vhost", meta.Key, sanitizeFileToken(domain)+".conf")
}

func extractRuleIDsFromFile(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	matches := ruleIDPattern.FindAllStringSubmatch(string(raw), -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		id := strings.TrimSpace(m[1])
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func buildVHostWAFOverrideConfig(meta ServiceMeta, manager string, vhost VirtualHostRecord, disabledRuleIDs []string) string {
	sort.Strings(disabledRuleIDs)
	if meta.Key == "nginx" {
		basePath := serviceWAFConfigPath(meta, manager)
		if len(disabledRuleIDs) == 0 {
			return fmt.Sprintf(`# RimauPanel WAF override for %s (%s)
Include %s
# Semua CRS rules aktif untuk vhost ini.
`, vhost.Domain, strings.ToUpper(meta.Key), basePath)
		}
		return fmt.Sprintf(`# RimauPanel WAF override for %s (%s)
Include %s
SecRuleRemoveById %s
`, vhost.Domain, strings.ToUpper(meta.Key), basePath, strings.Join(disabledRuleIDs, " "))
	}

	if len(disabledRuleIDs) == 0 {
		return fmt.Sprintf(`# RimauPanel WAF override for %s (%s)
# Semua CRS rules aktif untuk vhost ini.
`, vhost.Domain, strings.ToUpper(meta.Key))
	}
	return fmt.Sprintf(`# RimauPanel WAF override for %s (%s)
SecRuleRemoveById %s
`, vhost.Domain, strings.ToUpper(meta.Key), strings.Join(disabledRuleIDs, " "))
}

func (a *App) applySingleVHostWAFOverride(meta ServiceMeta, manager string, vhost VirtualHostRecord) error {
	if !modSecurityInstalled(meta, manager) {
		return nil
	}
	rules, err := a.listWAFRulesForVHost(meta.Key, vhost.ID)
	if err != nil {
		return err
	}

	disabledIDSet := map[string]struct{}{}
	for _, rule := range rules {
		if rule.Enabled {
			continue
		}
		for _, id := range extractRuleIDsFromFile(rule.FilePath) {
			disabledIDSet[id] = struct{}{}
		}
	}

	disabledIDs := make([]string, 0, len(disabledIDSet))
	for id := range disabledIDSet {
		disabledIDs = append(disabledIDs, id)
	}
	sort.Strings(disabledIDs)

	overridePath := serviceVHostWAFOverridePath(meta, vhost.Domain)
	content := buildVHostWAFOverrideConfig(meta, manager, vhost, disabledIDs)
	return writeConfigFileAsRoot(overridePath, content)
}

func (a *App) applyVHostWAFOverrides(meta ServiceMeta, manager string) error {
	vhosts, err := a.listVirtualHosts(meta.Key)
	if err != nil {
		return err
	}
	for _, vhost := range vhosts {
		if err := a.applySingleVHostWAFOverride(meta, manager, vhost); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) syncServiceVirtualHostConfigs(meta ServiceMeta, manager string) error {
	vhosts, err := a.listVirtualHosts(meta.Key)
	if err != nil {
		return err
	}
	for _, vh := range vhosts {
		aliasesRaw := strings.TrimSpace(vh.Aliases)
		if aliasesRaw == "-" {
			aliasesRaw = ""
		}
		aliases := parseHostList(aliasesRaw)
		content, buildErr := buildVirtualHostConfig(meta, manager, vh.Domain, aliases, vh.RootPath, vh.ListenPort, vh.AppRuntime)
		if buildErr != nil {
			return buildErr
		}
		if err := writeConfigFileAsRoot(vh.ConfigFile, content); err != nil {
			return err
		}
	}
	return nil
}

func defaultWAFConfig(serviceKey string) WAFConfig {
	mode := "detection"
	auditLogPath := "/var/log/modsec_audit.log"
	customRulesPath := "/etc/modsecurity/custom/*.conf"
	if serviceKey == "rimaupanel" {
		mode = "on"
		auditLogPath = "/var/log/rimaupanel-coraza-audit.log"
		customRulesPath = ""
	}
	return WAFConfig{
		ServiceKey:           serviceKey,
		Enabled:              true,
		Mode:                 mode,
		ParanoiaLevel:        1,
		InboundAnomalyScore:  5,
		OutboundAnomalyScore: 4,
		RequestBodyLimitKB:   1024,
		CRSEnabled:           true,
		CustomRulesPath:      customRulesPath,
		TrustedIPs:           "",
		ExcludedPaths:        "/healthz\n/metrics",
		AuditEnabled:         true,
		AuditLogPath:         auditLogPath,
		LogLevel:             "info",
		UpdatedAt:            time.Now().Unix(),
	}
}

func buildWAFConfigFromForm(r *http.Request, serviceKey string) WAFConfig {
	cfg := defaultWAFConfig(serviceKey)
	cfg.Enabled = r.FormValue("enabled") == "on"

	mode := strings.ToLower(strings.TrimSpace(r.FormValue("mode")))
	switch mode {
	case "on", "detection", "off":
		cfg.Mode = mode
	default:
		cfg.Mode = "detection"
	}

	cfg.ParanoiaLevel = parseIntWithDefault(r.FormValue("paranoia_level"), 1)
	if cfg.ParanoiaLevel < 1 || cfg.ParanoiaLevel > 4 {
		cfg.ParanoiaLevel = 1
	}
	cfg.InboundAnomalyScore = parseIntWithDefault(r.FormValue("inbound_anomaly_score"), 5)
	cfg.OutboundAnomalyScore = parseIntWithDefault(r.FormValue("outbound_anomaly_score"), 4)
	cfg.RequestBodyLimitKB = parseIntWithDefault(r.FormValue("request_body_limit_kb"), 1024)
	if cfg.RequestBodyLimitKB < 128 {
		cfg.RequestBodyLimitKB = 128
	}

	cfg.CRSEnabled = r.FormValue("crs_enabled") == "on"
	cfg.CustomRulesPath = strings.TrimSpace(r.FormValue("custom_rules_path"))
	cfg.TrustedIPs = strings.Join(parseListValues(r.FormValue("trusted_ips"), true), "\n")
	cfg.ExcludedPaths = strings.Join(parseListValues(r.FormValue("excluded_paths"), false), "\n")
	cfg.AuditEnabled = r.FormValue("audit_enabled") == "on"
	cfg.AuditLogPath = strings.TrimSpace(r.FormValue("audit_log_path"))
	cfg.LogLevel = strings.ToLower(strings.TrimSpace(r.FormValue("log_level")))
	switch cfg.LogLevel {
	case "error", "warn", "info", "debug":
	default:
		cfg.LogLevel = "info"
	}
	if cfg.AuditLogPath == "" {
		cfg.AuditLogPath = defaultWAFConfig(serviceKey).AuditLogPath
	}
	cfg.UpdatedAt = time.Now().Unix()
	return cfg
}

func buildRimauPanelCorazaConfig(cfg WAFConfig) string {
	mode := "DetectionOnly"
	if !cfg.Enabled || cfg.Mode == "off" {
		mode = "Off"
	} else if cfg.Mode == "on" {
		mode = "On"
	}

	requestBodyLimitKB := cfg.RequestBodyLimitKB
	if requestBodyLimitKB < 128 {
		requestBodyLimitKB = 128
	}

	paranoia := cfg.ParanoiaLevel
	if paranoia < 1 || paranoia > 4 {
		paranoia = 1
	}
	inbound := cfg.InboundAnomalyScore
	if inbound < 1 {
		inbound = 5
	}
	outbound := cfg.OutboundAnomalyScore
	if outbound < 1 {
		outbound = 4
	}

	return fmt.Sprintf(`# Coraza built-in rules for RimauPanel
SecRuleEngine %s
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecResponseBodyAccess Off

SecAction "id:210000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=%d"
SecAction "id:210001,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d"
SecAction "id:210002,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=%d"

# Trusted IP exclusions (comma/newline separated)
%s

# Path exclusions (comma/newline separated)
%s

# Block risky methods often used for probing
SecRule REQUEST_METHOD "@rx (?i:^(trace|track|debug)$)" "id:210100,phase:1,deny,log,status:403,msg:'Blocked risky HTTP method'"

# Block common scanner signatures
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(sqlmap|nikto|acunetix|nessus|masscan|nmap|zgrab|wpscan)" "id:210110,phase:1,deny,log,status:403,msg:'Scanner User-Agent blocked'"

# Basic path traversal signatures
SecRule REQUEST_URI|ARGS "@rx (?i)(\\.\\./|%2e%2e%2f|%2e%2e/)" "id:210120,phase:2,deny,log,status:403,msg:'Path traversal pattern blocked'"

# Built-in SQLi detection
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS "@detectSQLi" "id:210130,phase:2,deny,log,status:403,msg:'SQL injection pattern blocked'"

# Built-in XSS detection
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS "@detectXSS" "id:210140,phase:2,deny,log,status:403,msg:'XSS pattern blocked'"

# Basic command injection / remote fetch payload
SecRule ARGS|REQUEST_HEADERS "@rx (?i)(?:\\b(?:wget|curl|bash|sh|powershell|cmd\\.exe)\\b.{0,30}(?:https?|ftp)://)" "id:210150,phase:2,deny,log,status:403,msg:'Command injection payload blocked'"
`, mode, requestBodyLimitKB*1024, paranoia, inbound, outbound,
		corazaTrustedIPSnippet(cfg.TrustedIPs), corazaExcludedPathSnippet(cfg.ExcludedPaths))
}

func (a *App) getWAFConfig(serviceKey string) (WAFConfig, error) {
	cfg := defaultWAFConfig(serviceKey)
	var (
		enabled, crsEnabled, auditEnabled int
	)
	err := a.db.QueryRow(`
		SELECT service_key, enabled, mode, paranoia_level, inbound_anomaly_score, outbound_anomaly_score,
		       request_body_limit_kb, crs_enabled, custom_rules_path, trusted_ips, excluded_paths,
		       audit_enabled, audit_log_path, log_level, updated_at
		FROM waf_configs
		WHERE service_key = ?
	`, serviceKey).Scan(
		&cfg.ServiceKey,
		&enabled,
		&cfg.Mode,
		&cfg.ParanoiaLevel,
		&cfg.InboundAnomalyScore,
		&cfg.OutboundAnomalyScore,
		&cfg.RequestBodyLimitKB,
		&crsEnabled,
		&cfg.CustomRulesPath,
		&cfg.TrustedIPs,
		&cfg.ExcludedPaths,
		&auditEnabled,
		&cfg.AuditLogPath,
		&cfg.LogLevel,
		&cfg.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return cfg, nil
		}
		return cfg, err
	}
	cfg.Enabled = enabled == 1
	cfg.CRSEnabled = crsEnabled == 1
	cfg.AuditEnabled = auditEnabled == 1
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode != "on" && cfg.Mode != "detection" && cfg.Mode != "off" {
		cfg.Mode = defaultWAFConfig(serviceKey).Mode
	}
	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.ParanoiaLevel < 1 || cfg.ParanoiaLevel > 4 {
		cfg.ParanoiaLevel = 1
	}
	if cfg.RequestBodyLimitKB < 128 {
		cfg.RequestBodyLimitKB = 128
	}
	if serviceKey == "rimaupanel" {
		if strings.TrimSpace(cfg.AuditLogPath) == "" {
			cfg.AuditLogPath = "/var/log/rimaupanel-coraza-audit.log"
		}
	} else {
		if strings.TrimSpace(cfg.AuditLogPath) == "" || strings.Contains(strings.ToLower(cfg.AuditLogPath), "coraza") {
			cfg.AuditLogPath = "/var/log/modsec_audit.log"
		}
		if strings.TrimSpace(cfg.CustomRulesPath) == "" || strings.Contains(strings.ToLower(cfg.CustomRulesPath), "/etc/coraza/") {
			cfg.CustomRulesPath = "/etc/modsecurity/custom/*.conf"
		}
	}
	return cfg, nil
}

func (a *App) upsertWAFConfig(cfg WAFConfig) error {
	_, err := a.db.Exec(`
		INSERT INTO waf_configs(
			service_key, enabled, mode, paranoia_level, inbound_anomaly_score, outbound_anomaly_score,
			request_body_limit_kb, crs_enabled, custom_rules_path, trusted_ips, excluded_paths,
			audit_enabled, audit_log_path, log_level, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(service_key) DO UPDATE SET
			enabled=excluded.enabled,
			mode=excluded.mode,
			paranoia_level=excluded.paranoia_level,
			inbound_anomaly_score=excluded.inbound_anomaly_score,
			outbound_anomaly_score=excluded.outbound_anomaly_score,
			request_body_limit_kb=excluded.request_body_limit_kb,
			crs_enabled=excluded.crs_enabled,
			custom_rules_path=excluded.custom_rules_path,
			trusted_ips=excluded.trusted_ips,
			excluded_paths=excluded.excluded_paths,
			audit_enabled=excluded.audit_enabled,
			audit_log_path=excluded.audit_log_path,
			log_level=excluded.log_level,
			updated_at=excluded.updated_at
	`,
		cfg.ServiceKey,
		boolToInt(cfg.Enabled),
		cfg.Mode,
		cfg.ParanoiaLevel,
		cfg.InboundAnomalyScore,
		cfg.OutboundAnomalyScore,
		cfg.RequestBodyLimitKB,
		boolToInt(cfg.CRSEnabled),
		cfg.CustomRulesPath,
		cfg.TrustedIPs,
		cfg.ExcludedPaths,
		boolToInt(cfg.AuditEnabled),
		cfg.AuditLogPath,
		cfg.LogLevel,
		cfg.UpdatedAt,
	)
	return err
}

func serviceWAFConfigPath(meta ServiceMeta, manager string) string {
	switch meta.Key {
	case "apache":
		if manager == "apt" {
			return "/etc/modsecurity/rimaupanel-apache.conf"
		}
		return "/etc/httpd/modsecurity.d/rimaupanel-apache.conf"
	case "nginx":
		return "/etc/nginx/modsec/main.conf"
	default:
		return "/opt/rimaupanel/waf/" + meta.Key + ".conf"
	}
}

func buildServiceWAFConfig(meta ServiceMeta, manager string, cfg WAFConfig) string {
	mode := "DetectionOnly"
	if !cfg.Enabled || cfg.Mode == "off" {
		mode = "Off"
	} else if cfg.Mode == "on" {
		mode = "On"
	}

	auditEngine := "RelevantOnly"
	if !cfg.AuditEnabled {
		auditEngine = "Off"
	}

	crsInclude := "# OWASP CRS disabled"
	if cfg.CRSEnabled {
		lines := firstAvailableCRSIncludeLines(meta, manager)
		if len(lines) > 0 {
			crsInclude = strings.Join(lines, "\n")
		} else {
			crsInclude = "# OWASP CRS path tidak ditemui"
		}
	}

	customRules := "# tiada custom rules path"
	if strings.TrimSpace(cfg.CustomRulesPath) != "" {
		customRules = "IncludeOptional " + strings.TrimSpace(cfg.CustomRulesPath)
	}

	comment := "# Untuk Apache: pastikan modul security2/mod_security aktif."
	if meta.Key == "nginx" {
		comment = "# Untuk Nginx: aktifkan `modsecurity on;` dan `modsecurity_rules_file " + serviceWAFConfigPath(meta, manager) + "` pada server block."
	}

	return fmt.Sprintf(`# ModSecurity + OWASP CRS config - generated by RimauPanel
# Service: %s
%s
SecRuleEngine %s
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecAuditEngine %s
SecAuditLog %s
SecDebugLogLevel %s

# OWASP CRS
%s

# WAF tuning
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=%d"
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d"
SecAction "id:900120,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=%d"

# Trusted IP exclusions (comma/newline separated in panel)
%s

# Path exclusions (comma/newline separated in panel)
%s

# Custom rules
%s
`, strings.ToUpper(meta.Key), comment, mode, cfg.RequestBodyLimitKB*1024, auditEngine, cfg.AuditLogPath, cfg.LogLevel,
		crsInclude, cfg.ParanoiaLevel, cfg.InboundAnomalyScore, cfg.OutboundAnomalyScore,
		corazaTrustedIPSnippet(cfg.TrustedIPs), corazaExcludedPathSnippet(cfg.ExcludedPaths), customRules)
}

func applyServiceWAFConfig(meta ServiceMeta, manager string, cfg WAFConfig) error {
	configPath := serviceWAFConfigPath(meta, manager)
	content := buildServiceWAFConfig(meta, manager, cfg)
	return writeConfigFileAsRoot(configPath, content)
}

func corazaConfigPath(serviceKey string) string {
	return filepath.Join("/opt/rimaupanel/coraza", serviceKey+".conf")
}

func buildCorazaConfig(cfg WAFConfig) string {
	return buildRimauPanelCorazaConfig(cfg)
}

func corazaTrustedIPSnippet(raw string) string {
	items := parseListValues(raw, true)
	if len(items) == 0 {
		return "# none"
	}
	lines := make([]string, 0, len(items))
	for i, item := range items {
		lines = append(lines, fmt.Sprintf(`SecRule REMOTE_ADDR "@ipMatch %s" "id:%d,phase:1,nolog,pass,ctl:ruleEngine=Off"`, item, 100100+i))
	}
	return strings.Join(lines, "\n")
}

func corazaExcludedPathSnippet(raw string) string {
	items := parseListValues(raw, false)
	if len(items) == 0 {
		return "# none"
	}
	lines := make([]string, 0, len(items))
	for i, item := range items {
		path := strings.TrimSpace(item)
		if path == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf(`SecRule REQUEST_URI "@beginsWith %s" "id:%d,phase:1,nolog,pass,ctl:ruleEngine=Off"`, path, 100300+i))
	}
	if len(lines) == 0 {
		return "# none"
	}
	return strings.Join(lines, "\n")
}

func applyCorazaConfig(cfg WAFConfig) error {
	configPath := corazaConfigPath(cfg.ServiceKey)
	content := buildCorazaConfig(cfg)
	return writeConfigFileAsRoot(configPath, content)
}

func buildConfigFileName(domain, manager string, enabled bool) string {
	base := sanitizeFileToken(domain)
	if base == "" {
		base = "vhost"
	}
	if !enabled && (manager == "dnf" || manager == "yum") {
		return base + ".conf.disabled"
	}
	return base + ".conf"
}

func sanitizeFileToken(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	lastDash := false
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if r == '.' || r == '-' || r == '_' {
			if !lastDash {
				b.WriteRune('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "vhost"
	}
	return out
}

func isValidHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	return hostPattern.MatchString(host)
}

func parseHostList(raw string) []string {
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == ';'
	}
	parts := strings.FieldsFunc(raw, splitter)
	result := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		host := strings.ToLower(strings.TrimSpace(part))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		result = append(result, host)
	}
	return result
}

func parseListValues(raw string, toLower bool) []string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	normalized = strings.ReplaceAll(normalized, "\\n", "\n")
	splitter := func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t' || r == ';'
	}
	parts := strings.FieldsFunc(normalized, splitter)
	result := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if toLower {
			item = strings.ToLower(item)
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func normalizeAppRuntime(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "php":
		return "php"
	case "java":
		return "java"
	case "python":
		return "python"
	case "dotnet", ".net", "net":
		return "dotnet"
	default:
		return ""
	}
}

func runtimeLabel(runtime string) string {
	switch normalizeAppRuntime(runtime) {
	case "php":
		return "PHP"
	case "java":
		return "Java"
	case "python":
		return "Python"
	case "dotnet":
		return ".NET"
	default:
		return "-"
	}
}

func runtimeInstalled(runtime string) bool {
	switch normalizeAppRuntime(runtime) {
	case "php":
		return commandExists("php")
	case "java":
		return commandExists("java")
	case "python":
		return commandExists("python3") || commandExists("python")
	case "dotnet":
		return commandExists("dotnet")
	default:
		return false
	}
}

func runtimePackageCandidates(runtime, manager string) [][]string {
	switch normalizeAppRuntime(runtime) {
	case "php":
		switch manager {
		case "apt":
			return [][]string{{"php-fpm", "php-cli"}}
		case "dnf", "yum":
			return [][]string{{"php", "php-fpm", "php-cli"}}
		}
	case "java":
		switch manager {
		case "apt":
			return [][]string{{"default-jre-headless"}}
		case "dnf", "yum":
			return [][]string{{"java-17-openjdk"}}
		}
	case "python":
		switch manager {
		case "apt":
			return [][]string{{"python3", "python3-venv", "python3-pip"}}
		case "dnf", "yum":
			return [][]string{{"python3", "python3-pip"}}
		}
	case "dotnet":
		switch manager {
		case "apt":
			return [][]string{
				{"dotnet-runtime-8.0"},
				{"dotnet-runtime-7.0"},
				{"dotnet-runtime-6.0"},
				{"aspnetcore-runtime-8.0"},
				{"aspnetcore-runtime-7.0"},
				{"aspnetcore-runtime-6.0"},
			}
		case "dnf", "yum":
			return [][]string{
				{"dotnet-runtime-8.0"},
				{"dotnet-runtime-7.0"},
				{"dotnet-runtime-6.0"},
				{"aspnetcore-runtime-8.0"},
				{"aspnetcore-runtime-7.0"},
				{"aspnetcore-runtime-6.0"},
			}
		}
	}
	return nil
}

func apacheRuntimeSnippet(runtime string) string {
	switch normalizeAppRuntime(runtime) {
	case "php":
		return `    # PHP runtime
    DirectoryIndex index.php index.html
    <FilesMatch \.php$>
        SetHandler application/x-httpd-php
    </FilesMatch>`
	case "java":
		return `    # Java runtime (reverse proxy contoh)
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/`
	case "python":
		return `    # Python runtime (reverse proxy contoh)
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/`
	case "dotnet":
		return `    # .NET runtime (ASP.NET Core reverse proxy contoh)
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5000/
    ProxyPassReverse / http://127.0.0.1:5000/`
	default:
		return "    # Runtime tidak ditetapkan"
	}
}

func nginxRuntimeSnippet(runtime, manager string) string {
	switch normalizeAppRuntime(runtime) {
	case "php":
		socket := "/run/php/php-fpm.sock"
		if manager == "apt" {
			socket = "/run/php/php8.2-fpm.sock"
		} else if manager == "dnf" || manager == "yum" {
			socket = "/run/php-fpm/www.sock"
		}
		return fmt.Sprintf(`    # PHP runtime
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:%s;
    }`, socket)
	case "java":
		return `    # Java runtime (reverse proxy contoh)
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }`
	case "python":
		return `    # Python runtime (reverse proxy contoh)
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }`
	case "dotnet":
		return `    # .NET runtime (ASP.NET Core reverse proxy contoh)
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }`
	default:
		return "    # Runtime tidak ditetapkan"
	}
}

func buildVirtualHostConfig(meta ServiceMeta, manager, domain string, aliases []string, rootPath string, port int, appRuntime string) (string, error) {
	if port <= 0 || port > 65535 {
		return "", errors.New("listen port tidak sah")
	}
	appRuntime = normalizeAppRuntime(appRuntime)
	if appRuntime == "" {
		return "", errors.New("application runtime tidak sah")
	}

	switch meta.Key {
	case "apache":
		aliasLine := ""
		if len(aliases) > 0 {
			aliasLine = "    ServerAlias " + strings.Join(aliases, " ") + "\n"
		}
		runtimeSnippet := apacheRuntimeSnippet(appRuntime)
		errorLog := "/var/log/httpd/" + sanitizeFileToken(domain) + "_error.log"
		accessLog := "/var/log/httpd/" + sanitizeFileToken(domain) + "_access.log"
		if manager == "apt" {
			errorLog = "${APACHE_LOG_DIR}/" + sanitizeFileToken(domain) + "_error.log"
			accessLog = "${APACHE_LOG_DIR}/" + sanitizeFileToken(domain) + "_access.log"
		}
		wafSnippet := "    # ModSecurity belum dipasang untuk host ini"
		if modSecurityInstalled(meta, manager) {
			wafSnippet = fmt.Sprintf(`    <IfModule security2_module>
        IncludeOptional %s
    </IfModule>`, serviceVHostWAFOverridePath(meta, domain))
		}
		content := fmt.Sprintf(`<VirtualHost *:%d>
    ServerName %s
%s    DocumentRoot %s

	    <Directory %s>
	        AllowOverride All
	        Require all granted
	    </Directory>

	%s

	%s

	    ErrorLog %s
	    CustomLog %s combined
</VirtualHost>
`, port, domain, aliasLine, rootPath, rootPath, wafSnippet, runtimeSnippet, errorLog, accessLog)
		return content, nil
	case "nginx":
		serverNames := domain
		if len(aliases) > 0 {
			serverNames += " " + strings.Join(aliases, " ")
		}
		indexValue := "index.html"
		if appRuntime == "php" {
			indexValue = "index.php index.html"
		}
		runtimeSnippet := nginxRuntimeSnippet(appRuntime, manager)
		wafSnippet := "    # ModSecurity belum dipasang untuk host ini"
		if modSecurityInstalled(meta, manager) && nginxModSecurityModuleAvailable() {
			wafSnippet = fmt.Sprintf(`    modsecurity on;
    modsecurity_rules_file %s;`, serviceVHostWAFOverridePath(meta, domain))
		} else if modSecurityInstalled(meta, manager) {
			wafSnippet = "    # ModSecurity core installed, tetapi module connector Nginx tidak ditemui"
		}
		content := fmt.Sprintf(`server {
    listen %d;
    server_name %s;
    root %s;
    index %s;

%s

%s
}
`, port, serverNames, rootPath, indexValue, wafSnippet, runtimeSnippet)
		return content, nil
	default:
		return "", errors.New("service tidak disokong untuk virtual host")
	}
}

func writeConfigFileAsRoot(configPath, content string) error {
	tmpFile, err := os.CreateTemp("", "rimaupanel-vhost-*.conf")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpName)

	if err := os.WriteFile(tmpName, []byte(content), 0o644); err != nil {
		return err
	}
	if err := runAsRoot(nil, "mkdir", "-p", filepath.Dir(configPath)); err != nil {
		return err
	}
	if err := runAsRoot(nil, "install", "-m", "0644", tmpName, configPath); err != nil {
		return err
	}
	return nil
}

func ensureSymlinkAsRoot(targetPath, linkPath string) error {
	if err := runAsRoot(nil, "mkdir", "-p", filepath.Dir(linkPath)); err != nil {
		return err
	}
	if err := runAsRoot(nil, "ln", "-sfn", targetPath, linkPath); err != nil {
		return err
	}
	return nil
}

func removePathAsRoot(path string) error {
	return runAsRoot(nil, "rm", "-f", path)
}

func detectServiceRuntime(meta ServiceMeta, manager string) ServiceRuntime {
	candidates := serviceUnitCandidates(meta, manager)
	runtime := ServiceRuntime{
		State: "unknown",
	}
	if len(candidates) > 0 {
		runtime.Unit = candidates[0]
	}
	if !commandExists("systemctl") {
		return runtime
	}

	for _, unit := range candidates {
		loadState := strings.ToLower(strings.TrimSpace(systemctlProperty(unit, "LoadState")))
		if loadState == "" || loadState == "not-found" {
			continue
		}

		activeState := strings.ToLower(strings.TrimSpace(systemctlProperty(unit, "ActiveState")))
		if activeState == "" {
			activeState = "unknown"
		}

		runtime.Unit = unit
		runtime.State = activeState
		runtime.IsRunning = activeState == "active"
		runtime.CanControl = true
		return runtime
	}

	return runtime
}

func systemctlProperty(unit, prop string) string {
	if strings.TrimSpace(unit) == "" || strings.TrimSpace(prop) == "" {
		return ""
	}
	cmd := exec.Command("systemctl", "show", "-p", prop, "--value", unit)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

func checkServiceInstalled(meta ServiceMeta) (installed bool, canInstall bool, statusHint string) {
	manager := detectPackageManager()
	if manager != "" {
		pkgName, err := packageNameForManager(meta, manager)
		if err == nil {
			canInstall = true
			statusHint = fmt.Sprintf("Pengesanan distro: %s (package: %s)", strings.ToUpper(manager), pkgName)
			if ok, checkErr := isPackageInstalled(manager, pkgName); checkErr == nil && ok {
				return true, true, statusHint
			}
		}
	}

	for _, bin := range meta.BinaryCandidates {
		if commandExists(bin) {
			if statusHint == "" {
				statusHint = "Binary dikesan: " + bin
			}
			return true, canInstall, statusHint
		}
	}

	if statusHint == "" {
		statusHint = "Distro disokong: Debian/Ubuntu (apt) atau RedHat/Rocky (dnf/yum)."
	}
	return false, canInstall, statusHint
}

func isPackageInstalled(manager, pkgName string) (bool, error) {
	switch manager {
	case "apt":
		cmd := exec.Command("dpkg-query", "-W", "-f=${Status}", pkgName)
		out, err := cmd.Output()
		if err != nil {
			return false, nil
		}
		return strings.Contains(string(out), "install ok installed"), nil
	case "dnf", "yum":
		cmd := exec.Command("rpm", "-q", pkgName)
		if err := cmd.Run(); err != nil {
			return false, nil
		}
		return true, nil
	default:
		return false, errors.New("package manager tidak disokong")
	}
}

func runServiceAction(meta ServiceMeta, action string) error {
	if action != "start" && action != "restart" && action != "reload" && action != "stop" {
		return errors.New("aksi tidak disokong")
	}
	if !commandExists("systemctl") {
		return errors.New("systemctl tidak tersedia pada sistem ini")
	}

	manager := detectPackageManager()
	runtime := detectServiceRuntime(meta, manager)
	if runtime.Unit == "" {
		return errors.New("service unit tidak ditemui")
	}
	if !runtime.CanControl {
		return fmt.Errorf("service unit `%s` tidak dikesan oleh systemd", runtime.Unit)
	}

	if err := runAsRoot(nil, "systemctl", action, runtime.Unit); err != nil {
		return err
	}
	return nil
}

func runServiceEnableDisableAction(meta ServiceMeta, action string) error {
	if action != "enable" && action != "disable" {
		return errors.New("aksi tidak disokong")
	}
	if !commandExists("systemctl") {
		return errors.New("systemctl tidak tersedia pada sistem ini")
	}

	manager := detectPackageManager()
	runtime := detectServiceRuntime(meta, manager)
	if strings.TrimSpace(runtime.Unit) == "" {
		return errors.New("service unit tidak ditemui")
	}
	if !runtime.CanControl {
		return fmt.Errorf("service unit `%s` tidak dikesan oleh systemd", runtime.Unit)
	}
	if err := runAsRoot(nil, "systemctl", action, runtime.Unit); err != nil {
		return err
	}
	return nil
}

func runServiceConfigTest(meta ServiceMeta) (string, error) {
	type testCmd struct {
		name string
		args []string
	}
	candidates := []testCmd{}
	switch meta.Key {
	case "apache":
		candidates = []testCmd{
			{name: "apachectl", args: []string{"configtest"}},
			{name: "apache2ctl", args: []string{"configtest"}},
			{name: "httpd", args: []string{"-t"}},
		}
	case "nginx":
		candidates = []testCmd{
			{name: "nginx", args: []string{"-t"}},
		}
	default:
		return "", errors.New("service tidak disokong untuk semakan config")
	}

	errs := make([]string, 0, len(candidates))
	for _, c := range candidates {
		cmdPath, lookErr := exec.LookPath(c.name)
		if lookErr != nil {
			continue
		}
		out, err := exec.Command(cmdPath, c.args...).CombinedOutput()
		output := strings.TrimSpace(string(out))
		if err == nil {
			return output, nil
		}

		// Sesetengah distro perlukan root untuk `nginx -t` atau `apachectl configtest`.
		rootOut, rootErr := runAsRootWithOutput(nil, cmdPath, c.args...)
		if rootErr == nil {
			return strings.TrimSpace(rootOut), nil
		}

		if output == "" {
			output = err.Error()
		}
		errs = append(errs, fmt.Sprintf("%s %s: %s", cmdPath, strings.Join(c.args, " "), truncateString(output, 160)))
		errs = append(errs, fmt.Sprintf("root %s %s: %s", cmdPath, strings.Join(c.args, " "), truncateString(rootErr.Error(), 160)))
	}
	if len(errs) == 0 {
		return "", errors.New("command semakan config tidak ditemui")
	}
	return "", errors.New(strings.Join(errs, " | "))
}

func currentServiceStatusNotice(meta ServiceMeta) (string, error) {
	installed, _, _ := checkServiceInstalled(meta)
	if !installed {
		return "", errors.New(meta.Name + " belum dipasang")
	}

	manager := detectPackageManager()
	runtime := detectServiceRuntime(meta, manager)
	unit := runtime.Unit
	if strings.TrimSpace(unit) == "" {
		unit = serviceUnitForManager(meta, manager)
	}
	state := runtime.State
	if strings.TrimSpace(state) == "" {
		state = "unknown"
	}

	if runtime.IsRunning {
		return fmt.Sprintf("Status %s: running (unit: %s, state: %s).", meta.Name, unit, state), nil
	}
	return fmt.Sprintf("Status %s: not running (unit: %s, state: %s).", meta.Name, unit, state), nil
}

func installServicePackage(meta ServiceMeta) error {
	manager := detectPackageManager()
	if manager == "" {
		return errors.New("distro tidak disokong. Guna Debian/Ubuntu atau RedHat/Rocky Linux")
	}

	pkgName, err := packageNameForManager(meta, manager)
	if err != nil {
		return err
	}
	return installPackages(manager, []string{pkgName})
}

func installPackages(manager string, pkgs []string) error {
	if len(pkgs) == 0 {
		return errors.New("tiada pakej untuk dipasang")
	}
	switch manager {
	case "apt":
		if err := runAsRoot(nil, "apt-get", "update"); err != nil {
			return err
		}
		args := append([]string{"install", "-y"}, pkgs...)
		if err := runAsRoot([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", args...); err != nil {
			return err
		}
	case "dnf":
		args := append([]string{"install", "-y"}, pkgs...)
		if err := runAsRoot(nil, "dnf", args...); err != nil {
			return err
		}
	case "yum":
		args := append([]string{"install", "-y"}, pkgs...)
		if err := runAsRoot(nil, "yum", args...); err != nil {
			return err
		}
	default:
		return errors.New("package manager tidak disokong")
	}
	return nil
}

func runAsRoot(extraEnv []string, name string, args ...string) error {
	_, err := runAsRootWithOutput(extraEnv, name, args...)
	return err
}

func runAsRootWithOutput(extraEnv []string, name string, args ...string) (string, error) {
	cmdName := name
	cmdArgs := args

	if os.Geteuid() != 0 {
		if !commandExists("sudo") {
			return "", errors.New("sudo tidak tersedia. perlukan akses root")
		}
		cmdName = "sudo"
		cmdArgs = append([]string{"-n", name}, args...)
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Env = append(os.Environ(), extraEnv...)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Run(); err != nil {
		logLine := truncateString(strings.TrimSpace(output.String()), 300)
		if logLine == "" {
			logLine = err.Error()
		}
		return strings.TrimSpace(output.String()), fmt.Errorf("%s gagal: %s", name, logLine)
	}
	return strings.TrimSpace(output.String()), nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func truncateString(v string, max int) string {
	if max <= 0 || len(v) <= max {
		return v
	}
	return v[:max] + "..."
}

func kernelSysctlConfigPath() string {
	return "/etc/sysctl.d/99-rimaupanel-kernel.conf"
}

func kernelTunedInstalled(manager string) bool {
	if commandExists("tuned-adm") {
		return true
	}
	if manager == "" {
		manager = detectPackageManager()
	}
	if manager != "" {
		ok, _ := isPackageInstalled(manager, "tuned")
		return ok
	}
	return false
}

func kernelTunedStatus() (bool, string, []string) {
	manager := detectPackageManager()
	installed := kernelTunedInstalled(manager)
	active := "-"
	profiles := make([]string, 0)
	if !installed || !commandExists("tuned-adm") {
		return installed, active, profiles
	}

	out, _ := exec.Command("tuned-adm", "list").CombinedOutput()
	lines := strings.Split(string(out), "\n")
	seen := map[string]struct{}{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "current active profile:") {
			if idx := strings.Index(trimmed, ":"); idx >= 0 {
				candidate := strings.TrimSpace(trimmed[idx+1:])
				if candidate != "" {
					active = candidate
				}
			}
		}
		if strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "*") {
			candidate := strings.TrimSpace(strings.TrimLeft(trimmed, "-*"))
			fields := strings.Fields(candidate)
			if len(fields) == 0 {
				continue
			}
			profile := strings.TrimSpace(fields[0])
			if !tunedProfilePattern.MatchString(profile) {
				continue
			}
			if _, ok := seen[profile]; ok {
				continue
			}
			seen[profile] = struct{}{}
			profiles = append(profiles, profile)
		}
	}

	if active == "-" {
		outActive, _ := exec.Command("tuned-adm", "active").CombinedOutput()
		line := strings.TrimSpace(string(outActive))
		if idx := strings.Index(line, ":"); idx >= 0 {
			candidate := strings.TrimSpace(line[idx+1:])
			if candidate != "" && !strings.Contains(strings.ToLower(candidate), "no current") {
				active = candidate
			}
		}
	}

	if len(profiles) == 0 {
		profiles = []string{
			"balanced",
			"throughput-performance",
			"latency-performance",
			"network-throughput",
			"virtual-guest",
		}
	}
	return installed, active, profiles
}

func defaultKernelConfig() KernelConfig {
	return KernelConfig{
		Swappiness:          10,
		DirtyRatio:          15,
		DirtyBackground:     5,
		Somaxconn:           4096,
		TCPFinTimeout:       15,
		TCPKeepaliveTime:    600,
		TCPMaxSynBacklog:    8192,
		LocalPortRangeStart: 10240,
		LocalPortRangeEnd:   65535,
		PIDMax:              4194304,
	}
}

func readKernelRuntimeConfig() KernelConfig {
	cfg := defaultKernelConfig()
	cfg.Swappiness = readSysctlInt("vm.swappiness", cfg.Swappiness)
	cfg.DirtyRatio = readSysctlInt("vm.dirty_ratio", cfg.DirtyRatio)
	cfg.DirtyBackground = readSysctlInt("vm.dirty_background_ratio", cfg.DirtyBackground)
	cfg.Somaxconn = readSysctlInt("net.core.somaxconn", cfg.Somaxconn)
	cfg.TCPFinTimeout = readSysctlInt("net.ipv4.tcp_fin_timeout", cfg.TCPFinTimeout)
	cfg.TCPKeepaliveTime = readSysctlInt("net.ipv4.tcp_keepalive_time", cfg.TCPKeepaliveTime)
	cfg.TCPMaxSynBacklog = readSysctlInt("net.ipv4.tcp_max_syn_backlog", cfg.TCPMaxSynBacklog)
	cfg.PIDMax = readSysctlInt("kernel.pid_max", cfg.PIDMax)
	start, end := readSysctlRange("net.ipv4.ip_local_port_range", cfg.LocalPortRangeStart, cfg.LocalPortRangeEnd)
	cfg.LocalPortRangeStart = start
	cfg.LocalPortRangeEnd = end
	validated, err := validateKernelConfig(cfg)
	if err != nil {
		return defaultKernelConfig()
	}
	return validated
}

func readSysctlInt(key string, fallback int) int {
	if !commandExists("sysctl") {
		return fallback
	}
	out, err := exec.Command("sysctl", "-n", key).CombinedOutput()
	if err != nil {
		return fallback
	}
	n, convErr := strconv.Atoi(strings.TrimSpace(string(out)))
	if convErr != nil {
		return fallback
	}
	return n
}

func readSysctlRange(key string, fallbackStart, fallbackEnd int) (int, int) {
	if !commandExists("sysctl") {
		return fallbackStart, fallbackEnd
	}
	out, err := exec.Command("sysctl", "-n", key).CombinedOutput()
	if err != nil {
		return fallbackStart, fallbackEnd
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return fallbackStart, fallbackEnd
	}
	start, errStart := strconv.Atoi(fields[0])
	end, errEnd := strconv.Atoi(fields[1])
	if errStart != nil || errEnd != nil {
		return fallbackStart, fallbackEnd
	}
	return start, end
}

func validateKernelConfig(cfg KernelConfig) (KernelConfig, error) {
	if cfg.Swappiness < 0 || cfg.Swappiness > 100 {
		return cfg, errors.New("Swappiness mesti antara 0 hingga 100")
	}
	if cfg.DirtyBackground < 1 || cfg.DirtyBackground > 50 {
		return cfg, errors.New("dirty_background_ratio mesti antara 1 hingga 50")
	}
	if cfg.DirtyRatio < 1 || cfg.DirtyRatio > 90 {
		return cfg, errors.New("dirty_ratio mesti antara 1 hingga 90")
	}
	if cfg.DirtyRatio <= cfg.DirtyBackground {
		return cfg, errors.New("dirty_ratio mesti lebih besar daripada dirty_background_ratio")
	}
	if cfg.Somaxconn < 128 || cfg.Somaxconn > 65535 {
		return cfg, errors.New("somaxconn mesti antara 128 hingga 65535")
	}
	if cfg.TCPFinTimeout < 5 || cfg.TCPFinTimeout > 180 {
		return cfg, errors.New("tcp_fin_timeout mesti antara 5 hingga 180")
	}
	if cfg.TCPKeepaliveTime < 60 || cfg.TCPKeepaliveTime > 7200 {
		return cfg, errors.New("tcp_keepalive_time mesti antara 60 hingga 7200")
	}
	if cfg.TCPMaxSynBacklog < 512 || cfg.TCPMaxSynBacklog > 262144 {
		return cfg, errors.New("tcp_max_syn_backlog mesti antara 512 hingga 262144")
	}
	if cfg.LocalPortRangeStart < 1024 || cfg.LocalPortRangeStart > 65534 {
		return cfg, errors.New("local_port_start mesti antara 1024 hingga 65534")
	}
	if cfg.LocalPortRangeEnd <= cfg.LocalPortRangeStart || cfg.LocalPortRangeEnd > 65535 {
		return cfg, errors.New("local_port_end mesti lebih besar dari local_port_start dan <= 65535")
	}
	if cfg.PIDMax < 32768 || cfg.PIDMax > 4194304 {
		return cfg, errors.New("pid_max mesti antara 32768 hingga 4194304")
	}
	return cfg, nil
}

func buildKernelConfigContent(cfg KernelConfig) string {
	return fmt.Sprintf(`# RimauPanel kernel tuning (tanpa compile kernel)
vm.swappiness=%d
vm.dirty_ratio=%d
vm.dirty_background_ratio=%d
net.core.somaxconn=%d
net.ipv4.tcp_fin_timeout=%d
net.ipv4.tcp_keepalive_time=%d
net.ipv4.tcp_max_syn_backlog=%d
net.ipv4.ip_local_port_range=%d %d
kernel.pid_max=%d
`, cfg.Swappiness, cfg.DirtyRatio, cfg.DirtyBackground, cfg.Somaxconn, cfg.TCPFinTimeout,
		cfg.TCPKeepaliveTime, cfg.TCPMaxSynBacklog, cfg.LocalPortRangeStart, cfg.LocalPortRangeEnd, cfg.PIDMax)
}

func applyKernelConfig(cfg KernelConfig) error {
	validated, err := validateKernelConfig(cfg)
	if err != nil {
		return err
	}
	path := kernelSysctlConfigPath()
	if err := writeConfigFileAsRoot(path, buildKernelConfigContent(validated)); err != nil {
		return err
	}
	if !commandExists("sysctl") {
		return errors.New("sysctl tidak ditemui pada sistem")
	}
	if err := runAsRoot(nil, "sysctl", "-p", path); err != nil {
		return err
	}
	return nil
}

func kernelPresetConfig(name string) (KernelConfig, string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "balanced":
		return defaultKernelConfig(), "Balanced", nil
	case "web-latency":
		return KernelConfig{
			Swappiness:          5,
			DirtyRatio:          12,
			DirtyBackground:     3,
			Somaxconn:           8192,
			TCPFinTimeout:       15,
			TCPKeepaliveTime:    300,
			TCPMaxSynBacklog:    16384,
			LocalPortRangeStart: 10240,
			LocalPortRangeEnd:   65535,
			PIDMax:              4194304,
		}, "Web Low Latency", nil
	case "network-throughput":
		return KernelConfig{
			Swappiness:          10,
			DirtyRatio:          20,
			DirtyBackground:     7,
			Somaxconn:           16384,
			TCPFinTimeout:       20,
			TCPKeepaliveTime:    600,
			TCPMaxSynBacklog:    32768,
			LocalPortRangeStart: 10000,
			LocalPortRangeEnd:   65535,
			PIDMax:              4194304,
		}, "Network Throughput", nil
	default:
		return KernelConfig{}, "", errors.New("Preset kernel tidak disokong")
	}
}

func kernelOptimizeSuggestions() []string {
	return []string{
		"Gunakan tuned-adm profile untuk tukar optimasi sistem tanpa compile kernel.",
		"Naikkan `net.core.somaxconn` dan `net.ipv4.tcp_max_syn_backlog` untuk trafik web tinggi.",
		"Laraskan `vm.swappiness` rendah untuk server web supaya kurang swap.",
		"Tetapkan `net.ipv4.ip_local_port_range` lebih luas untuk sambungan keluar yang banyak.",
		"Simpan tuning dalam `/etc/sysctl.d/99-rimaupanel-kernel.conf` supaya kekal selepas reboot.",
	}
}

var malayToEnglishReplacer = strings.NewReplacer(
	"Sistem Login Pentadbiran", "Administration Login System",
	"Permintaan tidak sah.", "Invalid request.",
	"Username dan password wajib diisi.", "Username and password are required.",
	"Username atau password salah.", "Invalid username or password.",
	"Terlalu banyak percubaan login gagal. Cuba lagi dalam ", "Too many failed login attempts. Try again in ",
	"Cuba lagi dalam ", "Try again in ",
	" saat.", " seconds.",
	"Akaun login dikunci sementara.", "Login is temporarily locked.",
	"Sila tunggu sehingga kiraan tamat.", "Please wait until the countdown ends.",
	"Login sebagai", "Logged in as",
	"Status Sistem", "System Status",
	"Kernal", "Kernel",
	"Kernal Tuning Panel", "Kernel Tuning Panel",
	"Panel Tuning Kernal", "Kernel Tuning Panel",
	"Panel ini untuk optimize dan configure kernal Linux tanpa compile semula kernel.", "This panel is for optimizing and configuring the Linux kernel without recompiling it.",
	"Optimize Kernal", "Optimize Kernel",
	"Configure Kernal", "Configure Kernel",
	"Status tuned:", "tuned status:",
	"Sudah Dipasang", "Installed",
	"Belum Dipasang", "Not Installed",
	"Current active profile:", "Current active profile:",
	"Profil aktif semasa:", "Current active profile:",
	"Apply Profil", "Apply Profile",
	"Pasang tuned", "Install tuned",
	"Auto install tuned tidak tersedia untuk distro ini.", "Automatic tuned install is not available for this distro.",
	"Preset Seimbang", "Preset Balanced",
	"Apply Seimbang", "Apply Balanced",
	"Preset Web Latency Rendah", "Preset Web Low Latency",
	"Preset Throughput Rangkaian", "Preset Network Throughput",
	"Fail config:", "Config file:",
	"Pratonton:", "Preview:",
	"Preset seimbang untuk workload umum server.", "Balanced preset for general server workloads.",
	"Sesuai untuk web server latency rendah (Apache/Nginx).", "Suitable for low-latency web servers (Apache/Nginx).",
	"Optimasi network queue dan backlog untuk trafik tinggi.", "Optimizes network queue and backlog for high traffic.",
	"Cadangan optimasi tanpa compile kernel", "Optimization suggestions without compiling kernel",
	"Simpan dan Apply Kernel Config", "Save and Apply Kernel Config",
	"Maklumat OS", "OS Information",
	"Graph View Real-Time CPU dan Memory", "Real-Time CPU and Memory Graph View",
	"Digunakan", "Used",
	"Belum ada data", "No data yet",
	"Configure", "Configure",
	"Server not install", "Server not installed",
	"Server not running", "Server not running",
	"Server running", "Server running",
	"Install automatik tidak tersedia untuk distro ini.", "Automatic install is not available for this distro.",
	"Install automatik", "Automatic install",
	"Install Now", "Install Now",
	"Setting", "Settings",
	"Cadangan penting untuk Nginx configure panel.", "Important recommendations for Nginx configuration panel.",
	"Cadangan penting untuk Nginx WAF panel.", "Important recommendations for Nginx WAF panel.",
	"Cadangan penting untuk Apache WAF panel.", "Important recommendations for Apache WAF panel.",
	"Package Manager", "Package Manager",
	"Package", "Package",
	"Service Unit", "Service Unit",
	"Main Config", "Main Config",
	"Validate Config", "Validate Config",
	"Reload Service", "Reload Service",
	"Default Listen Port", "Default Listen Port",
	"Ubah Port Server", "Change Server Port",
	"Tetapan ini digunakan sebagai port default untuk virtual host baru. Anda boleh terus apply ke semua virtual host sedia ada.", "This setting is used as the default port for new virtual hosts. You can apply it to all existing virtual hosts.",
	"disimpan untuk", "saved for",
	"disimpan dan di-apply ke semua virtual host", "saved and applied to all virtual hosts",
	"Port default disimpan tetapi gagal apply ke virtual host", "Default port was saved but failed to apply to virtual host",
	"Port Server", "Server Port",
	"Apply ke semua virtual host", "Apply to all virtual hosts",
	"Simpan Port", "Save Port",
	"Direktori virtual host:", "Virtual host directory:",
	"Direktori enabled:", "Enabled directory:",
	"New Virtual Host", "New Virtual Host",
	"Alias (comma separated)", "Alias (comma separated)",
	"Document Root", "Document Root",
	"Port", "Port",
	"Pilih", "Select",
	"Simpan", "Save",
	"Aksi", "Action",
	"Created", "Created",
	"Padam", "Delete",
	"Simpan", "Save",
	"Tiada virtual host direkodkan.", "No virtual hosts recorded.",
	"Contoh konfigurasi asas:", "Basic configuration example:",
	"WAF ModSecurity + OWASP CRS", "WAF ModSecurity + OWASP CRS",
	"Config path:", "Config path:",
	"Install ModSecurity", "Install ModSecurity",
	"Install OWASP CRS", "Install OWASP CRS",
	"Virtual Host", "Virtual Host",
	"Tiada virtual host. Tambah virtual host dahulu untuk rule-level control.", "No virtual host. Add a virtual host first for rule-level control.",
	"Rule File", "Rule File",
	"Status", "Status",
	"Aksi", "Action",
	"Disable", "Disable",
	"Enable", "Enable",
	"Tiada fail rule CRS ditemui.", "No CRS rule files found.",
	"General", "General",
	"Rules", "Rules",
	"Exclusions", "Exclusions",
	"Logging", "Logging",
	"Preview", "Preview",
	"Enable ModSecurity WAF", "Enable ModSecurity WAF",
	"Paranoia Level", "Paranoia Level",
	"Inbound Score", "Inbound Score",
	"Outbound Score", "Outbound Score",
	"Request Body Limit (KB)", "Request Body Limit (KB)",
	"Enable OWASP Core Rule Set (CRS)", "Enable OWASP Core Rule Set (CRS)",
	"Custom Rules Path", "Custom Rules Path",
	"Trusted IPs / CIDR (satu baris satu nilai)", "Trusted IPs / CIDR (one value per line)",
	"Excluded Paths (satu baris satu path)", "Excluded Paths (one path per line)",
	"Enable Audit Log", "Enable Audit Log",
	"Audit Log Path", "Audit Log Path",
	"Log Level", "Log Level",
	"Generated ModSecurity Config Preview:", "Generated ModSecurity Config Preview:",
	"Save WAF Settings", "Save WAF Settings",
	"Configure Coraza (RimauPanel :8000)", "Configure Coraza (RimauPanel :8000)",
	"Coraza hanya untuk panel RimauPanel yang berjalan di port 8000.", "Coraza is only for the RimauPanel instance running on port 8000.",
	"Apply Coraza Config", "Apply Coraza Config",
	"Generated Coraza Config Preview:", "Generated Coraza Config Preview:",
	"Save Coraza Settings", "Save Coraza Settings",
	"Tukar Kata Laluan", "Change Password",
	"Kemaskini Kata Laluan", "Update Password",
	"Kembali", "Back",
	"Change Password", "Change Password",
	"Password Semasa", "Current Password",
	"Password Baru", "New Password",
	"Sahkan Password Baru", "Confirm New Password",
	"Minimum 8 aksara.", "Minimum 8 characters.",
	"Back", "Back",
	"Password semasa tidak tepat.", "Current password is incorrect.",
	"Password berjaya dikemas kini.", "Password updated successfully.",
	"Semua medan password wajib diisi.", "All password fields are required.",
	"Password baru mesti sekurang-kurangnya 8 aksara.", "New password must be at least 8 characters.",
	"Password baru terlalu panjang.", "New password is too long.",
	"Pengesahan password baru tidak sepadan.", "New password confirmation does not match.",
	"Password baru mesti berbeza daripada password lama.", "New password must be different from the current password.",
	"Gagal membaca maklumat pengguna.", "Failed to read user information.",
	"Gagal hasilkan hash password baharu.", "Failed to generate new password hash.",
	"Gagal kemas kini password.", "Failed to update password.",
	"Tiada virtual host direkodkan.", "No virtual hosts recorded.",
	"Tiada cadangan tersedia.", "No suggestions available.",
	"Tiada pakej runtime untuk distro ini.", "No runtime package available for this distro.",
	"Distro tidak disokong untuk auto install tuned.", "Distro is not supported for automatic tuned installation.",
	"tuned sudah dipasang.", "tuned is already installed.",
	"tuned berjaya dipasang.", "tuned installed successfully.",
	"tuned belum dipasang.", "tuned is not installed yet.",
	"tuned dipasang tetapi gagal aktifkan service:", "tuned was installed but failed to enable service:",
	"Profil tuned tidak sah.", "Invalid tuned profile.",
	"Gagal ubah profil tuned:", "Failed to change tuned profile:",
	"Profil tuned ditukar ke ", "tuned profile changed to ",
	"Preset kernel tidak disokong", "Unsupported kernel preset",
	"Gagal apply preset kernel:", "Failed to apply kernel preset:",
	"Preset kernel ", "Kernel preset ",
	" berjaya di-apply.", " applied successfully.",
	"Gagal apply konfigurasi kernel:", "Failed to apply kernel configuration:",
	"Konfigurasi kernel berjaya disimpan dan di-apply.", "Kernel configuration saved and applied successfully.",
	"Swappiness mesti antara 0 hingga 100", "Swappiness must be between 0 and 100",
	"dirty_background_ratio mesti antara 1 hingga 50", "dirty_background_ratio must be between 1 and 50",
	"dirty_ratio mesti antara 1 hingga 90", "dirty_ratio must be between 1 and 90",
	"dirty_ratio mesti lebih besar daripada dirty_background_ratio", "dirty_ratio must be greater than dirty_background_ratio",
	"somaxconn mesti antara 128 hingga 65535", "somaxconn must be between 128 and 65535",
	"tcp_fin_timeout mesti antara 5 hingga 180", "tcp_fin_timeout must be between 5 and 180",
	"tcp_keepalive_time mesti antara 60 hingga 7200", "tcp_keepalive_time must be between 60 and 7200",
	"tcp_max_syn_backlog mesti antara 512 hingga 262144", "tcp_max_syn_backlog must be between 512 and 262144",
	"local_port_start mesti antara 1024 hingga 65534", "local_port_start must be between 1024 and 65534",
	"local_port_end mesti lebih besar dari local_port_start dan <= 65535", "local_port_end must be greater than local_port_start and <= 65535",
	"pid_max mesti antara 32768 hingga 4194304", "pid_max must be between 32768 and 4194304",
	"Gunakan tuned-adm profile untuk tukar optimasi sistem tanpa compile kernel.", "Use tuned-adm profiles to switch system optimization without compiling the kernel.",
	"Naikkan `net.core.somaxconn` dan `net.ipv4.tcp_max_syn_backlog` untuk trafik web tinggi.", "Increase `net.core.somaxconn` and `net.ipv4.tcp_max_syn_backlog` for high web traffic.",
	"Laraskan `vm.swappiness` rendah untuk server web supaya kurang swap.", "Use lower `vm.swappiness` for web servers to reduce swap usage.",
	"Tetapkan `net.ipv4.ip_local_port_range` lebih luas untuk sambungan keluar yang banyak.", "Set a wider `net.ipv4.ip_local_port_range` for high outbound connections.",
	"Simpan tuning dalam `/etc/sysctl.d/99-rimaupanel-kernel.conf` supaya kekal selepas reboot.", "Persist tuning in `/etc/sysctl.d/99-rimaupanel-kernel.conf` so it remains after reboot.",
	"Runtime tidak sah. Pilih php/java/python/dotnet.", "Invalid runtime. Choose php/java/python/dotnet.",
	"Runtime tidak sah.", "Invalid runtime.",
	"Application runtime wajib dipilih (php/java/python/dotnet).", "Application runtime is required (php/java/python/dotnet).",
	"Virtual host wajib dipilih.", "Virtual host must be selected.",
	"Virtual host tidak ditemui.", "Virtual host not found.",
	"Virtual host berjaya ditambah. Sila klik Reload untuk aktifkan konfigurasi.", "Virtual host added successfully. Click Reload to activate configuration.",
	"Virtual host berjaya dikemas kini.", "Virtual host updated successfully.",
	"Virtual host berjaya dipadam.", "Virtual host deleted successfully.",
	"Konfigurasi ModSecurity + OWASP CRS berjaya disimpan.", "ModSecurity + OWASP CRS configuration saved successfully.",
	"ModSecurity + OWASP CRS config berjaya ditulis ke server.", "ModSecurity + OWASP CRS config written to server successfully.",
	"Coraza config panel berjaya disimpan.", "Coraza panel config saved successfully.",
	"Coraza config panel berjaya ditulis ke server.", "Coraza config written to server successfully.",
	"# Untuk Apache: pastikan modul security2/mod_security aktif.", "# For Apache: ensure security2/mod_security module is enabled.",
	"# Untuk Nginx: aktifkan `modsecurity on;` dan `modsecurity_rules_file ", "# For Nginx: enable `modsecurity on;` and `modsecurity_rules_file ",
	" pada server block.", " in the server block.",
	"# OWASP CRS path tidak ditemui", "# OWASP CRS path not found",
	"Gagal simpan", "Failed to save",
	"Gagal baca", "Failed to read",
	"Gagal apply", "Failed to apply",
	"Gagal pasang", "Failed to install",
	"Gagal padam", "Failed to delete",
	"Gagal kemas kini", "Failed to update",
	"Gagal semak", "Failed to check",
	"Gagal aktifkan", "Failed to enable",
	"berjaya dipasang", "installed successfully",
	"sudah dipasang", "already installed",
	"tidak ditemui", "not found",
	"tidak sah", "invalid",
	" wajib", " required",
	"Sila", "Please",
	"Halaman pengurusan", "Management page for",
	"Pengesanan distro", "Distro detection",
	"Distro disokong", "Supported distro",
	"Binary dikesan", "Detected binary",
	"Status ", "Status ",
	"Tiada ", "No ",
	"Ubah ", "Change ",
)

func translateMalayToEnglish(content string) string {
	return malayToEnglishReplacer.Replace(content)
}

func actionLabel(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "start":
		return "Start"
	case "restart":
		return "Restart"
	case "reload":
		return "Reload"
	case "stop":
		return "Stop"
	case "enable":
		return "Enable"
	case "disable":
		return "Disable"
	case "checkconfig":
		return "Check Config"
	default:
		return "Action"
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func parseIntWithDefault(v string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return n
}

func parseInt64WithDefault(v string, fallback int64) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func ensureVirtualHostColumns(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(virtual_hosts)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	hasRuntime := false
	for rows.Next() {
		var cid int
		var name string
		var ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, "app_runtime") {
			hasRuntime = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasRuntime {
		if _, err := db.Exec(`ALTER TABLE virtual_hosts ADD COLUMN app_runtime TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) getServiceDefaultListenPort(serviceKey string) int {
	var port int
	err := a.db.QueryRow(`SELECT default_listen_port FROM service_settings WHERE service_key = ?`, serviceKey).Scan(&port)
	if err == nil && port > 0 && port <= 65535 {
		return port
	}

	err = a.db.QueryRow(
		`SELECT listen_port FROM virtual_hosts WHERE service_key = ? ORDER BY created_at DESC LIMIT 1`,
		serviceKey,
	).Scan(&port)
	if err == nil && port > 0 && port <= 65535 {
		return port
	}
	return 80
}

func (a *App) upsertServiceSettingPort(serviceKey string, port int) error {
	if port <= 0 || port > 65535 {
		return errors.New("port tidak sah")
	}
	_, err := a.db.Exec(`
		INSERT INTO service_settings(service_key, default_listen_port, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(service_key) DO UPDATE SET
			default_listen_port=excluded.default_listen_port,
			updated_at=excluded.updated_at
	`, serviceKey, port, time.Now().Unix())
	return err
}

func (a *App) applyPortToAllVirtualHosts(meta ServiceMeta, port int) error {
	if port <= 0 || port > 65535 {
		return errors.New("port tidak sah")
	}
	vhosts, err := a.listVirtualHosts(meta.Key)
	if err != nil {
		return err
	}
	for _, vh := range vhosts {
		raw, readErr := os.ReadFile(vh.ConfigFile)
		if readErr != nil {
			return fmt.Errorf("gagal baca config %s: %w", vh.Domain, readErr)
		}
		content, rewriteErr := rewriteVirtualHostListenPort(meta, string(raw), port)
		if rewriteErr != nil {
			return fmt.Errorf("gagal ubah listen port %s: %w", vh.Domain, rewriteErr)
		}
		if err := writeConfigFileAsRoot(vh.ConfigFile, content); err != nil {
			return err
		}
	}
	if _, err := a.db.Exec(`UPDATE virtual_hosts SET listen_port = ? WHERE service_key = ?`, port, meta.Key); err != nil {
		return err
	}
	return nil
}

func rewriteVirtualHostListenPort(meta ServiceMeta, content string, port int) (string, error) {
	lines := strings.Split(content, "\n")
	replacementPort := strconv.Itoa(port)
	changed := false
	for i, line := range lines {
		switch meta.Key {
		case "apache":
			if apacheVHostListenPattern.MatchString(line) {
				lines[i] = apacheVHostListenPattern.ReplaceAllString(line, "${1}"+replacementPort+"${3}")
				changed = true
			}
		case "nginx":
			if nginxListenPortPattern.MatchString(line) {
				lines[i] = nginxListenPortPattern.ReplaceAllString(line, "${1}"+replacementPort+"${3}")
				changed = true
				continue
			}
			if nginxListenIPv6PortPattern.MatchString(line) {
				lines[i] = nginxListenIPv6PortPattern.ReplaceAllString(line, "${1}"+replacementPort+"${3}")
				changed = true
			}
		default:
			return "", errors.New("service tidak disokong")
		}
	}
	if !changed {
		return "", errors.New("directive listen tidak ditemui dalam fail config")
	}
	return strings.Join(lines, "\n"), nil
}
