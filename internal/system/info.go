package system

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Info menyimpan ringkasan status sistem untuk dipaparkan di dashboard.
type Info struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemUsed    uint64  `json:"mem_used"`
	MemTotal   uint64  `json:"mem_total"`
	MemPercent float64 `json:"mem_percent"`
	NetRXBytes uint64  `json:"net_rx_bytes"`
	NetTXBytes uint64  `json:"net_tx_bytes"`
	OSName     string  `json:"os_name"`
	Kernel     string  `json:"kernel"`
	Hostname   string  `json:"hostname"`
	Uptime     string  `json:"uptime"`
}

// Collect membaca status CPU, memory dan maklumat OS untuk Linux.
func Collect() (Info, error) {
	hostname, _ := os.Hostname()

	osName := runtime.GOOS
	if prettyName, err := readOSPrettyName(); err == nil && prettyName != "" {
		osName = prettyName
	}

	kernel := "N/A"
	if k, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(k))
	}

	cpuPercent, err := cpuUsagePercent()
	if err != nil {
		cpuPercent = 0
	}

	memTotal, memAvail, err := memoryStats()
	if err != nil {
		return Info{}, err
	}
	memUsed := uint64(0)
	memPercent := 0.0
	if memTotal > 0 && memAvail <= memTotal {
		memUsed = memTotal - memAvail
		memPercent = float64(memUsed) / float64(memTotal) * 100
	}

	netRXBytes, netTXBytes, err := networkStats()
	if err != nil {
		netRXBytes = 0
		netTXBytes = 0
	}

	uptime := "N/A"
	if up, err := readUptime(); err == nil {
		uptime = up
	}

	return Info{
		CPUPercent: cpuPercent,
		MemUsed:    memUsed,
		MemTotal:   memTotal,
		MemPercent: memPercent,
		NetRXBytes: netRXBytes,
		NetTXBytes: netTXBytes,
		OSName:     osName,
		Kernel:     kernel,
		Hostname:   hostname,
		Uptime:     uptime,
	}, nil
}

func networkStats() (rxTotal, txTotal uint64, err error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		// Abaikan 2 baris header.
		if lineNo <= 2 {
			continue
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}

		fields := strings.Fields(parts[1])
		// /proc/net/dev: receive(8 medan) + transmit(8 medan)
		if len(fields) < 16 {
			continue
		}

		rxBytes, convErr := strconv.ParseUint(fields[0], 10, 64)
		if convErr != nil {
			continue
		}
		txBytes, convErr := strconv.ParseUint(fields[8], 10, 64)
		if convErr != nil {
			continue
		}

		rxTotal += rxBytes
		txTotal += txBytes
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return 0, 0, scanErr
	}
	return rxTotal, txTotal, nil
}

func readOSPrettyName() (string, error) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			val := strings.TrimPrefix(line, "PRETTY_NAME=")
			val = strings.Trim(val, "\"")
			return val, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("PRETTY_NAME not found")
}

func readUptime() (string, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "", err
	}
	parts := strings.Fields(string(b))
	if len(parts) == 0 {
		return "", errors.New("invalid /proc/uptime")
	}
	secondsFloat, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return "", err
	}
	seconds := int64(secondsFloat)
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60

	if days > 0 {
		return fmt.Sprintf("%d hari %d jam %d minit", days, hours, minutes), nil
	}
	return fmt.Sprintf("%d jam %d minit", hours, minutes), nil
}

func memoryStats() (total, available uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			v, convErr := strconv.ParseUint(fields[1], 10, 64)
			if convErr != nil {
				return 0, 0, convErr
			}
			total = v * 1024
		case "MemAvailable:":
			v, convErr := strconv.ParseUint(fields[1], 10, 64)
			if convErr != nil {
				return 0, 0, convErr
			}
			available = v * 1024
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return 0, 0, scanErr
	}
	if total == 0 {
		return 0, 0, errors.New("MemTotal tidak ditemui")
	}
	return total, available, nil
}

func cpuUsagePercent() (float64, error) {
	idle1, total1, err := readCPUStat()
	if err != nil {
		return 0, err
	}
	time.Sleep(200 * time.Millisecond)
	idle2, total2, err := readCPUStat()
	if err != nil {
		return 0, err
	}

	deltaIdle := idle2 - idle1
	deltaTotal := total2 - total1
	if deltaTotal == 0 {
		return 0, nil
	}

	usage := (1 - float64(deltaIdle)/float64(deltaTotal)) * 100
	if usage < 0 {
		usage = 0
	}
	if usage > 100 {
		usage = 100
	}
	return usage, nil
}

func readCPUStat() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return 0, 0, err
		}
		return 0, 0, errors.New("/proc/stat kosong")
	}
	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, errors.New("format /proc/stat tidak sah")
	}

	values := make([]uint64, 0, len(fields)-1)
	for _, f := range fields[1:] {
		v, convErr := strconv.ParseUint(f, 10, 64)
		if convErr != nil {
			return 0, 0, convErr
		}
		values = append(values, v)
		total += v
	}

	idle = values[3]
	if len(values) > 4 {
		idle += values[4] // iowait
	}
	return idle, total, nil
}
