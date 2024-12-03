package main

import (
    "bytes"
    "crypto/x509"
    "encoding/asn1"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "strings"
    "sync"
    "time"
)

var verboseLogging = true // Set to true for verbose logging, false to disable

type CTLogEntry struct {
    LeafInput string `json:"leaf_input"`
}

type CTLogResponse struct {
    Entries []CTLogEntry `json:"entries"`
}

func fetchCTLogEntries(logURL string, start int, end int) ([]CTLogEntry, error) {
    url := fmt.Sprintf("%s?start=%d&end=%d", logURL, start, end)
    resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("error making request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    var logResponse CTLogResponse
    err = json.NewDecoder(resp.Body).Decode(&logResponse)
    if err != nil {
        return nil, fmt.Errorf("error decoding response: %w", err)
    }
    return logResponse.Entries, nil
}

func loadZones(filePath string) ([]string, error) {
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("error reading zones file: %w", err)
    }

    var zones []string
    err = json.Unmarshal(data, &zones)
    if err != nil {
        return nil, fmt.Errorf("error parsing zones file: %w", err)
    }
    return zones, nil
}

func matchesZone(certData []byte, zones []string) bool {
    for _, zone := range zones {
        if bytes.Contains(certData, []byte(zone)) {
            return true
        }
    }
    return false
}

func isValidCertData(data []byte) bool {
    // Add validation logic as needed
    return true // Placeholder
}

func extractCertMetadata(certData []byte) (string, []string, error) {
    if verboseLogging {
        log.Printf("Full certificate data: %x", certData)
    }

    // Try to decode as PEM first
    block, _ := pem.Decode(certData)
    if block != nil {
        if verboseLogging {
            log.Printf("PEM block found, type: %s", block.Type)
        }
        certData = block.Bytes
    } else {
        if verboseLogging {
            log.Printf("No PEM block found, assuming DER format")
        }
    }

    // Attempt to parse the certificate as DER
    cert, err := x509.ParseCertificate(certData)
    if err != nil {
        if verboseLogging {
            log.Printf("Failed to parse certificate as DER: %v", err)
        }
        // Try to parse the certificate as a raw ASN.1 structure
        var raw asn1.RawValue
        _, err = asn1.Unmarshal(certData, &raw)
        if err != nil {
            if verboseLogging {
                log.Printf("Failed to unmarshal ASN.1 data: %v", err)
            }
            return "", nil, fmt.Errorf("failed to parse certificate: %w", err)
        }

        if verboseLogging {
            log.Printf("Successfully unmarshaled ASN.1 data")
        }

        // If parsing is successful but it's not a certificate we recognize, return an error
        return "", nil, fmt.Errorf("unrecognized certificate data format")
    }

    return cert.Subject.CommonName, cert.DNSNames, nil
}

func worker(logURL string, zones []string, batchSize int, jobs <-chan int, results chan<- []CTLogEntry, wg *sync.WaitGroup) {
    defer wg.Done()
    for start := range jobs {
        end := start + batchSize
        log.Printf("Fetching entries from %d to %d...", start, end)
        entries, err := fetchCTLogEntries(logURL, start, end)
        if err != nil {
            log.Printf("Error fetching CT log entries: %v", err)
            continue
        }

        var matchingEntries []CTLogEntry
        for _, entry := range entries {
            certData, err := base64.StdEncoding.DecodeString(entry.LeafInput)
            if err != nil {
                log.Printf("Error decoding base64 leaf input: %v", err)
                continue
            }

            if verboseLogging {
                log.Printf("Decoded certificate data: %x", certData[:30]) // Log first 30 bytes for inspection
                log.Printf("Full certificate data: %x", certData)
            }

            cn, sans, err := extractCertMetadata(certData)
            if err != nil {
                log.Printf("Skipping unrecognized certificate format: %v", err)
                continue
            }

            if verboseLogging {
                log.Printf("Certificate CN: %s, SANs: %v", cn, sans)
            }

            if matchesZone([]byte(cn), zones) || matchesZone([]byte(strings.Join(sans, " ")), zones) {
                log.Printf("Certificate matches zone: CN=%s, SANs=%v", cn, sans)
                matchingEntries = append(matchingEntries, entry)
            } else {
                log.Printf("Certificate does not match any zone: CN=%s, SANs=%v", cn, sans)
            }
        }
        results <- matchingEntries
    }
}

func main() {
    const ctLogURL = "https://ct.googleapis.com/logs/argon2023/ct/v1/get-entries"
    const batchSize = 500000
    const zonesFile = "zones.json"
    const outputFile = "output.json"
    const threadCount = 500

    zones, err := loadZones(zonesFile)
    if err != nil {
        log.Fatalf("Error loading zones: %v", err)
    }

    jobs := make(chan int, threadCount)
    results := make(chan []CTLogEntry, threadCount)
    var wg sync.WaitGroup

    for i := 0; i < threadCount; i++ {
        wg.Add(1)
        go worker(ctLogURL, zones, batchSize, jobs, results, &wg)
    }

    go func() {
        start := 0
        for {
            jobs <- start
            start += batchSize
            time.Sleep(1 * time.Second) // To avoid overwhelming the server.
        }
    }()
    go func() {
        wg.Wait()
        close(jobs)
        close(results)
    }()

    var matchingEntries []CTLogEntry
    for result := range results {
        matchingEntries = append(matchingEntries, result...)
    }

    log.Printf("Found %d matching entries.", len(matchingEntries))

    jsonData, err := json.MarshalIndent(matchingEntries, "", "  ")
    if err != nil {
        log.Fatalf("Error marshaling JSON: %v", err)
    }

    err = ioutil.WriteFile(outputFile, jsonData, 0644)
    if err != nil {
        log.Fatalf("Error writing output file: %v", err)
    }
}