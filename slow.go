package main

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "sync"
    "time"
)

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

            if matchesZone(certData, zones) {
                matchingEntries = append(matchingEntries, entry)
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

    jobs := make(chan int, 100)
    results := make(chan []CTLogEntry, 100)
    var wg sync.WaitGroup

    for w := 1; w <= threadCount; w++ {
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
        close(jobs)
    }()

    go func() {
        wg.Wait()
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

    log.Printf("Matching certificates saved to %s", outputFile)
}
