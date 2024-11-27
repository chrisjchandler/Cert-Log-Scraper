package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
	// Placeholder for matching logic; implement based on your requirements.
	// For now, returns false always.
	return false
}

func main() {
	const ctLogURL = "https://ct.googleapis.com/logs/argon2023/ct/v1/get-entries"
	const batchSize = 100
	const zonesFile = "zones.json"
	const outputFile = "output.json"

	zones, err := loadZones(zonesFile)
	if err != nil {
		log.Fatalf("Error loading zones: %v", err)
	}

	var matchingEntries []CTLogEntry
	start := 0
	end := start + batchSize

	for {
		log.Printf("Fetching entries from %d to %d...", start, end)
		entries, err := fetchCTLogEntries(ctLogURL, start, end)
		if err != nil {
			log.Fatalf("Error fetching CT log entries: %v", err)
		}

		if len(entries) == 0 {
			log.Println("No more entries to fetch.")
			break
		}

		for _, entry := range entries {
			// Decode the leaf input from the log entry (currently base64 encoded).
			certData := []byte(entry.LeafInput) // Placeholder for decoding logic.

			if matchesZone(certData, zones) {
				matchingEntries = append(matchingEntries, entry)
			}
		}

		start = end + 1
		end = start + batchSize
		time.Sleep(1 * time.Second) // To avoid overwhelming the server.
	}

	log.Printf("Found %d matching entries.", len(matchingEntries))

	// Marshal the results to JSON and write to the output file.
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
