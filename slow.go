package main

import (
	"encoding/json"
	"github.com/CaliDog/certstream-go"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

// Struct to store the zone information
type Zone struct {
	Name string
}

func loadZones(filePath string) ([]string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var zones []string
	err = json.Unmarshal(data, &zones)
	if err != nil {
		return nil, err
	}

	return zones, nil
}

func monitorCertStream(zones []string, outputFile string) {
	// Infinite loop to ensure reconnection on EOF or other errors
	for {
		log.Println("Connecting to CertStream...")
		stream, errStream := certstream.CertStreamEventStream(false)

		for {
			select {
			case event := <-stream:
				// Access fields using `event` directly since `event` is of type `jsonq.JsonQuery`
				messageType, err := event.String("message_type")
				if err != nil {
					log.Printf("Error extracting message_type: %v", err)
					continue
				}

				if messageType == "certificate_update" {
					certData, err := event.Interface("data", "leaf_cert", "all_domains")
					if err != nil {
						log.Printf("Error extracting certificate data: %v", err)
						continue
					}

					allDomains, ok := certData.([]interface{})
					if !ok {
						log.Printf("Unexpected type for all_domains: %T", certData)
						continue
					}

					matchedDomains := []string{}
					for _, domain := range allDomains {
						domainStr, ok := domain.(string)
						if !ok {
							continue
						}
						for _, zone := range zones {
							if strings.Contains(domainStr, zone) {
								matchedDomains = append(matchedDomains, domainStr)
								break
							}
						}
					}

					if len(matchedDomains) > 0 {
						log.Printf("Match found: %v", matchedDomains)
						// Append to output.json
						appendToOutputFile(matchedDomains, outputFile)
					}
				}

			case err := <-errStream:
				log.Printf("Error reading message from CertStream: %v", err)
				log.Println("Attempting to reconnect after 5 seconds...")
				time.Sleep(5 * time.Second)
				break
			}
		}
	}
}

func appendToOutputFile(data []string, outputFile string) {
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening output file: %v", err)
		return
	}
	defer file.Close()

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling data: %v", err)
		return
	}

	_, err = file.WriteString(string(jsonData) + "\n")
	if err != nil {
		log.Printf("Error writing to output file: %v", err)
	}
}

func main() {
	const zonesFile = "zones.json"
	const outputFile = "output.json"

	zones, err := loadZones(zonesFile)
	if err != nil {
		log.Fatalf("Error loading zones: %v", err)
	}

	log.Println("Loaded zones from zones.json:", zones)
	monitorCertStream(zones, outputFile)
}
