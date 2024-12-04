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

// Struct to store the certificate information
type CertInfo struct {
    Index                int      `json:"index"`
    CertLink             string   `json:"cert_link"`
    AllDomains           []string `json:"all_domains"`
    SerialNumber         string   `json:"serial_number"`
    AuthorityInfoAccess  string   `json:"authorityInfoAccess"`
    SubjectAltName       string   `json:"subjectAltName"`
    IssuerCN             string   `json:"issuer_cn"`
    IssuerOU             string   `json:"issuer_ou"`
    NotBefore            string   `json:"not_before"`
    NotAfter             string   `json:"not_after"`
    Seen                 string   `json:"seen"`
    LogSourceName        string   `json:"log_source_name"`
    LogSourceURL         string   `json:"log_source_url"`
    UpdateType           string   `json:"update_type"`
    MessageType          string   `json:"message_type"`
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

                        // Extract additional fields
                        certIndex, _ := event.Int("data", "cert_index")
                        certLink, _ := event.String("data", "cert_link")
                        authorityInfoAccess, _ := event.String("data", "leaf_cert", "extensions", "authorityInfoAccess")
                        subjectAltName, _ := event.String("data", "leaf_cert", "extensions", "subjectAltName")
                        issuerCN, _ := event.String("data", "leaf_cert", "issuer", "CN")
                        issuerOU, _ := event.String("data", "leaf_cert", "issuer", "OU")
                        notBeforeInt, _ := event.Int("data", "leaf_cert", "not_before")
                        notAfterInt, _ := event.Int("data", "leaf_cert", "not_after")
                        seenFloat, _ := event.Float("data", "seen")
                        logSourceName, _ := event.String("data", "source", "name")
                        logSourceURL, _ := event.String("data", "source", "url")
                        updateType, _ := event.String("update_type")
                        serialNumber, _ := event.String("data", "leaf_cert", "serial_number")

                        // Convert Unix timestamps to human-readable format
                        notBefore := time.Unix(int64(notBeforeInt), 0).Format(time.RFC3339)
                        notAfter := time.Unix(int64(notAfterInt), 0).Format(time.RFC3339)
                        seen := time.Unix(int64(seenFloat), 0).Format(time.RFC3339)

                        certInfo := CertInfo{
                            Index:               certIndex,
                            CertLink:            certLink,
                            AllDomains:          matchedDomains,
                            SerialNumber:        serialNumber,
                            AuthorityInfoAccess: authorityInfoAccess,
                            SubjectAltName:      subjectAltName,
                            IssuerCN:            issuerCN,
                            IssuerOU:            issuerOU,
                            NotBefore:           notBefore,
                            NotAfter:            notAfter,
                            Seen:                seen,
                            LogSourceName:       logSourceName,
                            LogSourceURL:        logSourceURL,
                            UpdateType:          updateType,
                            MessageType:         messageType,
                        }

                        // Append to output.json
                        appendToOutputFile(certInfo, outputFile)
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

func appendToOutputFile(data CertInfo, outputFile string) {
    file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Printf("Error opening output file: %v", err)
        return
    }
    defer file.Close()

    jsonData, err := json.MarshalIndent(data, "", "  ")
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