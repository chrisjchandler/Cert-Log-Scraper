package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type CTLog struct {
	Description string `json:"description"`
	LogID       string `json:"log_id"`
	Key         string `json:"key"`
	URL         string `json:"url"`
	MMD         int    `json:"mmd"`
	State       LogState `json:"state"`
}

type LogState struct {
	Usable   *Timestamp `json:"usable,omitempty"`
	Rejected *Timestamp `json:"rejected,omitempty"`
	Retired  *Timestamp `json:"retired,omitempty"`
}

type Timestamp struct {
	Timestamp string `json:"timestamp"`
}

type CTLogList struct {
	Operators []Operator `json:"operators"`
}

type Operator struct {
	Name string `json:"name"`
	Logs []CTLog `json:"logs"`
}

func main() {
	filePath := "all_logs_list.json"
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	var logList CTLogList
	err = json.Unmarshal(byteValue, &logList)
	if err != nil {
		log.Fatalf("Error parsing CT log list: %v", err)
	}

	for _, operator := range logList.Operators {
		fmt.Printf("Operator: %s\n", operator.Name)
		for _, log := range operator.Logs {
			fmt.Printf("\tLog Description: %s\n", log.Description)
			fmt.Printf("\tLog URL: %s\n", log.URL)
			if log.State.Usable != nil {
				fmt.Printf("\tLog Usable Since: %s\n", log.State.Usable.Timestamp)
			}
			if log.State.Rejected != nil {
				fmt.Printf("\tLog Rejected Since: %s\n", log.State.Rejected.Timestamp)
			}
			if log.State.Retired != nil {
				fmt.Printf("\tLog Retired Since: %s\n", log.State.Retired.Timestamp)
			}
		}
	}
}

func fetchCTLog(logURL string) {
	response, err := http.Get(logURL)
	if err != nil {
		log.Printf("Error fetching CT log from %s: %v", logURL, err)
		return
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		log.Printf("Non-OK HTTP status: %d", response.StatusCode)
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return
	}

	fmt.Printf("Fetched data from %s:\n%s\n", logURL, string(body))
}
