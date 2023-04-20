/**
* Downloads the open-cvdb repository and parses the vulnerability data into a csv file.
*
* @Author: Jochen van Wylick
* @Date: 2023-04-19
 */

package main

import (
	"os"
	"time"

	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"gopkg.in/yaml.v3"
)

// Struct reflecting vulnerabitly data as can be
// found in the open-cvdb repository:
// https://github.com/wiz-sec/open-cvdb/tree/main/vulnerabilities
type Vulnerability struct {
	Title             string   `yaml:"title"`
	Severity          string   `yaml:"severity"`
	AffectedPlatforms []string `yaml:"affectedPlatforms,flow"`
	PublishedAt       string   `yaml:"publishedAt"`
	DisclosedAt       string   `yaml:"disclosedAt"`
	URL               string   // Enriched field
	SpecURL           string   // Enriched field
}

const (
	openvdbRepo       = "https://github.com/wiz-sec/open-cvdb"
	vulnDefRepoFolder = "/vulnerabilities"
	outputFilePostfix = "_vulnerabilities.csv"
)

func main() {
	log.SetOutput(os.Stdout)

	tmp_folder := "tmp/data"
	data_folder := tmp_folder + vulnDefRepoFolder
	// https://pkg.go.dev/time#pkg-constants - for reference
	// Golang time formatting is a bit different from other languages it seems
	YYYYMMDD_format := "20060102"
	filename := fmt.Sprintf("%s%s", time.Now().Format(YYYYMMDD_format), outputFilePostfix)

	cleanUp(tmp_folder)
	getVulns(openvdbRepo, tmp_folder)
	vulns := parseVulns(data_folder)
	storeVulns(vulns, filename)
	cleanUp(tmp_folder)

	log.Printf("All done!")
}

// Removes tmp folder - holding GIT repo and vulnerability data
func cleanUp(tmp_folder string) {
	if _, err := os.Stat(tmp_folder); !os.IsNotExist(err) {
		os.RemoveAll(tmp_folder)
		log.Printf("Cleaning up ... removing tmp folder: %s", tmp_folder)
	}
}

// GIT clone of open-cvdb repository in tmp folder
func getVulns(openvdbRepo string, tmp_folder string) {
	_, err := git.PlainClone(tmp_folder, false, &git.CloneOptions{
		URL: openvdbRepo,
	})
	if err != nil {
		panic(err)
	}
	log.Printf("Cloned openvdb repository %s into %s", openvdbRepo, tmp_folder)
}

// Parses vulnerability data from yaml files into Vulnerability struct and enriches with URL and SpecURL
func parseVulns(data_folder string) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	c := 0
	_ = filepath.Walk(data_folder, func(path string, info os.FileInfo, err error) error {

		// skip directories
		if info.IsDir() {
			return nil
		}

		vuln := Vulnerability{}

		file, err := os.Open(path)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		defer file.Close()

		data, err := ioutil.ReadAll(file)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		err2 := yaml.Unmarshal(data, &vuln)

		// URL seems to be composed of FQDN + .yml filename in repo
		const webFqdn = "https://www.cloudvulndb.org/"
		suffix := strings.Replace(filepath.Base(path), ".yaml", "", -1)
		vuln.URL = webFqdn + suffix

		// Link to GitHub repo file location
		const ghFqdn = "https://raw.githubusercontent.com/wiz-sec/open-cvdb/main/vulnerabilities/"
		vuln.SpecURL = ghFqdn + filepath.Base(path)

		if err2 != nil {
			log.Fatalf("error: %v", err)
		}

		vulnerabilities = append(vulnerabilities, vuln)
		c++
		return nil
	})
	log.Printf("Parsed %d vulnerabilities from %s", c, data_folder)
	return vulnerabilities
}

// Stores vulnerability data as csv file
func storeVulns(vulnerabilities []Vulnerability, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}

	// Header
	_, err = f.WriteString("\"Title\",\"Severity\",\"Published At\",\"Diclosed At\",\"Affected CSPs\",\"URL\",\"Source\"\n")
	if err != nil {
		panic(err)
	}

	// Entries
	for _, item := range vulnerabilities {
		_, err = f.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
			item.Title, item.Severity, item.PublishedAt, item.DisclosedAt, strings.Join(item.AffectedPlatforms, ","), item.URL, item.SpecURL))
		if err != nil {
			panic(err)
		}
	}
	path, _ := filepath.Abs(filename)
	log.Printf("Stored vulnerabilities as csv to %s (%s)", filename, path)
	defer f.Close()
}
