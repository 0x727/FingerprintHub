package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"gopkg.in/yaml.v2"
)


type Finger struct {
	Path           string            `yaml:"path"`
	StatusCode     int               `yaml:"status_code"`
	Headers        map[string]string `yaml:"headers"`
	RequestHeaders map[string]string `yaml:"request_headers"`
	RequestMethod  string            `yaml:"request_method"`
	Keyword        []string          `yaml:"keyword"`
	FaviconHash    []string          `yaml:"favicon_hash"`
	Priority       int               `yaml:"priority"`
}


type FingerInfo struct {
	Name        string   `yaml:"name"`
	Fingerprint []Finger `yaml:"fingerprint"`
}


func readYamlFile(path string)(finger FingerInfo){
	content, err := ioutil.ReadFile(path)
	if err != nil{
		return finger
	}
	err = yaml.Unmarshal(content,&finger)
	if err != nil{
		return finger
	}
	return finger
}

func main() {
	var Fingerprints  []FingerInfo
	path, _ := os.Getwd()
	path = filepath.Join(path,"../../fingerprint")
	files,err := os.ReadDir(path)
	if err != nil{
		log.Fatalln(err)
		return
	}

	for _,file := range files{
		if file.IsDir(){
			continue
		}

		yamlPath := filepath.Join(path,file.Name())
		if filepath.Ext(yamlPath) != ".yaml"{
			continue
		}

		Fingerprints = append(Fingerprints, readYamlFile(yamlPath))
	}

	result , _ := json.Marshal(Fingerprints)
	ioutil.WriteFile("../../web_fingerprint_v2.json",result,0777)
}