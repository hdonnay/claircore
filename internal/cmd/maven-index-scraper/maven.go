package main

type Metadata struct {
	Group      string     `xml:"groupId"`
	Artifact   string     `xml:"artifactId"`
	Versioning Versioning `xml:"versioning"`
}
type Versioning struct {
	Latest   string     `xml:"latest"`
	Release  string     `xml:"release"`
	Versions []Versions `xml:"versions"`
}
type Versions []struct {
	Version string `xml:"version"`
}
