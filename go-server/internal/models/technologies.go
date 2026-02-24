package models

import "time"

type Technology struct {
	TechnologyID uint   `json:"technology_id"`
	Name         string `json:"name"`
	Version      string `json:"version"`

	Subdomains []Subdomain `json:"subdomains,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}
