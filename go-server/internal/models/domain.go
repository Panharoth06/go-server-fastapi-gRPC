package models

import (
	"time"

	"github.com/google/uuid"
)

type Domain struct {
	DomainID        uint       `json:"domain_id"`
	UserID          uuid.UUID  `json:"user_id"`
	Name            string     `json:"name"`
	ScannedAt       *time.Time `json:"scanned_at,omitempty"`
	CountSubdomains int        `json:"count_subdomains"`

	Subdomains []Subdomain `json:"subdomains,omitempty"`
}
