package models

import "time"

type Subdomain struct {
	SubdomainID uint   `json:"subdomain_id"`
	DomainID    uint   `json:"domain_id"`
	Name        string `json:"name"`
	StatusCode  int    `json:"status_code"`
	TitlePage   string `json:"title_page"`
	IP          string `json:"ip"`
	IsAlive     bool   `json:"is_alive"`

	Domain       Domain       `json:"domain"`
	Technologies []Technology `json:"technologies,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

type SubdomainTechnology struct {
	SubdomainID  uint `json:"subdomain_id"`
	TechnologyID uint `json:"technology_id"`

	Subdomain  Subdomain  `json:"-"`
	Technology Technology `json:"-"`
}
