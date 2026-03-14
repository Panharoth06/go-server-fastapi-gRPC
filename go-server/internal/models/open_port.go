package models

import "time"

type OpenPort struct {
	OpenPortID      uint      `json:"open_port_id"`
	Port            int       `json:"port"`
	ServiceName     string    `json:"service_name"`
	ServiceVersion  string    `json:"service_version"`
	OperatingSystem string    `json:"operating_system"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
