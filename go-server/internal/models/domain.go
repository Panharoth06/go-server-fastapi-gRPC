package models

import (
	"time"

	"github.com/google/uuid"
)

type Domain struct {
	DomainID        uint       `gorm:"column:domain_id;primaryKey;autoIncrement" json:"domain_id"`
	UserID          uuid.UUID  `gorm:"column:user_id;type:uuid;not null;index;uniqueIndex:uq_domains_user_name,priority:1" json:"user_id"`
	Name            string     `gorm:"column:name;type:varchar(255);not null;uniqueIndex:uq_domains_user_name,priority:2" json:"name"`
	ScannedAt       *time.Time `gorm:"column:scanned_at" json:"scanned_at,omitempty"`
	CountSubdomains int        `gorm:"column:count_subdomains;not null;default:0" json:"count_subdomains"`

	Subdomains []Subdomain `gorm:"foreignKey:DomainID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"subdomains,omitempty"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

func (Domain) TableName() string {
	return "domains"
}
