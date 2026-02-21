package models

import "time"

type Technology struct {
	TechnologyID uint   `gorm:"column:technology_id;primaryKey;autoIncrement" json:"technology_id"`
	Name         string `gorm:"column:name;type:varchar(255);not null;index:idx_technologies_name_version,priority:1" json:"name"`
	Version      string `gorm:"column:version;type:varchar(100);index:idx_technologies_name_version,priority:2" json:"version"`

	Subdomains []Subdomain `gorm:"many2many:subdomain_technologies;joinForeignKey:TechnologyID;joinReferences:SubdomainID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"subdomains,omitempty"`
	CreatedAt  time.Time   `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt  time.Time   `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

func (Technology) TableName() string {
	return "technologies"
}
