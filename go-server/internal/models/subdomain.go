package models

import "time"

type Subdomain struct {
	SubdomainID uint   `gorm:"column:subdomain_id;primaryKey;autoIncrement" json:"subdomain_id"`
	DomainID    uint   `gorm:"column:domain_id;not null;index" json:"domain_id"`
	Name        string `gorm:"column:name;type:varchar(255);not null" json:"name"`
	StatusCode  int    `gorm:"column:status_code" json:"status_code"`
	TitlePage   string `gorm:"column:title_page;type:text" json:"title_page"`
	IP          string `gorm:"column:ip;type:varchar(45)" json:"ip"`
	IsAlive     bool   `gorm:"column:is_alive;not null;default:false" json:"is_alive"`

	Domain       Domain       `gorm:"foreignKey:DomainID;references:DomainID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"domain"`
	Technologies []Technology `gorm:"many2many:subdomain_technologies;joinForeignKey:SubdomainID;joinReferences:TechnologyID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"technologies,omitempty"`
	CreatedAt    time.Time    `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time    `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

type SubdomainTechnology struct {
	SubdomainID  uint `gorm:"column:subdomain_id;primaryKey"`
	TechnologyID uint `gorm:"column:technology_id;primaryKey"`
}

func (Subdomain) TableName() string {
	return "subdomains"
}

func (SubdomainTechnology) TableName() string {
	return "subdomain_technologies"
}
