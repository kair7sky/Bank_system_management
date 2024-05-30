package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name          string        `json:"name"`
	Email         string        `json:"email" gorm:"unique"`
	Password      string        `json:"password"`
	PhoneNumber   string        `json:"phone_number"`
	AccountNumber string        `json:"account_number"`
	Balance       float64       `json:"balance"`
	Transactions  []Transaction `json:"transactions" gorm:"foreignKey:UserID"`
}

type Transaction struct {
	gorm.Model
	UserID uint    `json:"user_id"`
	Amount float64 `json:"amount"`
	Type   string  `json:"type"`
}
