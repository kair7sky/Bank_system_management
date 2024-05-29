package models

import (
	"gorm.io/gorm"
)

// User представляет пользователя системы
type User struct {
	gorm.Model
	Name        string    `json:"name"`
	Email       string    `json:"email" gorm:"unique"`
	Password    string    `json:"password"`
	PhoneNumber string    `json:"phone_number"`
	Accounts    []Account `json:"accounts" gorm:"foreignKey:UserID"`
}

// Account представляет банковский счет пользователя
type Account struct {
	gorm.Model
	AccountNumber string        `json:"account_number"`
	Balance       float64       `json:"balance"`
	UserID        uint          `json:"user_id"`
	User          User          `json:"user"`
	Transactions  []Transaction `json:"transactions" gorm:"foreignKey:AccountID"`
}

// Transaction представляет транзакцию на счете
type Transaction struct {
	gorm.Model
	AccountID uint    `json:"account_id"`
	Amount    float64 `json:"amount"`
	Type      string  `json:"type"` // "withdrawal" или "deposit"
}
