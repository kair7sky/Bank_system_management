package main

import (
	"Bank_system_management/config"
	"Bank_system_management/models"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// main - точка входа в приложение
func main() {
	// Загрузка переменных окружения из .env файла
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}

	// Инициализация базы данных
	config.InitDB()

	// Автоматическая миграция моделей
	config.AutoMigrate(&models.User{}, &models.Transaction{})

	// Инициализация маршрутизатора Gin
	router := gin.Default()

	// Определение маршрутов и обработчиков
	router.POST("/register", RegisterUser)
	router.POST("/login", LoginUser)
	router.POST("/transaction", CreateTransaction)
	router.POST("/withdraw", Withdraw)
	router.POST("/deposit", Deposit)
	router.GET("/transaction/history", TransactionHistory)
	router.GET("/user/access/:id", UserAccess)
	router.GET("/user/details/:id", UserDetails)
	router.PUT("/user/update/:id", UpdateUserInfo)
	router.DELETE("/user/:id", DeleteUser)

	// Запуск сервера
	router.Run(":8080")
}

// HashPassword hashes the given password using bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash compares a plain password with a hashed password.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// RegisterUser - обработчик для регистрации нового пользователя
func RegisterUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash the password before saving
	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = hashedPassword

	if err := config.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

// LoginUser - обработчик для входа пользователя
func LoginUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var dbUser models.User
	if err := config.DB.Where("email = ?", user.Email).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	// Compare the hashed password with the plain password
	if !CheckPasswordHash(user.Password, dbUser.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User logged in successfully"})
}

// CreateTransaction - обработчик для создания новой транзакции
func CreateTransaction(c *gin.Context) {
	var transaction models.Transaction
	if err := c.ShouldBindJSON(&transaction); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Проверка наличия user_id в таблице users
	var user models.User
	if err := config.DB.First(&user, transaction.UserID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}

	if err := config.DB.Create(&transaction).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Transaction created successfully"})
}

// Withdraw - обработчик для снятия средств
func Withdraw(c *gin.Context) {
	var transaction models.Transaction
	if err := c.ShouldBindJSON(&transaction); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Проверка наличия user_id в таблице users
	var user models.User
	if err := config.DB.First(&user, transaction.UserID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	if user.Balance < transaction.Amount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient funds"})
		return
	}

	user.Balance -= transaction.Amount
	transaction.Type = "withdrawal"

	if err := config.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user balance"})
		return
	}

	if err := config.DB.Create(&transaction).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Withdrawal successful"})
}

// Deposit - обработчик для внесения средств
func Deposit(c *gin.Context) {
	var transaction models.Transaction
	if err := c.ShouldBindJSON(&transaction); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Проверка наличия user_id в таблице users
	var user models.User
	if err := config.DB.First(&user, transaction.UserID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	user.Balance += transaction.Amount
	transaction.Type = "deposit"

	if err := config.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user balance"})
		return
	}

	if err := config.DB.Create(&transaction).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Deposit successful"})
}

// TransactionHistory - обработчик для получения истории транзакций
func TransactionHistory(c *gin.Context) {
	var transactions []models.Transaction
	userID := c.Query("user_id")

	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	if err := config.DB.Where("user_id = ?", userID).Find(&transactions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch transaction history"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"transactions": transactions})
}

// UserAccess - обработчик для доступа к функциям пользователя
func UserAccess(c *gin.Context) {
	action := c.Query("action")
	userID := c.Param("id")

	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	switch action {
	case "view":
		c.JSON(http.StatusOK, gin.H{
			"name":           user.Name,
			"account_number": user.AccountNumber,
			"balance":        user.Balance,
			"email":          user.Email,
			"phone":          user.PhoneNumber,
		})
	case "update":
		var updatedInfo struct {
			Email       string `json:"email"`
			PhoneNumber string `json:"phone_number"`
		}

		if err := c.ShouldBindJSON(&updatedInfo); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user.Email = updatedInfo.Email
		user.PhoneNumber = updatedInfo.PhoneNumber

		if err := config.DB.Save(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user information"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User information updated successfully"})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action"})
	}
}

// UserDetails - обработчик для получения информации о пользователе
func UserDetails(c *gin.Context) {
	userID := c.Param("id")
	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":           user.Name,
		"account_number": user.AccountNumber,
		"balance":        user.Balance,
		"email":          user.Email,
		"phone":          user.PhoneNumber,
	})
}

// UpdateUserInfo - обработчик для обновления информации о пользователе
func UpdateUserInfo(c *gin.Context) {
	userID := c.Param("id")
	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	var updatedInfo struct {
		Email       string `json:"email"`
		PhoneNumber string `json:"phone_number"`
	}

	if err := c.ShouldBindJSON(&updatedInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user.Email = updatedInfo.Email
	user.PhoneNumber = updatedInfo.PhoneNumber

	if err := config.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user information"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User information updated successfully"})
}

// DeleteUser - обработчик для удаления пользователя
func DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	if err := config.DB.Delete(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}
