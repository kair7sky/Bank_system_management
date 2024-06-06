package main

import (
	"Bank_system_management/config"
	"Bank_system_management/models"
	"log"
	"net/http"
	"strconv"
	"time"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func GenerateToken(userID uint) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Issuer:    "bank-system-management",
		Subject:   strconv.Itoa(int(userID)), // сохранение только числового идентификатора
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("secret"))
	return tokenString, err
}

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Удаление префикса "Bearer "
		tokenString = tokenString[len("Bearer "):]

		token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		claims := token.Claims.(*jwt.StandardClaims)
		userID, err := strconv.Atoi(claims.Subject) // преобразование Subject обратно в число
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		var user models.User
		if err := config.DB.First(&user, userID).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading.env file:", err)
	}

	config.InitDB()
	config.AutoMigrate(&models.User{}, &models.Transaction{})

	router := gin.Default()
	router.POST("/auth/login", LoginUser)
	router.POST("/auth/register", RegisterUser)

	authRouter := router.Group("/").Use(JWTMiddleware())
	authRouter.POST("/transaction", CreateTransaction)
	authRouter.POST("/withdraw", Withdraw)
	authRouter.POST("/deposit", Deposit)
	authRouter.GET("/transaction/history", TransactionHistory)
	authRouter.GET("/user/access/:id", UserAccess)
	authRouter.GET("/user/details/:id", UserDetails)
	authRouter.PUT("/user/update/:id", UpdateUserInfo)
	authRouter.DELETE("/user/:id", DeleteUser)

	router.Run(":8080")
}

func RegisterUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	if err := config.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	token, err := GenerateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	c.Header("Authorization", "Bearer "+token)
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func LoginUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var dbUser models.User
	if err := config.DB.Where("email = ?", user.Email).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	token, err := GenerateToken(dbUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	c.Header("Authorization", "Bearer "+token)
	c.JSON(http.StatusOK, gin.H{"token": token})
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
