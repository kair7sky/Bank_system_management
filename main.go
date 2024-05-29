package main

import (
    "log"
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    "Bank_system_management/config"
    "Bank_system_management/models"
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
    config.AutoMigrate(&models.User{}, &models.Account{}, &models.Transaction{})

    // Инициализация маршрутизатора Gin
    router := gin.Default()

    // Определение маршрутов и обработчиков
    router.POST("/register", RegisterUser)
    router.POST("/login", LoginUser)
    router.GET("/accounts", GetAccounts)
    router.POST("/transaction", CreateTransaction)
    router.POST("/withdraw", Withdraw)
    router.POST("/deposit", Deposit)
    router.GET("/transaction/history", TransactionHistory)
    router.GET("/account/access/:id", AccountAccess)
    router.GET("/account/details/:id", AccountDetails)
    router.PUT("/account/update/:id", UpdateInfo)
    router.DELETE("/account/:id", DeleteAccount)

    // Запуск сервера
    router.Run(":8080")
}

// RegisterUser - обработчик для регистрации нового пользователя
func RegisterUser(c *gin.Context) {
    var user models.User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
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
    // Проверка пароля здесь (добавьте сравнение хэшированного пароля)
    if user.Password != dbUser.Password {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "User logged in successfully"})
}

// GetAccounts - обработчик для получения всех аккаунтов
func GetAccounts(c *gin.Context) {
    var accounts []models.Account
    if err := config.DB.Find(&accounts).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"accounts": accounts})
}

// CreateTransaction - обработчик для создания новой транзакции
func CreateTransaction(c *gin.Context) {
    var transaction models.Transaction
    if err := c.ShouldBindJSON(&transaction); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

    var account models.Account
    if err := config.DB.First(&account, transaction.AccountID).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Account not found"})
        return
    }

    if account.Balance < transaction.Amount {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient funds"})
        return
    }

    account.Balance -= transaction.Amount
    transaction.Type = "withdrawal"

    if err := config.DB.Save(&account).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update account balance"})
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

    var account models.Account
    if err := config.DB.First(&account, transaction.AccountID).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Account not found"})
        return
    }

    account.Balance += transaction.Amount
    transaction.Type = "deposit"

    if err := config.DB.Save(&account).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update account balance"})
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
    accountID := c.Query("account_id")

    if err := config.DB.Where("account_id = ?", accountID).Find(&transactions).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch transaction history"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"transactions": transactions})
}

// AccountAccess - обработчик для доступа к функциям аккаунта
func AccountAccess(c *gin.Context) {
    // Здесь вы можете реализовать логику выбора различных действий в зависимости от запроса
    c.JSON(http.StatusOK, gin.H{"message": "Account access endpoint"})
}

// AccountDetails - обработчик для получения информации об аккаунте
func AccountDetails(c *gin.Context) {
    accountID := c.Param("id")
    var account models.Account
    if err := config.DB.Preload("User").First(&account, accountID).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Account not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "name":           account.User.Name,
        "account_number": account.AccountNumber,
        "balance":        account.Balance,
        "email":          account.User.Email,
        "phone":          account.User.PhoneNumber,
    })
}

// UpdateInfo - обработчик для обновления информации об аккаунте
func UpdateInfo(c *gin.Context) {
    accountID := c.Param("id")
    var account models.Account
    if err := config.DB.Preload("User").First(&account, accountID).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Account not found"})
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

    account.User.Email = updatedInfo.Email
    account.User.PhoneNumber = updatedInfo.PhoneNumber

    if err := config.DB.Save(&account.User).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user information"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "User information updated successfully"})
}

// DeleteAccount - обработчик для удаления аккаунта
func DeleteAccount(c *gin.Context) {
    accountID := c.Param("id")
    var account models.Account
    if err := config.DB.First(&account, accountID).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Account not found"})
        return
    }

    if err := config.DB.Delete(&account).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete account"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Account deleted successfully"})
}
