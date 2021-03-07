package api

import (
	"github.com/gin-gonic/gin"
	"log"
	"login/pkg/login"
	"net/http"
)

var (
	router = gin.Default()
)

func Init() {

	router.POST("/api/login/", login.Login)
	router.POST("/token/refresh/", login.Refresh)
	router.POST("/api/todo/", login.TokenAuthMiddleware(), CreateTodo)
	router.POST("/logout/", login.TokenAuthMiddleware(), login.Logout)
	log.Fatal(router.Run(":8080"))
}

type Todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
}

func CreateTodo(c *gin.Context) {
	var td *Todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	tokenAuth, err := login.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userId, err := login.FetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = userId

	//you can proceed to save the Todo to a database
	//but we will just return it to the caller here:
	c.JSON(http.StatusCreated, td)
}
