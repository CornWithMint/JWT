package handlers

import (
	"JWT/internal/config"
	"JWT/internal/domain"
	"JWT/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(auth *service.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		user := &domain.User{}

		if err := ctx.ShouldBindJSON(user); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		Password_Hash, err := bcrypt.GenerateFromPassword([]byte(user.Password_Hash), bcrypt.DefaultCost)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		user.Password_Hash = string(Password_Hash)
		err = auth.Register(ctx, user)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		user.Password_Hash = ""

		ctx.JSON(http.StatusCreated, gin.H{
			"Created user: ": user,
		})

	}
}

func LoginHandler(auth *service.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		user := &domain.User{}

		if err := ctx.ShouldBindJSON(user); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		access, refresh, err := auth.Login(ctx, user)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		ctx.SetCookieData(&http.Cookie{
			Name:     "__Host-refresh_cookie",
			Value:    refresh,
			Path:     "/",
			MaxAge:   604800,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		ctx.JSON(http.StatusOK, gin.H{
			"access_token": access,
		})

	}
}

func Refresh(auth *service.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		refresh, err := ctx.Cookie("__Host-refresh_cookie")
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		new_access, new_refresh, err := auth.Refresh(ctx, refresh)
		if err != nil {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error": err.Error(),
			})
			ctx.SetCookieData(&http.Cookie{
				Name:  "__Host-refresh_cookie",
				Value: "",
			})
			return
		}
		ctx.SetCookieData(&http.Cookie{
			Name:     "__Host-refresh_cookie",
			Value:    new_refresh,
			Path:     "/",
			MaxAge:   604800,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		ctx.JSON(http.StatusOK, gin.H{
			"access_token": new_access,
		})

	}
}

func RouteAuth(rg *gin.RouterGroup, conf *config.Config, service *service.UserService) {
	rg.POST("/register", RegisterHandler(service))
	rg.POST("/login", LoginHandler(service))
	rg.POST("/refresh", Refresh(service))
}
