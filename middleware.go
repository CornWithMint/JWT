package jwt

import (
	"JWT/internal/domain"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		val := ctx.GetHeader("Authorization")

		if val == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
		}

		parts := strings.Split(val, " ")
		if !strings.EqualFold(parts[0], "bearer") {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
		}

		tokenstring := parts[1]

		token, err := jwt.ParseWithClaims(tokenstring, &domain.AccessClaims{}, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "Authorization header required",
				})

			}
			return nil, errors.ErrUnsupported
		})
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
		}
		claims, ok := token.Claims.(*domain.AccessClaims)
		if !ok || !token.Valid {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
		}
		ctx.Set("user_id", claims.UserID)
		ctx.Next()
	}
}
