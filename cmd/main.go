package main

import (
	"JWT/internal/config"
	"JWT/internal/handlers"
	"JWT/internal/repo"
	"JWT/internal/service"
	"context"
	"log"

	"github.com/fvbock/endless"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	//context
	ctx := context.Background()

	//loadin and initiolazing config
	if err := godotenv.Load(); err != nil {
		log.Fatalln(".Env didn`t loaded")
	}
	conf := config.NewConfig()

	//creating router
	r := gin.Default()

	//creating pool
	conn_str := ""
	pool, err := pgxpool.New(ctx, conn_str)
	if err != nil {
		log.Fatalln("Pgx didn`t created")
	}

	UsrRepo := repo.NewUserRepo(pool)
	RefreshRepo := repo.NewRefreshRepo(pool)
	AuthUsecase := service.NewAurhService(conf, UsrRepo, RefreshRepo)

	//routing
	rg := r.Group("/auth")
	handlers.RouteAuth(rg, conf, AuthUsecase)

	//starting server with GS
	endless.ListenAndServe(":8080", r)
}
